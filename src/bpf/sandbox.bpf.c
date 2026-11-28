/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

/* BPF LSM implementation of RestrictNamespaces= and RestrictSUIDSGID=.
 *
 * sd-executor stores the policy of a unit's processes in task local storage right before execve(), and the
 * task_alloc hook copies it to every task they create, including threads and io_uring workers. Like a seccomp
 * filter the policy hence survives execve(), applies to the whole process tree, and cannot be dropped or
 * escaped by moving to another cgroup. Unlike a seccomp filter it is checked on the operations themselves
 * rather than on system call arguments, so clone3() and openat2(), which pass their flags indirectly, don't
 * need to be blocked altogether.
 *
 * - namespace_init, namespace_install (Linux 7.4+): every way of creating a namespace (clone(), clone3(),
 *   unshare(), open_tree() and fsmount() for mount namespaces) or joining one (setns()), like Landlock's
 *   LANDLOCK_PERMISSION_NAMESPACE_USE. On older kernels sd-executor keeps the seccomp filter for unshare(),
 *   setns(), open_tree() and fsmount(), whose flags are passed directly and can be filtered exactly.
 * - task_alloc: clone() and clone3(), on all kernels.
 * - inode_create, inode_mknod, inode_setattr, file_open: creating files with the SUID/SGID bits set, or
 *   adding them to existing files.
 * - bpf_map, bpf: restricted tasks may not obtain file descriptors for our maps or links, which would allow
 *   them to change their own policy or detach the programs.
 *
 * Hook arguments are positional and some hooks gained arguments over time, hence some programs exist in
 * multiple variants. PID 1 loads the variant matching the running kernel's BTF. */

#include <errno.h>
#include <linux/bpf.h>
#include <linux/fcntl.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "sandbox-api.bpf.h"

/* Not exported to userspace. */
#define ATTR_MODE (1U << 0)

/* linux/stat.h only defines these when not building against glibc. */
#define S_ISUID 04000
#define S_ISGID 02000

typedef __u16 umode_t;

struct inode {
        umode_t i_mode;
} __attribute__((preserve_access_index));

struct dentry {
        struct inode *d_inode;
} __attribute__((preserve_access_index));

struct file {
        struct inode *f_inode;
        unsigned int f_flags;
} __attribute__((preserve_access_index));

struct iattr {
        unsigned int ia_valid;
        umode_t ia_mode;
} __attribute__((preserve_access_index));

struct ns_common {
        __u32 ns_type;
} __attribute__((preserve_access_index));

struct bpf_map {
        __u32 id;
} __attribute__((preserve_access_index));

struct mnt_idmap;
struct nsset;
struct task_struct;

struct {
        __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, int);
        __type(value, struct sandbox_policy);
} sandbox_policies SEC(".maps");

/* IDs of our maps and links, populated by PID 1 once all programs are attached. While they are 0, nothing is
 * protected, as no BPF object has ID 0. */
volatile __u32 protected_map_ids[SANDBOX_PROTECTED_MAPS_MAX];
volatile __u32 protected_link_ids[SANDBOX_PROTECTED_LINKS_MAX];

static const struct sandbox_policy *current_policy(void) {
        return bpf_task_storage_get(&sandbox_policies, bpf_get_current_task_btf(), /* value= */ NULL, /* flags= */ 0);
}

SEC("lsm/task_alloc")
int BPF_PROG(sandbox_task_alloc, struct task_struct *task, __u64 clone_flags, int ret) {
        const struct sandbox_policy *policy;
        struct sandbox_policy *child;

        if (ret != 0)
                return ret;

        policy = current_policy();
        if (!policy)
                return 0;

        /* The kernel acts on these flags, no matter whether they were passed to clone() or clone3(). With
         * the namespace_init hook this is redundant, but it refuses the request before any work is done. */
        if (clone_flags & policy->namespaces_deny)
                return -EPERM;

        /* Fail closed: a task we cannot tag would escape the policy. */
        child = bpf_task_storage_get(&sandbox_policies, task, /* value= */ NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!child)
                return -ENOMEM;

        *child = *policy;
        return 0;
}

static int check_namespace(const struct ns_common *ns) {
        const struct sandbox_policy *policy;

        policy = current_policy();
        if (!policy)
                return 0;

        /* ns_type is the CLONE_NEW* flag of the namespace type. */
        if (BPF_CORE_READ(ns, ns_type) & policy->namespaces_deny)
                return -EPERM;

        return 0;
}

/* Called for every namespace being created, before it is reachable from userspace. */
SEC("lsm/namespace_init")
int BPF_PROG(sandbox_namespace_init, struct ns_common *ns, int ret) {
        if (ret != 0)
                return ret;

        return check_namespace(ns);
}

/* Called by setns() for every namespace being joined. */
SEC("lsm/namespace_install")
int BPF_PROG(sandbox_namespace_install, const struct nsset *nsset, struct ns_common *ns, int ret) {
        if (ret != 0)
                return ret;

        return check_namespace(ns);
}

static int check_new_mode(umode_t mode) {
        const struct sandbox_policy *policy;

        if (!(mode & (S_ISUID|S_ISGID)))
                return 0;

        policy = current_policy();
        if (policy && (policy->flags & SANDBOX_POLICY_RESTRICT_SUID_SGID))
                return -EPERM;

        return 0;
}

/* open(), openat(), openat2() and creat() with O_CREAT, mknod() with S_IFREG, and the io_uring equivalents.
 * The mode is the one the file will get, i.e. after applying the umask, and with S_ISGID stripped if the
 * caller isn't a member of the owning group. Opening an existing file with O_CREAT and a SUID mode is
 * permitted, as nothing is created. */
SEC("lsm/inode_create")
int BPF_PROG(sandbox_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode, int ret) {
        if (ret != 0)
                return ret;

        return check_new_mode(mode);
}

/* Linux 7.4 added the mount idmap as first argument. */
SEC("lsm/inode_create")
int BPF_PROG(sandbox_inode_create_idmap, const struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret) {
        if (ret != 0)
                return ret;

        return check_new_mode(mode);
}

/* Device nodes, FIFOs and sockets. */
SEC("lsm/inode_mknod")
int BPF_PROG(sandbox_inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, __u32 dev, int ret) {
        if (ret != 0)
                return ret;

        return check_new_mode(mode);
}

SEC("lsm/inode_mknod")
int BPF_PROG(sandbox_inode_mknod_idmap, const struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry,
             umode_t mode, __u32 dev, int ret) {
        if (ret != 0)
                return ret;

        return check_new_mode(mode);
}

/* O_TMPFILE creates an unnamed inode without calling inode_create. It could be linked into place later. */
SEC("lsm/file_open")
int BPF_PROG(sandbox_file_open, struct file *file, int ret) {
        if (ret != 0)
                return ret;

        /* O_TMPFILE includes O_DIRECTORY, the other bit is only set when creating a file. */
        if (!(BPF_CORE_READ(file, f_flags) & (O_TMPFILE & ~O_DIRECTORY)))
                return 0;

        return check_new_mode(BPF_CORE_READ(file, f_inode, i_mode));
}

/* chmod(), fchmod(), fchmodat() and fchmodat2(). Only adding the bits is refused: when chown() or a write
 * strips the SUID bit, notify_change() passes ATTR_MODE with the remaining bits, which still include S_ISGID
 * for files without group execute permission. */
static int check_setattr(struct dentry *dentry, struct iattr *attr) {
        umode_t old;

        if (!(BPF_CORE_READ(attr, ia_valid) & ATTR_MODE))
                return 0;

        old = BPF_CORE_READ(dentry, d_inode, i_mode);
        return check_new_mode(BPF_CORE_READ(attr, ia_mode) & ~old);
}

SEC("lsm/inode_setattr")
int BPF_PROG(sandbox_inode_setattr, struct dentry *dentry, struct iattr *attr, int ret) {
        if (ret != 0)
                return ret;

        return check_setattr(dentry, attr);
}

/* Linux 6.9 added the mount idmap as first argument. */
SEC("lsm/inode_setattr")
int BPF_PROG(sandbox_inode_setattr_idmap, const struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr,
             int ret) {
        if (ret != 0)
                return ret;

        return check_setattr(dentry, attr);
}

/* Fires inside bpf_map_new_fd(), i.e. for every way of obtaining a new file descriptor for a map
 * (BPF_MAP_GET_FD_BY_ID, BPF_OBJ_GET), but not for inheriting or receiving one. */
SEC("lsm/bpf_map")
int BPF_PROG(sandbox_bpf_map, struct bpf_map *map, unsigned int fmode, int ret) {
        __u32 id;

        if (ret != 0)
                return ret;

        if (!current_policy())
                return 0;

        id = BPF_CORE_READ(map, id);
        if (id == 0)
                return 0;

        for (int i = 0; i < SANDBOX_PROTECTED_MAPS_MAX; i++)
                if (id == protected_map_ids[i])
                        return -EPERM;

        return 0;
}

/* There is no hook for obtaining link file descriptors, hence check the command. We never pin our links,
 * so BPF_LINK_GET_FD_BY_ID is the only way to obtain one. */
static int check_bpf_command(int cmd, union bpf_attr *attr) {
        __u32 id;

        if (cmd != BPF_LINK_GET_FD_BY_ID)
                return 0;

        if (!current_policy())
                return 0;

        id = BPF_CORE_READ(attr, link_id);
        if (id == 0)
                return 0;

        for (int i = 0; i < SANDBOX_PROTECTED_LINKS_MAX; i++)
                if (id == protected_link_ids[i])
                        return -EPERM;

        return 0;
}

SEC("lsm/bpf")
int BPF_PROG(sandbox_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret) {
        if (ret != 0)
                return ret;

        return check_bpf_command(cmd, attr);
}

/* Linux 6.15 added whether the command was issued by the kernel. */
SEC("lsm/bpf")
int BPF_PROG(sandbox_bpf_kernel, int cmd, union bpf_attr *attr, unsigned int size, __u8 kernel, int ret) {
        if (ret != 0)
                return ret;

        return check_bpf_command(cmd, attr);
}

static const char _license[] SEC("license") = "GPL";
