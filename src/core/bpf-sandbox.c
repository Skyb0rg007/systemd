/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/pidfd.h>
#include <unistd.h>

#include "bpf-sandbox.h"
#include "env-util.h"
#include "fd-util.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "process-util.h"
#include "serialize.h"
#include "string-util.h"

static const char* const bpf_sandbox_link_names[_BPF_SANDBOX_LINK_MAX] = {
        [BPF_SANDBOX_LINK_TASK_ALLOC]        = "bpf-sandbox-task-alloc-link",
        [BPF_SANDBOX_LINK_BPF_MAP]           = "bpf-sandbox-bpf-map-link",
        [BPF_SANDBOX_LINK_BPF]               = "bpf-sandbox-bpf-link",
        [BPF_SANDBOX_LINK_INODE_CREATE]      = "bpf-sandbox-inode-create-link",
        [BPF_SANDBOX_LINK_INODE_MKNOD]       = "bpf-sandbox-inode-mknod-link",
        [BPF_SANDBOX_LINK_INODE_SETATTR]     = "bpf-sandbox-inode-setattr-link",
        [BPF_SANDBOX_LINK_FILE_OPEN]         = "bpf-sandbox-file-open-link",
        [BPF_SANDBOX_LINK_NAMESPACE_INIT]    = "bpf-sandbox-namespace-init-link",
        [BPF_SANDBOX_LINK_NAMESPACE_INSTALL] = "bpf-sandbox-namespace-install-link",
};

static BPFSandboxFeatures bpf_sandbox_features_from_links(const int link_fds[static _BPF_SANDBOX_LINK_MAX]) {
        BPFSandboxFeatures features;

        /* Without these the policy is neither inherited by children nor protected from being changed. */
        if (link_fds[BPF_SANDBOX_LINK_TASK_ALLOC] < 0 ||
            link_fds[BPF_SANDBOX_LINK_BPF_MAP] < 0 ||
            link_fds[BPF_SANDBOX_LINK_BPF] < 0)
                return 0;

        features = BPF_SANDBOX_CLONE;

        if (link_fds[BPF_SANDBOX_LINK_INODE_CREATE] >= 0 &&
            link_fds[BPF_SANDBOX_LINK_INODE_MKNOD] >= 0 &&
            link_fds[BPF_SANDBOX_LINK_INODE_SETATTR] >= 0 &&
            link_fds[BPF_SANDBOX_LINK_FILE_OPEN] >= 0)
                features |= BPF_SANDBOX_SUID_SGID;

        if (link_fds[BPF_SANDBOX_LINK_NAMESPACE_INIT] >= 0 &&
            link_fds[BPF_SANDBOX_LINK_NAMESPACE_INSTALL] >= 0)
                features |= BPF_SANDBOX_NAMESPACES;

        return features;
}

static void bpf_sandbox_log_features(BPFSandboxFeatures features) {
        log_info("bpf-sandbox: RestrictSUIDSGID= is enforced via %s, RestrictNamespaces= via %s.",
                 FLAGS_SET(features, BPF_SANDBOX_SUID_SGID) ? "BPF LSM" : "seccomp",
                 FLAGS_SET(features, BPF_SANDBOX_NAMESPACES) ? "BPF LSM" :
                 FLAGS_SET(features, BPF_SANDBOX_CLONE) ? "BPF LSM for clone() and clone3(), and seccomp otherwise" :
                 "seccomp");
}

void bpf_sandbox_done(Manager *m) {
        assert(m);

        FOREACH_ELEMENT(fd, m->bpf_sandbox_link_fds)
                *fd = safe_close(*fd);

        m->bpf_sandbox_map_fd = safe_close(m->bpf_sandbox_map_fd);
        m->bpf_sandbox_features = 0;
}

int bpf_sandbox_serialize(Manager *m, FILE *f, FDSet *fds) {
        int r;

        assert(m);
        assert(f);
        assert(fds);

        /* The links stay attached as long as somebody holds them, i.e. even across reexec, and the policies
         * of the running processes live in the map. Hence pass both on, even if the new PID 1 might not use
         * them for new processes. */
        FOREACH_ELEMENT(fd, m->bpf_sandbox_link_fds) {
                r = serialize_fd(f, fds, bpf_sandbox_link_names[fd - m->bpf_sandbox_link_fds], *fd);
                if (r < 0)
                        return r;
        }

        return serialize_fd(f, fds, "bpf-sandbox-policy-map", m->bpf_sandbox_map_fd);
}

void bpf_sandbox_deserialize_item(Manager *m, const char *l, FDSet *fds) {
        const char *val;
        int fd;

        assert(m);
        assert(l);
        assert(fds);

        FOREACH_ELEMENT(name, bpf_sandbox_link_names) {
                val = startswith(l, *name);
                if (!val)
                        continue;
                val = startswith(val, "=");
                if (!val)
                        continue;

                fd = deserialize_fd(fds, val);
                if (fd < 0)
                        return (void) log_warning_errno(fd, "bpf-sandbox: Failed to deserialize FD for %s, ignoring: %m", *name);

                close_and_replace(m->bpf_sandbox_link_fds[name - bpf_sandbox_link_names], fd);
                return;
        }

        val = startswith(l, "bpf-sandbox-policy-map=");
        if (!val)
                return (void) log_notice("bpf-sandbox: Unknown serialization item '%s', ignoring.", l);

        fd = deserialize_fd(fds, val);
        if (fd < 0)
                return (void) log_warning_errno(fd, "bpf-sandbox: Failed to deserialize FD for the policy map, ignoring: %m");

        close_and_replace(m->bpf_sandbox_map_fd, fd);
}

#if BPF_FRAMEWORK
#include "bpf-util.h"
#include "sandbox-api.bpf.h"
#include "sandbox-skel.h"

assert_cc(_BPF_SANDBOX_LINK_MAX <= SANDBOX_PROTECTED_LINKS_MAX);

static struct sandbox_bpf* sandbox_bpf_free(struct sandbox_bpf *obj) {
        sandbox_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct sandbox_bpf *, sandbox_bpf_free);

/* The links indexed by slot, whichever variant of a program was loaded. */
#define SANDBOX_LINKS(obj) {                                                                                    \
        [BPF_SANDBOX_LINK_TASK_ALLOC]        = (obj)->links.sandbox_task_alloc,                                 \
        [BPF_SANDBOX_LINK_BPF_MAP]           = (obj)->links.sandbox_bpf_map,                                    \
        [BPF_SANDBOX_LINK_BPF]               = (obj)->links.sandbox_bpf ?: (obj)->links.sandbox_bpf_kernel,     \
        [BPF_SANDBOX_LINK_INODE_CREATE]      = (obj)->links.sandbox_inode_create ?:                             \
                                               (obj)->links.sandbox_inode_create_idmap,                         \
        [BPF_SANDBOX_LINK_INODE_MKNOD]       = (obj)->links.sandbox_inode_mknod ?:                              \
                                               (obj)->links.sandbox_inode_mknod_idmap,                          \
        [BPF_SANDBOX_LINK_INODE_SETATTR]     = (obj)->links.sandbox_inode_setattr ?:                            \
                                               (obj)->links.sandbox_inode_setattr_idmap,                        \
        [BPF_SANDBOX_LINK_FILE_OPEN]         = (obj)->links.sandbox_file_open,                                  \
        [BPF_SANDBOX_LINK_NAMESPACE_INIT]    = (obj)->links.sandbox_namespace_init,                             \
        [BPF_SANDBOX_LINK_NAMESPACE_INSTALL] = (obj)->links.sandbox_namespace_install,                          \
}

/* Enables the variant of each program whose number of arguments matches the hook of the running kernel.
 * Hooks the kernel lacks, or whose arguments match no variant, are left out, and so are the features that
 * depend on them. */
static int sandbox_select_programs(struct sandbox_bpf *obj, bool namespaces) {
        _cleanup_(sym_btf__freep) struct btf *btf = NULL;
        int r;

        assert(obj);

        if (!sym_btf__load_vmlinux_btf || !sym_btf__find_by_name_kind || !sym_btf__type_by_id)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "bpf-sandbox: libbpf is too old to inspect the kernel BTF.");

        btf = sym_btf__load_vmlinux_btf();
        r = bpf_get_error_translated(btf); /* libbpf < 1.0 returns error pointers, not NULL */
        if (r != 0)
                return log_debug_errno(r, "bpf-sandbox: Failed to load the kernel BTF: %m");

        const struct {
                const char *hook;
                struct bpf_program *prog;
                int nargs;
        } programs[] = {
                { "bpf_lsm_task_alloc",        obj->progs.sandbox_task_alloc,          2                  },
                { "bpf_lsm_bpf_map",           obj->progs.sandbox_bpf_map,             2                  },
                { "bpf_lsm_bpf",               obj->progs.sandbox_bpf,                 3                  },
                { "bpf_lsm_bpf",               obj->progs.sandbox_bpf_kernel,          4                  },
                { "bpf_lsm_inode_create",      obj->progs.sandbox_inode_create,        3                  },
                { "bpf_lsm_inode_create",      obj->progs.sandbox_inode_create_idmap,  4                  },
                { "bpf_lsm_inode_mknod",       obj->progs.sandbox_inode_mknod,         4                  },
                { "bpf_lsm_inode_mknod",       obj->progs.sandbox_inode_mknod_idmap,   5                  },
                { "bpf_lsm_inode_setattr",     obj->progs.sandbox_inode_setattr,       2                  },
                { "bpf_lsm_inode_setattr",     obj->progs.sandbox_inode_setattr_idmap, 3                  },
                { "bpf_lsm_file_open",         obj->progs.sandbox_file_open,           1                  },
                { "bpf_lsm_namespace_init",    obj->progs.sandbox_namespace_init,      namespaces ? 1 : -1 },
                { "bpf_lsm_namespace_install", obj->progs.sandbox_namespace_install,   namespaces ? 2 : -1 },
        };

        FOREACH_ELEMENT(p, programs) {
                int n;

                n = btf_func_nargs(btf, p->hook);
                if (n < 0 && n != -ENOENT)
                        return log_debug_errno(n, "bpf-sandbox: Failed to look up %s() in the kernel BTF: %m", p->hook);

                r = sym_bpf_program__set_autoload(p->prog, n == p->nargs);
                if (r < 0)
                        return log_debug_errno(r, "bpf-sandbox: Failed to set autoload of %s: %m",
                                               sym_bpf_program__name(p->prog));

                if (n == p->nargs)
                        log_debug("bpf-sandbox: Loading %s.", sym_bpf_program__name(p->prog));
        }

        return 0;
}

static int sandbox_load(bool namespaces, struct sandbox_bpf **ret) {
        _cleanup_(sandbox_bpf_freep) struct sandbox_bpf *obj = NULL;
        int r;

        assert(ret);

        obj = sandbox_bpf__open();
        if (!obj)
                return log_debug_errno(errno, "bpf-sandbox: Failed to open BPF object: %m");

        r = sandbox_select_programs(obj, namespaces);
        if (r < 0)
                return r;

        r = sandbox_bpf__load(obj);
        if (r < 0)
                return log_debug_errno(r, "bpf-sandbox: Failed to load BPF object%s: %m",
                                       namespaces ? "" : " without the namespace hooks");

        *ret = TAKE_PTR(obj);
        return 0;
}

static int bpf_map_get_info(int fd, struct bpf_map_info *ret) {
        uint32_t len = sizeof(*ret);

        assert(fd >= 0);
        assert(ret);

        *ret = (struct bpf_map_info) {};
        if (sym_bpf_obj_get_info_by_fd(fd, ret, &len) < 0)
                return -errno;

        return 0;
}

static int bpf_link_get_info(int fd, struct bpf_link_info *ret) {
        uint32_t len = sizeof(*ret);

        assert(fd >= 0);
        assert(ret);

        *ret = (struct bpf_link_info) {};
        if (sym_bpf_obj_get_info_by_fd(fd, ret, &len) < 0)
                return -errno;

        return 0;
}

/* Restricted processes must not obtain file descriptors for our maps and links, as they could change their
 * own policy or detach the programs. Tell the guard hooks the IDs of these objects. */
static int sandbox_populate_guard(struct sandbox_bpf *obj) {
        struct bpf_map_info map_info;
        struct bpf_link_info link_info;
        int r;

        assert(obj);

        r = bpf_map_get_info(sym_bpf_map__fd(obj->maps.sandbox_policies), &map_info);
        if (r < 0)
                return log_debug_errno(r, "bpf-sandbox: Failed to get ID of the policy map: %m");
        obj->bss->protected_map_ids[0] = map_info.id;

        /* Changing the guard's own IDs would disable it. */
        r = bpf_map_get_info(sym_bpf_map__fd(obj->maps.bss), &map_info);
        if (r < 0)
                return log_debug_errno(r, "bpf-sandbox: Failed to get ID of the .bss map: %m");
        obj->bss->protected_map_ids[1] = map_info.id;

        struct bpf_link *links[] = SANDBOX_LINKS(obj);
        assert_cc(ELEMENTSOF(links) == _BPF_SANDBOX_LINK_MAX);

        FOREACH_ELEMENT(link, links) {
                if (!*link)
                        continue;

                r = bpf_link_get_info(sym_bpf_link__fd(*link), &link_info);
                if (r < 0)
                        return log_debug_errno(r, "bpf-sandbox: Failed to get ID of %s: %m",
                                               bpf_sandbox_link_names[link - links]);

                obj->bss->protected_link_ids[link - links] = link_info.id;
        }

        return 0;
}

/* Validates the FDs a previous PID 1 passed on. The programs are attached, and running processes depend on
 * them, hence we never detach them, but only store new policies if the map is one we understand. */
static int sandbox_adopt(Manager *m) {
        struct bpf_map_info map_info;
        int r;

        assert(m);

        r = dlopen_bpf(LOG_WARNING);
        if (r < 0)
                return r;

        FOREACH_ELEMENT(fd, m->bpf_sandbox_link_fds) {
                struct bpf_link_info link_info;

                if (*fd < 0)
                        continue;

                r = bpf_link_get_info(*fd, &link_info);
                if (r < 0 || link_info.type != BPF_LINK_TYPE_TRACING || link_info.tracing.attach_type != BPF_LSM_MAC) {
                        log_warning("bpf-sandbox: Deserialized FD for %s is not an LSM BPF link, ignoring.",
                                    bpf_sandbox_link_names[fd - m->bpf_sandbox_link_fds]);
                        *fd = safe_close(*fd);
                }
        }

        if (m->bpf_sandbox_map_fd >= 0) {
                r = bpf_map_get_info(m->bpf_sandbox_map_fd, &map_info);
                if (r < 0 || map_info.type != BPF_MAP_TYPE_TASK_STORAGE || map_info.value_size != sizeof(struct sandbox_policy)) {
                        log_warning("bpf-sandbox: Deserialized policy map is not one we understand, using seccomp for new processes.");
                        m->bpf_sandbox_map_fd = safe_close(m->bpf_sandbox_map_fd);
                }
        }

        m->bpf_sandbox_features = m->bpf_sandbox_map_fd >= 0 ? bpf_sandbox_features_from_links(m->bpf_sandbox_link_fds) : 0;

        log_debug("bpf-sandbox: Recovered FDs from previous exec, programs still attached.");
        bpf_sandbox_log_features(m->bpf_sandbox_features);
        return 0;
}

int bpf_sandbox_setup(Manager *m) {
        _cleanup_(sandbox_bpf_freep) struct sandbox_bpf *obj = NULL;
        int r;

        assert(m);

        if (!MANAGER_IS_SYSTEM(m))
                return 0;

        if (m->bpf_sandbox_map_fd >= 0)
                return sandbox_adopt(m);
        FOREACH_ELEMENT(fd, m->bpf_sandbox_link_fds)
                if (*fd >= 0)
                        return sandbox_adopt(m);

        r = secure_getenv_bool("SYSTEMD_BPF_SANDBOX");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ECANCELED),
                                       "bpf-sandbox: Disabled via $SYSTEMD_BPF_SANDBOX, using seccomp.");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "bpf-sandbox: Failed to parse $SYSTEMD_BPF_SANDBOX, ignoring: %m");

        r = dlopen_bpf(LOG_DEBUG);
        if (r < 0)
                return r;

        r = lsm_supported("bpf");
        if (r == -ENOPKG)
                return log_debug_errno(r, "bpf-sandbox: securityfs not mounted, BPF LSM support not available, using seccomp.");
        if (r < 0)
                return log_debug_errno(r, "bpf-sandbox: Can't determine whether the BPF LSM module is used, using seccomp: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "bpf-sandbox: BPF LSM not enabled in the kernel, using seccomp.");

        /* The namespace hooks are new, if they are in the BTF but the verifier refuses the programs for
         * them, the other features are still useful. */
        r = sandbox_load(/* namespaces= */ true, &obj);
        if (r < 0)
                r = sandbox_load(/* namespaces= */ false, &obj);
        if (r < 0)
                return log_warning_errno(r, "bpf-sandbox: Failed to load BPF LSM programs, using seccomp: %m");

        r = sandbox_bpf__attach(obj);
        if (r < 0)
                return log_warning_errno(r, "bpf-sandbox: Failed to attach BPF LSM programs, using seccomp: %m");

        r = sandbox_populate_guard(obj);
        if (r < 0)
                return log_warning_errno(r, "bpf-sandbox: Failed to protect the BPF LSM programs, using seccomp: %m");

        /* Keep our own FDs, which keep the programs attached after the skeleton is destroyed. */
        struct bpf_link *links[] = SANDBOX_LINKS(obj);
        FOREACH_ELEMENT(link, links) {
                size_t i = link - links;

                if (!*link)
                        continue;

                m->bpf_sandbox_link_fds[i] = fcntl(sym_bpf_link__fd(*link), F_DUPFD_CLOEXEC, 3);
                if (m->bpf_sandbox_link_fds[i] < 0) {
                        r = log_warning_errno(errno, "bpf-sandbox: Failed to duplicate FD of %s, using seccomp: %m",
                                              bpf_sandbox_link_names[i]);
                        goto fail;
                }
        }

        m->bpf_sandbox_map_fd = fcntl(sym_bpf_map__fd(obj->maps.sandbox_policies), F_DUPFD_CLOEXEC, 3);
        if (m->bpf_sandbox_map_fd < 0) {
                r = log_warning_errno(errno, "bpf-sandbox: Failed to duplicate FD of the policy map, using seccomp: %m");
                goto fail;
        }

        m->bpf_sandbox_features = bpf_sandbox_features_from_links(m->bpf_sandbox_link_fds);

        log_debug("bpf-sandbox: LSM BPF programs attached.");
        bpf_sandbox_log_features(m->bpf_sandbox_features);
        return 0;

fail:
        bpf_sandbox_done(m);
        return r;
}

int bpf_sandbox_apply(int map_fd, uint64_t namespaces_deny, bool restrict_suid_sgid) {
        struct sandbox_policy policy = {};
        _cleanup_close_ int pidfd = -EBADF;
        int r;

        assert(map_fd >= 0);

        r = dlopen_bpf(LOG_DEBUG);
        if (r < 0)
                return r;

        /* Task local storage belongs to a single thread, other threads would escape the policy. */
        r = get_process_threads(0);
        if (r < 0)
                return log_debug_errno(r, "bpf-sandbox: Failed to count our threads: %m");
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "bpf-sandbox: Process has %i threads, refusing.", r);

        /* Maps of task local storage are keyed by pidfd. */
        pidfd = pidfd_open(getpid_cached(), /* flags= */ 0);
        if (pidfd < 0)
                return log_debug_errno(errno, "bpf-sandbox: Failed to open pidfd of ourselves: %m");

        /* Never loosen a policy we inherited. */
        if (sym_bpf_map_lookup_elem(map_fd, &pidfd, &policy) < 0) {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "bpf-sandbox: Failed to look up our policy: %m");

                policy = (struct sandbox_policy) {};
        }

        policy.namespaces_deny |= namespaces_deny;
        if (restrict_suid_sgid)
                policy.flags |= SANDBOX_POLICY_RESTRICT_SUID_SGID;

        if (sym_bpf_map_update_elem(map_fd, &pidfd, &policy, BPF_ANY) < 0)
                return log_debug_errno(errno, "bpf-sandbox: Failed to store our policy: %m");

        return 0;
}

#else /* ! BPF_FRAMEWORK */

int bpf_sandbox_setup(Manager *m) {
        assert(m);

        if (m->bpf_sandbox_map_fd >= 0)
                log_warning("bpf-sandbox: BPF framework is not compiled in, keeping the programs of the previous "
                            "PID 1 attached, but using seccomp for new processes.");

        return 0;
}

int bpf_sandbox_apply(int map_fd, uint64_t namespaces_deny, bool restrict_suid_sgid) {
        return -EOPNOTSUPP;
}

#endif
