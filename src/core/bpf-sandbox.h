/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

/* What the BPF LSM programs can enforce, passed to sd-executor in ExecParameters. */
typedef enum BPFSandboxFeatures {
        BPF_SANDBOX_SUID_SGID  = 1U << 0, /* RestrictSUIDSGID= */
        BPF_SANDBOX_CLONE      = 1U << 1, /* RestrictNamespaces= for clone() and clone3() */
        BPF_SANDBOX_NAMESPACES = 1U << 2, /* RestrictNamespaces= for all ways of creating or joining namespaces */
} BPFSandboxFeatures;

/* One slot per hook, whichever variant of the program was loaded for it. The names are serialized, so
 * that the programs stay attached across reexec. */
enum {
        BPF_SANDBOX_LINK_TASK_ALLOC,
        BPF_SANDBOX_LINK_BPF_MAP,
        BPF_SANDBOX_LINK_BPF,
        BPF_SANDBOX_LINK_INODE_CREATE,
        BPF_SANDBOX_LINK_INODE_MKNOD,
        BPF_SANDBOX_LINK_INODE_SETATTR,
        BPF_SANDBOX_LINK_FILE_OPEN,
        BPF_SANDBOX_LINK_NAMESPACE_INIT,
        BPF_SANDBOX_LINK_NAMESPACE_INSTALL,
        _BPF_SANDBOX_LINK_MAX,
};

int bpf_sandbox_setup(Manager *m);
void bpf_sandbox_done(Manager *m);
int bpf_sandbox_serialize(Manager *m, FILE *f, FDSet *fds);
void bpf_sandbox_deserialize_item(Manager *m, const char *l, FDSet *fds);

/* Called by sd-executor right before execve(). Stores the policy for the calling process, which must be
 * single-threaded, in the map. */
int bpf_sandbox_apply(int map_fd, uint64_t namespaces_deny, bool restrict_suid_sgid);
