/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include <linux/types.h>

/* The policy of a task, kept in task local storage and copied to every task it creates.
 *
 * The map outlives PID 1 across reexec, and the programs of the previous version keep using it. Hence only
 * ever append fields: PID 1 stops storing policies in a map whose value size differs from this struct. */
struct sandbox_policy {
        __u64 namespaces_deny;  /* CLONE_NEW* flags of the namespace types that may be neither created nor joined */
        __u32 flags;            /* SANDBOX_POLICY_* */
        __u32 reserved;
};

#define SANDBOX_POLICY_RESTRICT_SUID_SGID (1U << 0)

/* The number of map and link IDs the guard hooks protect. */
#define SANDBOX_PROTECTED_MAPS_MAX 2
#define SANDBOX_PROTECTED_LINKS_MAX 16
