/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/landlock.h>

#include "errno-util.h"
#include "fd-util.h"
#include "landlock-util.h"
#include "log.h"
#include "nsflags.h"

int landlock_abi_version(void) {
        int r;

        r = RET_NERRNO(landlock_create_ruleset(/* attr= */ NULL, /* size= */ 0, LANDLOCK_CREATE_RULESET_VERSION));
        /* ENOSYS if not compiled in, EOPNOTSUPP if disabled at boot, EPERM if blocked by some seccomp
         * filter of a container manager. */
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r))
                return -EOPNOTSUPP;

        return r;
}

static int landlock_check_abi(int required, const char *what) {
        int abi;

        abi = landlock_abi_version();
        if (abi == -EOPNOTSUPP)
                return log_debug_errno(abi, "Landlock is not available.");
        if (abi < 0)
                return log_debug_errno(abi, "Failed to query Landlock ABI version: %m");
        if (abi < required)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Landlock ABI version %i does not support %s (version %i required).",
                                       abi, what, required);

        return 0;
}

int landlock_ruleset_restrict_ptrace(LandlockRuleset *ruleset) {
        int r;

        assert(ruleset);

        /* Requests that a Landlock domain is enforced even if no other restriction is added to the
         * ruleset, for the ptrace restrictions every domain implies. Landlock refuses to create a ruleset
         * that handles nothing, hence such a domain handles the use of capabilities, and allows all of
         * them, which needs the same ABI version as namespace restrictions.
         *
         * Returns -EOPNOTSUPP if the running kernel's Landlock does not support this, or another negative
         * errno if the Landlock ABI version cannot be queried. In both cases the ruleset is left
         * unchanged. */

        r = landlock_check_abi(LANDLOCK_ABI_CAPABILITY_USE, "ptrace restrictions");
        if (r < 0)
                return r;

        ruleset->restrict_ptrace = true;
        return 0;
}

int landlock_ruleset_restrict_namespaces(LandlockRuleset *ruleset, unsigned long retain) {
        int r;

        assert(ruleset);

        /* Adds a restriction on creating and joining namespaces of types not in 'retain' to the ruleset.
         * Unlike the seccomp implementation this covers clone3() (whose flags seccomp cannot inspect, as
         * they are behind a pointer), as the kernel checks the actual namespace types involved.
         *
         * Returns -EOPNOTSUPP if the running kernel's Landlock does not support namespace restrictions,
         * or another negative errno if the Landlock ABI version cannot be queried. In both cases the ruleset
         * is left unchanged, so that the caller may fall back to the seccomp implementation. */

        if (FLAGS_SET(retain, NAMESPACE_FLAGS_ALL))
                return 0;

        r = landlock_check_abi(LANDLOCK_ABI_NAMESPACE_USE, "namespace restrictions");
        if (r < 0)
                return r;

        /* Landlock denies every namespace type not explicitly allowed, including types we do not know
         * about, which is what we want: any restriction also prohibits namespace types we cannot name. */
        uint64_t allowed = retain & NAMESPACE_FLAGS_ALL;

        if (FLAGS_SET(ruleset->handled_permissions, LANDLOCK_PERMISSION_NAMESPACE_USE))
                ruleset->allowed_namespace_types &= allowed;
        else {
                ruleset->handled_permissions |= LANDLOCK_PERMISSION_NAMESPACE_USE;
                ruleset->allowed_namespace_types = allowed;
        }

        return 0;
}

int landlock_ruleset_enforce(const LandlockRuleset *ruleset) {
        _cleanup_close_ int ruleset_fd = -EBADF;
        int r;

        assert(ruleset);

        /* Enforces all restrictions collected in the ruleset as a new Landlock domain on the calling thread.
         * The caller must either have no_new_privs set or CAP_SYS_ADMIN. */

        if (ruleset->handled_permissions == 0 && !ruleset->restrict_ptrace)
                return 0;

        /* If nothing else is restricted, handle the use of capabilities and allow all of them below, as a
         * ruleset that handles nothing is refused with ENOMSG. */
        bool allow_all_capabilities = ruleset->handled_permissions == 0;

        const struct landlock_ruleset_attr ruleset_attr = {
                .handled_permissions = allow_all_capabilities ? LANDLOCK_PERMISSION_CAPABILITY_USE : ruleset->handled_permissions,
        };

        ruleset_fd = RET_NERRNO(landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), /* flags= */ 0));
        if (ruleset_fd < 0)
                return log_debug_errno(ruleset_fd, "Failed to create Landlock ruleset: %m");

        if (allow_all_capabilities) {
                /* Bits above CAP_LAST_CAP are ignored by the kernel, so this allows every capability, and
                 * the domain restricts nothing but ptrace. */
                const struct landlock_capability_attr capability_attr = {
                        .permissions = LANDLOCK_PERMISSION_CAPABILITY_USE,
                        .allowed_capabilities = UINT64_MAX,
                };

                r = RET_NERRNO(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_CAPABILITY, &capability_attr, /* flags= */ 0));
                if (r < 0)
                        return log_debug_errno(r, "Failed to add Landlock capability rule: %m");
        }

        /* A rule allowing nothing is refused with ENOMSG, and is not needed: everything not allowed is
         * denied anyway. */
        if (FLAGS_SET(ruleset->handled_permissions, LANDLOCK_PERMISSION_NAMESPACE_USE) &&
            ruleset->allowed_namespace_types != 0) {
                const struct landlock_namespace_attr namespace_attr = {
                        .permissions = LANDLOCK_PERMISSION_NAMESPACE_USE,
                        .allowed_namespace_types = ruleset->allowed_namespace_types,
                };

                r = RET_NERRNO(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NAMESPACE, &namespace_attr, /* flags= */ 0));
                if (r < 0)
                        return log_debug_errno(r, "Failed to add Landlock namespace rule: %m");
        }

        r = RET_NERRNO(landlock_restrict_self(ruleset_fd, /* flags= */ 0));
        if (r == -E2BIG)
                return log_debug_errno(r, "Maximum number of stacked Landlock domains reached.");
        if (r < 0)
                return log_debug_errno(r, "Failed to enforce Landlock ruleset: %m");

        return 0;
}
