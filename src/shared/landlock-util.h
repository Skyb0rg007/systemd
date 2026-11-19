/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* First Landlock ABI version supporting LANDLOCK_PERMISSION_NAMESPACE_USE. */
#define LANDLOCK_ABI_NAMESPACE_USE 12
/* First Landlock ABI version supporting LANDLOCK_PERMISSION_CAPABILITY_USE. */
#define LANDLOCK_ABI_CAPABILITY_USE 12

/* Accumulates the restrictions requested by various callers, so that they are enforced as a single
 * Landlock domain with a single landlock_restrict_self() call. This matters because rules within one
 * domain are combined by OR (so we have to intersect restrictions of the same category ourselves) and
 * because the kernel limits how many domains may be stacked.
 *
 * Note that any Landlock domain also restricts ptrace(2) and every other operation subject to ptrace
 * access mode checks (e.g. reading /proc/PID/exe or /proc/PID/ns/) to processes in the same domain or in
 * domains nested below it, regardless of capabilities. Hence callers must only add restrictions to the
 * ruleset if that is acceptable, see landlock_ruleset_restrict_ptrace(). */
typedef struct LandlockRuleset {
        uint64_t handled_permissions;     /* LANDLOCK_PERMISSION_* */
        uint64_t allowed_namespace_types; /* CLONE_NEW*, if LANDLOCK_PERMISSION_NAMESPACE_USE is handled */
        bool restrict_ptrace;             /* Enforce a domain even if nothing else is restricted */
} LandlockRuleset;

int landlock_abi_version(void);

int landlock_ruleset_restrict_ptrace(LandlockRuleset *ruleset);
int landlock_ruleset_restrict_namespaces(LandlockRuleset *ruleset, unsigned long retain);
int landlock_ruleset_enforce(const LandlockRuleset *ruleset);
