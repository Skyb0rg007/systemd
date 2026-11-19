/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/landlock.h>

#include "libc-shim.h"

DEFINE_SYSCALL_SHIM(landlock_create_ruleset, int,
                    const struct landlock_ruleset_attr*, attr,
                    size_t, size,
                    uint32_t, flags)

DEFINE_SYSCALL_SHIM(landlock_add_rule, int,
                    int, ruleset_fd,
                    enum landlock_rule_type, rule_type,
                    const void*, rule_attr,
                    uint32_t, flags)

DEFINE_SYSCALL_SHIM(landlock_restrict_self, int,
                    int, ruleset_fd,
                    uint32_t, flags)
