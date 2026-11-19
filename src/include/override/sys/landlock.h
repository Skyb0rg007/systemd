/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/landlock.h>     /* IWYU pragma: export */
#include <stddef.h>
#include <stdint.h>

/* Not defined in glibc yet as of glibc-2.44.
 * Supported since kernel v5.13 (a49f4f81cb48925e8d7cbd9e59068f516e984144). */
int landlock_create_ruleset_shim(const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags);
#define landlock_create_ruleset landlock_create_ruleset_shim

int landlock_add_rule_shim(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags);
#define landlock_add_rule landlock_add_rule_shim

int landlock_restrict_self_shim(int ruleset_fd, uint32_t flags);
#define landlock_restrict_self landlock_restrict_self_shim
