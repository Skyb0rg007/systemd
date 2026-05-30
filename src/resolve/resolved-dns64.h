/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <stdint.h>

#include "resolved-forward.h"

static inline bool dns64_prefix_length_valid(uint8_t prefix_length) {
        return IN_SET(prefix_length, 32, 40, 48, 56, 64, 96);
}

int dns64_synthesize_aaaa(
                const struct in6_addr *prefix,
                uint8_t prefix_length,
                const struct in_addr *a,
                struct in6_addr *ret);

void dns64_on_a_query_complete(DnsQuery *aux);

int dns_query_dns64_redirect(DnsQuery *q, DnsTransactionState *state);
