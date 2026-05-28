/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <stdint.h>

#include "resolved-forward.h"

int dns64_synthesize_aaaa(
                const struct in6_addr *prefix,
                uint8_t prefix_length,
                const struct in_addr *a,
                struct in6_addr *ret);

int dns_query_dns64_redirect(DnsQuery *q, DnsTransactionState *state);
