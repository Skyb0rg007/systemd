/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* DNS64 implementation per RFC 6147 and RFC 6052. */

#include <netinet/in.h>
#include <string.h>

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "in-addr-util.h"
#include "log.h"
#include "resolved-dns-query.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-synthesize.h"
#include "resolved-dns64.h"
#include "resolved-link.h"
#include "resolved-manager.h"

/*
 * RFC 6052 §2.2 address mapping.
 *
 * The IPv4 address is embedded in the IPv6 address at a position that depends
 * on the prefix length.  Bits 64–71 ("u" octet) are always zero for prefix
 * lengths < 96.
 *
 *   PL  | IPv6 layout (bytes 0-15)
 *   ----+-------------------------------------
 *   32  | prefix[0-3]  v4[0-3]  0  suffix[5-11]
 *   40  | prefix[0-4]  v4[0-2]  0  v4[3]  suffix[6-11]
 *   48  | prefix[0-5]  v4[0-1]  0  v4[2-3]  suffix[7-11]
 *   56  | prefix[0-6]  v4[0]    0  v4[1-3]  suffix[8-11]
 *   64  | prefix[0-7]           0  v4[0-3]  suffix[9-11]
 *   96  | prefix[0-11]          v4[0-3]
 */
int dns64_synthesize_aaaa(
                const struct in6_addr *prefix,
                uint8_t prefix_length,
                const struct in_addr *a,
                struct in6_addr *ret) {

        assert(prefix);
        assert(a);
        assert(ret);

        if (!dns64_prefix_length_valid(prefix_length))
                return -EINVAL;

        uint8_t addr[16] = {};
        const uint8_t *v4 = (const uint8_t *) &a->s_addr;

        memcpy(addr, prefix->s6_addr, prefix_length / 8);

        switch (prefix_length) {
        case 32:
                addr[4] = v4[0]; addr[5] = v4[1]; addr[6] = v4[2]; addr[7] = v4[3];
                break;
        case 40:
                addr[5] = v4[0]; addr[6] = v4[1]; addr[7] = v4[2];
                addr[9] = v4[3];
                break;
        case 48:
                addr[6] = v4[0]; addr[7] = v4[1];
                addr[9] = v4[2]; addr[10] = v4[3];
                break;
        case 56:
                addr[7] = v4[0];
                addr[9] = v4[1]; addr[10] = v4[2]; addr[11] = v4[3];
                break;
        case 64:
                addr[9] = v4[0]; addr[10] = v4[1]; addr[11] = v4[2]; addr[12] = v4[3];
                break;
        case 96:
                addr[12] = v4[0]; addr[13] = v4[1]; addr[14] = v4[2]; addr[15] = v4[3];
                break;
        }

        memcpy(ret->s6_addr, addr, 16);
        return 0;
}

static DnsQuestion *dns_query_question(DnsQuery *q) {
        assert(q);
        return q->question_bypass ? q->question_bypass->question : q->question_utf8;
}

/* Returns the link with DNS64 enabled for q, or NULL if DNS64 doesn't apply. */
static Link *dns_query_get_dns64_link(DnsQuery *q) {
        assert(q);

        if (!q->manager->dns64_enabled)
                return NULL;

        Link *l = NULL;

        if (q->ifindex > 0)
                l = hashmap_get(q->manager->links, INT_TO_PTR(q->ifindex));

        if (!l) {
                LIST_FOREACH(candidates_by_query, c, q->candidates) {
                        if (c->scope && c->scope->link) {
                                l = c->scope->link;
                                break;
                        }
                }
        }

        if (!l || !l->dns64_prefix_set)
                return NULL;

        return l;
}

/* Build a set of synthesized AAAA RRs from A records in source_answer, using
 * l's configured PREF64 prefix. Each AAAA RR is named after a class-IN AAAA
 * key in q's question. Returns 0 on success; *ret_answer may be NULL if no
 * synthesis was possible. */
static int dns64_build_synthesized_answer(
                DnsQuery *q,
                Link *l,
                DnsAnswer *source_answer,
                int ifindex,
                DnsAnswer **ret_answer) {

        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key;
        int r;

        assert(q);
        assert(l);
        assert(ret_answer);

        DNS_QUESTION_FOREACH(key, dns_query_question(q)) {
                if (key->class != DNS_CLASS_IN || key->type != DNS_TYPE_AAAA)
                        continue;

                DnsResourceRecord *rr;
                DNS_ANSWER_FOREACH(rr, source_answer) {
                        if (rr->key->class != DNS_CLASS_IN || rr->key->type != DNS_TYPE_A)
                                continue;

                        union in_addr_union synth;
                        if (dns64_synthesize_aaaa(&l->dns64_prefix, l->dns64_prefix_length,
                                                   &rr->a.in_addr, &synth.in6) < 0)
                                continue;

                        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *aaaa = NULL;
                        r = dns_resource_record_new_address(&aaaa, AF_INET6, &synth,
                                                            dns_resource_key_name(key));
                        if (r < 0)
                                return r;

                        /* RFC 6147 §5.1.7: TTL = min(A TTL, SOA TTL); when SOA
                         * TTL is unknown use 600s. */
                        aaaa->ttl = MIN(rr->ttl, (uint32_t) 600);

                        r = dns_answer_add_extend(&answer, aaaa, ifindex, DNS_ANSWER_CACHEABLE, NULL);
                        if (r < 0)
                                return r;
                }
        }

        *ret_answer = TAKE_PTR(answer);
        return 0;
}

static void on_dns64_a_query_complete(DnsQuery *aux) {
        DnsQuery *q = ASSERT_PTR(aux->auxiliary_for);
        _cleanup_(dns_query_freep) DnsQuery *aux_owned = aux;
        int r;

        assert(q->n_auxiliary_queries > 0);
        q->n_auxiliary_queries--;
        LIST_REMOVE(auxiliary_queries, q->auxiliary_queries, aux);
        aux->auxiliary_for = NULL;

        Link *l = dns_query_get_dns64_link(q);
        if (!l)
                goto fail;

        if (aux->state != DNS_TRANSACTION_SUCCESS)
                goto fail;

        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        r = dns64_build_synthesized_answer(q, l, aux->answer, l->ifindex, &answer);
        if (r < 0)
                goto fail;

        if (dns_answer_isempty(answer))
                goto fail;

        log_debug("DNS64: synthesized %zu AAAA record(s) from auxiliary A query",
                  dns_answer_size(answer));

        dns_query_reset_answer(q);
        q->answer = TAKE_PTR(answer);
        q->answer_rcode = DNS_RCODE_SUCCESS;
        q->answer_protocol = dns_synthesize_protocol(q->flags);
        q->answer_family = dns_synthesize_family(q->flags);
        q->answer_query_flags = SD_RESOLVED_SYNTHETIC | (aux->answer_query_flags &
                                                          (SD_RESOLVED_AUTHENTICATED |
                                                           SD_RESOLVED_CONFIDENTIAL));
        dns_query_complete(q, DNS_TRANSACTION_SUCCESS);
        return;

fail:
        dns_query_complete(q, DNS_TRANSACTION_NOT_FOUND);
}

/*
 * Called from dns_query_accept() just before dns_query_complete().
 *
 * Returns > 0 if a DNS64 auxiliary A query was started — the caller MUST
 * defer completion. Returns 0 otherwise; the caller proceeds normally.
 *
 * When the original query is a combined A+AAAA lookup and the A records are
 * already in q->answer, this function synthesizes AAAA records in place and
 * returns 0 (no extra round trip).
 */
int dns_query_dns64_redirect(DnsQuery *q, DnsTransactionState *state) {
        int r;

        assert(q);
        assert(state);

        /* A DNS64 auxiliary query must not itself trigger DNS64. */
        if (q->auxiliary_for)
                return 0;

        if (FLAGS_SET(q->flags, SD_RESOLVED_NO_SYNTHESIZE))
                return 0;

        /* RFC 6147 §5.1: only act on class-IN AAAA queries. */
        DnsQuestion *question = dns_query_question(q);
        bool has_aaaa = false;
        DnsResourceKey *k;
        DNS_QUESTION_FOREACH(k, question)
                if (k->class == DNS_CLASS_IN && k->type == DNS_TYPE_AAAA) {
                        has_aaaa = true;
                        break;
                }
        if (!has_aaaa)
                return 0;

        Link *l = dns_query_get_dns64_link(q);
        if (!l)
                return 0;

        /* RFC 6147 §5.1.2: NXDOMAIN is returned unchanged — no synthesis. */
        if (*state == DNS_TRANSACTION_NOT_FOUND)
                return 0;
        if (*state == DNS_TRANSACTION_RCODE_FAILURE && q->answer_rcode == DNS_RCODE_NXDOMAIN)
                return 0;

        /* RFC §5.1.1 + §5.1.4: if any usable (non-::ffff/96) AAAA record is in
         * the answer, do not synthesize. */
        if (*state == DNS_TRANSACTION_SUCCESS) {
                DnsResourceRecord *rr;
                DNS_ANSWER_FOREACH(rr, q->answer)
                        if (rr->key->class == DNS_CLASS_IN &&
                            rr->key->type == DNS_TYPE_AAAA &&
                            !in6_addr_is_ipv4_mapped_address(&rr->aaaa.in6_addr))
                                return 0;
        }

        /* States where the AAAA answer is effectively empty/failed and the
         * RFC asks us to attempt synthesis. */
        if (!IN_SET(*state,
                    DNS_TRANSACTION_SUCCESS,
                    DNS_TRANSACTION_RCODE_FAILURE,
                    DNS_TRANSACTION_TIMEOUT,
                    DNS_TRANSACTION_ATTEMPTS_MAX_REACHED))
                return 0;

        /* Optimization: combined A+AAAA queries already have the A records.
         * Synthesize AAAA in place and let dns_query_complete() proceed. */
        if (*state == DNS_TRANSACTION_SUCCESS) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

                r = dns64_build_synthesized_answer(q, l, q->answer, l->ifindex, &answer);
                if (r < 0)
                        return r;

                if (!dns_answer_isempty(answer)) {
                        r = dns_answer_extend(&q->answer, answer);
                        if (r < 0)
                                return r;

                        q->answer_query_flags |= SD_RESOLVED_SYNTHETIC;
                        log_debug("DNS64: synthesized %zu AAAA record(s) inline from A+AAAA answer",
                                  dns_answer_size(answer));
                        return 0; /* completion proceeds normally */
                }
        }

        const char *name = dns_question_first_name(question);
        if (!name)
                return 0;

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        r = dns_question_new_address(&question_a, AF_INET, name, false);
        if (r < 0)
                return r;

        uint64_t flags = q->flags | SD_RESOLVED_NO_SEARCH | SD_RESOLVED_NO_SYNTHESIZE;

        _cleanup_(dns_query_freep) DnsQuery *aux = NULL;
        r = dns_query_new(q->manager, &aux, question_a, question_a, NULL, l->ifindex, flags);
        if (r < 0)
                return r;

        r = dns_query_make_auxiliary(aux, q);
        if (r < 0)
                return r;

        aux->complete = on_dns64_a_query_complete;

        r = dns_query_go(aux);
        if (r < 0)
                return r;

        TAKE_PTR(aux);

        log_debug("DNS64: started auxiliary A-record lookup for %s on interface %d", name, l->ifindex);

        return 1; /* completion deferred */
}
