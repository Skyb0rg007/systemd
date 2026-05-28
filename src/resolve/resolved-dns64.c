/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* DNS64 implementation per RFC 6147 and RFC 6052.
 *
 * When a AAAA query returns no results but DNS64 is enabled on the link with a
 * configured PREF64 prefix, we fire off a secondary A query for the same name.
 * If that succeeds we synthesize AAAA records by embedding the IPv4 address
 * into the NAT64 prefix according to RFC 6052 §2.2.
 */

#include <netinet/in.h>
#include <string.h>

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "dns-type.h"
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

        if (!IN_SET(prefix_length, 32, 40, 48, 56, 64, 96))
                return -EINVAL;

        uint8_t addr[16] = {};
        const uint8_t *v4 = (const uint8_t *) &a->s_addr;

        /* Copy the NAT64 prefix bits */
        memcpy(addr, prefix->s6_addr, prefix_length / 8);

        /* Embed the IPv4 address; byte 8 is always zero */
        switch (prefix_length) {
        case 32:
                addr[4] = v4[0]; addr[5] = v4[1]; addr[6] = v4[2]; addr[7] = v4[3];
                break;
        case 40:
                addr[5] = v4[0]; addr[6] = v4[1]; addr[7] = v4[2];
                /* addr[8] = 0 (the u octet) */
                addr[9] = v4[3];
                break;
        case 48:
                addr[6] = v4[0]; addr[7] = v4[1];
                /* addr[8] = 0 */
                addr[9] = v4[2]; addr[10] = v4[3];
                break;
        case 56:
                addr[7] = v4[0];
                /* addr[8] = 0 */
                addr[9] = v4[1]; addr[10] = v4[2]; addr[11] = v4[3];
                break;
        case 64:
                /* addr[8] = 0 */
                addr[9] = v4[0]; addr[10] = v4[1]; addr[11] = v4[2]; addr[12] = v4[3];
                break;
        case 96:
                addr[12] = v4[0]; addr[13] = v4[1]; addr[14] = v4[2]; addr[15] = v4[3];
                break;
        }

        memcpy(ret->s6_addr, addr, 16);
        return 0;
}

/* Returns true if the question asks only for AAAA records (not A+AAAA). */
static bool dns_query_is_aaaa_only(DnsQuery *q) {
        DnsQuestion *question;
        DnsResourceKey *k;

        assert(q);

        question = q->question_bypass ? q->question_bypass->question : q->question_utf8;

        DNS_QUESTION_FOREACH(k, question) {
                if (k->type == DNS_TYPE_A)
                        return false;
                if (k->type == DNS_TYPE_ANY)
                        return false;
        }

        DNS_QUESTION_FOREACH(k, question)
                if (k->type == DNS_TYPE_AAAA)
                        return true;

        return false;
}

/* Returns the PREF64 prefix for the link associated with the query, or NULL. */
static Link *dns_query_get_dns64_link(DnsQuery *q) {
        assert(q);

        if (!q->manager->dns64_enabled)
                return NULL;

        Link *l = NULL;

        if (q->ifindex > 0)
                l = hashmap_get(q->manager->links, INT_TO_PTR(q->ifindex));

        if (!l) {
                /* Fall back to the link of the scope that answered (or attempted) the query. */
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

static void on_dns64_a_query_complete(DnsQuery *aux) {
        DnsQuery *q = ASSERT_PTR(aux->auxiliary_for);
        _cleanup_(dns_query_freep) DnsQuery *aux_owned = aux;

        /* Remove the auxiliary query from the parent */
        assert(q->n_auxiliary_queries > 0);
        q->n_auxiliary_queries--;
        LIST_REMOVE(auxiliary_queries, q->auxiliary_queries, aux);
        aux->auxiliary_for = NULL;

        /* Re-acquire the link to get the prefix */
        Link *l = dns_query_get_dns64_link(q);
        if (!l)
                goto fail;

        if (aux->state != DNS_TRANSACTION_SUCCESS)
                goto fail;

        /* Build the synthesized AAAA answer from the A records */
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsQuestion *question = q->question_bypass ? q->question_bypass->question : q->question_utf8;
        DnsResourceKey *key;

        DNS_QUESTION_FOREACH(key, question) {
                if (key->type != DNS_TYPE_AAAA)
                        continue;

                DnsResourceRecord *rr;
                DNS_ANSWER_FOREACH(rr, aux->answer) {
                        if (rr->key->type != DNS_TYPE_A)
                                continue;

                        struct in6_addr synth;
                        if (dns64_synthesize_aaaa(&l->dns64_prefix, l->dns64_prefix_length,
                                                   &rr->a.in_addr, &synth) < 0)
                                continue;

                        int r = dns_answer_reserve(&answer, 1);
                        if (r < 0)
                                goto fail;

                        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *aaaa = NULL;
                        aaaa = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA,
                                                            dns_resource_key_name(key));
                        if (!aaaa)
                                goto fail;

                        aaaa->aaaa.in6_addr = synth;
                        aaaa->ttl = rr->ttl;

                        r = dns_answer_add(answer, aaaa, aux->answer_family, DNS_ANSWER_CACHEABLE, NULL);
                        if (r < 0)
                                goto fail;
                }
        }

        if (dns_answer_isempty(answer))
                goto fail;

        log_debug("DNS64: synthesized %zu AAAA record(s) for %s from A records",
                  dns_answer_size(answer),
                  dns_question_first_name(question) ?: "(unknown)");

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
 * If applicable, starts a DNS64 A-record lookup and returns > 0 to
 * defer the completion of q.  Returns 0 if DNS64 does not apply and
 * the caller should proceed normally.
 */
int dns_query_dns64_redirect(DnsQuery *q, DnsTransactionState *state) {
        int r;

        assert(q);
        assert(state);

        /* Only synthesize for pure AAAA queries */
        if (!dns_query_is_aaaa_only(q))
                return 0;

        /* Don't recurse: a DNS64 auxiliary query should not itself trigger DNS64 */
        if (q->auxiliary_for)
                return 0;

        /* Don't synthesize if explicitly suppressed */
        if (FLAGS_SET(q->flags, SD_RESOLVED_NO_SYNTHESIZE))
                return 0;

        /* Only trigger on "no results" outcomes */
        if (!IN_SET(*state,
                    DNS_TRANSACTION_RCODE_FAILURE,
                    DNS_TRANSACTION_NO_SERVERS,
                    DNS_TRANSACTION_TIMEOUT,
                    DNS_TRANSACTION_ATTEMPTS_MAX_REACHED,
                    DNS_TRANSACTION_NETWORK_DOWN,
                    DNS_TRANSACTION_NOT_FOUND,
                    DNS_TRANSACTION_SUCCESS))
                return 0;

        /* For SUCCESS state, only redirect if there are no AAAA records in the answer */
        if (*state == DNS_TRANSACTION_SUCCESS) {
                DnsQuestion *question = q->question_bypass ? q->question_bypass->question
                                                           : q->question_utf8;
                DnsResourceKey *k;
                bool has_aaaa = false;

                DNS_QUESTION_FOREACH(k, question) {
                        if (k->type != DNS_TYPE_AAAA)
                                continue;
                        DnsResourceRecord *rr;
                        DNS_ANSWER_FOREACH(rr, q->answer) {
                                if (rr->key->type == DNS_TYPE_AAAA) {
                                        has_aaaa = true;
                                        break;
                                }
                        }
                        if (has_aaaa)
                                break;
                }

                if (has_aaaa)
                        return 0; /* We already have AAAA records, no need for DNS64 */
        }

        Link *l = dns_query_get_dns64_link(q);
        if (!l)
                return 0;

        /* Build an A-record question for the same name */
        const char *name = dns_question_first_name(
                q->question_bypass ? q->question_bypass->question : q->question_utf8);
        if (!name)
                return 0;

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        r = dns_question_new_address(&question_a, AF_INET, name, false);
        if (r < 0)
                return r;

        /* Flags: no search domains, no synthesize, no CNAME */
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

        log_debug("DNS64: started A-record lookup for %s on interface %d", name, l->ifindex);

        return 1; /* completion deferred */
}
