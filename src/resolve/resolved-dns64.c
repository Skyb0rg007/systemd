/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* DNS64 implementation per RFC 6147 and RFC 6052. */

#include <netinet/in.h>
#include <string.h>

#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "in-addr-util.h"
#include "log.h"
#include "resolved-dns-query.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-synthesize.h"
#include "resolved-dns64.h"
#include "resolved-link.h"
#include "resolved-manager.h"

static const struct in6_addr dns64_well_known_prefix = {
        .s6_addr = { 0x00, 0x64, 0xff, 0x9b },
};

bool dns64_prefix_valid(const struct in6_addr *prefix, uint8_t prefix_length) {
        assert(prefix);

        if (!dns64_prefix_length_valid(prefix_length) ||
            (prefix_length == 96 && prefix->s6_addr[8] != 0))
                return false;

        return prefix_length == 96 ||
                memcmp(prefix, &dns64_well_known_prefix, prefix_length / 8) != 0;
}

/* RFC 6052 §2.2 address mapping. Bits 64–71 (the "u" octet) are skipped. */
int dns64_synthesize_aaaa(
                const struct in6_addr *prefix,
                uint8_t prefix_length,
                const struct in_addr *a,
                struct in6_addr *ret) {

        assert(prefix);
        assert(a);
        assert(ret);

        if (!dns64_prefix_valid(prefix, prefix_length))
                return -EINVAL;

        struct in6_addr result = {};
        const uint8_t *v4 = (const uint8_t *) &a->s_addr;
        size_t offset = prefix_length / 8;

        memcpy(result.s6_addr, prefix->s6_addr, offset);
        for (size_t i = 0; i < 4; i++) {
                if (offset == 8)
                        offset++;
                result.s6_addr[offset++] = v4[i];
        }

        *ret = result;
        return 0;
}

/* Inverse of dns64_synthesize_aaaa(): if addr falls under prefix/prefix_length, extract the embedded IPv4
 * address (RFC 6052 §2.2). Returns -ENXIO if addr is not a valid DNS64 address for this prefix. All valid
 * prefix lengths are byte-aligned, hence the prefix match is a plain byte comparison. */
int dns64_extract_ipv4(
                const struct in6_addr *prefix,
                uint8_t prefix_length,
                const struct in6_addr *addr,
                struct in_addr *ret) {

        assert(prefix);
        assert(addr);
        assert(ret);

        if (!dns64_prefix_valid(prefix, prefix_length))
                return -EINVAL;

        if (memcmp(prefix->s6_addr, addr->s6_addr, prefix_length / 8) != 0)
                return -ENXIO;

        /* RFC 6052 §2.2: the "u" octet (byte 8) must be zero for prefix lengths shorter than 96. */
        if (prefix_length < 96 && addr->s6_addr[8] != 0)
                return -ENXIO;

        uint8_t *v4 = (uint8_t*) &ret->s_addr;
        size_t offset = prefix_length / 8;
        for (size_t i = 0; i < 4; i++) {
                if (offset == 8)
                        offset++;
                v4[i] = addr->s6_addr[offset++];
        }

        return 0;
}

static DnsQuestion *dns_query_question(DnsQuery *q) {
        assert(q);

        DnsQuestion *question = dns_query_question_for_protocol(q, q->answer_protocol);
        return question ?: q->question_utf8;
}

/* Returns the DNS64-enabled link with the given ifindex, or NULL if DNS64
 * doesn't apply to it. */
static Link *dns64_enabled_link(Manager *m, int ifindex) {
        assert(m);

        if (!m->dns64_enabled || ifindex <= 0)
                return NULL;

        Link *l = hashmap_get(m->links, INT_TO_PTR(ifindex));
        if (!l || l->n_dns64_prefixes == 0)
                return NULL;

        return l;
}

/* Returns the link whose PREF64 should be used to synthesize for q, or NULL if
 * DNS64 doesn't apply. answer_scope is the scope that actually resolved the
 * query (may be NULL when no scope produced an answer). */
static Link *dns_query_get_dns64_link(DnsQuery *q, DnsScope *answer_scope) {
        assert(q);

        if (!q->manager->dns64_enabled)
                return NULL;

        Link *l = NULL;

        if (q->ifindex > 0)
                l = hashmap_get(q->manager->links, INT_TO_PTR(q->ifindex));
        if (!l && answer_scope)
                l = answer_scope->link;

        if (!l || l->n_dns64_prefixes == 0)
                return NULL;

        return l;
}

static bool dns64_answer_item_is_in_answer_section(const DnsAnswerItem *item) {
        assert(item);

        return (item->flags & DNS_ANSWER_MASK_SECTIONS) == 0 ||
                FLAGS_SET(item->flags, DNS_ANSWER_SECTION_ANSWER);
}

static bool dns64_prefix_is_well_known(const Dns64Prefix *prefix) {
        assert(prefix);

        return prefix->length == 96 &&
                memcmp(&prefix->address, &dns64_well_known_prefix, 12) == 0;
}

static bool dns64_well_known_prefix_supports_address(const struct in_addr *address) {
        uint32_t a;

        assert(address);

        a = be32toh(address->s_addr);
        return
                (a & UINT32_C(0xff000000)) != UINT32_C(0x00000000) && /* 0/8 */
                (a & UINT32_C(0xff000000)) != UINT32_C(0x0a000000) && /* 10/8 */
                (a & UINT32_C(0xffc00000)) != UINT32_C(0x64400000) && /* 100.64/10 */
                (a & UINT32_C(0xff000000)) != UINT32_C(0x7f000000) && /* 127/8 */
                (a & UINT32_C(0xffff0000)) != UINT32_C(0xa9fe0000) && /* 169.254/16 */
                (a & UINT32_C(0xfff00000)) != UINT32_C(0xac100000) && /* 172.16/12 */
                (a & UINT32_C(0xffffff00)) != UINT32_C(0xc0000000) && /* 192.0.0/24 */
                (a & UINT32_C(0xffffff00)) != UINT32_C(0xc0000200) && /* 192.0.2/24 */
                (a & UINT32_C(0xffffff00)) != UINT32_C(0xc0586300) && /* 192.88.99/24 */
                (a & UINT32_C(0xffff0000)) != UINT32_C(0xc0a80000) && /* 192.168/16 */
                (a & UINT32_C(0xfffe0000)) != UINT32_C(0xc6120000) && /* 198.18/15 */
                (a & UINT32_C(0xffffff00)) != UINT32_C(0xc6336400) && /* 198.51.100/24 */
                (a & UINT32_C(0xffffff00)) != UINT32_C(0xcb007100) && /* 203.0.113/24 */
                a < UINT32_C(0xe0000000);                            /* 224/3 */
}

static bool dns64_aaaa_is_excluded(DnsResourceRecord *rr) {
        assert(rr);

        return rr->key->class == DNS_CLASS_IN &&
                rr->key->type == DNS_TYPE_AAAA &&
                in6_addr_is_ipv4_mapped_address(&rr->aaaa.in6_addr);
}

static int dns64_strip_excluded_aaaa(DnsAnswer **answer) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *filtered = NULL;
        DnsAnswerItem *item;
        bool changed = false;
        int r;

        assert(answer);

        DNS_ANSWER_FOREACH_ITEM(item, *answer) {
                if (dns64_answer_item_is_in_answer_section(item) &&
                    dns64_aaaa_is_excluded(item->rr)) {
                        changed = true;
                        continue;
                }

                r = dns_answer_add_extend(&filtered, item->rr, item->ifindex, item->flags, item->rrsig);
                if (r < 0)
                        return r;
        }

        if (!changed)
                return 0;

        DNS_ANSWER_REPLACE(*answer, TAKE_PTR(filtered));
        return 1;
}

static bool dns64_answer_has_usable_aaaa(DnsAnswer *answer) {
        DnsAnswerItem *item;

        DNS_ANSWER_FOREACH_ITEM(item, answer)
                if (dns64_answer_item_is_in_answer_section(item) &&
                    item->rr->key->class == DNS_CLASS_IN &&
                    item->rr->key->type == DNS_TYPE_AAAA &&
                    !dns64_aaaa_is_excluded(item->rr))
                        return true;

        return false;
}

static size_t dns64_answer_count_usable_aaaa(DnsAnswer *answer) {
        DnsAnswerItem *item;
        size_t n = 0;

        DNS_ANSWER_FOREACH_ITEM(item, answer)
                if (dns64_answer_item_is_in_answer_section(item) &&
                    item->rr->key->class == DNS_CLASS_IN &&
                    item->rr->key->type == DNS_TYPE_AAAA &&
                    !dns64_aaaa_is_excluded(item->rr))
                        n++;

        return n;
}

static int dns64_copy_cname_dname(DnsAnswer **answer, DnsAnswer *source) {
        DnsAnswerItem *item;
        int r;

        assert(answer);

        DNS_ANSWER_FOREACH_ITEM(item, source) {
                if (!dns64_answer_item_is_in_answer_section(item) ||
                    !IN_SET(item->rr->key->type, DNS_TYPE_CNAME, DNS_TYPE_DNAME))
                        continue;

                r = dns_answer_add_extend(answer, item->rr, item->ifindex, item->flags, item->rrsig);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dns64_copy_auxiliary_answer(DnsAnswer **answer, DnsAnswer *source) {
        DnsAnswerItem *item;
        int r;

        assert(answer);

        DNS_ANSWER_FOREACH_ITEM(item, source) {
                if (dns64_answer_item_is_in_answer_section(item) &&
                    (item->rr->key->type == DNS_TYPE_A ||
                     (item->rr->key->type == DNS_TYPE_RRSIG &&
                      item->rr->rrsig.type_covered == DNS_TYPE_A)))
                        continue;

                r = dns_answer_add_extend(answer, item->rr, item->ifindex, item->flags, item->rrsig);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Fallback cap for the TTL of synthesized records when no SOA is available to bound it (RFC 6147 §5.1.7).
 * Also keeps synthetic records short-lived so clients refresh promptly after a PREF64 change. */
#define DNS64_SOA_TTL_FALLBACK ((uint32_t) 600)

static DnsResourceKey *dns64_question_aaaa_key(DnsQuestion *question) {
        DnsResourceKey *k;

        DNS_QUESTION_FOREACH(k, question)
                if (k->class == DNS_CLASS_IN && k->type == DNS_TYPE_AAAA)
                        return k;

        return NULL;
}

static int dns64_query_aaaa_key(DnsQuery *q, DnsResourceKey **ret) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsResourceKey *question_key;
        int r;

        assert(q);
        assert(ret);

        question_key = dns64_question_aaaa_key(dns_query_question(q));
        if (!question_key)
                return -ENXIO;

        if (q->answer_search_domain) {
                r = dns_resource_key_new_append_suffix(&key, question_key, q->answer_search_domain->name);
                if (r < 0)
                        return r;
        } else
                key = dns_resource_key_ref(question_key);

        *ret = TAKE_PTR(key);
        return 0;
}

static void dns64_query_reset_answer_preserve_search_domain(DnsQuery *q) {
        DnsSearchDomain *search_domain;

        assert(q);

        search_domain = dns_search_domain_ref(q->answer_search_domain);
        dns_query_reset_answer(q);
        q->answer_search_domain = search_domain;
}

/* RFC 6147 §5.1.7: the synthesized AAAA TTL is capped at min(A TTL, SOA TTL). The relevant SOA is the one
 * bounding the (empty) AAAA response for the queried name, whose negative-caching TTL is min(SOA TTL, SOA
 * MINIMUM) per RFC 2308. */
static uint32_t dns64_soa_ttl_cap(DnsAnswer *answer, DnsResourceKey *aaaa_key) {
        DnsResourceRecord *soa;

        if (!aaaa_key || dns_answer_find_soa(answer, aaaa_key, &soa, NULL) <= 0)
                return DNS64_SOA_TTL_FALLBACK;

        return MIN(soa->ttl, soa->soa.minimum);
}

/* Build synthesized AAAA RRs from the A records in source_answer, using l's configured PREF64 prefixes.
 * Each AAAA RR is named after the source A RR and its TTL is capped at ttl_cap (see dns64_soa_ttl_cap()). */
static int dns64_build_synthesized_answer(
                Link *l,
                DnsAnswer *source_answer,
                int ifindex,
                uint32_t ttl_cap,
                DnsAnswer **ret_answer) {

        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsAnswerItem *item;
        int r;

        assert(l);
        assert(ret_answer);

        FOREACH_ARRAY(prefix, l->dns64_prefixes, l->n_dns64_prefixes)
                DNS_ANSWER_FOREACH_ITEM(item, source_answer) {
                        DnsResourceRecord *rr = item->rr;

                        if (!dns64_answer_item_is_in_answer_section(item))
                                continue;
                        if (rr->key->class != DNS_CLASS_IN || rr->key->type != DNS_TYPE_A)
                                continue;
                        if (dns64_prefix_is_well_known(prefix) &&
                            !dns64_well_known_prefix_supports_address(&rr->a.in_addr))
                                continue;

                        union in_addr_union synth;
                        if (dns64_synthesize_aaaa(&prefix->address, prefix->length,
                                                  &rr->a.in_addr, &synth.in6) < 0)
                                continue;

                        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *aaaa = NULL;
                        r = dns_resource_record_new_address(
                                        &aaaa, AF_INET6, &synth, dns_resource_key_name(rr->key));
                        if (r < 0)
                                return r;

                        /* RFC 6147 §5.1.7: TTL = min(A TTL, SOA TTL). */
                        aaaa->ttl = MIN(rr->ttl, ttl_cap);

                        r = dns_answer_add_extend(&answer, aaaa, ifindex, DNS_ANSWER_CACHEABLE, NULL);
                        if (r < 0)
                                return r;
                }

        *ret_answer = TAKE_PTR(answer);
        return 0;
}

static int dns64_build_auxiliary_answer(
                Link *l,
                DnsAnswer *original_answer,
                DnsAnswer *auxiliary_answer,
                DnsResourceKey *aaaa_key,
                int ifindex,
                DnsAnswer **ret_answer) {

        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *synthesized = NULL;
        int r;

        assert(l);
        assert(ret_answer);

        r = dns64_copy_cname_dname(&answer, original_answer);
        if (r < 0)
                return r;

        r = dns64_copy_auxiliary_answer(&answer, auxiliary_answer);
        if (r < 0)
                return r;

        /* The SOA bounding "no AAAA" comes from the original AAAA response. */
        r = dns64_build_synthesized_answer(l, auxiliary_answer, ifindex,
                                           dns64_soa_ttl_cap(original_answer, aaaa_key),
                                           &synthesized);
        if (r < 0)
                return r;

        r = dns_answer_extend(&answer, synthesized);
        if (r < 0)
                return r;

        *ret_answer = TAKE_PTR(answer);
        return 0;
}

static uint64_t dns64_synthesized_query_flags(DnsQuery *q, uint64_t flags) {
        assert(q);

        if (q->request_packet && !dns_packet_do(q->request_packet))
                flags &= ~SD_RESOLVED_AUTHENTICATED;

        return flags | SD_RESOLVED_SYNTHETIC;
}

/* Take over the auxiliary query's outcome, stripping its answer section: the auxiliary question does not
 * match the original one, so its answer-section records would only confuse the client. Authority-section
 * records (i.e. the SOA) are kept. */
static int dns64_query_propagate_auxiliary_result(DnsQuery *q, DnsQuery *aux) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsAnswerItem *item;
        int r;

        assert(q);
        assert(aux);

        DNS_ANSWER_FOREACH_ITEM(item, aux->answer) {
                if (dns64_answer_item_is_in_answer_section(item))
                        continue;

                r = dns_answer_add_extend(&answer, item->rr, item->ifindex, item->flags, item->rrsig);
                if (r < 0)
                        return r;
        }

        dns64_query_reset_answer_preserve_search_domain(q);
        q->answer = TAKE_PTR(answer);
        q->answer_rcode = aux->answer_rcode;
        q->answer_ede_rcode = aux->answer_ede_rcode;
        q->answer_ede_msg = TAKE_PTR(aux->answer_ede_msg);
        q->answer_dnssec_result = aux->answer_dnssec_result;
        q->answer_errno = aux->answer_errno;
        q->answer_query_flags = aux->answer_query_flags;
        q->answer_protocol = aux->answer_protocol;
        q->answer_family = aux->answer_family;
        return 0;
}

static void dns64_query_complete_errno(DnsQuery *q, int error) {
        assert(q);
        assert(error < 0);

        dns64_query_reset_answer_preserve_search_domain(q);
        q->answer_errno = -error;
        dns_query_complete(q, DNS_TRANSACTION_ERRNO);
}

void dns64_on_a_query_complete(DnsQuery *aux) {
        DnsQuery *q = ASSERT_PTR(aux->auxiliary_for);
        _cleanup_(dns_query_freep) DnsQuery *aux_owned = aux;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *aaaa_key = NULL;
        uint64_t original_flags;
        int r;

        assert(q->n_auxiliary_queries > 0);
        q->n_auxiliary_queries--;
        LIST_REMOVE(auxiliary_queries, q->auxiliary_queries, aux);
        aux->auxiliary_for = NULL;

        /* Re-resolve the link we synthesized against: the auxiliary query was scoped to its ifindex. This
         * yields NULL if the interface or its PREF64 went away while the A query was in flight. */
        Link *l = dns64_enabled_link(q->manager, aux->ifindex);
        if (!l || aux->state != DNS_TRANSACTION_SUCCESS)
                goto fallback;

        r = dns64_query_aaaa_key(q, &aaaa_key);
        if (r < 0)
                goto error;

        original_flags = q->answer_query_flags;
        DnssecResult original_dnssec_result = q->answer_dnssec_result;
        r = dns64_build_auxiliary_answer(l, q->answer, aux->answer,
                                         aaaa_key,
                                         l->ifindex, &answer);
        if (r < 0)
                goto error;

        size_t n_synthesized = dns64_answer_count_usable_aaaa(answer);
        if (n_synthesized == 0)
                goto fallback;

        log_debug("DNS64: synthesized %zu AAAA record(s) from auxiliary A query", n_synthesized);

        dns64_query_reset_answer_preserve_search_domain(q);
        q->answer = TAKE_PTR(answer);
        q->answer_rcode = DNS_RCODE_SUCCESS;
        q->answer_protocol = dns_synthesize_protocol(q->flags);
        q->answer_family = dns_synthesize_family(q->flags);
        /* Like dns_query_accept(): report the DNSSEC result of the unvalidated part, if any — the answer is
         * only as trustworthy as the weaker of the negative AAAA response and the A response. */
        q->answer_dnssec_result = FLAGS_SET(original_flags, SD_RESOLVED_AUTHENTICATED) &&
                !FLAGS_SET(aux->answer_query_flags, SD_RESOLVED_AUTHENTICATED) ?
                aux->answer_dnssec_result : original_dnssec_result;
        q->answer_query_flags = dns64_synthesized_query_flags(
                        q,
                        (original_flags & aux->answer_query_flags &
                         (SD_RESOLVED_AUTHENTICATED | SD_RESOLVED_CONFIDENTIAL)) |
                        ((original_flags | aux->answer_query_flags) & SD_RESOLVED_FROM_MASK));
        q->answer_non_authoritative = true;
        dns_query_complete(q, DNS_TRANSACTION_SUCCESS);
        return;

fallback:
        /* RFC 6147 §5.1.2: when no synthesis is possible — the A lookup failed, returned nothing usable,
         * or the PREF64 went away — return the original AAAA response, which is still intact in q. */
        dns_query_complete(q, q->dns64_original_state);
        return;

error:
        dns64_query_complete_errno(q, r);
}

/* Called from dns_query_accept() just before dns_query_complete(). Returns > 0 if a DNS64 auxiliary
 * A query was started and the caller must defer completion, 0 if completion shall proceed normally. For
 * combined A+AAAA lookups the AAAA records are synthesized in place, without an extra round trip. */
int dns_query_dns64_redirect(DnsQuery *q, DnsScope *answer_scope, DnsTransactionState *state) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *aaaa_key = NULL;
        int r;

        assert(q);
        assert(state);

        /* A DNS64 auxiliary query must not itself trigger DNS64. */
        if (q->auxiliary_for)
                return 0;

        if (FLAGS_SET(q->flags, SD_RESOLVED_NO_SYNTHESIZE))
                return 0;

        if (q->request_packet &&
            DNS_PACKET_CD(q->request_packet) &&
            dns_packet_do(q->request_packet))
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

        Link *l = dns_query_get_dns64_link(q, answer_scope);
        if (!l)
                return 0;

        r = dns64_query_aaaa_key(q, &aaaa_key);
        if (r < 0)
                return r;

        /* RFC 6147 §5.1.2: NXDOMAIN is returned unchanged — no synthesis. */
        if (*state == DNS_TRANSACTION_NOT_FOUND)
                return 0;
        if (*state == DNS_TRANSACTION_RCODE_FAILURE && q->answer_rcode == DNS_RCODE_NXDOMAIN)
                return 0;

        /* RFC §5.1.1 + §5.1.4: if any usable (non-::ffff/96) AAAA record is in
         * the answer, do not synthesize. */
        if (*state == DNS_TRANSACTION_SUCCESS) {
                r = dns64_strip_excluded_aaaa(&q->answer);
                if (r < 0)
                        return r;
                if (r > 0)
                        /* Drop the upstream packet, so that stub bypass replies are reassembled from the
                         * stripped answer instead of propagating the excluded records verbatim. */
                        q->answer_full_packet = dns_packet_unref(q->answer_full_packet);

                if (dns64_answer_has_usable_aaaa(q->answer))
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

                /* The combined A+AAAA answer carries the SOA for the empty AAAA
                 * part in its authority section. */
                r = dns64_build_synthesized_answer(l, q->answer, l->ifindex,
                                                   dns64_soa_ttl_cap(q->answer, aaaa_key),
                                                   &answer);
                if (r < 0)
                        return r;

                if (!dns_answer_isempty(answer)) {
                        r = dns_answer_extend(&q->answer, answer);
                        if (r < 0)
                                return r;

                        /* The upstream packet lacks the synthesized records; make sure replies are
                         * reassembled from the extended answer. */
                        q->answer_full_packet = dns_packet_unref(q->answer_full_packet);
                        q->answer_query_flags = dns64_synthesized_query_flags(q, q->answer_query_flags);
                        q->answer_non_authoritative = true;
                        log_debug("DNS64: synthesized %zu AAAA record(s) inline from A+AAAA answer",
                                  dns_answer_size(answer));
                        return 0; /* completion proceeds normally */
                }
        }

        const char *name = dns_resource_key_name(aaaa_key);
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

        /* RFC 6147 §5.1.2: if synthesis cannot be attempted — e.g. the auxiliary query limit is reached or
         * the lookup cannot be started — return the original AAAA response rather than an error. */
        r = dns_query_make_auxiliary(aux, q);
        if (r < 0) {
                log_debug_errno(r, "DNS64: failed to make auxiliary A-record query, returning unsynthesized response: %m");
                return 0;
        }

        aux->complete = dns64_on_a_query_complete;

        log_debug("DNS64: starting auxiliary A-record lookup for %s on interface %d", name, l->ifindex);

        /* Remember the original AAAA outcome so it can be restored if synthesis fails. */
        q->dns64_original_state = *state;

        r = dns_query_go(aux);
        if (r < 0) {
                log_debug_errno(r, "DNS64: failed to start auxiliary A-record query, returning unsynthesized response: %m");
                return 0;
        }

        TAKE_PTR(aux);

        return 1; /* completion deferred */
}

static int dns64_add_ipv4only_address(
                DnsAnswer **answer,
                Link *l,
                const Dns64Prefix *prefix,
                const char *name,
                int family,
                uint32_t ipv4) {

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        union in_addr_union address = { .in.s_addr = htobe32(ipv4) };
        int r;

        assert(answer);
        assert(l);
        assert(name);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (family == AF_INET6) {
                assert(prefix);
                r = dns64_synthesize_aaaa(
                                &prefix->address,
                                prefix->length,
                                &address.in,
                                &address.in6);
                if (r < 0)
                        return r;
        }

        r = dns_resource_record_new_address(&rr, family, &address, name);
        if (r < 0)
                return r;

        rr->ttl = DNS64_SOA_TTL_FALLBACK;
        return dns_answer_add_extend(answer, rr, l->ifindex, DNS_ANSWER_AUTHENTICATED, NULL);
}

int dns_query_dns64_synthesize_ipv4only_arpa(DnsQuery *q, DnsTransactionState *state) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsScope *scope = NULL;
        DnsQuestion *question;
        DnsResourceKey *key;
        const char *name;
        int r;

        assert(q);
        assert(state);

        if (q->auxiliary_for ||
            FLAGS_SET(q->flags, SD_RESOLVED_NO_SYNTHESIZE))
                return 0;

        /* RFC 6147 §5.5: let validating clients see the real (insecurely delegated) zone. */
        if (q->request_packet &&
            DNS_PACKET_CD(q->request_packet) &&
            dns_packet_do(q->request_packet))
                return 0;

        question = dns_query_question(q);
        name = dns_question_first_name(question);
        if (!name)
                return 0;

        r = dns_name_endswith(name, "ipv4only.arpa");
        if (r <= 0)
                return r;

        DNS_QUESTION_FOREACH(key, question)
                if (key->class == DNS_CLASS_IN && key->type == DNS_TYPE_DS)
                        return 0;

        if (q->ifindex <= 0) {
                DnsScopeMatch found = DNS_SCOPE_NO;

                LIST_FOREACH(scopes, s, q->manager->dns_scopes) {
                        DnsScopeMatch match = dns_scope_good_domain(s, q, q->flags);

                        assert(match >= 0);
                        if (match > found) {
                                found = match;
                                scope = s;
                        }
                }
        }

        Link *l = dns_query_get_dns64_link(q, scope);
        if (!l)
                return 0;

        dns_query_reset_answer(q);
        q->answer_protocol = dns_synthesize_protocol(q->flags);
        q->answer_family = dns_synthesize_family(q->flags);
        q->answer_query_flags = SD_RESOLVED_AUTHENTICATED|SD_RESOLVED_CONFIDENTIAL|SD_RESOLVED_SYNTHETIC;

        r = dns_name_equal(name, "ipv4only.arpa");
        if (r < 0)
                return r;
        if (r == 0) {
                q->answer_rcode = DNS_RCODE_NXDOMAIN;
                *state = DNS_TRANSACTION_RCODE_FAILURE;
                return 1;
        }

        static const uint32_t addresses[] = { UINT32_C(0xc00000aa), UINT32_C(0xc00000ab) };

        DNS_QUESTION_FOREACH(key, question) {
                if (key->class != DNS_CLASS_IN)
                        continue;

                if (key->type == DNS_TYPE_A)
                        FOREACH_ELEMENT(a, addresses) {
                                r = dns64_add_ipv4only_address(&answer, l, /* prefix= */ NULL, name, AF_INET, *a);
                                if (r < 0)
                                        return r;
                        }
                else if (key->type == DNS_TYPE_AAAA)
                        FOREACH_ARRAY(prefix, l->dns64_prefixes, l->n_dns64_prefixes)
                                FOREACH_ELEMENT(a, addresses) {
                                        r = dns64_add_ipv4only_address(&answer, l, prefix, name, AF_INET6, *a);
                                        if (r < 0)
                                                return r;
                                }
        }

        q->answer = TAKE_PTR(answer);
        q->answer_rcode = DNS_RCODE_SUCCESS;
        *state = DNS_TRANSACTION_SUCCESS;
        return 1;
}

static int dns64_extract_ipv4_for_prefix(
                const Dns64Prefix *prefix,
                const struct in6_addr *addr,
                struct in_addr *ret) {
        int r;

        assert(prefix);

        r = dns64_extract_ipv4(&prefix->address, prefix->length, addr, ret);
        if (r < 0)
                return r;

        if (dns64_prefix_is_well_known(prefix) &&
            !dns64_well_known_prefix_supports_address(ret) &&
            !IN_SET(be32toh(ret->s_addr), UINT32_C(0xc00000aa), UINT32_C(0xc00000ab)))
                return -ENXIO;

        return 0;
}

static int dns64_extract_ipv4_for_link(
                Link *l,
                const struct in6_addr *addr,
                struct in_addr *ret,
                uint8_t *ret_prefixlen) {

        const Dns64Prefix *best = NULL;
        struct in_addr best_v4;

        assert(l);

        FOREACH_ARRAY(prefix, l->dns64_prefixes, l->n_dns64_prefixes) {
                struct in_addr v4;

                if (dns64_extract_ipv4_for_prefix(prefix, addr, &v4) < 0 ||
                    (best && prefix->length <= best->length))
                        continue;

                best = prefix;
                best_v4 = v4;
        }

        if (!best)
                return -ENXIO;

        *ret = best_v4;
        if (ret_prefixlen)
                *ret_prefixlen = best->length;
        return 0;
}

/* Returns the link whose PREF64 embeds addr (extracting the IPv4 into ret_v4),
 * or NULL if no configured PREF64 covers it. A query bound to an interface only
 * considers that interface; an unbound query considers every link, which lets
 * us answer a PTR for an address a different (site-provided) DNS64 handed out. */
static Link *dns64_ptr_link_for_address(DnsQuery *q, const struct in6_addr *addr, struct in_addr *ret_v4) {
        assert(q);
        assert(addr);
        assert(ret_v4);

        if (q->ifindex > 0) {
                Link *l = hashmap_get(q->manager->links, INT_TO_PTR(q->ifindex));
                if (l && dns64_extract_ipv4_for_link(l, addr, ret_v4, NULL) >= 0)
                        return l;
                return NULL;
        }

        Link *best = NULL, *l;
        uint8_t best_prefixlen = 0;
        struct in_addr v4;
        HASHMAP_FOREACH(l, q->manager->links) {
                uint8_t prefixlen;

                if (dns64_extract_ipv4_for_link(l, addr, &v4, &prefixlen) < 0 ||
                    (best && prefixlen <= best_prefixlen))
                        continue;

                best = l;
                best_prefixlen = prefixlen;
                *ret_v4 = v4;
        }

        return best;
}

static bool dns64_answer_has_direct_ptr(DnsAnswer *answer, const char *name) {
        DnsResourceRecord *rr;
        bool found = false;

        assert(name);

        DNS_ANSWER_FOREACH(rr, answer)
                if (rr->key->class == DNS_CLASS_IN &&
                    dns_name_equal(dns_resource_key_name(rr->key), name) > 0) {
                        if (rr->key->type == DNS_TYPE_CNAME)
                                return false;
                        if (rr->key->type == DNS_TYPE_PTR)
                                found = true;
                }

        return found;
}

/* Assemble the reverse-DNS64 answer: a synthesized CNAME mapping the queried
 * IP6.ARPA name to the corresponding IN-ADDR.ARPA name (RFC 6147 §5.3.1
 * option 2), followed by the records the auxiliary IN-ADDR.ARPA PTR lookup
 * returned (the real PTR RRs plus any further CNAME/DNAME chain). */
static int dns64_build_ptr_answer(DnsQuery *q, DnsQuery *aux, DnsAnswer **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL;
        const char *ip6_name, *in_addr_name;
        int r;

        assert(q);
        assert(aux);
        assert(ret);

        ip6_name = dns_question_first_name(dns_query_question(q));
        in_addr_name = dns_question_first_name(aux->question_utf8);
        if (!ip6_name || !in_addr_name)
                return -EINVAL;

        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, ip6_name);
        if (!cname)
                return -ENOMEM;

        cname->cname.name = strdup(in_addr_name);
        if (!cname->cname.name)
                return -ENOMEM;

        /* The CNAME is synthesized locally; cap its lifetime like the AAAA path. */
        cname->ttl = DNS64_SOA_TTL_FALLBACK;

        r = dns_answer_add_extend(&answer, cname, aux->ifindex, DNS_ANSWER_CACHEABLE, NULL);
        if (r < 0)
                return r;

        r = dns_answer_extend(&answer, aux->answer);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(answer);
        return 0;
}

void dns64_on_ptr_query_complete(DnsQuery *aux) {
        DnsQuery *q = ASSERT_PTR(aux->auxiliary_for);
        _cleanup_(dns_query_freep) DnsQuery *aux_owned = aux;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int r;

        assert(q->n_auxiliary_queries > 0);
        q->n_auxiliary_queries--;
        LIST_REMOVE(auxiliary_queries, q->auxiliary_queries, aux);
        aux->auxiliary_for = NULL;

        if (aux->state != DNS_TRANSACTION_SUCCESS)
                goto propagate;

        /* RFC 6147 §5.3.1 option 2: only synthesize the CNAME when the
         * IN-ADDR.ARPA name actually has a PTR, so we never point a CNAME at
         * nothing. Without one, report the reverse lookup's own outcome. */
        if (!dns64_answer_has_direct_ptr(aux->answer, dns_question_first_name(aux->question_utf8)))
                goto propagate;

        r = dns64_build_ptr_answer(q, aux, &answer);
        if (r < 0)
                goto error;

        log_debug("DNS64: synthesized reverse CNAME %s -> %s",
                  dns_question_first_name(dns_query_question(q)),
                  dns_question_first_name(aux->question_utf8));

        dns_query_reset_answer(q);
        q->answer = TAKE_PTR(answer);
        q->answer_rcode = DNS_RCODE_SUCCESS;
        q->answer_protocol = dns_synthesize_protocol(q->flags);
        q->answer_family = dns_synthesize_family(q->flags);
        q->answer_query_flags = dns64_synthesized_query_flags(
                        q,
                        aux->answer_query_flags &
                        (SD_RESOLVED_AUTHENTICATED | SD_RESOLVED_CONFIDENTIAL | SD_RESOLVED_FROM_MASK));
        q->answer_non_authoritative = true;
        dns_query_complete(q, DNS_TRANSACTION_SUCCESS);
        return;

propagate:
        r = dns64_query_propagate_auxiliary_result(q, aux);
        if (r < 0)
                goto error;
        dns_query_complete(q, aux->state);
        return;

error:
        dns64_query_complete_errno(q, r);
}

/* Called from dns_query_go() before the query is dispatched to any scope. RFC 6147 §5.3.1: for a PTR query
 * in the IP6.ARPA domain whose address falls under a configured PREF64, synthesize a CNAME to the matching
 * IN-ADDR.ARPA name (option 2) and resolve that reverse name instead — the IP6.ARPA subtree of a synthetic
 * prefix has no authority upstream. Returns > 0 if an auxiliary PTR query was started and the caller must
 * defer completion, 0 if DNS64 does not apply and normal resolution shall proceed. */
int dns_query_dns64_ptr_redirect(DnsQuery *q) {
        int r;

        assert(q);

        /* A DNS64 auxiliary query must not itself trigger DNS64. */
        if (q->auxiliary_for)
                return 0;

        if (FLAGS_SET(q->flags, SD_RESOLVED_NO_SYNTHESIZE))
                return 0;

        if (q->request_packet &&
            DNS_PACKET_CD(q->request_packet) &&
            dns_packet_do(q->request_packet))
                return 0;

        if (!q->manager->dns64_enabled)
                return 0;

        /* Find a class-IN PTR question for a name in the IP6.ARPA domain. */
        DnsResourceKey *ptr_key = NULL, *k;
        DNS_QUESTION_FOREACH(k, dns_query_question(q)) {
                if (k->class != DNS_CLASS_IN || k->type != DNS_TYPE_PTR)
                        continue;

                r = dns_name_endswith(dns_resource_key_name(k), "ip6.arpa");
                if (r < 0)
                        return r;
                if (r > 0) {
                        ptr_key = k;
                        break;
                }
        }
        if (!ptr_key)
                return 0;

        /* Parse the reversed address out of the QNAME. */
        union in_addr_union addr;
        int family;
        r = dns_name_address(dns_resource_key_name(ptr_key), &family, &addr);
        if (r < 0)
                return r;
        if (r == 0 || family != AF_INET6)
                return 0;

        /* Does the address fall under any configured PREF64? If so, extract the
         * embedded IPv4 address. */
        union in_addr_union v4;
        Link *l = dns64_ptr_link_for_address(q, &addr.in6, &v4.in);
        if (!l)
                return 0;

        /* Resolve the corresponding IN-ADDR.ARPA PTR instead. */
        _cleanup_(dns_question_unrefp) DnsQuestion *question_ptr = NULL;
        r = dns_question_new_reverse(&question_ptr, AF_INET, &v4);
        if (r < 0)
                return r;

        uint64_t flags = q->flags | SD_RESOLVED_NO_SEARCH | SD_RESOLVED_NO_SYNTHESIZE;

        _cleanup_(dns_query_freep) DnsQuery *aux = NULL;
        r = dns_query_new(q->manager, &aux, question_ptr, question_ptr, NULL, l->ifindex, flags);
        if (r < 0)
                return r;

        /* If the redirection cannot be attempted — e.g. the auxiliary query limit is reached or the lookup
         * cannot be started — fall back to resolving the IP6.ARPA name normally rather than failing. */
        r = dns_query_make_auxiliary(aux, q);
        if (r < 0) {
                log_debug_errno(r, "DNS64: failed to make auxiliary reverse lookup, resolving IP6.ARPA name directly: %m");
                return 0;
        }

        aux->complete = dns64_on_ptr_query_complete;

        log_debug("DNS64: starting auxiliary reverse lookup %s -> %s on interface %d",
                  dns_resource_key_name(ptr_key),
                  dns_question_first_name(question_ptr),
                  l->ifindex);

        r = dns_query_go(aux);
        if (r < 0) {
                log_debug_errno(r, "DNS64: failed to start auxiliary reverse lookup, resolving IP6.ARPA name directly: %m");
                return 0;
        }

        TAKE_PTR(aux);

        return 1; /* completion deferred */
}
