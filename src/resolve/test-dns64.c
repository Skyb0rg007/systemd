/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "resolved-dns-query.h"
#include "resolved-dns64.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "tests.h"

/* RFC 6147 / RFC 6052 test fixtures.
 *
 * The address-mapping tests use the worked examples from RFC 6052 §2.4
 * (Table 1).  Every prefix length the algorithm supports is covered. */

static struct in6_addr in6(const char *s) {
        struct in6_addr a;
        ASSERT_EQ(inet_pton(AF_INET6, s, &a), 1);
        return a;
}

static struct in_addr in4(const char *s) {
        struct in_addr a;
        ASSERT_EQ(inet_pton(AF_INET, s, &a), 1);
        return a;
}

static void assert_synth(const char *prefix_str,
                         uint8_t prefix_length,
                         const char *v4_str,
                         const char *expected_v6_str) {
        struct in6_addr prefix = in6(prefix_str);
        struct in_addr v4 = in4(v4_str);
        struct in6_addr expected = in6(expected_v6_str);
        struct in6_addr got;

        ASSERT_OK(dns64_synthesize_aaaa(&prefix, prefix_length, &v4, &got));
        ASSERT_EQ(memcmp(&got, &expected, sizeof got), 0);
}

/* ================================================================
 * dns64_synthesize_aaaa() — RFC 6052 §2.4 worked examples
 * ================================================================ */

TEST(dns64_synthesize_aaaa_pl_32) {
        assert_synth("2001:db8::", 32, "192.0.2.33", "2001:db8:c000:221::");
}

TEST(dns64_synthesize_aaaa_pl_40) {
        assert_synth("2001:db8:100::", 40, "192.0.2.33", "2001:db8:1c0:2:21::");
}

TEST(dns64_synthesize_aaaa_pl_48) {
        assert_synth("2001:db8:122::", 48, "192.0.2.33", "2001:db8:122:c000:2:2100::");
}

TEST(dns64_synthesize_aaaa_pl_56) {
        assert_synth("2001:db8:122:300::", 56, "192.0.2.33", "2001:db8:122:3c0:0:221::");
}

TEST(dns64_synthesize_aaaa_pl_64) {
        assert_synth("2001:db8:122:344::", 64, "192.0.2.33", "2001:db8:122:344:c0:2:2100::");
}

TEST(dns64_synthesize_aaaa_pl_96) {
        assert_synth("2001:db8:122:344::", 96, "192.0.2.33", "2001:db8:122:344::c000:221");
}

/* The Well-Known Prefix from RFC 6052 §2.1. */
TEST(dns64_synthesize_aaaa_wellknown_prefix) {
        assert_synth("64:ff9b::", 96, "192.0.2.1", "64:ff9b::c000:201");
        assert_synth("64:ff9b::", 96, "8.8.8.8",   "64:ff9b::808:808");
}

/* RFC 6052 §2.2: bits 64–71 (the "u" octet) MUST be zero for prefix lengths
 * shorter than 96.  Verify that synthesis never produces a non-zero u octet
 * even when the IPv4 address has bytes that would otherwise land there. */
TEST(dns64_synthesize_aaaa_u_octet_is_zero) {
        struct in6_addr prefix = in6("2001:db8::");
        struct in_addr v4 = in4("255.255.255.255");
        struct in6_addr got;

        for (uint8_t pl = 32; pl <= 64; pl += 8) {
                /* /32, /40, /48, /56, /64 each have an internal "u" octet. */
                prefix = in6(pl == 32 ? "2001:db8::"
                            : pl == 40 ? "2001:db8:00::"
                            : pl == 48 ? "2001:db8:0:0::"
                            : pl == 56 ? "2001:db8:0:0::"
                            : "2001:db8:0:0::");

                ASSERT_OK(dns64_synthesize_aaaa(&prefix, pl, &v4, &got));
                ASSERT_EQ(got.s6_addr[8], (uint8_t) 0);
        }
}

TEST(dns64_synthesize_aaaa_edge_addresses) {
        /* All-zero and all-one IPv4 addresses still map cleanly. */
        assert_synth("64:ff9b::", 96, "0.0.0.0",         "64:ff9b::");
        assert_synth("64:ff9b::", 96, "255.255.255.255", "64:ff9b::ffff:ffff");
}

TEST(dns64_synthesize_aaaa_invalid_prefix_length) {
        struct in6_addr prefix = in6("2001:db8::");
        struct in_addr v4 = in4("192.0.2.1");
        struct in6_addr got;

        /* RFC 6052 §2.2 enumerates exactly six valid prefix lengths.
         * Everything else must be rejected. */
        for (unsigned pl = 0; pl <= 128; pl++) {
                if (IN_SET(pl, 32, 40, 48, 56, 64, 96))
                        continue;
                ASSERT_ERROR(dns64_synthesize_aaaa(&prefix, pl, &v4, &got), EINVAL);
        }
}

/* ================================================================
 * dns_query_dns64_redirect() — RFC 6147 §5.1
 *
 * Every test here exercises a path that does NOT need to fire an
 * auxiliary A query, so we never touch the network or any scopes.
 * That keeps these as pure unit tests.
 * ================================================================ */

static int build_query(Manager *m,
                       DnsQuery **ret_query,
                       int family,
                       int ifindex) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        int r;

        r = dns_question_new_address(&q, family, "www.example.com", false);
        if (r < 0)
                return r;

        return dns_query_new(m, ret_query, q, q, NULL, ifindex, 0);
}

static void link_set_pref64(Link *l, const char *prefix, uint8_t pl) {
        struct in6_addr p = in6(prefix);
        ASSERT_OK(link_set_dns64_prefix(l, &p, pl));
}

static int add_a_rr(DnsAnswer **answer, const char *name, const char *ipv4, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
        if (!rr)
                return -ENOMEM;

        rr->a.in_addr = in4(ipv4);
        rr->ttl = ttl;

        return dns_answer_add_extend(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
}

static int add_aaaa_rr(DnsAnswer **answer, const char *name, const char *ipv6, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, name);
        if (!rr)
                return -ENOMEM;

        rr->aaaa.in6_addr = in6(ipv6);
        rr->ttl = ttl;

        return dns_answer_add_extend(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
}

static int add_cname_rr(DnsAnswer **answer, const char *name, const char *canonical, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, name);
        if (!rr)
                return -ENOMEM;

        rr->cname.name = strdup(canonical);
        if (!rr->cname.name)
                return -ENOMEM;

        rr->ttl = ttl;
        return dns_answer_add_extend(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
}

static int add_dname_rr(DnsAnswer **answer, const char *name, const char *target, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, name);
        if (!rr)
                return -ENOMEM;

        rr->dname.name = strdup(target);
        if (!rr->dname.name)
                return -ENOMEM;

        rr->ttl = ttl;
        return dns_answer_add_extend(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
}

static bool answer_has_aaaa(DnsAnswer *answer, const char *expected_ipv6) {
        struct in6_addr expected = in6(expected_ipv6);
        DnsResourceRecord *rr;

        DNS_ANSWER_FOREACH(rr, answer) {
                if (rr->key->type != DNS_TYPE_AAAA)
                        continue;
                if (memcmp(&rr->aaaa.in6_addr, &expected, sizeof expected) == 0)
                        return true;
        }
        return false;
}

static bool answer_has_rr(DnsAnswer *answer, uint16_t type, const char *name) {
        DnsResourceRecord *rr;

        DNS_ANSWER_FOREACH(rr, answer)
                if (rr->key->type == type && dns_name_equal(dns_resource_key_name(rr->key), name) > 0)
                        return true;

        return false;
}

static bool answer_has_aaaa_name(DnsAnswer *answer, const char *name, const char *expected_ipv6) {
        struct in6_addr expected = in6(expected_ipv6);
        DnsResourceRecord *rr;

        DNS_ANSWER_FOREACH(rr, answer) {
                if (rr->key->type != DNS_TYPE_AAAA)
                        continue;
                if (dns_name_equal(dns_resource_key_name(rr->key), name) <= 0)
                        continue;
                if (memcmp(&rr->aaaa.in6_addr, &expected, sizeof expected) == 0)
                        return true;
        }

        return false;
}

static size_t answer_count_aaaa(DnsAnswer *answer) {
        DnsResourceRecord *rr;
        size_t n = 0;

        DNS_ANSWER_FOREACH(rr, answer)
                if (rr->key->type == DNS_TYPE_AAAA)
                        n++;

        return n;
}

static void query_complete_record_state(DnsQuery *q) {
        assert(q);
}

static DnsTransactionState completed_state;

static void query_complete_free_record_state(DnsQuery *q) {
        assert(q);

        completed_state = q->state;
        dns_query_free(q);
}

/* §5.1: DNS64 acts on AAAA queries.  Pure-A queries are pass-through. */
TEST(dns_query_dns64_redirect_a_only_question_skipped) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET, 1));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);
}

/* Global toggle: DNS64=no in resolved.conf means we never act, even if PREF64 is set on the link. */
TEST(dns_query_dns64_redirect_globally_disabled) {
        Manager manager = { .dns64_enabled = false };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_NOT_FOUND;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);
}

/* No PREF64 configured on the link → we never act. */
TEST(dns_query_dns64_redirect_no_pref64_on_link) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        /* No link_set_dns64_prefix() call. */

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);
}

/* §5.1.1: real AAAA records in the answer must not be replaced. */
TEST(dns_query_dns64_redirect_real_aaaa_blocks_synthesis) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));
        ASSERT_OK(add_aaaa_rr(&query->answer, "www.example.com", "2001:db8::1", 300));

        size_t aaaa_before = answer_count_aaaa(query->answer);

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        /* No synthesis happened; the answer is untouched. */
        ASSERT_EQ(answer_count_aaaa(query->answer), aaaa_before);
        ASSERT_TRUE(answer_has_aaaa(query->answer, "2001:db8::1"));
}

/* §5.1.4: v4-mapped AAAA records are stripped even when another AAAA record
 * lets the answer complete without DNS64 synthesis. */
TEST(dns_query_dns64_redirect_mapped_aaaa_stripped_with_real_aaaa) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));
        ASSERT_OK(add_aaaa_rr(&query->answer, "www.example.com", "::ffff:192.0.2.1", 300));
        ASSERT_OK(add_aaaa_rr(&query->answer, "www.example.com", "2001:db8::1", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 1);
        ASSERT_TRUE(answer_has_aaaa(query->answer, "2001:db8::1"));
        ASSERT_FALSE(answer_has_aaaa(query->answer, "::ffff:192.0.2.1"));
}

/* §5.1.4: AAAA records inside ::ffff:0:0/96 are not usable by IPv6-only
 * clients and MUST be treated as though the answer were empty.  When the
 * original query also carried A records, we synthesize inline. */
TEST(dns_query_dns64_redirect_v4_mapped_aaaa_is_excluded) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        /* AF_UNSPEC → combined A+AAAA question */
        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_aaaa_rr(&query->answer, "www.example.com", "::ffff:192.0.2.1", 300));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "192.0.2.1", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        /* Inline synthesis produced a real AAAA from the A record. */
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::c000:201"));
        ASSERT_FALSE(answer_has_aaaa(query->answer, "::ffff:192.0.2.1"));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
}

/* §5.1.2 first paragraph: NXDOMAIN is returned as-is.  In systemd-resolved
 * this state is DNS_TRANSACTION_NOT_FOUND ("like NXDOMAIN"). */
TEST(dns_query_dns64_redirect_nxdomain_state_skipped) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_NOT_FOUND;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);
}

/* §5.1.2: an RCODE_FAILURE state whose rcode is NXDOMAIN must also be left
 * alone — distinguishes "name doesn't exist" from "transient failure". */
TEST(dns_query_dns64_redirect_nxdomain_rcode_skipped) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_RCODE_FAILURE;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));
        query->answer_rcode = DNS_RCODE_NXDOMAIN;

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);
}

/* SD_RESOLVED_NO_SYNTHESIZE explicitly opts out of all synthesis. */
TEST(dns_query_dns64_redirect_no_synthesize_flag_skipped) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(dns_question_new_address(&q, AF_INET6, "www.example.com", false));
        ASSERT_OK(dns_query_new(&manager, &query, q, q, NULL, 1, SD_RESOLVED_NO_SYNTHESIZE));

        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "192.0.2.1", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        /* No AAAA was synthesized despite an A being present. */
        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 0);
}

/* §5.1.6 happy path with the A+AAAA optimization: A records already in
 * q->answer; AAAA records get synthesized in place, no auxiliary query. */
TEST(dns_query_dns64_redirect_inline_synthesis_from_combined_query) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "192.0.2.1", 300));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "192.0.2.2", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 2);
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::c000:201"));
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::c000:202"));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
}

/* Inline synthesis respects the configured PREF64 — varies prefix length. */
TEST(dns_query_dns64_redirect_inline_synthesis_pl_64) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "2001:db8:122:344::", 64);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "192.0.2.33", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        ASSERT_TRUE(answer_has_aaaa(query->answer, "2001:db8:122:344:c0:2:2100:0"));
}

/* §5.1.7: TTL of synthesized AAAA must not exceed min(A TTL, 600).
 * Given A TTL=86400, synthesized AAAA TTL should be capped at 600. */
TEST(dns_query_dns64_redirect_ttl_capped_at_600) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "192.0.2.1", 86400));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        DnsResourceRecord *rr;
        bool found = false;
        DNS_ANSWER_FOREACH(rr, query->answer)
                if (rr->key->type == DNS_TYPE_AAAA) {
                        ASSERT_EQ(rr->ttl, (uint32_t) 600);
                        found = true;
                }
        ASSERT_TRUE(found);
}

/* §5.1.7: when the A TTL is below 600, the synthesized TTL must match
 * the A TTL exactly (not be raised to 600). */
TEST(dns_query_dns64_redirect_ttl_inherits_short_a_ttl) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "192.0.2.1", 60));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        DnsResourceRecord *rr;
        bool found = false;
        DNS_ANSWER_FOREACH(rr, query->answer)
                if (rr->key->type == DNS_TYPE_AAAA) {
                        ASSERT_EQ(rr->ttl, (uint32_t) 60);
                        found = true;
                }
        ASSERT_TRUE(found);
}

TEST(dns64_auxiliary_success_uses_a_owner_name_and_preserves_chains) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));
        query->complete = query_complete_record_state;
        query->dns64_original_state = DNS_TRANSACTION_SUCCESS;
        ASSERT_OK(add_cname_rr(&query->answer, "www.example.com", "alias.example.com", 300));
        ASSERT_OK(add_dname_rr(&query->answer, "example.com", "example.net", 300));

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        ASSERT_OK(dns_question_new_address(&question_a, AF_INET, "www.example.com", false));
        ASSERT_OK(dns_query_new(&manager, &aux, question_a, question_a, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        ASSERT_OK(add_cname_rr(&aux->answer, "www.example.com", "alias.example.com", 300));
        ASSERT_OK(add_a_rr(&aux->answer, "alias.example.com", "192.0.2.33", 1200));
        aux->state = DNS_TRANSACTION_SUCCESS;

        dns64_on_a_query_complete(aux);

        ASSERT_EQ(query->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_TRUE(answer_has_rr(query->answer, DNS_TYPE_CNAME, "www.example.com"));
        ASSERT_TRUE(answer_has_rr(query->answer, DNS_TYPE_DNAME, "example.com"));
        ASSERT_TRUE(answer_has_aaaa_name(query->answer, "alias.example.com", "64:ff9b::c000:221"));
        ASSERT_FALSE(answer_has_rr(query->answer, DNS_TYPE_A, "alias.example.com"));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
}

TEST(dns64_auxiliary_empty_restores_original_state) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));
        query->complete = query_complete_free_record_state;
        query->dns64_original_state = DNS_TRANSACTION_TIMEOUT;
        completed_state = _DNS_TRANSACTION_STATE_INVALID;

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        ASSERT_OK(dns_question_new_address(&question_a, AF_INET, "www.example.com", false));
        ASSERT_OK(dns_query_new(&manager, &aux, question_a, question_a, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        aux->state = DNS_TRANSACTION_SUCCESS;

        dns64_on_a_query_complete(aux);

        ASSERT_EQ(completed_state, DNS_TRANSACTION_TIMEOUT);
}

TEST(dns64_auxiliary_failure_restores_original_state) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));
        query->complete = query_complete_free_record_state;
        query->dns64_original_state = DNS_TRANSACTION_ATTEMPTS_MAX_REACHED;
        completed_state = _DNS_TRANSACTION_STATE_INVALID;

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        ASSERT_OK(dns_question_new_address(&question_a, AF_INET, "www.example.com", false));
        ASSERT_OK(dns_query_new(&manager, &aux, question_a, question_a, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        aux->state = DNS_TRANSACTION_TIMEOUT;

        dns64_on_a_query_complete(aux);

        ASSERT_EQ(completed_state, DNS_TRANSACTION_ATTEMPTS_MAX_REACHED);
}

TEST(dns_query_dns64_redirect_cd_do_request_skips_synthesis) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "192.0.2.1", 300));

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, 0, true));
        packet->opt = dns_resource_record_new_full(DNS_PACKET_UNICAST_SIZE_LARGE_MAX, DNS_TYPE_OPT, "");
        ASSERT_NOT_NULL(packet->opt);
        packet->opt->ttl = 1U << 15;
        query->request_packet = dns_packet_ref(packet);

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);

        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 0);
        ASSERT_FALSE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
}

/* A combined A+AAAA where the A query yielded zero records and we got
 * SUCCESS with an empty answer should NOT trigger inline synthesis
 * (there's nothing to synthesize from).  Without firing an aux query
 * the function would return 1; here we configure no DNS64 link so it
 * short-circuits cleanly and returns 0. */
TEST(dns_query_dns64_redirect_empty_success_no_link_short_circuits) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        /* No PREF64 set on link — short-circuits before any aux-query path. */

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));

        ASSERT_EQ(dns_query_dns64_redirect(query, &state), 0);
        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
