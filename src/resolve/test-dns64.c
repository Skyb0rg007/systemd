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
#include "resolved-dns-search-domain.h"
#include "resolved-dns-scope.h"
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

TEST(dns64_synthesize_aaaa_rfc6052_examples) {
        assert_synth("2001:db8::", 32, "192.0.2.33", "2001:db8:c000:221::");
        assert_synth("2001:db8:100::", 40, "192.0.2.33", "2001:db8:1c0:2:21::");
        assert_synth("2001:db8:122::", 48, "192.0.2.33", "2001:db8:122:c000:2:2100::");
        assert_synth("2001:db8:122:300::", 56, "192.0.2.33", "2001:db8:122:3c0:0:221::");
        assert_synth("2001:db8:122:344::", 64, "192.0.2.33", "2001:db8:122:344:c0:2:2100::");
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

TEST(dns64_synthesize_aaaa_nonzero_u_octet_in_96_prefix) {
        struct in6_addr prefix = in6("2001:db8:0:0:100::");
        struct in_addr v4 = in4("192.0.2.1");
        struct in6_addr got;

        ASSERT_ERROR(dns64_synthesize_aaaa(&prefix, 96, &v4, &got), EINVAL);
}

/* ================================================================
 * dns64_extract_ipv4() — inverse mapping (RFC 6052 §2.2)
 * ================================================================ */

static void assert_extract(const char *prefix_str,
                           uint8_t prefix_length,
                           const char *v6_str,
                           const char *expected_v4_str) {
        struct in6_addr prefix = in6(prefix_str);
        struct in6_addr v6 = in6(v6_str);
        struct in_addr expected = in4(expected_v4_str);
        struct in_addr got;

        ASSERT_OK(dns64_extract_ipv4(&prefix, prefix_length, &v6, &got));
        ASSERT_EQ(memcmp(&got, &expected, sizeof got), 0);
}

/* Each is the exact reverse of the corresponding dns64_synthesize_aaaa test. */
TEST(dns64_extract_ipv4_roundtrip) {
        assert_extract("2001:db8::",        32, "2001:db8:c000:221::",        "192.0.2.33");
        assert_extract("2001:db8:100::",    40, "2001:db8:1c0:2:21::",        "192.0.2.33");
        assert_extract("2001:db8:122::",    48, "2001:db8:122:c000:2:2100::", "192.0.2.33");
        assert_extract("2001:db8:122:300::", 56, "2001:db8:122:3c0:0:221::",  "192.0.2.33");
        assert_extract("2001:db8:122:344::", 64, "2001:db8:122:344:c0:2:2100::", "192.0.2.33");
        assert_extract("2001:db8:122:344::", 96, "2001:db8:122:344::c000:221", "192.0.2.33");
        assert_extract("64:ff9b::",         96, "64:ff9b::c000:201",          "192.0.2.1");
}

/* An address that does not share the configured prefix is rejected. */
TEST(dns64_extract_ipv4_prefix_mismatch) {
        struct in6_addr prefix = in6("64:ff9b::");
        struct in6_addr v6 = in6("2001:db8::c000:201");
        struct in_addr got;

        ASSERT_ERROR(dns64_extract_ipv4(&prefix, 96, &v6, &got), ENXIO);
}

/* RFC 6052 §2.2: for prefix lengths < 96 the "u" octet (byte 8) must be zero;
 * an address with a non-zero "u" octet is not a valid embedded IPv4 address. */
TEST(dns64_extract_ipv4_nonzero_u_octet_rejected) {
        struct in6_addr prefix = in6("2001:db8::");
        struct in6_addr v6 = in6("2001:db8:c000:221:ff00::"); /* byte 8 = 0xff */
        struct in_addr got;

        ASSERT_ERROR(dns64_extract_ipv4(&prefix, 32, &v6, &got), ENXIO);
}

TEST(dns64_extract_ipv4_invalid_prefix_length) {
        struct in6_addr prefix = in6("64:ff9b::");
        struct in6_addr v6 = in6("64:ff9b::c000:201");
        struct in_addr got;

        for (unsigned pl = 0; pl <= 128; pl++) {
                if (IN_SET(pl, 32, 40, 48, 56, 64, 96))
                        continue;
                ASSERT_ERROR(dns64_extract_ipv4(&prefix, pl, &v6, &got), EINVAL);
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

static int build_record_query(
                Manager *m,
                DnsQuery **ret_query,
                const char *name,
                uint16_t type,
                int ifindex) {

        _cleanup_(dns_question_unrefp) DnsQuestion *question = dns_question_new(1);
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        int r;

        if (!question)
                return -ENOMEM;

        key = dns_resource_key_new(DNS_CLASS_IN, type, name);
        if (!key)
                return -ENOMEM;

        r = dns_question_add(question, key, 0);
        if (r < 0)
                return r;

        return dns_query_new(m, ret_query, question, question, NULL, ifindex, 0);
}

/* Build a PTR query for the IP6.ARPA name of the given IPv6 address. */
static int build_ptr_query(Manager *m,
                           DnsQuery **ret_query,
                           const char *v6_str,
                           int ifindex,
                           uint64_t flags) {
        union in_addr_union a = { .in6 = in6(v6_str) };
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        int r;

        r = dns_question_new_reverse(&q, AF_INET6, &a);
        if (r < 0)
                return r;

        return dns_query_new(m, ret_query, q, q, NULL, ifindex, flags);
}

static void link_set_pref64(Link *l, const char *prefix, uint8_t pl) {
        Dns64Prefix p = {
                .address = in6(prefix),
                .length = pl,
        };
        ASSERT_OK(link_set_dns64_prefixes(l, &p, 1));
}

static void link_add_pref64(Link *l, const char *prefix, uint8_t pl) {
        struct in6_addr p = in6(prefix);
        ASSERT_OK_POSITIVE(link_add_dns64_prefix(l, &p, pl));
}

TEST(link_set_dns64_prefixes_normalizes_and_validates_prefix) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        struct in6_addr expected;
        Dns64Prefix prefix;

        ASSERT_OK(link_new(&manager, &link, 1));

        prefix = (Dns64Prefix) { .address = in6("2001:db8:1:2:3:4:5:6"), .length = 64 };
        ASSERT_OK(link_set_dns64_prefixes(link, &prefix, 1));
        expected = in6("2001:db8:1:2::");
        ASSERT_EQ(link->n_dns64_prefixes, (size_t) 1);
        ASSERT_EQ(memcmp(&link->dns64_prefixes[0].address, &expected, sizeof expected), 0);

        prefix = (Dns64Prefix) { .address = in6("2001:db8:0:0:100::"), .length = 96 };
        ASSERT_ERROR(link_set_dns64_prefixes(link, &prefix, 1), EINVAL);

        prefix = (Dns64Prefix) { .address = in6("64:ff9b::"), .length = 64 };
        ASSERT_ERROR(link_set_dns64_prefixes(link, &prefix, 1), EINVAL);
}

TEST(link_add_dns64_prefix_preserves_order_and_deduplicates) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        struct in6_addr first = in6("2001:db8:1::"), second = in6("2001:db8:2::");

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "2001:db8:1::", 96);
        link_add_pref64(link, "2001:db8:2::", 96);

        struct in6_addr duplicate = in6("2001:db8:1::1234");
        ASSERT_OK(link_add_dns64_prefix(link, &duplicate, 96));

        ASSERT_EQ(link->n_dns64_prefixes, (size_t) 2);
        ASSERT_EQ(memcmp(&link->dns64_prefixes[0].address, &first, sizeof first), 0);
        ASSERT_EQ(memcmp(&link->dns64_prefixes[1].address, &second, sizeof second), 0);
}

static int add_a_rr(DnsAnswer **answer, const char *name, const char *ipv4, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
        if (!rr)
                return -ENOMEM;

        rr->a.in_addr = in4(ipv4);
        rr->ttl = ttl;

        return dns_answer_add_extend(
                        answer,
                        rr,
                        1,
                        DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ANSWER,
                        NULL);
}

static int add_aaaa_rr(DnsAnswer **answer, const char *name, const char *ipv6, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, name);
        if (!rr)
                return -ENOMEM;

        rr->aaaa.in6_addr = in6(ipv6);
        rr->ttl = ttl;

        return dns_answer_add_extend(
                        answer, rr, 1, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ANSWER, NULL);
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
        return dns_answer_add_extend(
                        answer, rr, 1, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ANSWER, NULL);
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
        return dns_answer_add_extend(
                        answer, rr, 1, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ANSWER, NULL);
}

static int add_ptr_rr(DnsAnswer **answer, const char *name, const char *target, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, name);
        if (!rr)
                return -ENOMEM;

        rr->ptr.name = strdup(target);
        if (!rr->ptr.name)
                return -ENOMEM;

        rr->ttl = ttl;
        return dns_answer_add_extend(
                        answer, rr, 1, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ANSWER, NULL);
}

static int add_soa_rr(DnsAnswer **answer, const char *name, uint32_t ttl, uint32_t minimum) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, name);
        if (!rr)
                return -ENOMEM;

        rr->soa.mname = strdup("ns.example.com");
        rr->soa.rname = strdup("hostmaster.example.com");
        if (!rr->soa.mname || !rr->soa.rname)
                return -ENOMEM;

        rr->soa.serial = 1;
        rr->soa.refresh = 3600;
        rr->soa.retry = 600;
        rr->soa.expire = 86400;
        rr->soa.minimum = minimum;
        rr->ttl = ttl;

        return dns_answer_add_extend(
                        answer, rr, 1, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_AUTHORITY, NULL);
}

/* True if the answer contains a CNAME with the given owner name and target. */
static bool answer_has_cname(DnsAnswer *answer, const char *owner, const char *target) {
        DnsResourceRecord *rr;

        DNS_ANSWER_FOREACH(rr, answer)
                if (rr->key->type == DNS_TYPE_CNAME &&
                    dns_name_equal(dns_resource_key_name(rr->key), owner) > 0 &&
                    dns_name_equal(rr->cname.name, target) > 0)
                        return true;

        return false;
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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);
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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);
}

/* No PREF64 configured on the link → we never act. */
TEST(dns_query_dns64_redirect_no_pref64_on_link) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        /* No link_set_dns64_prefixes() call. */

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);
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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

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
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        /* Inline synthesis produced a real AAAA from the A record. */
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::808:808"));
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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);
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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);
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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

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
        query->answer_query_flags = SD_RESOLVED_FROM_NETWORK;
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 300));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "1.1.1.1", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 2);
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::808:808"));
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::101:101"));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_FROM_NETWORK));
        ASSERT_FALSE(dns_query_fully_authoritative(query));
}

TEST(dns_query_dns64_redirect_synthesizes_all_prefixes_in_order) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;
        struct in6_addr expected[] = {
                in6("2001:db8:1::808:808"),
                in6("2001:db8:2::808:808"),
        };

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "2001:db8:1::", 96);
        link_add_pref64(link, "2001:db8:2::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        size_t i = 0;
        DnsResourceRecord *rr;
        DNS_ANSWER_FOREACH(rr, query->answer) {
                if (rr->key->type != DNS_TYPE_AAAA)
                        continue;

                ASSERT_LT(i, ELEMENTSOF(expected));
                ASSERT_EQ(memcmp(&rr->aaaa.in6_addr, &expected[i], sizeof(struct in6_addr)), 0);
                i++;
        }
        ASSERT_EQ(i, ELEMENTSOF(expected));
}

TEST(dns_query_dns64_redirect_well_known_prefix_excludes_non_global_ipv4) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "10.0.0.1", 300));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 1);
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::808:808"));
        ASSERT_FALSE(answer_has_aaaa(query->answer, "64:ff9b::a00:1"));
}

TEST(dns_query_dns64_synthesize_ipv4only_arpa) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);
        link_add_pref64(link, "2001:db8:64::", 96);

        ASSERT_OK(build_record_query(&manager, &query, "ipv4only.arpa", DNS_TYPE_AAAA, 1));
        ASSERT_EQ(dns_query_dns64_synthesize_ipv4only_arpa(query, &state), 1);
        ASSERT_EQ(state, DNS_TRANSACTION_SUCCESS);
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::c000:aa"));
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::c000:ab"));
        ASSERT_TRUE(answer_has_aaaa(query->answer, "2001:db8:64::c000:aa"));
        ASSERT_TRUE(answer_has_aaaa(query->answer, "2001:db8:64::c000:ab"));
        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 4);

        query = dns_query_free(query);
        ASSERT_OK(build_record_query(&manager, &query, "ipv4only.arpa", DNS_TYPE_TXT, 1));
        ASSERT_EQ(dns_query_dns64_synthesize_ipv4only_arpa(query, &state), 1);
        ASSERT_EQ(state, DNS_TRANSACTION_SUCCESS);
        ASSERT_TRUE(dns_answer_isempty(query->answer));

        query = dns_query_free(query);
        ASSERT_OK(build_record_query(&manager, &query, "child.ipv4only.arpa", DNS_TYPE_A, 1));
        ASSERT_EQ(dns_query_dns64_synthesize_ipv4only_arpa(query, &state), 1);
        ASSERT_EQ(state, DNS_TRANSACTION_RCODE_FAILURE);
        ASSERT_EQ(query->answer_rcode, DNS_RCODE_NXDOMAIN);

        query = dns_query_free(query);
        ASSERT_OK(build_record_query(&manager, &query, "ipv4only.arpa", DNS_TYPE_DS, 1));
        ASSERT_EQ(dns_query_dns64_synthesize_ipv4only_arpa(query, &state), 0);
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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        ASSERT_TRUE(answer_has_aaaa(query->answer, "2001:db8:122:344:c0:2:2100:0"));
}

/* Multi-homed host: two interfaces each with a PREF64.  For a query that is
 * not bound to an interface, synthesis must use the PREF64 of the scope that
 * actually resolved the name — which dns_scope_good_domain() selected using
 * per-link routing domains (e.g. eth1 carries the "example.com" routing
 * domain, so foo.example.com resolves there and synthesizes with eth1's
 * PREF64), not the first link that happens to have one configured. */
TEST(dns_query_dns64_redirect_multihome_uses_answer_scope_link) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link1 = NULL, *link2 = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link1, 1));
        link_set_pref64(link1, "64:ff9b::", 96);
        ASSERT_OK(link_new(&manager, &link2, 2));
        link_set_pref64(link2, "2001:db8:64::", 96);

        /* Unbound query (ifindex 0) resolved through link2's scope. */
        DnsScope answer_scope = { .link = link2 };
        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 0));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, &answer_scope, &state), 0);

        /* Synthesized with link2's PREF64, not link1's. */
        ASSERT_TRUE(answer_has_aaaa(query->answer, "2001:db8:64::808:808"));
        ASSERT_FALSE(answer_has_aaaa(query->answer, "64:ff9b::808:808"));
}

/* An explicitly bound interface wins over the answering scope: a query pinned
 * to eth0 synthesizes with eth0's PREF64 even if some other scope answered. */
TEST(dns_query_dns64_redirect_bound_ifindex_overrides_scope) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link1 = NULL, *link2 = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link1, 1));
        link_set_pref64(link1, "64:ff9b::", 96);
        ASSERT_OK(link_new(&manager, &link2, 2));
        link_set_pref64(link2, "2001:db8:64::", 96);

        DnsScope answer_scope = { .link = link2 };
        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, &answer_scope, &state), 0);

        /* Bound to link1: link1's PREF64 wins over the answering scope link2. */
        ASSERT_TRUE(answer_has_aaaa(query->answer, "64:ff9b::808:808"));
        ASSERT_FALSE(answer_has_aaaa(query->answer, "2001:db8:64::808:808"));
}

/* §5.1.7: with no SOA in the answer to bound it, the synthesized AAAA TTL
 * falls back to min(A TTL, 600).  Given A TTL=86400, it is capped at 600. */
TEST(dns_query_dns64_redirect_ttl_capped_at_600) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 86400));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

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
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 60));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        DnsResourceRecord *rr;
        bool found = false;
        DNS_ANSWER_FOREACH(rr, query->answer)
                if (rr->key->type == DNS_TYPE_AAAA) {
                        ASSERT_EQ(rr->ttl, (uint32_t) 60);
                        found = true;
                }
        ASSERT_TRUE(found);
}

/* §5.1.7: when a covering SOA is present, the synthesized AAAA TTL is capped at
 * min(A TTL, SOA negative TTL) rather than the 600s fallback. Here the SOA's
 * MINIMUM field (300) is the binding constraint. */
TEST(dns_query_dns64_redirect_ttl_capped_at_soa_minimum) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 86400));
        /* SOA for the enclosing zone: rr TTL 1800, MINIMUM 300. */
        ASSERT_OK(add_soa_rr(&query->answer, "example.com", 1800, 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        DnsResourceRecord *rr;
        bool found = false;
        DNS_ANSWER_FOREACH(rr, query->answer)
                if (rr->key->type == DNS_TYPE_AAAA) {
                        ASSERT_EQ(rr->ttl, (uint32_t) 300);
                        found = true;
                }
        ASSERT_TRUE(found);
}

/* §5.1.7 / RFC 2308: the SOA negative TTL is min(SOA RR TTL, SOA MINIMUM).
 * Here the SOA's own RR TTL (120) is smaller than its MINIMUM (300), so it
 * binds. */
TEST(dns_query_dns64_redirect_ttl_capped_at_soa_rr_ttl) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_UNSPEC, 1));
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 86400));
        ASSERT_OK(add_soa_rr(&query->answer, "example.com", 120, 300));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        DnsResourceRecord *rr;
        bool found = false;
        DNS_ANSWER_FOREACH(rr, query->answer)
                if (rr->key->type == DNS_TYPE_AAAA) {
                        ASSERT_EQ(rr->ttl, (uint32_t) 120);
                        found = true;
                }
        ASSERT_TRUE(found);
}

TEST(dns_query_dns64_redirect_uses_expanded_search_name) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *search_domain = NULL;
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsTransactionState state = DNS_TRANSACTION_SUCCESS;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);
        ASSERT_OK(dns_search_domain_new(&manager, &search_domain, DNS_SEARCH_DOMAIN_SYSTEM,
                                        /* link= */ NULL, /* delegate= */ NULL, "example.com"));

        ASSERT_OK(build_record_query(&manager, &query, "www", DNS_TYPE_AAAA, 1));
        query->answer_protocol = DNS_PROTOCOL_DNS;
        query->answer_search_domain = dns_search_domain_ref(search_domain);
        ASSERT_OK(add_a_rr(&query->answer, "www.example.com", "8.8.8.8", 300));
        ASSERT_OK(add_soa_rr(&query->answer, "example.com", 45, 60));

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

        ASSERT_TRUE(answer_has_aaaa_name(query->answer, "www.example.com", "64:ff9b::808:808"));
        ASSERT_PTR_EQ(query->answer_search_domain, search_domain);

        DnsResourceRecord *rr;
        DNS_ANSWER_FOREACH(rr, query->answer)
                if (rr->key->type == DNS_TYPE_AAAA)
                        ASSERT_EQ(rr->ttl, (uint32_t) 45);

        dns_search_domain_unlink(search_domain);
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
        query->answer_query_flags = SD_RESOLVED_AUTHENTICATED|SD_RESOLVED_CONFIDENTIAL|SD_RESOLVED_FROM_NETWORK;
        ASSERT_OK(add_cname_rr(&query->answer, "www.example.com", "alias.example.com", 300));
        ASSERT_OK(add_dname_rr(&query->answer, "example.com", "example.net", 300));

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        ASSERT_OK(dns_question_new_address(&question_a, AF_INET, "www.example.com", false));
        ASSERT_OK(dns_query_new(&manager, &aux, question_a, question_a, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        ASSERT_OK(add_cname_rr(&aux->answer, "www.example.com", "alias.example.com", 300));
        ASSERT_OK(add_a_rr(&aux->answer, "alias.example.com", "8.8.8.8", 1200));
        ASSERT_OK(add_soa_rr(&aux->answer, "example.com", 300, 300));
        aux->answer_query_flags = SD_RESOLVED_CONFIDENTIAL | SD_RESOLVED_FROM_CACHE;
        aux->state = DNS_TRANSACTION_SUCCESS;

        dns64_on_a_query_complete(aux);

        ASSERT_EQ(query->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_TRUE(answer_has_rr(query->answer, DNS_TYPE_CNAME, "www.example.com"));
        ASSERT_TRUE(answer_has_rr(query->answer, DNS_TYPE_DNAME, "example.com"));
        ASSERT_TRUE(answer_has_aaaa_name(query->answer, "alias.example.com", "64:ff9b::808:808"));
        ASSERT_FALSE(answer_has_rr(query->answer, DNS_TYPE_A, "alias.example.com"));
        ASSERT_TRUE(answer_has_rr(query->answer, DNS_TYPE_SOA, "example.com"));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_CONFIDENTIAL));
        ASSERT_FALSE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_AUTHENTICATED));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_FROM_NETWORK));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_FROM_CACHE));
        ASSERT_FALSE(dns_query_fully_authoritative(query));
}

TEST(dns64_auxiliary_success_preserves_expanded_search_name) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *search_domain = NULL;
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);
        ASSERT_OK(dns_search_domain_new(&manager, &search_domain, DNS_SEARCH_DOMAIN_SYSTEM,
                                        /* link= */ NULL, /* delegate= */ NULL, "example.com"));

        ASSERT_OK(build_record_query(&manager, &query, "www", DNS_TYPE_AAAA, 1));
        query->complete = query_complete_record_state;
        query->answer_protocol = DNS_PROTOCOL_DNS;
        query->answer_search_domain = dns_search_domain_ref(search_domain);
        ASSERT_OK(add_soa_rr(&query->answer, "example.com", 45, 60));

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        ASSERT_OK(dns_question_new_address(&question_a, AF_INET, "www.example.com", false));
        ASSERT_OK(dns_query_new(&manager, &aux, question_a, question_a, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        ASSERT_OK(add_a_rr(&aux->answer, "www.example.com", "8.8.8.8", 300));
        aux->state = DNS_TRANSACTION_SUCCESS;

        dns64_on_a_query_complete(aux);

        ASSERT_EQ(query->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_TRUE(answer_has_aaaa_name(query->answer, "www.example.com", "64:ff9b::808:808"));
        ASSERT_PTR_EQ(query->answer_search_domain, search_domain);

        DnsResourceRecord *rr;
        DNS_ANSWER_FOREACH(rr, query->answer)
                if (rr->key->type == DNS_TYPE_AAAA)
                        ASSERT_EQ(rr->ttl, (uint32_t) 45);

        dns_search_domain_unlink(search_domain);
}

/* RFC 6147 §5.1.2: an A lookup that yields nothing usable must not change the original AAAA outcome. */
TEST(dns64_auxiliary_empty_returns_original_aaaa_outcome) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));
        query->complete = query_complete_record_state;
        query->answer_rcode = DNS_RCODE_SUCCESS;
        query->answer_query_flags = SD_RESOLVED_AUTHENTICATED | SD_RESOLVED_FROM_NETWORK;
        query->dns64_original_state = DNS_TRANSACTION_SUCCESS;

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        ASSERT_OK(dns_question_new_address(&question_a, AF_INET, "www.example.com", false));
        ASSERT_OK(dns_query_new(&manager, &aux, question_a, question_a, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        aux->state = DNS_TRANSACTION_SUCCESS;
        aux->answer_rcode = DNS_RCODE_SERVFAIL;

        dns64_on_a_query_complete(aux);

        ASSERT_EQ(query->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_EQ(query->answer_rcode, DNS_RCODE_SUCCESS);
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_AUTHENTICATED));
        ASSERT_FALSE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
}

/* A failed auxiliary A lookup (e.g. timeout) must not override a valid original AAAA response. */
TEST(dns64_auxiliary_failure_returns_original_aaaa_outcome) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));
        query->complete = query_complete_record_state;
        query->answer_rcode = DNS_RCODE_SUCCESS;
        query->dns64_original_state = DNS_TRANSACTION_SUCCESS;

        _cleanup_(dns_question_unrefp) DnsQuestion *question_a = NULL;
        ASSERT_OK(dns_question_new_address(&question_a, AF_INET, "www.example.com", false));
        ASSERT_OK(dns_query_new(&manager, &aux, question_a, question_a, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        aux->state = DNS_TRANSACTION_TIMEOUT;

        dns64_on_a_query_complete(aux);

        ASSERT_EQ(query->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_EQ(query->answer_rcode, DNS_RCODE_SUCCESS);
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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);

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

        ASSERT_EQ(dns_query_dns64_redirect(query, NULL, &state), 0);
        ASSERT_EQ(answer_count_aaaa(query->answer), (size_t) 0);
}

/* ================================================================
 * dns_query_dns64_ptr_redirect() / dns64_on_ptr_query_complete()
 * — RFC 6147 §5.3.1 (synthesized-CNAME approach)
 * ================================================================ */

/* The completion path builds the final answer: a synthesized CNAME from the
 * IP6.ARPA name to the corresponding IN-ADDR.ARPA name, followed by the real
 * PTR records the reverse lookup returned. */
TEST(dns64_ptr_synthesizes_cname_to_in_addr_arpa) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        /* Original query: PTR for the IP6.ARPA name of 64:ff9b::c000:201, i.e.
         * the DNS64 address embedding 192.0.2.1. */
        ASSERT_OK(build_ptr_query(&manager, &query, "64:ff9b::c000:201", 1, 0));
        query->complete = query_complete_record_state;
        const char *ip6_name = dns_question_first_name(query->question_utf8);

        /* Auxiliary reverse lookup for 192.0.2.1 -> 1.2.0.192.in-addr.arpa,
         * answered with a real PTR record. */
        union in_addr_union v4 = { .in = in4("192.0.2.1") };
        _cleanup_(dns_question_unrefp) DnsQuestion *question_ptr = NULL;
        ASSERT_OK(dns_question_new_reverse(&question_ptr, AF_INET, &v4));
        const char *in_addr_name = dns_question_first_name(question_ptr);

        ASSERT_OK(dns_query_new(&manager, &aux, question_ptr, question_ptr, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        ASSERT_OK(add_ptr_rr(&aux->answer, in_addr_name, "host.example.com", 300));
        aux->state = DNS_TRANSACTION_SUCCESS;

        dns64_on_ptr_query_complete(aux);

        ASSERT_EQ(query->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_TRUE(answer_has_cname(query->answer, ip6_name, in_addr_name));
        ASSERT_TRUE(answer_has_rr(query->answer, DNS_TYPE_PTR, in_addr_name));
        ASSERT_TRUE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
}

TEST(dns64_ptr_existing_cname_suppresses_synthetic_cname) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_ptr_query(&manager, &query, "64:ff9b::808:808", 1, 0));
        query->complete = query_complete_record_state;

        union in_addr_union v4 = { .in = in4("8.8.8.8") };
        _cleanup_(dns_question_unrefp) DnsQuestion *question_ptr = NULL;
        ASSERT_OK(dns_question_new_reverse(&question_ptr, AF_INET, &v4));
        const char *in_addr_name = dns_question_first_name(question_ptr);

        ASSERT_OK(dns_query_new(&manager, &aux, question_ptr, question_ptr, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        ASSERT_OK(add_cname_rr(&aux->answer, in_addr_name, "alias.example.com", 300));
        ASSERT_OK(add_ptr_rr(&aux->answer, "alias.example.com", "host.example.com", 300));
        aux->state = DNS_TRANSACTION_SUCCESS;

        dns64_on_ptr_query_complete(aux);

        ASSERT_EQ(query->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_TRUE(dns_answer_isempty(query->answer));
        ASSERT_FALSE(FLAGS_SET(query->answer_query_flags, SD_RESOLVED_SYNTHETIC));
}

/* RFC 6147 §5.3.1: if the IN-ADDR.ARPA name has no PTR, we must not synthesize
 * a CNAME pointing at nothing; the reverse lookup's outcome is returned. */
TEST(dns64_ptr_no_reverse_record_propagates_outcome) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        DnsQuery *query = NULL;
        DnsQuery *aux = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_ptr_query(&manager, &query, "64:ff9b::c000:201", 1, 0));
        query->complete = query_complete_free_record_state;
        completed_state = _DNS_TRANSACTION_STATE_INVALID;

        union in_addr_union v4 = { .in = in4("192.0.2.1") };
        _cleanup_(dns_question_unrefp) DnsQuestion *question_ptr = NULL;
        ASSERT_OK(dns_question_new_reverse(&question_ptr, AF_INET, &v4));
        ASSERT_OK(dns_query_new(&manager, &aux, question_ptr, question_ptr, NULL, 1, 0));
        ASSERT_OK(dns_query_make_auxiliary(aux, query));
        aux->state = DNS_TRANSACTION_NOT_FOUND; /* NXDOMAIN-ish, no records */

        dns64_on_ptr_query_complete(aux);

        ASSERT_EQ(completed_state, DNS_TRANSACTION_NOT_FOUND);
}

/* A PTR for an address that does not fall under any configured PREF64 is left
 * for normal resolution (returns 0, fires no auxiliary query). */
TEST(dns_query_dns64_ptr_redirect_no_pref64_match_skipped) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        /* 2001:db8::1 is not under 64:ff9b::/96. */
        ASSERT_OK(build_ptr_query(&manager, &query, "2001:db8::1", 1, 0));

        ASSERT_EQ(dns_query_dns64_ptr_redirect(query), 0);
}

/* A forward (non-PTR) query is never intercepted by the reverse path. */
TEST(dns_query_dns64_ptr_redirect_non_ptr_skipped) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_query(&manager, &query, AF_INET6, 1));

        ASSERT_EQ(dns_query_dns64_ptr_redirect(query), 0);
}

/* SD_RESOLVED_NO_SYNTHESIZE opts the query out of reverse DNS64 entirely. */
TEST(dns_query_dns64_ptr_redirect_no_synthesize_flag_skipped) {
        Manager manager = { .dns64_enabled = true };
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        link_set_pref64(link, "64:ff9b::", 96);

        ASSERT_OK(build_ptr_query(&manager, &query, "64:ff9b::c000:201", 1, SD_RESOLVED_NO_SYNTHESIZE));

        ASSERT_EQ(dns_query_dns64_ptr_redirect(query), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
