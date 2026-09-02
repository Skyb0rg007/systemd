/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/in.h>

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

DEFINE_TEST_MAIN(LOG_DEBUG);
