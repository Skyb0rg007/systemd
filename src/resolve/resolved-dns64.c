/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* DNS64 implementation per RFC 6147 and RFC 6052. */

#include <netinet/in.h>
#include <string.h>

#include "log.h"
#include "resolved-dns64.h"

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
