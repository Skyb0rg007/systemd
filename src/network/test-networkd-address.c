/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_addr.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>

#include "dhcp6-address-registration.h"
#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"
#include "networkd-address.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-wifi.h"
#include "networkd-wwan.h"
#include "tests.h"
#include "time-util.h"
#include "unaligned.h"

static void test_FORMAT_LIFETIME_one(usec_t lifetime, const char *expected) {
        const char *t = FORMAT_LIFETIME(lifetime);

        log_debug(USEC_FMT " → \"%s\" (expected \"%s\")", lifetime, t, strna(expected));
        if (expected)
                ASSERT_STREQ(t, expected);
}

TEST(FORMAT_LIFETIME) {
        usec_t now_usec;

        now_usec = now(CLOCK_BOOTTIME);

        test_FORMAT_LIFETIME_one(now_usec, "for 0");
        test_FORMAT_LIFETIME_one(USEC_INFINITY, "forever");

        /* These two are necessarily racy, especially for slow test environment. */
        test_FORMAT_LIFETIME_one(usec_add(now_usec, 2 * USEC_PER_SEC - 1), NULL);
        test_FORMAT_LIFETIME_one(usec_add(now_usec, 3 * USEC_PER_WEEK + USEC_PER_SEC - 1), NULL);
}

TEST(dhcp6_address_registration_eligibility) {
        Link link = {};
        Address address = {
                .link = &link,
                .family = AF_INET6,
                .scope = RT_SCOPE_UNIVERSE,
                .source = NETWORK_CONFIG_SOURCE_STATIC,
                .state = NETWORK_CONFIG_STATE_CONFIGURED,
                .lifetime_preferred_usec = USEC_INFINITY,
                .lifetime_valid_usec = USEC_INFINITY,
        };

        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));

        address.family = AF_INET;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.family = AF_INET6;

        address.scope = RT_SCOPE_LINK;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.scope = RT_SCOPE_UNIVERSE;

        address.flags = IFA_F_TENTATIVE;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.flags = 0;

        address.state = NETWORK_CONFIG_STATE_CONFIGURING;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.state = NETWORK_CONFIG_STATE_CONFIGURED;

        address.lifetime_valid_usec = now(CLOCK_BOOTTIME);
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.lifetime_valid_usec = usec_add(now(CLOCK_BOOTTIME), USEC_PER_HOUR);

        address.source = NETWORK_CONFIG_SOURCE_DHCP6;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.source = NETWORK_CONFIG_SOURCE_NDISC;
        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));
        address.source = NETWORK_CONFIG_SOURCE_DHCP_PD;
        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));
        address.source = NETWORK_CONFIG_SOURCE_FOREIGN;
        address.lifetime_valid_usec = USEC_INFINITY;
        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));
}

TEST(dhcp6_address_registration_synchronization) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        Network network = {
                .dhcp6_register_addresses = true,
        };
        Link link = {
                .network = &network,
        };
        Address address = {
                .link = &link,
                .family = AF_INET6,
                .scope = RT_SCOPE_UNIVERSE,
                .source = NETWORK_CONFIG_SOURCE_STATIC,
                .state = NETWORK_CONFIG_STATE_CONFIGURED,
                .in_addr.in6 = { .s6_addr = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 } },
                .lifetime_preferred_usec = USEC_INFINITY,
                .lifetime_valid_usec = USEC_INFINITY,
        };

        ASSERT_OK(sd_dhcp6_client_new(&client));
        link.dhcp6_client = client;

        ASSERT_EQ(dhcp6_sync_address_registration(&link, &address), 1);
        ASSERT_EQ(dhcp6_client_address_registration_count(client), 1U);

        usec_t preferred_usec = usec_add(now(CLOCK_BOOTTIME), USEC_PER_HOUR);
        usec_t valid_usec = usec_add(now(CLOCK_BOOTTIME), 2 * USEC_PER_HOUR);
        address.lifetime_preferred_usec = preferred_usec;
        address.lifetime_valid_usec = valid_usec;
        ASSERT_EQ(dhcp6_sync_address_registration(&link, &address), 1);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        dhcp6_client_get_address_registration(client, &address.in_addr.in6));
        ASSERT_EQ(registration->lifetime_preferred_usec, preferred_usec);
        ASSERT_EQ(registration->lifetime_valid_usec, valid_usec);

        address.flags = IFA_F_TENTATIVE;
        ASSERT_OK(dhcp6_sync_address_registration(&link, &address));
        ASSERT_EQ(dhcp6_client_address_registration_count(client), 0U);

        address.flags = 0;
        ASSERT_EQ(dhcp6_sync_address_registration(&link, &address), 1);
        dhcp6_remove_address_registration(&link, &address);
        ASSERT_EQ(dhcp6_client_address_registration_count(client), 0U);

        network.dhcp6_register_addresses = false;
        ASSERT_OK(dhcp6_sync_address_registration(&link, &address));
        ASSERT_EQ(dhcp6_client_address_registration_count(client), 0U);
}

static int address_registration_open_fail(int ifindex, void *userdata) {
        return -EIO;
}

static uint32_t address_registration_random_u32(void *userdata) {
        return 1;
}

static uint64_t address_registration_random_u64_range(uint64_t upper_bound, void *userdata) {
        assert(upper_bound > 0);
        return 0;
}

static const DHCP6AddressRegistrationIO address_registration_failing_io = {
        .open_socket = address_registration_open_fail,
        .random_u32 = address_registration_random_u32,
        .random_u64_range = address_registration_random_u64_range,
};

TEST(dhcp6_address_registration_best_effort) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        Network network = {
                .dhcp6_register_addresses = true,
        };
        Link link = {
                .ifname = (char*) "test",
                .network = &network,
                .state = LINK_STATE_CONFIGURED,
        };
        Address address = {
                .link = &link,
                .family = AF_INET6,
                .scope = RT_SCOPE_UNIVERSE,
                .source = NETWORK_CONFIG_SOURCE_STATIC,
                .state = NETWORK_CONFIG_STATE_CONFIGURED,
                .in_addr.in6 = { .s6_addr = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 } },
                .lifetime_preferred_usec = USEC_INFINITY,
                .lifetime_valid_usec = USEC_INFINITY,
        };

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_set_ifindex(client, 42));
        dhcp6_client_set_address_registration_io(client, &address_registration_failing_io, NULL);
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        link.dhcp6_client = client;

        ASSERT_OK(dhcp6_sync_address_registration(&link, &address));
        ASSERT_EQ(link.state, LINK_STATE_CONFIGURED);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        dhcp6_client_get_address_registration(client, &address.in_addr.in6));
        ASSERT_TRUE(registration->transaction_active);
        ASSERT_FALSE(registration->has_been_registered);
        ASSERT_EQ(registration->transmission_count, 0U);
}

static int address_registration_defer_handler(sd_event_source *s, void *userdata) {
        return 0;
}

TEST(dhcp6_address_registration_attachment_boundaries) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_free_ uint8_t *buf = NULL;
        const struct ether_addr bssid1 = { .ether_addr_octet = { 0, 1, 2, 3, 4, 5 } };
        const struct ether_addr bssid2 = { .ether_addr_octet = { 0, 1, 2, 3, 4, 6 } };
        Link link = {
                .wlan_iftype = NL80211_IFTYPE_STATION,
        };
        Bearer bearer = {
                .connected = true,
        };
        size_t offset = 0, option_offset = 0, optlen;
        const uint8_t *optval;
        unsigned n_address_registration = 0;
        uint16_t optcode;
        int enabled;

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, event, 0));
        ASSERT_OK(dhcp6_client_set_address_registration_parameters(
                          client,
                          /* enabled= */ true,
                          DHCP6_ADDRESS_REGISTRATION_DEFAULT_IRT,
                          DHCP6_ADDRESS_REGISTRATION_DEFAULT_MRC,
                          DHCP6_ADDRESS_REGISTRATION_DEFAULT_STATIC_REFRESH_INTERVAL));
        ASSERT_OK(sd_event_add_defer(
                          event, &client->receive_message, address_registration_defer_handler, NULL));
        client->information_request = true;
        client->state = DHCP6_STATE_INFORMATION_REQUEST;
        link.dhcp6_client = client;

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        ASSERT_EQ(link_update_wifi_bssid(&link, &bssid1), 1);
        ASSERT_FALSE(client->address_registration.supported);
        ASSERT_EQ(client->state, DHCP6_STATE_INFORMATION_REQUEST);
        ASSERT_NOT_NULL(client->timeout_resend);
        ASSERT_OK(sd_event_source_get_enabled(client->timeout_resend, &enabled));
        ASSERT_EQ(enabled, SD_EVENT_ONESHOT);

        ASSERT_NOT_NULL(buf = new0(uint8_t, 1));
        ASSERT_OK(dhcp6_client_append_oro(client, &buf, &offset));
        ASSERT_OK(dhcp6_option_parse(buf, offset, &option_offset, &optcode, &optlen, &optval));
        ASSERT_EQ(optcode, SD_DHCP6_OPTION_ORO);
        for (size_t i = 0; i < optlen / sizeof(be16_t); i++)
                if (unaligned_read_be16(optval + i * sizeof(be16_t)) == SD_DHCP6_OPTION_ADDR_REG_ENABLE)
                        n_address_registration++;
        ASSERT_EQ(n_address_registration, 1U);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        ASSERT_OK(link_update_wifi_bssid(&link, &bssid1));
        ASSERT_TRUE(client->address_registration.supported);

        ASSERT_EQ(link_update_wifi_bssid(&link, &bssid2), 1);
        ASSERT_FALSE(client->address_registration.supported);
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        link_clear_wifi_bssid(&link);
        ASSERT_FALSE(client->address_registration.supported);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        ASSERT_EQ(link_update_wwan_attachment(&link, &bearer), 1);
        ASSERT_FALSE(client->address_registration.supported);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        ASSERT_OK(link_update_wwan_attachment(&link, &bearer));
        ASSERT_TRUE(client->address_registration.supported);

        bearer.connected = false;
        ASSERT_EQ(link_update_wwan_attachment(&link, &bearer), 1);
        ASSERT_FALSE(client->address_registration.supported);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        bearer.connected = true;
        ASSERT_EQ(link_update_wwan_attachment(&link, &bearer), 1);
        ASSERT_FALSE(client->address_registration.supported);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        Bearer replacement = {
                .connected = true,
        };
        ASSERT_EQ(link_update_wwan_attachment(&link, &replacement), 1);
        ASSERT_FALSE(client->address_registration.supported);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
