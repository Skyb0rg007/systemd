/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>

#include "sd-event.h"
#include "sd-netlink.h"

#include "dns-packet.h"
#include "netlink-internal.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-server.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "tests.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(LinkAddress*, link_address_free);

/* ================================================================
 * link_new()
 * ================================================================ */

TEST(link_new) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);
}

/* ================================================================
 * link_process_rtnl()
 * ================================================================ */

TEST(link_process_rtnl) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *nl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *msg = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);

        ASSERT_OK(netlink_open_family(&nl, AF_INET));
        nl->protocol = NETLINK_ROUTE;

        ASSERT_OK(sd_rtnl_message_new_link(nl, &msg, RTM_NEWLINK, 1));
        ASSERT_NOT_NULL(msg);
        message_seal(msg);

        ASSERT_OK(link_process_rtnl(link, msg));
}

/* ================================================================
 * link_relevant()
 * ================================================================ */

TEST(link_relevant) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(link_address_freep) LinkAddress *address = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);

        link->flags = IFF_LOOPBACK;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP | IFF_MULTICAST;
        link->operstate = IF_OPER_UP;

        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        union in_addr_union ip = { .in.s_addr = htobe32(0xc0a84301) };
        union in_addr_union bcast = { .in.s_addr = htobe32(0xc0a843ff) };

        ASSERT_OK(link_address_new(link, &address, AF_INET, &ip, &bcast));
        ASSERT_NOT_NULL(address);

        ASSERT_TRUE(link_relevant(link, AF_INET, true));
        ASSERT_TRUE(link_relevant(link, AF_INET, false));

        link->flags = IFF_UP | IFF_LOWER_UP;
        ASSERT_FALSE(link_relevant(link, AF_INET, true));
        ASSERT_TRUE(link_relevant(link, AF_INET, false));

        link->is_managed = true;
        ASSERT_FALSE(link_relevant(link, AF_INET, false));

        link->networkd_operstate = LINK_OPERSTATE_DEGRADED_CARRIER;
        ASSERT_TRUE(link_relevant(link, AF_INET, false));
}

/* ================================================================
 * link_find_address()
 * ================================================================ */

TEST(link_find_address) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(link_address_freep) LinkAddress *v4addr = NULL, *v6addr = NULL, *ret_addr = NULL;

        union in_addr_union ipv4 = { .in.s_addr = htobe32(0xc0a84301) };
        union in_addr_union ipv6 = { .in6.s6_addr = { 0xf2, 0x34, 0x32, 0x2e, 0xb8, 0x25, 0x38, 0x35, 0x2f, 0xd7, 0xdb, 0x7b, 0x28, 0x7e, 0x60, 0xbb } };

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);

        ASSERT_OK(link_address_new(link, &v4addr, AF_INET, &ipv4, &ipv4));
        ASSERT_NOT_NULL(v4addr);
        ASSERT_OK(link_address_new(link, &v6addr, AF_INET6, &ipv6, &ipv6));
        ASSERT_NOT_NULL(v6addr);

        ret_addr = link_find_address(link, AF_INET, &ipv4);
        ASSERT_TRUE(ret_addr == v4addr);

        ret_addr = link_find_address(link, AF_INET6, &ipv6);
        ASSERT_TRUE(ret_addr == v6addr);

        ret_addr = link_find_address(link, AF_INET6, &ipv4);
        ASSERT_NULL(ret_addr);
}

/* ================================================================
 * link_allocate_scopes()
 * ================================================================ */

typedef struct LinkAllocEnv {
        Manager manager;
        int ifindex;
        Link *link;
        union in_addr_union ip_addr;
        LinkAddress *address;
        DnsServerType server_type;
        union in_addr_union server_addr;
        char *server_name;
        uint16_t server_port;
        DnsServer *server;
} LinkAllocEnv;

static void link_alloc_env_teardown(LinkAllocEnv *env) {
        ASSERT_NOT_NULL(env);

        free(env->server_name);
        link_address_free(env->address);
        dns_server_unref(env->server);
        sd_event_unref(env->manager.event);
}

static void link_alloc_env_setup(LinkAllocEnv *env, int family, DnsServerType server_type) {
        Link *link = NULL;

        ASSERT_NOT_NULL(env);

        env->manager = (Manager) {};
        env->ifindex = 1;

        ASSERT_OK(sd_event_new(&env->manager.event));
        ASSERT_NOT_NULL(env->manager.event);

        ASSERT_OK(link_new(&env->manager, &env->link, env->ifindex));
        ASSERT_NOT_NULL(env->link);
        env->link->flags = IFF_UP | IFF_LOWER_UP;
        env->link->operstate = IF_OPER_UP;

        env->ip_addr.in.s_addr = htobe32(0xc0a84301);
        ASSERT_OK(link_address_new(env->link, &env->address, family, &env->ip_addr, &env->ip_addr));
        ASSERT_NOT_NULL(env->address);

        env->server_type = server_type;
        env->server_addr.in.s_addr = htobe32(0x7f000001);
        env->server_name = strdup("localhost");
        env->server_port = 53;

        if (server_type == DNS_SERVER_LINK)
                link = env->link;

        ASSERT_OK(dns_server_new(&env->manager, &env->server, env->server_type,
                        link, /* delegate= */ NULL, family, &env->server_addr, env->server_port,
                        env->ifindex, env->server_name, RESOLVE_CONFIG_SOURCE_DBUS));

        ASSERT_NOT_NULL(env->server);
}

TEST(link_allocate_scopes_resets_manager_dns_server) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_SYSTEM);

        env.link->unicast_relevant = false;
        env.manager.dns_servers->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
        env.manager.dns_servers->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;
        env.manager.dns_servers->received_udp_fragment_max = 1024u;

        link_allocate_scopes(env.link);

        ASSERT_TRUE(env.link->unicast_relevant);
        ASSERT_EQ(env.manager.dns_servers->verified_feature_level, _DNS_SERVER_FEATURE_LEVEL_INVALID);
        ASSERT_EQ(env.manager.dns_servers->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_BEST);
        ASSERT_EQ(env.manager.dns_servers->received_udp_fragment_max, DNS_PACKET_UNICAST_SIZE_MAX);

        ASSERT_FALSE(env.manager.dns_servers->packet_bad_opt);
        ASSERT_FALSE(env.manager.dns_servers->packet_rrsig_missing);
        ASSERT_FALSE(env.manager.dns_servers->packet_do_off);
        ASSERT_FALSE(env.manager.dns_servers->warned_downgrade);

        ASSERT_NULL(env.link->unicast_scope);
        ASSERT_NULL(env.link->llmnr_ipv4_scope);
        ASSERT_NULL(env.link->llmnr_ipv6_scope);
        ASSERT_NULL(env.link->mdns_ipv4_scope);
        ASSERT_NULL(env.link->mdns_ipv6_scope);
}

TEST(link_allocate_scopes_unicast) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_LINK);

        env.link->unicast_relevant = true;
        env.link->dns_servers->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
        env.link->dns_servers->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;
        env.link->dns_servers->received_udp_fragment_max = 1024u;

        link_allocate_scopes(env.link);

        ASSERT_TRUE(env.link->unicast_relevant);
        ASSERT_EQ(env.link->dns_servers->verified_feature_level, _DNS_SERVER_FEATURE_LEVEL_INVALID);
        ASSERT_EQ(env.link->dns_servers->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_BEST);
        ASSERT_EQ(env.link->dns_servers->received_udp_fragment_max, DNS_PACKET_UNICAST_SIZE_MAX);

        ASSERT_FALSE(env.link->dns_servers->packet_bad_opt);
        ASSERT_FALSE(env.link->dns_servers->packet_rrsig_missing);
        ASSERT_FALSE(env.link->dns_servers->packet_do_off);
        ASSERT_FALSE(env.link->dns_servers->warned_downgrade);

        ASSERT_NULL(env.link->llmnr_ipv4_scope);
        ASSERT_NULL(env.link->llmnr_ipv6_scope);
        ASSERT_NULL(env.link->mdns_ipv4_scope);
        ASSERT_NULL(env.link->mdns_ipv6_scope);

        ASSERT_TRUE(env.link->unicast_scope->link == env.link);
        ASSERT_EQ(env.link->unicast_scope->protocol, DNS_PROTOCOL_DNS);
        ASSERT_EQ(env.link->unicast_scope->family, AF_UNSPEC);
}

TEST(link_allocate_scopes_llmnr_ipv4) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_LINK);

        env.link->flags |= IFF_MULTICAST;
        env.link->llmnr_support = RESOLVE_SUPPORT_YES;
        env.manager.llmnr_support = RESOLVE_SUPPORT_YES;

        link_allocate_scopes(env.link);

        ASSERT_NOT_NULL(env.link->unicast_scope);
        ASSERT_NULL(env.link->llmnr_ipv6_scope);
        ASSERT_NULL(env.link->mdns_ipv4_scope);
        ASSERT_NULL(env.link->mdns_ipv6_scope);

        ASSERT_TRUE(env.link->llmnr_ipv4_scope->link == env.link);
        ASSERT_EQ(env.link->llmnr_ipv4_scope->protocol, DNS_PROTOCOL_LLMNR);
        ASSERT_EQ(env.link->llmnr_ipv4_scope->family, AF_INET);
}

TEST(link_allocate_scopes_llmnr_ipv6) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET6, DNS_SERVER_LINK);

        env.link->flags |= IFF_MULTICAST;
        env.link->llmnr_support = RESOLVE_SUPPORT_YES;
        env.manager.llmnr_support = RESOLVE_SUPPORT_YES;

        link_allocate_scopes(env.link);

        ASSERT_NOT_NULL(env.link->unicast_scope);
        ASSERT_NULL(env.link->llmnr_ipv4_scope);
        ASSERT_NULL(env.link->mdns_ipv4_scope);
        ASSERT_NULL(env.link->mdns_ipv6_scope);

        ASSERT_TRUE(env.link->llmnr_ipv6_scope->link == env.link);
        ASSERT_EQ(env.link->llmnr_ipv6_scope->protocol, DNS_PROTOCOL_LLMNR);
        ASSERT_EQ(env.link->llmnr_ipv6_scope->family, AF_INET6);
}

TEST(link_allocate_scopes_mdns_ipv4) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_LINK);

        env.link->flags |= IFF_MULTICAST;
        env.link->mdns_support = RESOLVE_SUPPORT_YES;
        env.manager.mdns_support = RESOLVE_SUPPORT_YES;

        link_allocate_scopes(env.link);

        ASSERT_NOT_NULL(env.link->unicast_scope);
        ASSERT_NULL(env.link->llmnr_ipv4_scope);
        ASSERT_NULL(env.link->llmnr_ipv6_scope);
        ASSERT_NULL(env.link->mdns_ipv6_scope);

        ASSERT_TRUE(env.link->mdns_ipv4_scope->link == env.link);
        ASSERT_EQ(env.link->mdns_ipv4_scope->protocol, DNS_PROTOCOL_MDNS);
        ASSERT_EQ(env.link->mdns_ipv4_scope->family, AF_INET);
}

TEST(link_allocate_scopes_mdns_ipv6) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET6, DNS_SERVER_LINK);

        env.link->flags |= IFF_MULTICAST;
        env.link->mdns_support = RESOLVE_SUPPORT_YES;
        env.manager.mdns_support = RESOLVE_SUPPORT_YES;

        link_allocate_scopes(env.link);

        ASSERT_NOT_NULL(env.link->unicast_scope);
        ASSERT_NULL(env.link->llmnr_ipv4_scope);
        ASSERT_NULL(env.link->llmnr_ipv6_scope);
        ASSERT_NULL(env.link->mdns_ipv4_scope);

        ASSERT_TRUE(env.link->mdns_ipv6_scope->link == env.link);
        ASSERT_EQ(env.link->mdns_ipv6_scope->protocol, DNS_PROTOCOL_MDNS);
        ASSERT_EQ(env.link->mdns_ipv6_scope->family, AF_INET6);
}

/* ================================================================
 * dns_server_possible_feature_level()
 * ================================================================ */

TEST(dns_server_possible_feature_level_dnssec_on_request) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_LINK);

        /* In DNSSEC=on-request mode, the DNSSEC feature levels are not probed, as only lookups requesting
         * validation use them */
        env.link->dnssec_mode = DNSSEC_ON_REQUEST;
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_EDNS0);

        /* … and responses to those don't bump the feature level used by all other lookups */
        dns_server_packet_received(env.server, IPPROTO_UDP, DNS_SERVER_FEATURE_LEVEL_DO, 512);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_EDNS0);

        /* In the other DNSSEC modes they are */
        env.link->dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        dns_server_reset_features(env.server);
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_DO);
        dns_server_packet_received(env.server, IPPROTO_UDP, DNS_SERVER_FEATURE_LEVEL_DO, 512);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_DO);
}

TEST(dns_server_possible_feature_level_dnssec_turned_off) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_LINK);

        env.link->dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_DO);
        dns_server_packet_received(env.server, IPPROTO_UDP, DNS_SERVER_FEATURE_LEVEL_DO, 512);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_DO);

        /* A previously verified DNSSEC feature level must not be used once DNSSEC is turned off */
        env.link->dnssec_mode = DNSSEC_NO;
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_EDNS0);
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_EDNS0);
}

/* ================================================================
 * dns_server_packet_rrsig_missing()
 * ================================================================ */

TEST(dns_server_packet_rrsig_missing_dnssec_on_request) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_LINK);

        /* In DNSSEC=on-request mode missing RRSIGs in responses to lookups requesting validation don't
         * make the server unsuitable for DNSSEC RR lookups of all other clients… */
        env.link->dnssec_mode = DNSSEC_ON_REQUEST;
        ASSERT_TRUE(dns_server_dnssec_supported(env.server));
        dns_server_packet_rrsig_missing(env.server, DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_FALSE(env.server->packet_rrsig_missing);
        ASSERT_TRUE(dns_server_dnssec_supported(env.server));

        /* … while they do in DNSSEC=allow-downgrade mode */
        env.link->dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        dns_server_reset_features(env.server);
        ASSERT_TRUE(dns_server_dnssec_supported(env.server));
        dns_server_packet_rrsig_missing(env.server, DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_TRUE(env.server->packet_rrsig_missing);
        ASSERT_FALSE(dns_server_dnssec_supported(env.server));
}

/* ================================================================
 * dns_server_packet_bad_opt()
 * ================================================================ */

TEST(dns_server_packet_bad_opt_dnssec_on_request) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_LINK);

        /* In DNSSEC=on-request mode a missing OPT RR in responses to lookups requesting validation doesn't
         * downgrade the feature level used by all other lookups… */
        env.link->dnssec_mode = DNSSEC_ON_REQUEST;
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_EDNS0);
        dns_server_packet_bad_opt(env.server, DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_FALSE(env.server->packet_bad_opt);
        ASSERT_TRUE(dns_server_dnssec_supported(env.server));
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_EDNS0);

        /* … while a missing OPT RR in responses to the other lookups does */
        dns_server_packet_bad_opt(env.server, DNS_SERVER_FEATURE_LEVEL_EDNS0);
        ASSERT_TRUE(env.server->packet_bad_opt);
        ASSERT_FALSE(dns_server_dnssec_supported(env.server));
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_UDP);

        /* In DNSSEC=allow-downgrade mode it always does */
        env.link->dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        dns_server_reset_features(env.server);
        ASSERT_EQ(dns_server_possible_feature_level(env.server), DNS_SERVER_FEATURE_LEVEL_DO);
        dns_server_packet_bad_opt(env.server, DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_TRUE(env.server->packet_bad_opt);
        ASSERT_FALSE(dns_server_dnssec_supported(env.server));
}

/* ================================================================
 * dns_scope_normalize_query_flags()
 * ================================================================ */

TEST(dns_scope_normalize_query_flags) {
        _cleanup_(link_alloc_env_teardown) LinkAllocEnv env = {};

        link_alloc_env_setup(&env, AF_INET, DNS_SERVER_LINK);

        /* Requesting validation only makes a difference in DNSSEC=on-request mode */
        env.link->dnssec_mode = DNSSEC_ON_REQUEST;
        env.link->unicast_relevant = true;
        link_allocate_scopes(env.link);
        ASSERT_NOT_NULL(env.link->unicast_scope);
        ASSERT_EQ(dns_scope_normalize_query_flags(env.link->unicast_scope, SD_RESOLVED_VALIDATE|SD_RESOLVED_DNS),
                  SD_RESOLVED_VALIDATE|SD_RESOLVED_DNS);

        /* Not using link_set_dnssec_mode() here, as it ignores the mode if built without OpenSSL */
        env.link->dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        env.link->unicast_scope = dns_scope_free(env.link->unicast_scope);
        link_allocate_scopes(env.link);
        ASSERT_NOT_NULL(env.link->unicast_scope);
        ASSERT_EQ(dns_scope_normalize_query_flags(env.link->unicast_scope, SD_RESOLVED_VALIDATE|SD_RESOLVED_DNS),
                  SD_RESOLVED_DNS);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
