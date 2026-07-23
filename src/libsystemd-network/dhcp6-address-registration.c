/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp6-address-registration.h"
#include "dhcp6-internal.h"
#include "dhcp6-option.h"
#include "dhcp6-protocol.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "macro.h"
#include "network-common.h"
#include "random-util.h"
#include "socket-util.h"

static int address_registration_receive_event(sd_event_source *s, int fd, uint32_t revents, void *userdata);
static int address_registration_retransmit_event(sd_event_source *s, uint64_t usec, void *userdata);

static int address_registration_open_socket(int ifindex, void *userdata) {
        union sockaddr_union source = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = IN6ADDR_ANY_INIT,
                .in6.sin6_port = htobe16(DHCP6_PORT_CLIENT),
        };
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(ifindex > 0);

        fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
        if (fd < 0)
                return -errno;

        r = setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, false);
        if (r < 0)
                return r;

        r = socket_set_recvpktinfo(fd, AF_INET6, true);
        if (r < 0)
                return r;

        r = socket_bind_to_ifindex(fd, ifindex);
        if (r < 0)
                return r;

        if (bind(fd, &source.sa, sizeof(source.in6)) < 0)
                return -errno;

        return TAKE_FD(fd);
}

static int address_registration_send(
                int fd,
                const struct in6_addr *source,
                int ifindex,
                const struct sockaddr_in6 *destination,
                const void *packet,
                size_t len,
                void *userdata) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        struct iovec iov = IOVEC_MAKE((void*) packet, len);
        struct msghdr message = {
                .msg_name = (struct sockaddr_in6*) destination,
                .msg_namelen = sizeof(*destination),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        struct in6_pktinfo *pktinfo;
        ssize_t n;

        assert(fd >= 0);
        assert(source);
        assert(ifindex > 0);
        assert(destination);
        assert(packet);

        cmsg = CMSG_FIRSTHDR(&message);
        assert(cmsg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        pktinfo = (struct in6_pktinfo*) CMSG_DATA(cmsg);
        *pktinfo = (struct in6_pktinfo) {
                .ipi6_addr = *source,
                .ipi6_ifindex = ifindex,
        };

        n = sendmsg(fd, &message, MSG_NOSIGNAL);
        if (n < 0)
                return -errno;
        if ((size_t) n != len)
                return -EIO;

        return 0;
}

static int address_registration_receive(
                int fd,
                void **ret_packet,
                size_t *ret_len,
                struct sockaddr_in6 *ret_sender,
                struct in6_addr *ret_destination,
                int *ret_ifindex,
                bool *ret_truncated,
                void *userdata) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        union sockaddr_union sender = {};
        _cleanup_free_ void *packet = NULL;
        struct iovec iov;
        struct msghdr message = {
                .msg_name = &sender.sa,
                .msg_namelen = sizeof(sender),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        ssize_t buflen, len;

        assert(fd >= 0);
        assert(ret_packet);
        assert(ret_len);
        assert(ret_sender);
        assert(ret_destination);
        assert(ret_ifindex);
        assert(ret_truncated);

        buflen = next_datagram_size_fd(fd);
        if (buflen < 0)
                return (int) buflen;

        packet = malloc(MAX(buflen, (ssize_t) 1));
        if (!packet)
                return -ENOMEM;

        iov = IOVEC_MAKE(packet, buflen);
        len = recvmsg_safe(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (len < 0)
                return (int) len;

        struct in6_pktinfo *pktinfo =
                CMSG_FIND_DATA(&message, IPPROTO_IPV6, IPV6_PKTINFO, struct in6_pktinfo);

        *ret_packet = TAKE_PTR(packet);
        *ret_len = MIN((size_t) len, (size_t) buflen);
        *ret_sender = sender.in6;
        *ret_destination = pktinfo ? pktinfo->ipi6_addr : in6addr_any;
        *ret_ifindex = pktinfo ? pktinfo->ipi6_ifindex : 0;
        *ret_truncated = FLAGS_SET(message.msg_flags, MSG_TRUNC);
        return 0;
}

static uint32_t address_registration_random_u32(void *userdata) {
        return random_u32();
}

static uint64_t address_registration_random_u64_range(uint64_t upper_bound, void *userdata) {
        return random_u64_range(upper_bound);
}

static const DHCP6AddressRegistrationIO address_registration_default_io = {
        .open_socket = address_registration_open_socket,
        .send = address_registration_send,
        .receive = address_registration_receive,
        .random_u32 = address_registration_random_u32,
        .random_u64_range = address_registration_random_u64_range,
};

static const DHCP6AddressRegistrationIO* address_registration_get_io(sd_dhcp6_client *client) {
        assert(client);

        return client->address_registration.io ?: &address_registration_default_io;
}

static DHCP6AddressRegistration *address_registration_free(DHCP6AddressRegistration *registration) {
        if (!registration)
                return NULL;

        sd_event_source_disable_unref(registration->retransmit_event);
        return mfree(registration);
}

static void address_registration_cancel_transaction(DHCP6AddressRegistration *registration) {
        assert(registration);

        (void) event_source_disable(registration->retransmit_event);
        registration->transaction_active = false;
        registration->retransmit_deadline_usec = USEC_INFINITY;
}

static void address_registration_close_socket(sd_dhcp6_client *client) {
        DHCP6AddressRegistrationEngine *engine;

        assert(client);

        engine = &client->address_registration;
        engine->receive_event = sd_event_source_disable_unref(engine->receive_event);
        engine->fd = safe_close(engine->fd);
}

static int address_registration_attach_receive_event(sd_dhcp6_client *client) {
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *source = NULL;
        DHCP6AddressRegistrationEngine *engine;
        int r;

        assert(client);

        engine = &client->address_registration;
        if (!client->event || engine->fd < 0 || engine->receive_event)
                return 0;

        r = sd_event_add_io(
                        client->event,
                        &source,
                        engine->fd,
                        EPOLLIN,
                        address_registration_receive_event,
                        client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(source, client->event_priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(source, "dhcp6-address-registration-receive");
        if (r < 0)
                return r;

        engine->receive_event = TAKE_PTR(source);
        return 0;
}

static int address_registration_ensure_socket(sd_dhcp6_client *client) {
        DHCP6AddressRegistrationEngine *engine;
        const DHCP6AddressRegistrationIO *io;
        int r;

        assert(client);

        engine = &client->address_registration;
        if (engine->fd < 0) {
                assert(engine->enabled);
                assert(engine->supported);
                assert(client->ifindex > 0);

                io = address_registration_get_io(client);
                r = io->open_socket(client->ifindex, engine->io_userdata);
                if (r < 0)
                        return r;

                engine->fd = r;
        }

        r = address_registration_attach_receive_event(client);
        if (r < 0)
                address_registration_close_socket(client);

        return r;
}

static usec_t address_registration_lifetime_remaining(usec_t expiry_usec, usec_t now_usec) {
        if (expiry_usec == USEC_INFINITY)
                return USEC_INFINITY;

        return usec_sub_unsigned(expiry_usec, now_usec);
}

static int address_registration_send_message(DHCP6AddressRegistration *registration, usec_t now_usec) {
        _cleanup_free_ uint8_t *buf = NULL;
        sd_dhcp6_client *client;
        struct iaaddr iaaddr;
        struct sockaddr_in6 destination;
        DHCP6Message *message;
        size_t offset;
        int r;

        assert(registration);

        client = ASSERT_PTR(registration->client);
        assert(client->address_registration.enabled);
        assert(client->address_registration.supported);

        destination = (struct sockaddr_in6) {
                .sin6_family = AF_INET6,
                .sin6_addr = IN6_ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS,
                .sin6_port = htobe16(DHCP6_PORT_SERVER),
                .sin6_scope_id = client->ifindex,
        };

        usec_t valid_usec = address_registration_lifetime_remaining(
                        registration->lifetime_valid_usec, now_usec);
        if (valid_usec == 0)
                return -EADDRNOTAVAIL;

        r = address_registration_ensure_socket(client);
        if (r < 0)
                goto fail;

        if (!GREEDY_REALLOC0(buf, offsetof(DHCP6Message, options))) {
                r = -ENOMEM;
                goto fail;
        }

        message = (DHCP6Message*) buf;
        message->transaction_id = registration->transaction_id;
        message->type = DHCP6_MESSAGE_ADDR_REG_INFORM;
        offset = offsetof(DHCP6Message, options);

        assert(sd_dhcp_duid_is_set(&client->duid));
        r = dhcp6_option_append(
                        &buf,
                        &offset,
                        SD_DHCP6_OPTION_CLIENTID,
                        client->duid.size,
                        &client->duid.duid);
        if (r < 0)
                goto fail;

        iaaddr = (struct iaaddr) {
                .address = registration->address,
                .lifetime_preferred = usec_to_be32_sec(address_registration_lifetime_remaining(
                                registration->lifetime_preferred_usec, now_usec)),
                .lifetime_valid = usec_to_be32_sec(valid_usec),
        };
        r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_IAADDR, sizeof(iaaddr), &iaaddr);
        if (r < 0)
                goto fail;

        r = address_registration_get_io(client)->send(
                        client->address_registration.fd,
                        &registration->address,
                        client->ifindex,
                        &destination,
                        buf,
                        offset,
                        client->address_registration.io_userdata);
        if (r < 0)
                goto fail;

        log_dhcp6_client(client, "Sent Address Registration Inform for %s",
                         IN6_ADDR_TO_STRING(&registration->address));
        return 0;

fail:
        address_registration_close_socket(client);
        return r;
}

usec_t dhcp6_address_registration_initial_retransmission_time(usec_t irt_usec, uint64_t random) {
        usec_t span;

        assert(irt_usec > 0);

        span = irt_usec / 5;
        assert(random <= span);

        return usec_add(usec_sub_unsigned(irt_usec, irt_usec / 10), random);
}

usec_t dhcp6_address_registration_next_retransmission_time(usec_t previous_usec, uint64_t random) {
        usec_t doubled, span;

        assert(previous_usec > 0);

        span = previous_usec / 5;
        assert(random <= span);

        doubled = usec_add(previous_usec, previous_usec);
        return usec_add(usec_sub_unsigned(doubled, previous_usec / 10), random);
}

static usec_t address_registration_randomized_initial_retransmission_time(sd_dhcp6_client *client) {
        DHCP6AddressRegistrationEngine *engine;
        usec_t span;

        assert(client);

        engine = &client->address_registration;
        span = engine->initial_retransmission_time_usec / 5;
        return dhcp6_address_registration_initial_retransmission_time(
                        engine->initial_retransmission_time_usec,
                        address_registration_get_io(client)->random_u64_range(
                                span + 1, engine->io_userdata));
}

static usec_t address_registration_randomized_next_retransmission_time(
                sd_dhcp6_client *client,
                usec_t previous_usec) {

        usec_t span;

        assert(client);

        span = previous_usec / 5;
        return dhcp6_address_registration_next_retransmission_time(
                        previous_usec,
                        address_registration_get_io(client)->random_u64_range(
                                span + 1, client->address_registration.io_userdata));
}

static int address_registration_arm_retransmission(DHCP6AddressRegistration *registration) {

        sd_dhcp6_client *client;

        assert(registration);

        client = ASSERT_PTR(registration->client);
        if (!client->event || registration->retransmit_deadline_usec == USEC_INFINITY)
                return 0;

        return event_reset_time(
                        client->event,
                        &registration->retransmit_event,
                        CLOCK_BOOTTIME,
                        registration->retransmit_deadline_usec,
                        0,
                        address_registration_retransmit_event,
                        registration,
                        client->event_priority,
                        "dhcp6-address-registration-retransmit",
                        true);
}

static int address_registration_schedule_retransmission(
                DHCP6AddressRegistration *registration,
                usec_t now_usec) {

        assert(registration);

        registration->retransmit_deadline_usec = usec_add(now_usec, registration->retransmit_time_usec);

        return address_registration_arm_retransmission(registration);
}

static int address_registration_start_transaction(
                DHCP6AddressRegistration *registration,
                usec_t now_usec) {

        sd_dhcp6_client *client;
        uint32_t transaction_id;
        int r, q;

        assert(registration);

        client = ASSERT_PTR(registration->client);
        if (address_registration_lifetime_remaining(registration->lifetime_valid_usec, now_usec) == 0)
                return -EADDRNOTAVAIL;

        address_registration_cancel_transaction(registration);

        transaction_id = address_registration_get_io(client)->random_u32(
                                client->address_registration.io_userdata) & 0x00ffffffU;
        registration->transaction_id = htobe32(transaction_id);
        registration->transmission_count = 0;
        registration->retransmit_time_usec =
                address_registration_randomized_initial_retransmission_time(client);
        registration->transaction_active = true;

        r = address_registration_send_message(registration, now_usec);
        if (r >= 0) {
                registration->transmission_count++;
                registration->has_been_registered = true;
        }

        q = address_registration_schedule_retransmission(registration, now_usec);
        if (q < 0)
                return q;

        return r;
}

DHCP6AddressRegistration *dhcp6_client_get_address_registration(
                sd_dhcp6_client *client,
                const struct in6_addr *address) {

        assert(client);
        assert(address);

        return hashmap_get(client->address_registration.registrations, address);
}

size_t dhcp6_client_address_registration_count(sd_dhcp6_client *client) {
        assert(client);

        return hashmap_size(client->address_registration.registrations);
}

int dhcp6_client_update_address_registration_at(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec,
                usec_t now_usec) {

        _cleanup_free_ DHCP6AddressRegistration *allocated = NULL;
        DHCP6AddressRegistration *registration;
        bool is_new = false;
        int r;

        assert(client);
        assert(address);

        if (lifetime_valid_usec != USEC_INFINITY && lifetime_valid_usec <= now_usec) {
                dhcp6_client_remove_address_registration(client, address);
                return 0;
        }

        registration = dhcp6_client_get_address_registration(client, address);
        if (!registration) {
                allocated = new(DHCP6AddressRegistration, 1);
                if (!allocated)
                        return -ENOMEM;

                *allocated = (DHCP6AddressRegistration) {
                        .client = client,
                        .address = *address,
                        .retransmit_deadline_usec = USEC_INFINITY,
                };

                r = hashmap_ensure_put(
                                &client->address_registration.registrations,
                                &in6_addr_hash_ops,
                                &allocated->address,
                                allocated);
                if (r < 0)
                        return r;

                registration = allocated;
                is_new = true;
        }

        registration->lifetime_preferred_usec = lifetime_preferred_usec;
        registration->lifetime_valid_usec = lifetime_valid_usec;

        if (client->address_registration.supported &&
            !registration->has_been_registered &&
            !registration->transaction_active) {
                r = address_registration_start_transaction(registration, now_usec);
                if (r < 0) {
                        if (is_new)
                                TAKE_PTR(allocated);
                        return r;
                }
        }

        if (is_new)
                TAKE_PTR(allocated);

        return 1;
}

int dhcp6_client_update_address_registration(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

        return dhcp6_client_update_address_registration_at(
                        client,
                        address,
                        lifetime_preferred_usec,
                        lifetime_valid_usec,
                        now(CLOCK_BOOTTIME));
}

void dhcp6_client_remove_address_registration(
                sd_dhcp6_client *client,
                const struct in6_addr *address) {

        DHCP6AddressRegistration *registration;

        assert(client);
        assert(address);

        registration = hashmap_remove(client->address_registration.registrations, address);
        address_registration_free(registration);
}

int dhcp6_client_set_address_registration_enabled(sd_dhcp6_client *client, bool enabled) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp6_client_is_running(client), -EBUSY);

        client->address_registration.enabled = enabled;
        if (!enabled)
                dhcp6_client_address_registration_reset(client);

        return 0;
}

int dhcp6_client_address_registration_discover(
                sd_dhcp6_client *client,
                uint8_t message_type,
                bool advertised) {

        DHCP6AddressRegistration *registration;
        int r, ret = 1;

        assert(client);

        if (!IN_SET(message_type, DHCP6_MESSAGE_ADVERTISE, DHCP6_MESSAGE_REPLY))
                return 0;
        if (!client->address_registration.enabled || !advertised || client->address_registration.supported)
                return 0;

        client->address_registration.supported = true;

        HASHMAP_FOREACH(registration, client->address_registration.registrations) {
                r = address_registration_start_transaction(registration, now(CLOCK_BOOTTIME));
                if (r < 0)
                        ret = r;
        }

        return ret;
}

void dhcp6_client_address_registration_reset(sd_dhcp6_client *client) {
        DHCP6AddressRegistration *registration;

        assert(client);

        client->address_registration.supported = false;

        HASHMAP_FOREACH(registration, client->address_registration.registrations) {
                address_registration_cancel_transaction(registration);
                registration->has_been_registered = false;
        }

        address_registration_close_socket(client);
}

void dhcp6_client_address_registration_detach_event(sd_dhcp6_client *client) {
        DHCP6AddressRegistration *registration;

        assert(client);

        client->address_registration.receive_event =
                sd_event_source_disable_unref(client->address_registration.receive_event);

        HASHMAP_FOREACH(registration, client->address_registration.registrations)
                registration->retransmit_event =
                        sd_event_source_disable_unref(registration->retransmit_event);
}

int dhcp6_client_address_registration_attach_event(sd_dhcp6_client *client) {
        DHCP6AddressRegistration *registration;
        int r;

        assert(client);
        assert(client->event);

        r = address_registration_attach_receive_event(client);
        if (r < 0)
                goto fail;

        HASHMAP_FOREACH(registration, client->address_registration.registrations) {
                r = address_registration_arm_retransmission(registration);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        dhcp6_client_address_registration_detach_event(client);
        return r;
}

void dhcp6_client_address_registration_done(sd_dhcp6_client *client) {
        DHCP6AddressRegistration *registration;

        if (!client)
                return;

        dhcp6_client_address_registration_reset(client);

        HASHMAP_FOREACH(registration, client->address_registration.registrations)
                address_registration_free(registration);
        client->address_registration.registrations =
                hashmap_free(client->address_registration.registrations);
}

int dhcp6_client_address_registration_retransmit_at(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t now_usec) {

        DHCP6AddressRegistration *registration;
        int r;

        assert(client);
        assert(address);

        registration = dhcp6_client_get_address_registration(client, address);
        if (!registration || !registration->transaction_active)
                return 0;

        if (address_registration_lifetime_remaining(registration->lifetime_valid_usec, now_usec) == 0) {
                dhcp6_client_remove_address_registration(client, address);
                return 0;
        }

        if (client->address_registration.max_retransmissions > 0 &&
            registration->transmission_count >= client->address_registration.max_retransmissions) {
                address_registration_cancel_transaction(registration);
                return 0;
        }

        r = address_registration_send_message(registration, now_usec);
        if (r >= 0) {
                registration->transmission_count++;
                registration->has_been_registered = true;
        }

        registration->retransmit_time_usec = address_registration_randomized_next_retransmission_time(
                        client, registration->retransmit_time_usec);

        int q = address_registration_schedule_retransmission(registration, now_usec);
        if (q < 0)
                return q;

        return r < 0 ? r : 1;
}

static int address_registration_retransmit_event(sd_event_source *s, uint64_t usec, void *userdata) {
        DHCP6AddressRegistration *registration = ASSERT_PTR(userdata);
        int r;

        r = dhcp6_client_address_registration_retransmit_at(
                        ASSERT_PTR(registration->client), &registration->address, now(CLOCK_BOOTTIME));
        if (r < 0)
                log_dhcp6_client_errno(registration->client, r,
                                       "Failed to retransmit address registration for %s, retrying: %m",
                                       IN6_ADDR_TO_STRING(&registration->address));

        return 0;
}

int dhcp6_client_process_address_registration_reply_at(
                sd_dhcp6_client *client,
                const void *packet,
                size_t len,
                const struct sockaddr_in6 *sender,
                const struct in6_addr *destination,
                int ifindex,
                bool truncated,
                usec_t now_usec) {

        DHCP6AddressRegistration *registration;
        const DHCP6Message *message = packet;
        size_t offset = offsetof(DHCP6Message, options), n_iaaddr = 0;

        assert(client);
        assert(packet || len == 0);

        if (truncated || len < sizeof(DHCP6Message) || !sender || !destination)
                return 0;
        if (sender->sin6_family != AF_INET6 || sender->sin6_port != htobe16(DHCP6_PORT_SERVER))
                return 0;
        if (ifindex != client->ifindex)
                return 0;

        registration = dhcp6_client_get_address_registration(client, destination);
        if (!registration || !registration->transaction_active)
                return 0;
        if (registration->lifetime_valid_usec != USEC_INFINITY &&
            registration->lifetime_valid_usec <= now_usec) {
                dhcp6_client_remove_address_registration(client, destination);
                return 0;
        }
        if (message->type != DHCP6_MESSAGE_ADDR_REG_REPLY ||
            (message->transaction_id & htobe32(0x00ffffffU)) != registration->transaction_id)
                return 0;

        while (offset < len) {
                const uint8_t *optval;
                size_t optlen;
                uint16_t optcode;
                int r;

                r = dhcp6_option_parse(packet, len, &offset, &optcode, &optlen, &optval);
                if (r < 0)
                        return 0;

                if (optcode != SD_DHCP6_OPTION_IAADDR)
                        continue;

                if (++n_iaaddr > 1 || optlen != sizeof(struct iaaddr))
                        return 0;

                struct in6_addr address;
                memcpy(&address, optval, sizeof(address));
                if (!in6_addr_equal(&address, &registration->address))
                        return 0;
        }

        if (n_iaaddr != 1)
                return 0;

        address_registration_cancel_transaction(registration);
        log_dhcp6_client(client, "Received Address Registration Reply for %s",
                         IN6_ADDR_TO_STRING(&registration->address));
        return 1;
}

int dhcp6_client_receive_address_registration_reply(sd_dhcp6_client *client) {
        const DHCP6AddressRegistrationIO *io = address_registration_get_io(client);
        _cleanup_free_ void *packet = NULL;
        struct sockaddr_in6 sender;
        struct in6_addr destination;
        bool truncated;
        size_t len;
        int ifindex, r;

        assert(client);

        r = io->receive(
                        client->address_registration.fd,
                        &packet,
                        &len,
                        &sender,
                        &destination,
                        &ifindex,
                        &truncated,
                        client->address_registration.io_userdata);
        if (ERRNO_IS_TRANSIENT(r) || ERRNO_IS_DISCONNECT(r))
                return 0;
        if (r < 0) {
                log_dhcp6_client_errno(client, r, "Failed to receive address registration reply, ignoring: %m");
                return 0;
        }

        (void) dhcp6_client_process_address_registration_reply_at(
                        client,
                        packet,
                        len,
                        &sender,
                        &destination,
                        ifindex,
                        truncated,
                        now(CLOCK_BOOTTIME));
        return 0;
}

static int address_registration_receive_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp6_client *client = ASSERT_PTR(userdata);

        return dhcp6_client_receive_address_registration_reply(client);
}

void dhcp6_client_set_address_registration_io(
                sd_dhcp6_client *client,
                const DHCP6AddressRegistrationIO *io,
                void *userdata) {

        assert(client);
        assert(client->address_registration.fd < 0);

        client->address_registration.io = io;
        client->address_registration.io_userdata = userdata;
}
