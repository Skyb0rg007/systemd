/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp6-client.h"

#include "forward.h"

typedef struct DHCP6AddressRegistrationEngine {
        bool enabled;
        bool supported;
} DHCP6AddressRegistrationEngine;

int dhcp6_client_set_address_registration_enabled(sd_dhcp6_client *client, bool enabled);
int dhcp6_client_address_registration_discover(
                sd_dhcp6_client *client,
                uint8_t message_type,
                bool advertised);
void dhcp6_client_address_registration_reset(sd_dhcp6_client *client);
