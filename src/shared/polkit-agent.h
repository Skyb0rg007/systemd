/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* If password_fd is valid, answers PAM prompts with lines from it instead of spawning pkttyagent on the TTY. */
int polkit_agent_open_full(int password_fd);
int polkit_agent_open(void);
void polkit_agent_close(void);

int polkit_agent_open_if_enabled_full(BusTransport transport, bool ask_password, int password_fd);
int polkit_agent_open_if_enabled(BusTransport transport, bool ask_password);
