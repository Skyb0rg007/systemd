#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# Tests for Delegate=yes in combination with PrivateUsers=managed on the system service manager. See
# TEST-13-NSPAWN.pull-oci.sh for the user service manager.

if [[ ! -f /usr/lib/systemd/system/systemd-nsresourced.socket ]] ||
   ! grep -q bpf /sys/kernel/security/lsm ||
   ! find /usr/lib* -name "libbpf.so.*" 2>/dev/null | grep . >/dev/null; then
    echo "systemd-nsresourced not available, skipping"
    exit 77
fi

systemctl start systemd-nsresourced.socket

DELEGATE=(-p PrivateUsers=managed -p Delegate=yes -p DelegateSubgroup=payload -p ProtectControlGroups=private)

# The DelegateSubgroup= cgroup is passed to the user namespace and becomes the root of its cgroup namespace, while
# the unit's cgroup stays with the service manager, which still needs to place ExecStopPost= in it. Control
# processes don't get the cgroup.
systemd-run -q --wait --pipe --unit=delegate-managed "${DELEGATE[@]}" \
            -p ExecStartPre="bash -c '[[ ! -O /sys/fs/cgroup ]]'" \
            -p ExecStartPost="bash -c '[[ ! -O /sys/fs/cgroup ]]'" \
            -p ExecStopPost="bash -c '[[ ! -O /sys/fs/cgroup ]]'" \
            bash -c '[[ -O /sys/fs/cgroup ]] && test "$(cat /proc/self/cgroup)" = "0::/" && mkdir /sys/fs/cgroup/child'

# Everything is cleaned up afterwards
timeout 30 bash -c 'while [[ -e /sys/fs/cgroup/system.slice/delegate-managed.service ]]; do sleep .5; done'

# Without DelegateSubgroup=, nothing is passed to the user namespace
systemd-run -q --wait --pipe -p PrivateUsers=managed -p Delegate=yes -p ProtectControlGroups=private \
            bash -c '[[ ! -O /sys/fs/cgroup ]]'

# Each main process of a oneshot service gets a fresh subgroup, even though the previous one left a cgroup behind in
# it, and its user namespace might not have been released yet
systemd-run -q --wait --pipe "${DELEGATE[@]}" -p Type=oneshot \
            -p ExecStart="bash -c '[[ -O /sys/fs/cgroup ]] && mkdir /sys/fs/cgroup/child'" \
            bash -c '[[ -O /sys/fs/cgroup ]] && mkdir /sys/fs/cgroup/child'

# ...but not if processes of the previous one still run in it
(! systemd-run -q --wait --collect "${DELEGATE[@]}" -p Type=oneshot \
               -p ExecStart="bash -c 'sleep infinity &'" \
               true)
