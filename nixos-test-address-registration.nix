# NixOS VM test: RFC 9686 DHCPv6 address registration.
#
# Three VMs:
#  - `server1`/`server2`: each sends stateless RAs (M=0, O=1) via radvd on its
#    own link, and runs its own independent Kea DHCPv6 instance with RFC 9686
#    address registration enabled.
#  - `client`: runs *this* checkout's systemd and systemd-networkd (patched
#    forward from nixpkgs' stock v261 build), with one interface per server
#    (eth1 -> server1, eth2 -> server2). Each interface carries a statically
#    configured address plus permanent and privacy SLAAC addresses formed
#    from that link's RA prefix, and registers all of them with the Kea
#    instance on the other end of that same link.
#
# The test checks that address registration doesn't leak across interfaces
# (server1's Kea only ever hears about eth1's addresses, never eth2's, and
# vice versa), that renumbering eth1's RA prefix mid-test produces fresh
# SLAAC addresses that get registered while the old ones are deprecated,
# without touching eth2 at all, and that replacing eth1's static address
# cancels the old address's periodic registration-refresh timer rather than
# leaving it to keep firing.
#
# Run with:
#   nix-build nixos-test-address-registration.nix
#
# Iterate on the systemd source without re-running this file by just editing
# files under SYSTEMD_SRC and re-running the same command — the overlay reads
# only git-tracked files, so commit (or `git add`) changes first.

{
  pkgs ? import <nixpkgs> { },
}:

let
  lib = pkgs.lib;

  # nixpkgs' 0002-Change-usr-share-zoneinfo-to-etc-zoneinfo.patch was written
  # against the exact v261 tag. Our branch's base (main, as of when we
  # branched) is a handful of upstream commits past that tag, and one of
  # those commits renamed symlinkat_atomic_full -> symlinkat_atomic_full_label
  # (added an arg_label_context parameter) in src/firstboot/firstboot.c's
  # process_timezone(). That's an unrelated upstream change — nothing to do
  # with the RFC 9686 commits themselves — but it shifts firstboot.c's
  # content enough that hunk #2 of that patch no longer applies (verified:
  # the other four files it touches, and firstboot.c's other hunk, all still
  # apply cleanly). This is the same patch with just that one hunk rebased
  # onto the new signature; verified with `patch -p1 --dry-run` against this
  # tree before wiring it in here.
  zoneinfoPatch = ./0002-zoneinfo-firstboot-fixed.patch;

  # Keep this override out of the package set used by the test driver. In
  # particular, qemu_test depends on systemd's libraries and would otherwise
  # be rebuilt after every source change. The client selects this package via
  # systemd.package below; QEMU and the server VMs keep using stock nixpkgs.
  systemd = pkgs.systemd.overrideAttrs (old: {
    version = "261-rfc9686";
    src = pkgs.lib.fileset.toSource {
      root = ./.;
      fileset =
        with pkgs.lib.fileset;
        difference (gitTracked ./.) (unions [
          ./nixos-test-address-registration.nix
          ./0002-zoneinfo-firstboot-fixed.patch
        ]);
    };
    patches = map (
      p:
      if lib.hasSuffix "0002-Change-usr-share-zoneinfo-to-etc-zoneinfo.patch" (toString p) then
        zoneinfoPatch
      else
        p
    ) old.patches;
  });

  # Shared Kea config: RFC 9686 support (added in Kea 3.1.4; nixpkgs ships
  # 3.2.0), plus the ORO-echo entry that actually gets OPTION_ADDR_REG_ENABLE
  # (148) into Information-Request replies (allow-address-registration alone
  # only gates *accepting* an inbound ADDR-REG-INFORM; whether the option is
  # advertised is Kea's ordinary generic option-echo mechanism, and needs its
  # own option-data entry -- the option is zero-length so no value is
  # needed). No `pools`: this is deliberately stateless, Kea is here only to
  # answer Information-Request and process ADDR-REG-INFORM/-REPLY.
  mkKeaSettings =
    { extraSettings }:
    {
      interfaces-config.interfaces = [ "eth1" ];
      allow-address-registration = true;
      option-data = [ { name = "addr-reg-enable"; } ];
      lease-database = {
        type = "memfile";
        persist = true;
        name = "/var/lib/kea/dhcp6.leases";
      };
    }
    // extraSettings;

  # eth1's RA prefix, before and after the mid-test renumbering. v2 sets the
  # old prefix's lifetimes to zero and advertises the new prefix alongside
  # it. Per RFC 4862 s.5.5.3(e), a lifetime of zero deprecates (but, thanks
  # to the 2-hour anti-flushing floor on a single RA, does not immediately
  # invalidate/remove) addresses formed from it -- see the renumbered()
  # check below.
  radvdEth1V1 = pkgs.writeText "radvd-eth1-v1.conf" ''
    interface eth1 {
      AdvSendAdvert on;
      AdvManagedFlag off;
      AdvOtherConfigFlag on;
      prefix 2001:db8:1::/64 {
        AdvOnLink on;
        AdvAutonomous on;
      };
    };
  '';
  radvdEth1V2 = pkgs.writeText "radvd-eth1-v2.conf" ''
    interface eth1 {
      AdvSendAdvert on;
      AdvManagedFlag off;
      AdvOtherConfigFlag on;
      prefix 2001:db8:1::/64 {
        AdvOnLink on;
        AdvAutonomous on;
        AdvValidLifetime 0;
        AdvPreferredLifetime 0;
      };
      prefix 2001:db8:1:1::/64 {
        AdvOnLink on;
        AdvAutonomous on;
      };
    };
  '';

  # SLAAC address + privacy extensions + address registration, on the given
  # interface/prefix. Also carries a statically configured address, which is
  # eligible for registration the same as any other non-DHCP6-sourced
  # RT_SCOPE_UNIVERSE address on the link (see
  # dhcp6_address_is_eligible_for_registration() in networkd-dhcp6.c).
  mkClientNetwork = { name, staticAddress }: {
    matchConfig.Name = name;
    address = [ staticAddress ];
    networkConfig = {
      IPv6AcceptRA = true;
      # Both a permanent and a privacy (temporary) SLAAC address.
      IPv6PrivacyExtensions = "prefer-public";
    };
    # RegisterAddresses= is new in this branch, so it isn't in nixpkgs'
    # generated `dhcpV6Config` option schema yet (that submodule is strictly
    # typed against stock systemd's known keys). It's also already the
    # systemd-side default (true), so this is just making the test's intent
    # explicit via raw text rather than the typed option.
    extraConfig = ''
      [DHCPv6]
      RegisterAddresses=yes
    '';
  };

  # eth1's own network file, before and after its static address changes.
  # Written by hand rather than through mkClientNetwork/systemd.network.networks
  # (which nixpkgs renders straight to an immutable-looking, but in fact
  # swappable, /etc/systemd/network/10-eth1.network -- same trick as
  # radvdEth1V1/V2 above) so the test script can point it at a new file and
  # `networkctl reload && networkctl reconfigure eth1` mid-test.
  #
  # StaticAddressRegistrationRefreshIntervalSec is turned way down from its
  # 4-hour default so a refresh is actually observable inside a test's
  # timeframe -- without that, "no more registration messages after the
  # address changes" would hold trivially regardless of whether the
  # underlying timer was really cancelled, since a 4-hour refresh was never
  # going to fire in this test either way.
  mkClientEth1Network =
    staticAddress:
    pkgs.writeText "client-eth1.network" ''
      [Match]
      Name=eth1

      [Network]
      Address=${staticAddress}
      IPv6AcceptRA=yes
      IPv6PrivacyExtensions=prefer-public

      [DHCPv6]
      RegisterAddresses=yes
      StaticAddressRegistrationRefreshIntervalSec=5
    '';
  clientEth1V1 = mkClientEth1Network "2001:db8:1::dead:beef/64";
  clientEth1V2 = mkClientEth1Network "2001:db8:1::feed/64";
in
pkgs.testers.runNixOSTest {
  name = "systemd-networkd-address-registration";

  nodes = {
    server1 =
      { lib, pkgs, ... }:
      {
        virtualisation.vlans = [ 1 ];
        networking.useNetworkd = true;
        networking.useDHCP = false;
        networking.firewall.enable = false;
        networking.interfaces.eth1 = lib.mkForce { };
        services.resolved.enable = false;

        systemd.network = {
          enable = true;
          networks."10-eth1" = {
            matchConfig.Name = "eth1";
            address = [ "2001:db8:1::1/64" ];
            networkConfig.IPv6Forwarding = true;
          };
        };

        # A hand-rolled unit instead of services.radvd: that module bakes its
        # config file's store path directly into ExecStart at build time, so
        # there's no way to point it at a new config after boot. Routing it
        # through a plain /etc file that the test script can re-symlink and
        # `systemctl restart radvd` lets us change the RA prefix mid-test.
        environment.etc."radvd.conf".source = radvdEth1V1;
        users.users.radvd = {
          isSystemUser = true;
          group = "radvd";
        };
        users.groups.radvd = { };
        systemd.services.radvd = {
          description = "IPv6 Router Advertisement Daemon";
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig = {
            ExecStart = "${pkgs.radvd}/bin/radvd -n -u radvd -d 5 -C /etc/radvd.conf";
            Restart = "always";
          };
        };

        services.kea.dhcp6 = {
          enable = true;
          # A single /48 covering both the original RA prefix
          # (2001:db8:1::/64) and the post-renumbering one
          # (2001:db8:1:1::/64, chosen to differ only in the /64 subnet
          # nibble -- a realistic same-site renumbering), rather than one
          # Kea subnet per /64. Confirmed from actual runs that a second,
          # narrower /64 subnet doesn't work here, even wrapped in
          # shared-networks: for non-relayed traffic Kea's ADDR-REG-INFORM
          # handling resolves eth1 to a single subnet and validates strictly
          # against it, rejecting registrations for the other one with
          # "Address ... is not in subnet 2001:db8:1::/64 (id 1)" regardless
          # of shared-networks grouping. A single subnet wide enough to
          # contain every address we'll ever register sidesteps that
          # entirely.
          settings = mkKeaSettings {
            extraSettings.subnet6 = [
              {
                id = 1;
                interface = "eth1";
                subnet = "2001:db8:1::/48";
              }
            ];
          };
        };
      };

    server2 =
      { lib, ... }:
      {
        virtualisation.vlans = [ 2 ];
        networking.useNetworkd = true;
        networking.useDHCP = false;
        networking.firewall.enable = false;
        networking.interfaces.eth1 = lib.mkForce { };
        services.resolved.enable = false;

        systemd.network = {
          enable = true;
          networks."10-eth1" = {
            matchConfig.Name = "eth1";
            address = [ "2001:db8:2::1/64" ];
            networkConfig.IPv6Forwarding = true;
          };
        };

        services.radvd = {
          enable = true;
          config = ''
            interface eth1 {
              AdvSendAdvert on;
              AdvManagedFlag off;
              AdvOtherConfigFlag on;
              prefix 2001:db8:2::/64 {
                AdvOnLink on;
                AdvAutonomous on;
              };
            };
          '';
        };

        services.kea.dhcp6 = {
          enable = true;
          settings = mkKeaSettings {
            extraSettings.subnet6 = [
              {
                id = 1;
                interface = "eth1";
                subnet = "2001:db8:2::/64";
              }
            ];
          };
        };
      };

    client =
      { ... }:
      {
        systemd.package = systemd;

        virtualisation.vlans = [
          1
          2
        ];
        networking.useNetworkd = true;
        networking.useDHCP = false;
        networking.firewall.enable = false;
        services.resolved.enable = false;
        systemd.services.systemd-networkd.environment.SYSTEMD_LOG_LEVEL = "debug";

        environment.etc."systemd/network/10-eth1.network".source = clientEth1V1;

        systemd.network = {
          enable = true;
          networks."10-eth2" = mkClientNetwork {
            name = "eth2";
            staticAddress = "2001:db8:2::dead:beef/64";
          };
        };
      };
  };

  testScript = ''
    import json
    import re
    import time

    def global_addrs(node, iface):
        # `ip --json` piped through python3 *inside the guest* would fail:
        # the client VM is a minimal NixOS closure without python3 installed.
        # Parsing the JSON here instead, in the test driver's own python
        # interpreter, avoids that entirely.
        data = json.loads(node.succeed(f"ip -6 -json addr show dev {iface} scope global"))
        # `ip -json addr` has a longstanding cosmetic quirk of appending a
        # spurious empty `{}` to addr_info; filter out anything without a
        # "local" key rather than relying on that not happening.
        return [a for a in data[0]["addr_info"] if "local" in a] if data else []

    def global_ips(node, iface):
        return {a["local"] for a in global_addrs(node, iface)}

    def wait_for_addr_count(node, iface, count, timeout=120):
        def check(last):
            addrs = global_addrs(node, iface)
            if last:
                assert len(addrs) >= count, addrs
            return len(addrs) >= count
        retry(check, timeout_seconds=timeout)

    def expect_registered(server, addr, timeout=60):
        # Confirmed from actual log output: Kea's generic per-packet
        # DHCP6_PACKET_SEND message names the DHCPv6 message type verbatim,
        # e.g. "... trying to send packet ADDR_REG_REPLY (type 37) ... to
        # [ADDR]:546 ...". Matching on the *reply* rather than the inform is
        # deliberate: DHCP6_PACKET_RECEIVED is logged for every inbound
        # ADDR-REG-INFORM regardless of outcome, including ones Kea goes on
        # to reject (e.g. DHCP6_ADDR_REG_INFORM_FAIL, logged with no
        # corresponding reply at all) -- only a logged reply means Kea
        # actually accepted the registration.
        pattern = re.escape("ADDR_REG_REPLY") + r".*" + re.escape(addr)
        server.wait_until_succeeds(
            f"journalctl -u kea-dhcp6-server --grep='{pattern}'", timeout=timeout
        )

    def expect_not_registered(server, addr):
        pattern = re.escape("ADDR_REG_REPLY") + r".*" + re.escape(addr)
        server.fail(f"journalctl -u kea-dhcp6-server --grep='{pattern}'")

    def count_registrations(server, addr):
        # journalctl exits non-zero when --grep matches nothing, which would
        # trip `set -euo pipefail` if piped straight into `wc -l`; `|| true`
        # keeps a genuine "zero matches" from being treated as a command
        # failure. (execute()'s check_return=False isn't a substitute here:
        # per its own docstring it always returns -1 for the status rather
        # than the command's real exit code.)
        pattern = re.escape("ADDR_REG_REPLY") + r".*" + re.escape(addr)
        out = server.succeed(
            f"(journalctl -u kea-dhcp6-server --grep='{pattern}' || true) | wc -l"
        )
        return int(out.strip())

    start_all()

    server1.wait_for_unit("radvd.service")
    server1.wait_for_unit("kea-dhcp6-server.service")
    server2.wait_for_unit("radvd.service")
    server2.wait_for_unit("kea-dhcp6-server.service")

    client.systemctl("start network-online.target")
    client.wait_for_unit("network-online.target")

    static1 = "2001:db8:1::dead:beef"
    static2 = "2001:db8:2::dead:beef"

    with subtest(
        "client formed a static address plus permanent and privacy SLAAC "
        "addresses on both interfaces"
    ):
        wait_for_addr_count(client, "eth1", 3)
        wait_for_addr_count(client, "eth2", 3)

        eth1_addrs = global_addrs(client, "eth1")
        eth2_addrs = global_addrs(client, "eth2")

        eth1_ips = {a["local"] for a in eth1_addrs}
        eth2_ips = {a["local"] for a in eth2_addrs}

        # iproute2's `-json` output represents each address flag as its own
        # top-level boolean key (e.g. "temporary": true), not as a "flags"
        # list -- confirmed from actual `ip -6 -json addr show` output.
        assert static1 in eth1_ips, eth1_addrs
        assert static2 in eth2_ips, eth2_addrs
        assert any(a.get("temporary", False) for a in eth1_addrs), eth1_addrs
        assert any(a.get("temporary", False) for a in eth2_addrs), eth2_addrs
        assert any(
            a["local"] != static1 and not a.get("temporary", False)
            for a in eth1_addrs
        ), eth1_addrs
        assert any(
            a["local"] != static2 and not a.get("temporary", False)
            for a in eth2_addrs
        ), eth2_addrs

    with subtest(
        "each Kea instance registered every address on its own interface, "
        "and none of the addresses on the other interface"
    ):
        for addr in eth1_ips:
            expect_registered(server1, addr)
        for addr in eth2_ips:
            expect_registered(server2, addr)

        # Give a moment for any (incorrect) cross-interface registration to
        # show up before asserting that it never does.
        time.sleep(5)
        for addr in eth2_ips:
            expect_not_registered(server1, addr)
        for addr in eth1_ips:
            expect_not_registered(server2, addr)

    with subtest(
        "changing the RA prefix on eth1 replaces its SLAAC addresses with "
        "newly advertised ones, while eth2's are unaffected"
    ):
        old_slaac_ips = eth1_ips - {static1}

        server1.succeed("ln -sf ${radvdEth1V2} /etc/radvd.conf")
        server1.succeed("systemctl restart radvd")

        # "No longer considered" is checked as deprecated (preferred lifetime
        # 0), not removed outright: RFC 4862 s.5.5.3(e)'s anti-flushing rule
        # means a valid lifetime of 0 from a single RA only deprecates a
        # matching address immediately, it does *not* invalidate/remove it --
        # the remaining valid lifetime is instead floored at 2 hours so that
        # one stray or malicious RA can't wipe out addresses outright.
        # Confirmed against this test's own run: valid_life_time settled at
        # ~7100s (just under the 7200s/2h floor) rather than dropping to 0.
        def renumbered(last):
            addrs = global_addrs(client, "eth1")
            by_ip = {a["local"]: a for a in addrs}
            new_slaac = [a for a in addrs if a["local"].startswith("2001:db8:1:1:")]
            old_deprecated = all(
                by_ip[ip]["preferred_life_time"] == 0
                for ip in old_slaac_ips
                if ip in by_ip
            )
            ok = (
                static1 in by_ip
                and len(new_slaac) >= 2
                and any(a.get("temporary", False) for a in new_slaac)
                and old_deprecated
            )
            if last:
                assert ok, addrs
            return ok
        retry(renumbered, timeout_seconds=90)

        new_slaac_ips = {
            a["local"]
            for a in global_addrs(client, "eth1")
            if a["local"].startswith("2001:db8:1:1:")
        }

        # Not checking deregistration of the old addresses -- only that the
        # new ones show up registered, and that eth2/server2 never see any of
        # this (renumbering one link doesn't affect the other).
        for addr in new_slaac_ips:
            expect_registered(server1, addr)

        assert global_ips(client, "eth2") == eth2_ips
        for addr in new_slaac_ips:
            expect_not_registered(server2, addr)

    with subtest(
        "changing eth1's static address cancels registration refreshes for "
        "the old one"
    ):
        static1_new = "2001:db8:1::feed"

        # Prove the (deliberately short, 5s) refresh timer is actually alive
        # before touching anything: without this positive control, "no more
        # registration messages for the old address after it's replaced"
        # would hold trivially whether or not address removal really
        # cancels the timer, since we'd have no evidence a refresh was ever
        # going to fire in the first place.
        def refreshed(last):
            n = count_registrations(server1, static1)
            if last:
                assert n >= 2, n
            return n >= 2
        retry(refreshed, timeout_seconds=30)

        client.succeed("ln -sf ${clientEth1V2} /etc/systemd/network/10-eth1.network")
        client.succeed("networkctl reload")
        client.succeed("networkctl reconfigure eth1")

        expect_registered(server1, static1_new)
        assert static1_new in global_ips(client, "eth1")
        assert static1 not in global_ips(client, "eth1")

        # Give anything already in flight at the moment of the swap a
        # moment to land, so it isn't misread below as a refresh that fired
        # *after* removal.
        time.sleep(2)
        baseline = count_registrations(server1, static1)

        # Four refresh intervals' worth of time: long enough that, if
        # removing the address hadn't cancelled its registration timer,
        # we'd expect to see at least one more refresh for it here.
        time.sleep(20)
        after = count_registrations(server1, static1)
        assert after == baseline, (baseline, after)
  '';
}
