"""Measured client kill-switch test inside a disposable network namespace.

Run: python3 tests/lab/check_client_firewall.py
Requires Linux, iproute2, nftables and unprivileged user namespaces.
Does not modify the invoking host network namespace.
"""
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from privacyvpn.firewall import client_policy  # noqa: E402


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True)


def counters():
    document = json.loads(command("nft", "-j", "list", "chain", "inet",
                                  "gcvpn_client", "output").stdout)
    values = {}
    for record in document["nftables"]:
        expr = record.get("rule", {}).get("expr", [])
        counter = next((item["counter"] for item in expr if "counter" in item), None)
        if counter is None:
            continue
        category = ("ipv6_blocked" if any("drop" in item for item in expr) else
                    "entry_allowed" if any("accept" in item for item in expr) else
                    "other_blocked")
        values[category] = counter["packets"]
    return values


def inside():
    original = os.environ.get("GCVPN_PARENT_NETNS")
    if not original or os.readlink("/proc/self/ns/net") == original:
        raise RuntimeError("Refusing to run without a distinct network namespace")
    command("ip", "link", "set", "lo", "up")
    command("ip", "link", "add", "gcu0", "type", "dummy")
    command("ip", "addr", "add", "192.0.2.2/24", "dev", "gcu0")
    command("ip", "link", "set", "gcu0", "up")
    command("ip", "-4", "route", "add", "default", "dev", "gcu0")
    command("ip", "-6", "addr", "add", "2001:db8::2/64", "dev", "gcu0")
    command("ip", "-6", "route", "add", "default", "dev", "gcu0")
    policy = client_policy("203.0.113.10", 51820)
    policy = policy.replace("meta nfproto ipv6 drop",
                            "meta nfproto ipv6 counter drop")
    policy = policy.replace("ip daddr 203.0.113.10 udp dport 51820 accept",
                            "ip daddr 203.0.113.10 udp dport 51820 counter accept")
    policy = policy.replace("  }\n}\n", "    counter\n  }\n}\n")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft") as config:
        config.write(policy)
        config.flush()
        command("nft", "-f", config.name)

    before = counters()
    if set(before) != {"entry_allowed", "other_blocked", "ipv6_blocked"}:
        raise AssertionError(f"Unexpected counters: {before}")

    def expect_blocked(sock, payload, destination):
        try:
            sock.sendto(payload, destination)
        except OSError as err:
            if err.errno != errno.EPERM:
                raise

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ipv4:
        ipv4.sendto(b"allow", ("203.0.113.10", 51820))
        expect_blocked(ipv4, b"deny", ("198.51.100.20", 51820))
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as ipv6:
        expect_blocked(ipv6, b"deny-v6", ("2001:db8::10", 5353))
    after = counters()
    for category in before:
        if after[category] <= before[category]:
            raise AssertionError(f"Counter did not advance: {category}, {before}, {after}")
    print("PASS: kernel accepted pinned entry UDP and blocked other IPv4/IPv6 "
          "within the disposable network namespace")
    print("Namespace packet counters:", after)

    # Verify DNS cannot bypass the tunnel over the physical/underlay interface.
    # These are direct socket sends, not a system-resolver integration test.
    dns_before = counters()["other_blocked"]

    def deny_direct_dns(send):
        before_probe = counters()["other_blocked"]
        try:
            send()
        except OSError as err:
            # A UDP DROP normally returns EPERM; TCP DROP may time out.
            if err.errno != errno.EPERM and not isinstance(err, TimeoutError):
                raise
        else:
            raise AssertionError("Direct DNS packet was not rejected")
        if counters()["other_blocked"] <= before_probe:
            raise AssertionError("DNS probe did not hit nftables default-deny")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_udp:
        deny_direct_dns(lambda: dns_udp.sendto(b"synthetic-dns", ("9.9.9.9", 53)))
        # Entry IPv4 is allowed only on the configured WireGuard port.
        deny_direct_dns(lambda: dns_udp.sendto(b"synthetic-dns", ("203.0.113.10", 53)))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dns_tcp:
        dns_tcp.settimeout(1)
        deny_direct_dns(lambda: dns_tcp.connect(("9.9.9.9", 53)))

    dns_after = counters()["other_blocked"]
    if dns_after - dns_before < 3:
        raise AssertionError("Expected direct DNS probes to hit default-deny")
    print("PASS: underlay UDP/TCP DNS on port 53 denied, including to pinned entry")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--inside":
        inside()
    elif len(sys.argv) == 1:
        env = dict(os.environ, GCVPN_PARENT_NETNS=os.readlink("/proc/self/ns/net"))
        namespace = ["unshare", "-n"] if os.geteuid() == 0 else ["unshare", "-Urn"]
        result = subprocess.run(namespace + [sys.executable,
                                str(Path(__file__).resolve()), "--inside"],
                                check=False, env=env)
        if result.returncode:
            raise SystemExit(result.returncode)
    else:
        raise SystemExit("Usage: python3 tests/lab/check_client_firewall.py")


if __name__ == "__main__":
    main()
