# Three-node WireGuard acceptance lab

This test creates an **isolated simulated underlay router**, plus **client**, **entry** and **exit** network namespaces. It uses kernel WireGuard interfaces, disposable keys, the project's generated peer configurations and entry/exit nftables policies. All documentation addresses are synthetic. No VPS, host network interface, real DNS, public endpoint or existing VPN is altered.

Run on a Linux development machine that supports creating user/network namespaces and the tools `wg`, `ip`, `nft`, `nsenter`, `unshare`:

```sh
python3 tests/lab/check_twohop_wireguard.py
```

The test launches an isolated user/network namespace when run unprivileged, creates three child network namespaces and ephemeral veth links, generates four disposable WireGuard key pairs and applies configurations on the corresponding nodes. Private keys live only in a temporary owner-only directory deleted when the test ends; none are printed, committed or uploaded.

An in-namespace UDP service emulates the Internet. The client must exchange a UDP datagram and receive an acknowledgement through **both real WireGuard tunnels**. The service must observe the exit-node NAT source (`203.0.113.2`) rather than the client source. The test then takes down the entry-to-exit WireGuard interface and verifies a second probe does **not** reach the simulated service.

The fixture intentionally uses operator-controlled static IPv4 underlay routes and a direct `wg setconf` translation of the repository-rendered profiles, rather than altering any system-managed VPN or resolver configuration. It tests network forwarding and failure handling; it is **not** a complete `wg-quick` lifecycle or DNS integration test.

**Not verified by this lab:** trusted TLS/WSS transport behavior, real physical peers, DNS queries or resolver leaks, IPv6 support beyond the separate kill-switch test, multi-client isolation, full outage/recovery matrix, host routing integration, persistence, migration, or production readiness.

For GitHub Actions, install `wireguard-tools` and invoke the test inside the disposable runner. Failure to create namespaces, load WireGuard interfaces, or complete any probe must fail the test; no silent skipping.
