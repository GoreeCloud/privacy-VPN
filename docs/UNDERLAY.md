# Optional TLS transport: underlay routing

The client TLS/WebSocket transport is a **separate user-space network client**. When WireGuard changes the system's default route, the TLS connection must still reach the entry server through the original network connection rather than trying to travel inside its own VPN tunnel.

In `wstunnel` mode the renderer emits `client-underlay-route.sh`. It is intentionally **not executed automatically**. You must supply your real WAN interface and IPv4 gateway, inspect the command, and ensure the entry endpoint is trustworthy. The helper only attempts to **add** a host route; it refuses to replace existing routes. It does not take responsibility for other system routes.

Before using the helper, inspect `ip -4 route show default` and `ip -4 route get ENTRY_IPV4` through local console access. With an isolated lab and recovery access, run the helper with `WAN_IFACE WAN_IPV4_GATEWAY` arguments before bringing up the client full tunnel. Inspect the resulting host-specific route, then load the kill switch and start the TLS transport and WireGuard.

The endpoint allowlist in `client-killswitch.nft` permits only the selected protocol and port to the configured entry IPv4 underlay address. The TLS hostname must resolve to that address without any DNS bootstrap leak; a separately verified hosts entry may be necessary. Certificate validation must not be disabled.

**Failure handling:** Do not indiscriminately delete or replace pre-existing routes. The helper's `proto 188` route is meant only for this project's isolated setup. Record the pre-change routing table, the route actually added, and a recovery procedure before activation. Always test loss of entry, relay, DNS, gateway and physical connectivity with packet captures before claiming leak resistance.

No live activation was performed while preparing this documentation.
