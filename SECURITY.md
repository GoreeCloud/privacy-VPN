# Security policy

## Maturity

**Experimental development source — not audited or deployment-ready.** The project has not passed a privacy/security Stable gate. Do not place real users or critical workloads on these configurations without isolated deployment testing, threat modeling, independent verification where useful, and rollback validation.

## Reporting vulnerabilities

Report security flaws through GitHub's **private vulnerability reporting** if enabled, or the maintainer's verified private contact channel. Do **not** place passwords, WireGuard private keys, certificate private keys, tokens, operational public IP inventories, or exploitable undisclosed issues in public discussions.

## Security boundaries

- Standard WireGuard provides authenticated encryption on each WireGuard hop. The entry relay decrypts the first hop and forwards packets through a distinct WireGuard tunnel to the exit relay.
- Exit relay sees internet destinations and can see unencrypted application-layer data. HTTPS and secure application protocols remain necessary.
- Double-hop does not eliminate traffic correlation, protect against collusion between relays, or make users anonymous.
- The optional WebSocket/TLS transport changes the outer packet shape but does not guarantee that traffic is indistinguishable from normal browsing or will defeat deep-packet inspection.
- Client firewall policy rejects output that is not loopback, VPN, or the pinned relay IPv4 transport endpoint. It also blocks direct IPv6 output. It intentionally blocks LAN, DHCP, NTP, captive portals and other traffic unless routed through the VPN or specifically handled outside this prototype.
- The CLI never installs firewall rules or activates interfaces; all network operations are explicit operator actions.
- Private keys must remain on their respective hosts in mode-0600 files and must never be committed or transmitted through issue trackers or CI.
- Relay host INPUT firewalls, DNS policy, log retention, automatic service supervision, network namespace isolation and production hardening are operator responsibilities until implemented and verified.

## Emergency recovery

Require out-of-band administration and a known-good rollback path before applying nftables policies. A restrictive rule can disconnect a machine. Keep a local console available; never rely on a remote SSH session alone.
