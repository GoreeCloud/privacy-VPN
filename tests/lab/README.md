# Disposable Linux firewall lab

The opt-in smoke test `check_client_firewall.py` measures client kill-switch behavior using an **isolated Linux network namespace**. It does not configure the machine's real network interfaces or the GoreeCloud VPS.

Run on a development machine with Python 3.10+, `ip`, `nft`, and `unshare`:

```sh
python3 tests/lab/check_client_firewall.py
```

The launcher creates a disposable user/network namespace as a regular user, or a network namespace when invoked as root (for the isolated GitHub Actions runner). A separate namespace identity is checked before any interface or nftables change. The namespace is destroyed automatically when the child process exits.

The test creates a dummy underlay interface and documentation-only IPv4/IPv6 routes **inside that namespace**, then loads a counter-instrumented copy of the production client policy. Local UDP socket sends trigger the kernel's nftables hooks. Counters must show a permitted packet to the pinned entry IPv4 and denied packets to another IPv4 and to an IPv6 destination. The ordinary production firewall rules remain unchanged by this test instrumentation.

**Limits:** This verifies an isolated client's nftables OUTPUT matching, not live VPN connectivity, DNS behavior, multiple relays, TLS identity, a full fail-closed outage, host NetworkManager integration, or production leak resistance. The dummy interface does not route to the Internet. Complete end-to-end acceptance, outage and recovery testing before deployment. If user/network namespace creation is unavailable, this test fails and must not be represented as passing.
