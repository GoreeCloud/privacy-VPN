# Loopback WSS/TLS certificate-rejection test

Run `python3 tests/lab/check_wss_tls.py` with the `GCVPN_WSTUNNEL` environment variable pointing to an authenticated upstream `wstunnel` binary. This is a local **development-only** test; it neither changes the host trust store nor starts a public listener. CI downloads upstream release v11.0.0 and verifies SHA-256 `9708a99717b5a951453c2ff7c14c25d3418d02ca7fcb96fdb382a8f2083bab5e` before running the binary.

The test starts `wstunnel` on `127.0.0.1` with a one-day self-signed certificate generated in a temporary directory, an isolated UDP echo target, and a client command derived from GoreeCloud's generated WSS template. It asserts the production template includes `--tls-verify-certificate`. With that flag, the untrusted server must not carry UDP traffic. The test then removes the flag **only in a disposable test control** and confirms WSS carries an identical UDP echo, so a broken connection cannot masquerade as successful certificate rejection. Keys and the server process are deleted/terminated on exit.

The control's disabled verification must **never** be copied into generated, installed, or production GoreeCloud profiles.

This test does **not** validate a legitimately trusted certificate, a DNS-name mismatch, rotation, certificate expiry, external network reachability, or actual WireGuard datagrams through WSS. Those remain separate acceptance requirements. The TLS test uses the upstream version pinned by the CI download and checksum; update both atomically when upgrading.
