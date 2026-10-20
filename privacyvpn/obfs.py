"""Optional WireGuard-over-TLS/WebSocket transport templates.

Uses upstream wstunnel, not custom encryption or a bespoke wire protocol.
TLS certificate validation must remain enabled.
"""


def render_client(topology):
    entry = topology["entry"]
    tr = topology["transport"]
    listen = entry["listen_port"]
    host = tr["hostname"]
    port = tr["tls_port"]
    return (
        "#!/bin/sh\nset -eu\n"
        f"# Before starting, pin {host} to {entry['endpoint']} in /etc/hosts.\n"
        "# Provide a publicly trusted matching TLS server certificate.\n"
        "exec wstunnel client --tls-verify-certificate "
        f"-L 'udp://127.0.0.1:{listen}:127.0.0.1:{listen}?timeout_sec=0' "
        f"'wss://{host}:{port}'\n"
    )


def render_server(topology):
    entry = topology["entry"]
    tr = topology["transport"]
    return (
        "#!/bin/sh\nset -eu\n"
        'test "$#" -eq 2 || { echo "usage: server CERT_PEM KEY_PEM" >&2; exit 2; }\n'
        "exec wstunnel server "
        f"--restrict-to 127.0.0.1:{entry['listen_port']} "
        '--tls-certificate "$1" --tls-private-key "$2" '
        f"'wss://0.0.0.0:{tr['tls_port']}'\n"
    )
