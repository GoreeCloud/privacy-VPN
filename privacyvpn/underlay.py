"""Render a guarded, operator-invoked underlay host-route helper.

A transport connection to the WSS entry endpoint must bypass the full-tunnel
WireGuard route. The provisioning CLI never executes this script.
"""


def render_client_underlay(endpoint):
    return (
        "#!/bin/sh\n"
        "# Isolated lab use only. Verify the actual WAN interface/gateway first.\n"
        "# Apply BEFORE enabling the client WireGuard full tunnel.\n"
        "# Adds, never replaces, one explicit host route.\n"
        "set -eu\n"
        'if [ "$#" -ne 2 ]; then\n'
        '  echo "Usage: sh client-underlay-route.sh WAN_IFACE WAN_IPV4_GATEWAY" >&2\n'
        "  exit 2\n"
        "fi\n"
        'WAN_IFACE="$1"\n'
        'GATEWAY="$2"\n'
        'case "$WAN_IFACE" in ""|*[!a-zA-Z0-9_.-]*) echo "Invalid interface" >&2; exit 2;; esac\n'
        'case "$GATEWAY" in ""|*[!0-9.]*) echo "Invalid IPv4 gateway" >&2; exit 2;; esac\n'
        f'ip -4 route add {endpoint}/32 via "$GATEWAY" dev "$WAN_IFACE" proto 188\n'
        f'echo "Inspect the host route: ip -4 route get {endpoint}"\n'
        "# Recovery: inspect route ownership before deleting only this host route.\n"
    )
