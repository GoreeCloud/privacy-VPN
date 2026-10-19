"""Entry node WireGuard profiles and policy-based routing."""
from .model import CLIENT, CLIENT_CIDR, ENTRY, ENTRY_T
from .firewall import entry_policy


def render_entry(topology, private_key, transit_key):
    entry = topology["entry"]
    client = topology["client"]
    exit_node = topology["exit"]
    access = (
        "[Interface]\n"
        f"Address = {ENTRY}/24\n"
        f"ListenPort = {entry['listen_port']}\n"
        f"PrivateKey = {private_key}\n\n"
        "[Peer]\n"
        f"PublicKey = {client['public_key']}\n"
        f"AllowedIPs = {CLIENT}/32\n"
    )
    transit = (
        "[Interface]\n"
        f"Address = {ENTRY_T}/30\n"
        f"PrivateKey = {transit_key}\n"
        "Table = off\n\n"
        "[Peer]\n"
        f"PublicKey = {exit_node['transit_public_key']}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {exit_node['endpoint']}:{exit_node['listen_port']}\n"
        "PersistentKeepalive = 25\n"
    )
    route_up = (
        "#!/bin/sh\nset -eu\n"
        "ip route replace default dev gpt0 table 51820\n"
        f"if ! ip -4 rule show | grep -Fq 'from {CLIENT_CIDR} lookup 51820'; then\n"
        f"  ip rule add pref 10000 from {CLIENT_CIDR} lookup 51820\n"
        "fi\n"
    )
    route_down = (
        "#!/bin/sh\nset -eu\n"
        f"ip rule del pref 10000 from {CLIENT_CIDR} lookup 51820 2>/dev/null || true\n"
        "ip route flush table 51820\n"
    )
    return {
        "gpe0.conf": access,
        "gpt0.conf": transit,
        "entry-firewall.nft": entry_policy(),
        "entry-routing-up.sh": route_up,
        "entry-routing-down.sh": route_down,
    }
