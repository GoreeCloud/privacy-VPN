"""Exit relay interface and WAN-only NAT policy."""
from .model import CLIENT_CIDR, ENTRY_T, EXIT_T
from .firewall import exit_policy


def render_exit(topology, private_key):
    entry = topology["entry"]
    exit_node = topology["exit"]
    transit = (
        "[Interface]\n"
        f"Address = {EXIT_T}/30\n"
        f"ListenPort = {exit_node['listen_port']}\n"
        f"PrivateKey = {private_key}\n\n"
        "[Peer]\n"
        f"PublicKey = {entry['transit_public_key']}\n"
        f"AllowedIPs = {CLIENT_CIDR}, {ENTRY_T}/32\n"
    )
    return {
        "gpt0.conf": transit,
        "exit-firewall.nft": exit_policy(exit_node["wan_interface"]),
    }
