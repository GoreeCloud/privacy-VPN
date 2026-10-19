"""Render a WireGuard client profile for the entry relay."""
from .model import CLIENT


def render_client(topology, private_key):
    entry = topology["entry"]
    client = topology["client"]
    endpoint = str(entry["endpoint"]) + ":" + str(entry["listen_port"])
    return {"gpv0.conf": (
        "[Interface]\n"
        f"Address = {CLIENT}/32\n"
        f"PrivateKey = {private_key}\n"
        f"DNS = {client['dns']}\n\n"
        "[Peer]\n"
        f"PublicKey = {entry['public_key']}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {endpoint}\n"
        "PersistentKeepalive = 25\n"
    )}
