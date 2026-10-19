"""Validate a public-only, single-client two-hop topology."""
import base64
import binascii
import ipaddress
import json
import re
from pathlib import Path

CLIENT = "10.77.1.2"
CLIENT_CIDR = "10.77.1.0/24"
ENTRY = "10.77.1.1"
ENTRY_T = "10.77.2.1"
EXIT_T = "10.77.2.2"
NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$")
HOST = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")


class Invalid(ValueError):
    pass


def key(value):
    if not isinstance(value, str):
        raise Invalid("Key must be a base64-encoded string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as err:
        raise Invalid("Invalid WireGuard public key") from err
    if len(raw) != 32:
        raise Invalid("WireGuard key must contain 32 bytes")
    return value


def exact(value, names, label):
    if not isinstance(value, dict) or set(value) != set(names):
        raise Invalid(f"{label}: unexpected or missing fields")
    return value


def endpoint(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError) as err:
        raise Invalid("Endpoints must use a literal IPv4 address") from err
    if address.is_multicast or address.is_unspecified or address.is_loopback:
        raise Invalid("Invalid endpoint IPv4 address")
    return str(address)


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise Invalid("Port must be an integer 1..65535")
    return value


def load(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
        raise Invalid("Topology must be a small regular file")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError, UnicodeError) as err:
        raise Invalid("Cannot parse topology JSON") from err
    exact(config, ["client", "entry", "exit", "transport"], "topology")
    c = exact(config["client"], ["public_key", "dns"], "client")
    e = exact(config["entry"], ["endpoint", "listen_port", "public_key", "transit_public_key"], "entry")
    x = exact(config["exit"], ["endpoint", "listen_port", "transit_public_key", "wan_interface"], "exit")
    public_keys = (c["public_key"], e["public_key"], e["transit_public_key"], x["transit_public_key"])
    for value in public_keys:
        key(value)
    if len(set(public_keys)) != len(public_keys):
        raise Invalid("Every WireGuard interface must have a distinct public key")
    for node in (e, x):
        node["endpoint"] = endpoint(node["endpoint"])
        node["listen_port"] = port(node["listen_port"])
    if e["endpoint"] == x["endpoint"]:
        raise Invalid("Entry and exit must have different IPv4 endpoints")
    if not isinstance(x["wan_interface"], str) or not NAME.fullmatch(x["wan_interface"]):
        raise Invalid("Invalid egress network interface")
    if x["wan_interface"] in ("gpv0", "gpe0", "gpt0"):
        raise Invalid("WAN interface conflicts with VPN interface")
    try:
        resolver = ipaddress.IPv4Address(c["dns"])
    except (ValueError, ipaddress.AddressValueError) as err:
        raise Invalid("DNS must be a literal IPv4 address") from err
    if resolver.is_loopback or resolver.is_multicast or resolver.is_unspecified:
        raise Invalid("Invalid DNS resolver")
    t = config["transport"]
    if not isinstance(t, dict):
        raise Invalid("Invalid transport configuration")
    if t.get("mode") == "wireguard":
        exact(t, ["mode"], "transport")
    elif t.get("mode") == "wstunnel":
        exact(t, ["mode", "tls_port", "hostname"], "transport")
        port(t["tls_port"])
        if not isinstance(t["hostname"], str) or not HOST.fullmatch(t["hostname"]):
            raise Invalid("wstunnel requires a TLS DNS hostname")
    else:
        raise Invalid("Transport must be wireguard or wstunnel")
    return config
