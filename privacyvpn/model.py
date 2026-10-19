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
HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class Invalid(ValueError):
    pass


def key(value):
    if not isinstance(value, str):
        raise Invalid("Key must be a base64-encoded string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as err:
        raise Invalid("Invalid WireGuard public key") from err
    if len(raw) != 32 or raw == bytes(32):
        raise Invalid("WireGuard key must be a nonzero 32-byte value")
    if base64.b64encode(raw).decode("ascii") != value:
        raise Invalid("WireGuard key must use canonical base64 encoding")
    return value


def _unique_fields(pairs):
    output = {}
    for name, value in pairs:
        if name in output:
            raise Invalid("Duplicate JSON fields are not allowed")
        output[name] = value
    return output


def exact(value, names, label):
    if not isinstance(value, dict) or set(value) != set(names):
        raise Invalid(f"{label}: unexpected or missing fields")
    return value


def endpoint(value):
    if not isinstance(value, str):
        raise Invalid("Endpoints must be dotted-decimal IPv4 strings")
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
        config = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_fields)
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
    if not isinstance(c["dns"], str):
        raise Invalid("DNS must be a dotted-decimal IPv4 string")
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
        hostname = t["hostname"]
        if (not isinstance(hostname, str) or len(hostname) > 253 or
                len(hostname.split(".")) < 2 or
                any(not HOST_LABEL.fullmatch(label) for label in hostname.split("."))):
            raise Invalid("wstunnel requires a valid TLS DNS hostname")
    else:
        raise Invalid("Transport must be wireguard or wstunnel")
    return config
