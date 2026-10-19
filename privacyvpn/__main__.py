"""Offline provisioning CLI; never changes network state or logs private keys."""
import argparse
import sys
from pathlib import Path
from .model import Invalid, load
from .secrets import read_secret, write_files
from .client import render_client
from .entry import render_entry
from .exit import render_exit
from .firewall import client_policy
from .obfs import render_client as obfs_client, render_server as obfs_server


def main(argv=None):
    p = argparse.ArgumentParser(prog="privacyvpn", description="WireGuard privacy relay provisioning")
    sub = p.add_subparsers(dest="action", required=True)
    val = sub.add_parser("validate")
    val.add_argument("topology", type=Path)
    rnd = sub.add_parser("render")
    rnd.add_argument("role", choices=("client", "entry", "exit"))
    rnd.add_argument("topology", type=Path)
    rnd.add_argument("--key", type=Path, required=True, help="Private key of this role only")
    rnd.add_argument("--transit-key", type=Path, help="Separate entry-transit private key; entry role only")
    rnd.add_argument("--output", type=Path, required=True, help="Empty, owner-only output folder")
    args = p.parse_args(argv)
    try:
        cfg = load(args.topology)
        if args.action == "validate":
            print("Valid public topology.")
            return 0
        if args.role == "entry" and args.transit_key is None:
            raise Invalid("Entry role needs --transit-key")
        if args.role != "entry" and args.transit_key is not None:
            raise Invalid("--transit-key only applies to entry")
        secret = read_secret(args.key)
        if args.role == "client":
            files = render_client(cfg, secret)
            obfuscated = cfg["transport"]["mode"] == "wstunnel"
            if obfuscated:
                entry = cfg["entry"]
                files["gpv0.conf"] = files["gpv0.conf"].replace(
                    f"Endpoint = {entry['endpoint']}:{entry['listen_port']}",
                    f"Endpoint = 127.0.0.1:{entry['listen_port']}"
                )
                files["wstunnel-client.sh"] = obfs_client(cfg)
            port = cfg["transport"]["tls_port"] if obfuscated else cfg["entry"]["listen_port"]
            proto = "tcp" if obfuscated else "udp"
            files["client-killswitch.nft"] = client_policy(cfg["entry"]["endpoint"], port, proto)
        elif args.role == "entry":
            transit_secret = read_secret(args.transit_key)
            if secret == transit_secret:
                raise Invalid("Entry access and transit keys must be different")
            files = render_entry(cfg, secret, transit_secret)
            if cfg["transport"]["mode"] == "wstunnel":
                files["wstunnel-server.sh"] = obfs_server(cfg)
        else:
            files = render_exit(cfg, secret)
        n = write_files(args.output, files)
        print(f"Rendered {n} role-scoped files in {args.output}; no network changes made.")
        return 0
    except Invalid as err:
        print(f"Configuration rejected: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
