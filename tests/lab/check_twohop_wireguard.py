"""Offline three-node WireGuard integration in isolated Linux network namespaces.

Requires iproute2, nftables, wg and unshare. Never modifies the host namespace.
All peers, private keys, routing, firewall rules and interfaces are disposable.
"""
import configparser
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from privacyvpn.client import render_client
from privacyvpn.entry import render_entry
from privacyvpn.exit import render_exit
from privacyvpn.firewall import client_policy


def run(*args, input_text=None, env=None):
    return subprocess.run(args, input=input_text, text=True, capture_output=True,
                          check=True, env=env).stdout.strip()


def node(pid, *cmd):
    return run("nsenter", "-t", str(pid), "-n", *map(str, cmd))


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def create_keys(directory, wg):
    values = {}
    for label in ("client", "entry", "transit", "exit"):
        private = run(wg, "genkey") + "\n"
        public = run(wg, "pubkey", input_text=private)
        path = directory / (label + ".private")
        write_private(path, private)
        values[label] = {"private": private.strip(), "public": public}
    return values


def wg_conf(interface, rendered, directory, wg, pid):
    """Use the repository-rendered peer fields, removing wg-quick-only options."""
    source = configparser.ConfigParser(interpolation=None)
    source.optionxform = str
    source.read_string(rendered)
    supported = {"PrivateKey", "ListenPort", "PublicKey", "AllowedIPs",
                 "Endpoint", "PersistentKeepalive"}
    lines = []
    for section in source.sections():
        lines.append("[" + section + "]")
        lines += [k + " = " + v for k, v in source.items(section)
                  if k in supported]
        lines.append("")
    output = directory / (interface + "-" + str(pid) + ".wgconf")
    write_private(output, "\n".join(lines))
    node(pid, "ip", "link", "add", interface, "type", "wireguard")
    node(pid, wg, "setconf", interface, output)


def connect(pid, label, guest_addr, router_addr):
    local = "r" + label
    run("ip", "link", "add", local, "type", "veth", "peer", "name", "eth0")
    run("ip", "link", "set", "eth0", "netns", str(pid))
    run("ip", "addr", "add", router_addr, "dev", local)
    run("ip", "link", "set", local, "up")
    node(pid, "ip", "link", "set", "lo", "up")
    node(pid, "ip", "addr", "add", guest_addr, "dev", "eth0")
    node(pid, "ip", "link", "set", "eth0", "up")
    node(pid, "ip", "route", "add", "default", "via", router_addr.split("/")[0])


def udp_client(pid, destination, port, payload, *, require_reply=False):
    client_code = (
        "import socket,sys\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        "s.settimeout(8)\n"
        "s.sendto(sys.argv[1].encode(),(sys.argv[2],int(sys.argv[3])))\n"
        "print(s.recvfrom(1024)[0].decode() if sys.argv[4]=='yes' else 'sent')\n"
    )
    return subprocess.Popen(
        ["nsenter", "-t", str(pid), "-n", sys.executable, "-c",
         client_code, payload, destination, str(port),
         "yes" if require_reply else "no"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def verify_traffic(nodes, scenario="transit"):
    target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target.bind(("10.88.0.1", 9955))
    target.settimeout(10)
    try:
        client = udp_client(nodes["client"].pid, "10.88.0.1", 9955,
                            "two-hop-probe", require_reply=True)
        data, addr = target.recvfrom(1024)
        assert data == b"two-hop-probe", f"unexpected message {data!r}"
        assert addr[0] == "203.0.113.2", f"exit NAT not observed: {addr}"
        target.sendto(b"two-hop-ok", addr)
        stdout, stderr = client.communicate(timeout=8)
        assert client.returncode == 0, stderr
        assert stdout.strip() == "two-hop-ok", stdout
        print("PASS three-node WireGuard: encrypted client-entry-exit tunnel,"
              " exit source NAT and reverse UDP response")
        print("Exit NAT source in isolated lab:", addr[0])

        failure_interfaces = {
            "transit": ("entry", "gpt0"),
            "entry": ("entry", "gpe0"),
            "exit": ("exit", "gpt0"),
        }
        if scenario not in failure_interfaces:
            raise ValueError(f"Unsupported failure scenario: {scenario}")
        failing_node, interface = failure_interfaces[scenario]
        node(nodes[failing_node].pid, "ip", "link", "set", interface, "down")
        paused = udp_client(nodes["client"].pid, "10.88.0.1", 9955,
                             f"{scenario}-down-probe")
        stdout, stderr = paused.communicate(timeout=8)
        assert paused.returncode == 0, stderr
        target.settimeout(2)
        try:
            leaked, source = target.recvfrom(1024)
        except socket.timeout:
            print(f"PASS {scenario}-down: target received no further client packets")
        else:
            raise AssertionError(f"traffic reached target after {scenario} failure:"
                                 f" {leaked!r} from {source}")
    finally:
        target.close()


def inside(wg):
    prior = os.environ.get("GCVPN_PARENT_NETNS")
    if not prior or os.readlink("/proc/self/ns/net") == prior:
        raise RuntimeError("Refusing to modify host network namespace")
    children = {}
    with tempfile.TemporaryDirectory(prefix="gcvpn-wg-lab-") as temporary:
        directory = Path(temporary)
        try:
            for label in ("client", "entry", "exit"):
                children[label] = subprocess.Popen(
                    ["unshare", "-n", "sleep", "90"], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            time.sleep(0.3)
            if any(p.poll() is not None for p in children.values()):
                raise RuntimeError("Child network namespace setup failed")

            run("ip", "link", "set", "lo", "up")
            connect(children["client"].pid, "client",
                    "192.0.2.2/30", "192.0.2.1/30")
            connect(children["entry"].pid, "entry",
                    "198.51.100.2/30", "198.51.100.1/30")
            connect(children["exit"].pid, "exit",
                    "203.0.113.2/30", "203.0.113.1/30")
            run("ip", "addr", "add", "10.88.0.1/32", "dev", "lo")
            run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            node(children["entry"].pid, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            node(children["exit"].pid, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")

            keys = create_keys(directory, wg)
            topology = {
                "client": {"public_key": keys["client"]["public"],
                           "dns": "10.88.0.1"},
                "entry": {"endpoint": "198.51.100.2", "listen_port": 51820,
                          "public_key": keys["entry"]["public"],
                          "transit_public_key": keys["transit"]["public"]},
                "exit": {"endpoint": "203.0.113.2", "listen_port": 51821,
                         "transit_public_key": keys["exit"]["public"],
                         "wan_interface": "eth0"},
                "transport": {"mode": "wireguard"},
            }
            client = render_client(topology, keys["client"]["private"])
            entry = render_entry(topology, keys["entry"]["private"],
                                 keys["transit"]["private"])
            exit_node = render_exit(topology, keys["exit"]["private"])
            for label, iface, config, addr in (
                ("client", "gpv0", client["gpv0.conf"], "10.77.1.2/32"),
                ("entry", "gpe0", entry["gpe0.conf"], "10.77.1.1/24"),
                ("entry", "gpt0", entry["gpt0.conf"], "10.77.2.1/30"),
                ("exit", "gpt0", exit_node["gpt0.conf"], "10.77.2.2/30"),
            ):
                pid = children[label].pid
                wg_conf(iface, config, directory, wg, pid)
                node(pid, "ip", "addr", "add", addr, "dev", iface)
                node(pid, "ip", "link", "set", iface, "up")

            for label, file in (("entry", entry["entry-firewall.nft"]),
                                ("exit", exit_node["exit-firewall.nft"]),
                                ("client", client_policy("198.51.100.2", 51820))):
                conf = directory / (label + ".nft")
                conf.write_text(file)
                node(children[label].pid, "nft", "-f", conf)

            node(children["exit"].pid, "ip", "route", "add",
                 "10.77.1.0/24", "dev", "gpt0")
            routing = directory / "entry-route.sh"
            routing.write_text(entry["entry-routing-up.sh"])
            node(children["entry"].pid, "sh", routing)
            node(children["client"].pid, "ip", "route", "add",
                 "198.51.100.2/32", "via", "192.0.2.1", "dev", "eth0")
            node(children["client"].pid, "ip", "route", "replace",
                 "default", "dev", "gpv0")
            verify_traffic(children, os.environ.get("GCVPN_FAILURE", "transit"))
        finally:
            for proc in children.values():
                proc.terminate()
            for proc in children.values():
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def main():
    wg = os.environ.get("GCVPN_WG") or shutil.which("wg")
    if not wg or not Path(wg).is_file():
        raise SystemExit("SKIP: WireGuard command-line tool unavailable")
    if len(sys.argv) == 2 and sys.argv[1] == "--inside":
        inside(wg)
    elif len(sys.argv) == 1:
        env = dict(os.environ, GCVPN_WG=wg,
                   GCVPN_PARENT_NETNS=os.readlink("/proc/self/ns/net"))
        prefix = ["unshare", "-n"] if os.geteuid() == 0 else ["unshare", "-Urn"]
        raise SystemExit(subprocess.run(
            prefix + [sys.executable, str(Path(__file__).resolve()), "--inside"],
            check=False, env=env,
        ).returncode)
    else:
        raise SystemExit("Usage: python3 tests/lab/check_twohop_wireguard.py")


if __name__ == "__main__":
    main()
