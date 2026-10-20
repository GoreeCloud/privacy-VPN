"""Unit tests use synthetic keys only; no interfaces or firewall rules are applied."""
import base64
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from privacyvpn.model import Invalid, load
from privacyvpn.client import render_client
from privacyvpn.entry import render_entry
from privacyvpn.exit import render_exit
from privacyvpn.firewall import client_policy
from privacyvpn.secrets import read_secret, write_files
from privacyvpn.__main__ import main


K = base64.b64encode(b"\x11" * 32).decode()
K2 = base64.b64encode(b"\x22" * 32).decode()
K3 = base64.b64encode(b"\x33" * 32).decode()
K4 = base64.b64encode(b"\x44" * 32).decode()


def topology(mode="wireguard"):
    return {
        "client": {"public_key": K, "dns": "9.9.9.9"},
        "entry": {"endpoint": "203.0.113.10", "listen_port": 51820, "public_key": K2, "transit_public_key": K3},
        "exit": {"endpoint": "198.51.100.20", "listen_port": 51821, "transit_public_key": K4, "wan_interface": "eth0"},
        "transport": {"mode": "wireguard"} if mode == "wireguard" else
                     {"mode": "wstunnel", "tls_port": 443, "hostname": "vpn.example.org"},
    }


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "topology.json"

    def read(self, obj):
        self.manifest.write_text(json.dumps(obj), encoding="utf-8")
        return load(self.manifest)

    def test_accepts_both_transports(self):
        for mode in ("wireguard", "wstunnel"):
            self.assertEqual(self.read(topology(mode))["transport"]["mode"], mode)

    def test_rejects_extra_properties(self):
        obj = topology()
        obj["entry"]["private_key"] = K
        with self.assertRaises(Invalid):
            self.read(obj)

    def test_rejects_reused_wireguard_public_keys(self):
        obj = topology()
        obj["entry"]["public_key"] = obj["client"]["public_key"]
        with self.assertRaises(Invalid):
            self.read(obj)

    def test_rejects_same_relay(self):
        obj = topology()
        obj["exit"]["endpoint"] = obj["entry"]["endpoint"]
        with self.assertRaises(Invalid):
            self.read(obj)

    def test_rejects_injected_interface(self):
        obj = topology()
        obj["exit"]["wan_interface"] = "eth0;id"
        with self.assertRaises(Invalid):
            self.read(obj)

    def test_rejects_dns_hostname(self):
        obj = topology()
        obj["client"]["dns"] = "dns.example.net"
        with self.assertRaises(Invalid):
            self.read(obj)

    def test_rejects_symlink_manifest(self):
        self.read(topology())
        target = self.root / "symlink.json"
        target.symlink_to(self.manifest)
        with self.assertRaises(Invalid):
            load(target)

    def test_distinct_hops_and_firewall(self):
        t = self.read(topology())
        client = render_client(t, K)["gpv0.conf"]
        entry = render_entry(t, K, K)
        exit_node = render_exit(t, K)
        self.assertIn("203.0.113.10:51820", client)
        self.assertIn("198.51.100.20:51821", entry["gpt0.conf"])
        self.assertIn("Table = off", entry["gpt0.conf"])
        self.assertIn("10.77.1.0/24", exit_node["gpt0.conf"])
        self.assertIn("masquerade", exit_node["exit-firewall.nft"])
        self.assertIn("policy drop", client_policy("203.0.113.10", 51820))
        self.assertIn("meta nfproto ipv6 drop", client_policy("203.0.113.10", 51820))

    def test_key_file_permissions_and_create_only_output(self):
        keyfile = self.root / "role.key"
        keyfile.write_text(K + "\n")
        keyfile.chmod(0o600)
        self.assertEqual(read_secret(keyfile), K)
        keyfile.chmod(0o644)
        with self.assertRaises(Invalid):
            read_secret(keyfile)
        keyfile.chmod(0o600)
        out = self.root / "generated"
        self.assertEqual(write_files(out, {"gpv0.conf": "synthetic"}), 1)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((out / "gpv0.conf").stat().st_mode), 0o600)
        with self.assertRaises(Invalid):
            write_files(out, {"gpv0.conf": "overwrite"})

    def test_output_writer_refuses_unsafe_filenames_without_side_effects(self):
        for index, unsafe in enumerate(("../outside.conf", "nested/gpv0.conf",
                                        "/tmp/gpv0.conf", "", ".", "..",
                                        "name\\with-backslash", "bad\x00name")):
            with self.subTest(filename=repr(unsafe)):
                output = self.root / f"unsafe-{index}"
                with self.assertRaises(Invalid):
                    write_files(output, {unsafe: "synthetic"})
                self.assertFalse(output.exists())
        self.assertFalse((self.root / "outside.conf").exists())

    def test_cli_rejects_entry_key_reuse(self):
        self.read(topology())
        entry_key = self.root / "entry.key"
        transit_key = self.root / "transit.key"
        for target in (entry_key, transit_key):
            target.write_text(K)
            target.chmod(0o600)
        output = self.root / "bad-entry"
        self.assertEqual(main(["render", "entry", str(self.manifest), "--key", str(entry_key),
                               "--transit-key", str(transit_key), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

    def test_cli_render_client_wstunnel(self):
        self.read(topology("wstunnel"))
        keyfile = self.root / "client.key"
        keyfile.write_text(K)
        keyfile.chmod(0o600)
        out = self.root / "rendered"
        code = main(["render", "client", str(self.manifest), "--key", str(keyfile), "--output", str(out)])
        self.assertEqual(code, 0)
        self.assertIn("127.0.0.1:51820", (out / "gpv0.conf").read_text())
        self.assertIn("tcp dport 443", (out / "client-killswitch.nft").read_text())
        self.assertIn("wss://vpn.example.org:443", (out / "wstunnel-client.sh").read_text())
        self.assertIn("client --tls-verify-certificate ", (out / "wstunnel-client.sh").read_text())
        self.assertTrue((out / "client-underlay-route.sh").is_file())


if __name__ == "__main__":
    unittest.main()
