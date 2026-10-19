"""Adversarial validation tests; no networking or secrets used."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from privacyvpn.model import Invalid, key, load


def public(n):
    return base64.b64encode(bytes([n]) * 32).decode()


def sample():
    return {
        "client": {"public_key": public(1), "dns": "9.9.9.9"},
        "entry": {"endpoint": "203.0.113.10", "listen_port": 51820,
                  "public_key": public(2), "transit_public_key": public(3)},
        "exit": {"endpoint": "198.51.100.20", "listen_port": 51821,
                 "transit_public_key": public(4), "wan_interface": "eth0"},
        "transport": {"mode": "wireguard"},
    }


class AdversarialTopologyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "topology.json"

    def parsed(self, topology):
        self.path.write_text(json.dumps(topology), encoding="utf-8")
        return load(self.path)

    def test_existing_example_valid(self):
        self.assertEqual(self.parsed(sample())["client"]["dns"], "9.9.9.9")

    def test_duplicate_object_property_rejected(self):
        valid = json.dumps(sample())
        self.path.write_text(valid.replace('"client": {', '"client": {}, "client": {', 1))
        with self.assertRaises(Invalid):
            load(self.path)

    def test_zero_key_rejected(self):
        with self.assertRaises(Invalid):
            key(base64.b64encode(bytes(32)).decode())

    def test_noncanonical_base64_key_rejected(self):
        valid = public(1)
        # The last base64 symbol before '=' contains two unused bits for a 32-byte key.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        pos = alphabet.index(valid[-2])
        noncanonical = valid[:-2] + alphabet[pos ^ 1] + "="
        self.assertEqual(base64.b64decode(valid), base64.b64decode(noncanonical))
        with self.assertRaises(Invalid):
            key(noncanonical)

    def test_ipv4_integer_endpoint_rejected(self):
        config = sample()
        config["entry"]["endpoint"] = 3232235777
        with self.assertRaises(Invalid):
            self.parsed(config)

    def test_numeric_dns_rejected(self):
        config = sample()
        config["client"]["dns"] = 16843009
        with self.assertRaises(Invalid):
            self.parsed(config)

    def test_invalid_tls_hostname_labels_rejected(self):
        for host in ("-vpn.example.org", "vpn-.example.org", "vpn..example.org",
                     "a" * 64 + ".example.org", "justoneword", "vpn_example.org"):
            config = sample()
            config["transport"] = {"mode": "wstunnel", "hostname": host, "tls_port": 443}
            with self.subTest(host=host), self.assertRaises(Invalid):
                self.parsed(config)

    def test_normal_tls_hostname_accepted(self):
        config = sample()
        config["transport"] = {"mode": "wstunnel", "hostname": "vpn.example.org", "tls_port": 443}
        self.assertEqual(self.parsed(config)["transport"]["hostname"], "vpn.example.org")


if __name__ == "__main__":
    unittest.main()
