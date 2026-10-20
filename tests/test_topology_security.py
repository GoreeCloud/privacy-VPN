"""Adversarial validation tests; no networking or secrets used."""
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
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

    def test_oversized_regular_file_is_rejected(self):
        self.path.write_bytes(json.dumps(sample()).encode() + b" " * 32769)
        with self.assertRaises(Invalid):
            load(self.path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Requires POSIX FIFO support")
    def test_named_pipe_is_rejected_without_reading(self):
        fifo = self.path.parent / "topology.fifo"
        os.mkfifo(fifo)
        with self.assertRaises(Invalid):
            load(fifo)

    def test_path_replacement_after_open_does_not_change_loaded_topology(self):
        self.path.write_text(json.dumps(sample()), encoding="utf-8")
        original_fdopen = os.fdopen
        replacement = sample()
        replacement["entry"]["endpoint"] = "203.0.113.55"

        def swap_path_after_open(fd, mode):
            new_file = self.path.parent / "replacement.json"
            new_file.write_text(json.dumps(replacement), encoding="utf-8")
            new_file.replace(self.path)
            return original_fdopen(fd, mode)

        with patch("privacyvpn.model.os.fdopen", side_effect=swap_path_after_open) as opened:
            result = load(self.path)
        opened.assert_called_once()
        self.assertEqual(result["entry"]["endpoint"], "203.0.113.10")
        self.assertEqual(json.loads(self.path.read_text())["entry"]["endpoint"],
                         "203.0.113.55")


if __name__ == "__main__":
    unittest.main()
