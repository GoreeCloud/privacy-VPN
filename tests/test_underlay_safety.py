"""Offline WSS underlay and IPv6-policy regression tests.

Commands are parsed or run with an isolated mock 'ip' executable, never applied.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from privacyvpn.firewall import client_policy, entry_policy, exit_policy
from privacyvpn.underlay import render_client_underlay


class UnderlaySafetyTests(unittest.TestCase):
    def setUp(self):
        self.script = render_client_underlay("203.0.113.10")

    def run_script(self, *args, env=None):
        return subprocess.run(
            ["sh", "-s", "--", *args], input=self.script, text=True,
            capture_output=True, check=False, env=env,
        )

    def test_shell_syntax_and_exact_host_route(self):
        parsed = subprocess.run(["sh", "-n"], input=self.script,
                                text=True, capture_output=True, check=False)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        self.assertIn("route add 203.0.113.10/32", self.script)
        self.assertIn("proto 188", self.script)
        self.assertNotIn("route replace", self.script)

    def test_missing_arguments_rejected(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stderr)

    def test_invalid_interface_rejected(self):
        result = self.run_script("eth0;bad", "192.0.2.1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Invalid interface", result.stderr)

    def test_non_ipv4_gateway_rejected(self):
        result = self.run_script("eth0", "host.example")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Invalid IPv4 gateway", result.stderr)

    def test_command_uses_pinned_endpoint_and_selected_underlay(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_ip = Path(tmp, "ip")
            output = Path(tmp, "args")
            fake_ip.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$UNDERLAY_TEST_ARGS"\n')
            fake_ip.chmod(0o700)
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ.get("PATH", ""),
                       UNDERLAY_TEST_ARGS=str(output))
            result = self.run_script("eth0", "192.0.2.1", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text().splitlines(),
                             ["-4", "route", "add", "203.0.113.10/32", "via",
                              "192.0.2.1", "dev", "eth0", "proto", "188"])

    def test_client_filters_ipv6_before_wg_interface(self):
        policy = client_policy("203.0.113.10", 443, "tcp")
        self.assertLess(policy.index("meta nfproto ipv6 drop"),
                        policy.index('oifname "gpv0" accept'))

    def test_relay_filters_both_directions(self):
        for policy, interface in ((entry_policy(), "gpe0"),
                                  (exit_policy("eth0"), "gpt0")):
            with self.subTest(interface=interface):
                self.assertIn(f'iifname "{interface}" meta nfproto ipv6 drop', policy)
                self.assertIn(f'oifname "{interface}" meta nfproto ipv6 drop', policy)


    def test_gateway_requires_canonical_ipv4_before_running_ip(self):
        for gateway in ("1.2.3", "1.2.3.4.5", "1..2.3", ".1.2.3",
                        "1.2.3.", "01.2.3.4", "256.2.3.4",
                        "224.0.0.1", "0.0.0.0", "999999999999999.2.3.4"):
            with self.subTest(gateway=gateway):
                result = self.run_script("eth0", gateway)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("Invalid IPv4 gateway", result.stderr)


if __name__ == "__main__":
    unittest.main()
