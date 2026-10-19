"""Offline checks; no host routes are changed."""
import subprocess
import unittest
from privacyvpn.underlay import render_client_underlay


class UnderlayTests(unittest.TestCase):
    def test_route_is_scoped_and_additive(self):
        output = render_client_underlay("203.0.113.10")
        self.assertIn("203.0.113.10/32", output)
        self.assertIn("proto 188", output)
        self.assertNotIn("route replace", output)

    def test_generated_script_has_valid_shell_syntax(self):
        script = render_client_underlay("203.0.113.10")
        result = subprocess.run(["sh", "-n"], input=script, text=True,
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
