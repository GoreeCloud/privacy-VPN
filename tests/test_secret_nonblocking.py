"""Private-key path regression tests; no real keys or network operations."""
import base64
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from privacyvpn.model import Invalid
from privacyvpn.secrets import read_secret


class PrivateKeyPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "Requires POSIX nonblocking FIFOs")
    def test_fifo_is_rejected_without_hanging(self):
        fifo = self.root / "secret.fifo"
        os.mkfifo(fifo, 0o600)
        # A timeout ensures the regression test itself never hangs CI even if
        # someone accidentally removes O_NONBLOCK in the future.
        program = (
            "import sys\n"
            "from privacyvpn.model import Invalid\n"
            "from privacyvpn.secrets import read_secret\n"
            "try:\n"
            "    read_secret(sys.argv[1])\n"
            "except Invalid:\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", program, str(fifo)],
            capture_output=True, text=True, check=False, timeout=3,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_secret_symlink(self):
        secret = self.root / "source.key"
        secret.write_text(base64.b64encode(b"\x11" * 32).decode() + "\n")
        secret.chmod(0o600)
        link = self.root / "linked.key"
        link.symlink_to(secret)
        with self.assertRaises(Invalid):
            read_secret(link)

    def test_regular_private_key_remains_supported(self):
        secret = self.root / "regular.key"
        value = base64.b64encode(b"\x11" * 32).decode()
        secret.write_text(value + "\n")
        secret.chmod(0o600)
        self.assertEqual(read_secret(secret), value)


if __name__ == "__main__":
    unittest.main()
