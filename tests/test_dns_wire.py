"""DNS wire-format fixture checks; no sockets or host resolver changes."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "lab"))
import dns_wire


class DNSWireTests(unittest.TestCase):
    def test_valid_a_query_and_reply(self):
        query = dns_wire.query()
        self.assertEqual(len(query[:12]), 12)
        dns_wire.assert_query(query)
        dns_wire.assert_reply(dns_wire.reply(query))

    def test_response_carries_documentation_address(self):
        response = dns_wire.reply(dns_wire.query())
        self.assertEqual(response[-4:], bytes([192, 0, 2, 123]))

    def test_invalid_query_rejected(self):
        with self.assertRaises(AssertionError):
            dns_wire.assert_query(dns_wire.query()[:-1])

    def test_invalid_answer_rejected(self):
        response = dns_wire.reply(dns_wire.query())
        with self.assertRaises(AssertionError):
            dns_wire.assert_reply(response[:-1] + b"\x01")


if __name__ == "__main__":
    unittest.main()
