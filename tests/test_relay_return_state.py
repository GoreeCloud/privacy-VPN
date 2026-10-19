"""Relay return-direction gates must use positive connection-state matching."""
import unittest
from privacyvpn.firewall import entry_policy, exit_policy


class RelayReturnStateTests(unittest.TestCase):
    def test_entry_only_accepts_stateful_reverse_traffic(self):
        policy = entry_policy()
        allow = 'oifname "gpe0" ct state established,related accept'
        deny = 'oifname "gpe0" drop'
        self.assertIn(allow, policy)
        self.assertIn(deny, policy)
        self.assertLess(policy.index(allow), policy.index(deny))
        self.assertNotIn('ct state != established,related', policy)

    def test_exit_only_accepts_stateful_reverse_traffic(self):
        policy = exit_policy("eth0")
        allow = 'oifname "gpt0" ct state established,related accept'
        deny = 'oifname "gpt0" drop'
        self.assertIn(allow, policy)
        self.assertIn(deny, policy)
        self.assertLess(policy.index(allow), policy.index(deny))
        self.assertNotIn('ct state != established,related', policy)


if __name__ == "__main__":
    unittest.main()
