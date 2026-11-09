"""Static contracts for bounded offline DNS REFUSED wire checks.

The actual DNS protocol behavior is only established by the opt-in isolated
runtime smoke test, not by this source-level check.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DnsRefusalResponseBounds(unittest.TestCase):
    def test_offline_smoke_rejects_answer_leakage_and_truncation(self):
        smoke = (ROOT / "tests/smoke_dns_protocol.pl").read_text(encoding="utf-8")
        harness = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        self.assertIn("--network=none", harness)
        self.assertIn("perl /work/smoke_dns_protocol.pl udp", harness)
        self.assertIn("perl /work/smoke_dns_protocol.pl tcp", harness)
        self.assertIn("($flags & 0x7800) == 0", smoke)
        self.assertIn("($flags & 0x0200) == 0", smoke)
        self.assertIn("$answers == 0", smoke)
        self.assertIn("$authority == 0", smoke)
        self.assertIn("$additional == 0", smoke)
        self.assertIn("length($response) == 12 + length($expected_question)", smoke)
        self.assertIn("my $expected_question = substr($question, 12)", smoke)
        self.assertIn("substr($response, 12, length($expected_question)) eq $expected_question", smoke)
        self.assertIn("($flags & 15) == 5", smoke)


if __name__ == "__main__":
    unittest.main()
