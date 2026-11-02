"""Offline authoritative negative DNS answer regression contracts."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NegativeDnsResponseContracts(unittest.TestCase):
    def test_disposable_zone_and_negative_response_codes(self):
        harness = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        auth = (ROOT / "tests/smoke_auth_session.pl").read_text(encoding="utf-8")
        probe = (ROOT / "tests/smoke_authoritative_negative.pl").read_text(encoding="utf-8")
        self.assertIn("--network=none", harness)
        self.assertIn("smoke_authoritative_negative.pl", harness)
        self.assertIn("smoke_authoritative_negative.pl", auth)
        self.assertIn("absent.smoke.invalid", probe)
        self.assertIn("host.smoke.invalid", probe)
        self.assertIn("verify_negative($proto, 'absent.smoke.invalid', 1, 3", probe)
        self.assertIn("verify_negative($proto, 'host.smoke.invalid', 28, 0", probe)
        self.assertIn("$flags & 0x0400", probe)
        self.assertIn("$an == 0", probe)
        self.assertIn("$rrtype == 6", probe)
        self.assertIn("for my $proto ('udp', 'tcp')", probe)
        self.assertNotIn("8.8.8.8", probe)

    def test_ci_validates_perl_syntax(self):
        workflow = (ROOT / ".github/workflows/goreecloud-static-checks.yml").read_text(encoding="utf-8")
        self.assertIn("perl -c tests/smoke_authoritative_negative.pl", workflow)


if __name__ == "__main__":
    unittest.main()
