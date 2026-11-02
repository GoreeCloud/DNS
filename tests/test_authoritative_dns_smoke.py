"""Static safety and protocol contracts for disposable authoritative DNS smoke tests."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AuthoritativeDnsSmokeContracts(unittest.TestCase):
    def test_authoritative_zone_only_runs_in_isolated_smoke(self):
        harness = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        auth = (ROOT / "tests/smoke_auth_session.pl").read_text(encoding="utf-8")
        probe = (ROOT / "tests/smoke_authoritative.pl").read_text(encoding="utf-8")
        self.assertIn("--network=none", harness)
        self.assertIn("--security-opt=no-new-privileges", harness)
        self.assertIn("smoke_authoritative.pl", harness)
        self.assertIn("smoke_authoritative.pl", auth)
        self.assertIn("smoke.invalid", probe)
        self.assertIn("192.0.2.42", probe)
        self.assertIn("udp", probe)
        self.assertIn("tcp", probe)
        self.assertIn("0x0400", probe)
        self.assertIn("0xc0", probe)
        self.assertNotIn("8.8.8.8", probe)
        self.assertNotIn("1.1.1.1", probe)

    def test_ci_syntax_check_covers_protocol_probe(self):
        flow = (ROOT / ".github/workflows/goreecloud-static-checks.yml").read_text(encoding="utf-8")
        self.assertIn("perl -c tests/smoke_authoritative.pl", flow)


if __name__ == "__main__":
    unittest.main()
