"""Static contracts for offline DNSSEC publication probes; not cryptographic validation."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class OfflineDnssecContracts(unittest.TestCase):
    def test_dnssec_signing_remains_disposable_and_locally_scoped(self):
        runtime = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        auth = (ROOT / "tests/smoke_auth_session.pl").read_text(encoding="utf-8")
        script = (ROOT / "tests/smoke_dnssec.pl").read_text(encoding="utf-8")
        self.assertIn("--network=none", runtime)
        self.assertIn("--user=0:0 --cap-drop=ALL", runtime)
        self.assertIn("smoke_dnssec.pl", runtime)
        self.assertIn("smoke_dnssec.pl", auth)
        self.assertIn("zone=smoke.invalid", script)
        self.assertIn("algorithm=ECDSA", script)
        self.assertIn("curve=P256", script)
        self.assertIn("nxProof=NSEC", script)
        self.assertIn("0x8000", script)
        self.assertIn("signed_query($transport", script)
        self.assertIn("48", script)
        self.assertIn("46", script)
        self.assertIn("RRSIG", script)
        self.assertNotIn("dnssec-validation=passed", script)

    def test_dnssec_helper_compilation_is_in_ci(self):
        workflow = (ROOT / ".github/workflows/goreecloud-static-checks.yml").read_text(encoding="utf-8")
        self.assertIn("perl -c tests/smoke_dnssec.pl", workflow)

    def test_math_verification_is_opt_in_and_fails_closed_without_dependencies(self):
        runtime = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        perl = (ROOT / "tests/smoke_dnssec.pl").read_text(encoding="utf-8")
        verifier = (ROOT / "tests/verify_dnssec_crypto.py").read_text(encoding="utf-8")
        self.assertIn("verify_dnssec_crypto.py", runtime)
        self.assertIn("import dns.dnssec, cryptography", runtime)
        self.assertIn("dnssec-wire-$transport-$qtype.bin", perl)
        self.assertIn("dns.dnssec.validate", verifier)
        self.assertIn("production_dnssec_ready", verifier)
        self.assertIn("O_NOFOLLOW", verifier)
        self.assertNotIn("dnssec-validation=passed", verifier)


if __name__ == "__main__":
    unittest.main()
