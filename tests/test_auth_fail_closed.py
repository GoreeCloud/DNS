"""Regression contract: explicit administrator password-file failures cannot use known credentials."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AdminPasswordFileSecurity(unittest.TestCase):
    def test_configured_secret_has_no_default_password_fallback(self):
        source = (ROOT / "DnsServerCore/Auth/AuthManager.cs").read_text(encoding="utf-8")
        start = source.index('else if (!string.IsNullOrEmpty(adminPasswordFile))', source.index("private void CreateDefaultConfig()"))
        end = source.index('            else\n', start)
        block = source[start:end]

        self.assertIn('string.IsNullOrWhiteSpace(password)', block)
        self.assertIn('throw new InvalidDataException(', block)
        self.assertIn('throw new InvalidOperationException(', block)
        self.assertIn('DNS_SERVER_ADMIN_PASSWORD_FILE.', block)
        self.assertNotIn('CreateUser("Administrator", "admin", "admin")', block)

    def test_offline_negative_runtime_scenario_is_documented(self):
        smoke = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        self.assertIn("DNS_SERVER_ADMIN_PASSWORD_FILE=/work/absent-admin-password-file", smoke)
        self.assertIn("missing admin password file fails closed", smoke)
        self.assertIn('--network=none', smoke)


if __name__ == "__main__":
    unittest.main()
