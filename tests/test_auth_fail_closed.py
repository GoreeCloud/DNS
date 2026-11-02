"""Static contracts for secure DNS bootstrap and disposable authentication smoke tests."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AdminPasswordFileSecurity(unittest.TestCase):
    def test_configured_secret_has_no_default_password_fallback(self):
        source = (ROOT / "DnsServerCore/Auth/AuthManager.cs").read_text(encoding="utf-8")
        start = source.index('else if (!string.IsNullOrEmpty(adminPasswordFile))',
                             source.index("private void CreateDefaultConfig()"))
        end = source.index('            else\n', start)
        block = source[start:end]
        self.assertIn('string.IsNullOrWhiteSpace(password)', block)
        self.assertIn('throw new InvalidDataException(', block)
        self.assertIn('throw new InvalidOperationException(', block)
        self.assertIn('DNS_SERVER_ADMIN_PASSWORD_FILE.', block)
        self.assertNotIn('CreateUser("Administrator", "admin", "admin")', block)

    def test_offline_negative_runtime_scenario_is_documented(self):
        smoke = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        self.assertIn("secret_file=/work/absent-admin-password-file", smoke)
        self.assertIn("secret_file=/work/empty-admin-password-file", smoke)
        self.assertIn("secret_file=/work/whitespace-admin-password-file", smoke)
        self.assertIn("for scenario in missing empty whitespace; do", smoke)
        self.assertIn('DNS_SERVER_ADMIN_PASSWORD_FILE="$secret_file"', smoke)
        self.assertIn('failed_status" -eq 0', smoke)
        self.assertIn('failed_status" -eq 124', smoke)
        self.assertIn("Could not initialize administrator credentials from DNS_SERVER_ADMIN_PASSWORD_FILE.", smoke)
        self.assertIn("admin password file fails closed", smoke)
        self.assertIn("--network=none", smoke)

    def test_startup_failure_reports_nonzero_exit_status(self):
        entrypoint = (ROOT / "DnsServerApp/Program.cs").read_text(encoding="utf-8")
        self.assertIn("catch (Exception ex)", entrypoint)
        start = entrypoint.index("catch (Exception ex)")
        failure_path = entrypoint[start:entrypoint.index("finally", start)]
        self.assertIn("Environment.ExitCode = 1;", failure_path)
        smoke = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        self.assertIn('failed_status" -eq 0', smoke)
        self.assertIn('failed_status" -eq 124', smoke)

    def test_isolated_bootstrap_and_session_lifecycle_contract(self):
        harness = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        helper = (ROOT / "tests/smoke_auth_session.pl").read_text(encoding="utf-8")
        self.assertIn("smoke_auth_session.pl", harness)
        self.assertIn("od -An -N24 -tx1 /dev/urandom", harness)
        self.assertIn("DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password", harness)
        self.assertIn("perl /work/smoke_auth_session.pl", harness)
        self.assertIn("--network=none", harness)
        self.assertIn("pass@/work/admin-password", helper)
        self.assertIn("known default admin password rejected", helper)
        self.assertIn("/api/settings/get", helper)
        self.assertIn("/api/user/logout", helper)
        self.assertIn("logged-out token cannot access settings", helper)


if __name__ == "__main__":
    unittest.main()
