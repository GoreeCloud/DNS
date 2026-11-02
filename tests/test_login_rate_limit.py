"""Offline-only login rate-limiter regression contracts."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AdminLoginRateLimiter(unittest.TestCase):
    def test_authentication_limit_is_defined_and_enforced(self):
        source = (ROOT / "DnsServerCore/Auth/AuthManager.cs").read_text(encoding="utf-8")
        self.assertIn("const int MAX_LOGIN_ATTEMPTS = 5;", source)
        self.assertIn("const int BLOCK_NETWORK_INTERVAL = 5 * 60 * 1000;", source)
        self.assertIn("if (IsNetworkBlocked(network))", source)
        self.assertIn("MarkFailedLoginAttempt(network);", source)
        self.assertIn("BlockNetwork(network, BLOCK_NETWORK_INTERVAL);", source)

    def test_negative_requests_are_only_in_network_disabled_disposable_smoke(self):
        runtime = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        helper = (ROOT / "tests/smoke_login_lockout.pl").read_text(encoding="utf-8")
        self.assertIn("--network=none", runtime)
        self.assertIn("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1", runtime)
        self.assertIn("perl /work/smoke_auth_session.pl\nperl /work/smoke_login_lockout.pl", runtime)
        self.assertIn("127.0.0.1:5380", helper)
        self.assertIn("for my $attempt (1..5)", helper)
        self.assertIn("pass@/work/admin-password", helper)
        self.assertIn("Max limit of 5 attempts exceeded", helper)
        self.assertNotIn("https://", helper)

    def test_ci_checks_helper_syntax(self):
        workflow = (ROOT / ".github/workflows/goreecloud-static-checks.yml").read_text(encoding="utf-8")
        self.assertIn("perl -c tests/smoke_login_lockout.pl", workflow)


if __name__ == "__main__":
    unittest.main()
