"""Source contracts for opt-in, network-isolated DoH/DoT TLS smoke tests."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EncryptedDnsSmokeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        cls.auth = (ROOT / "tests/smoke_auth_session.pl").read_text(encoding="utf-8")
        cls.doh = (ROOT / "tests/smoke_doh_tls.pl").read_text(encoding="utf-8")
        cls.dot = (ROOT / "tests/smoke_dot_tls.pl").read_text(encoding="utf-8")

    def test_isolated_disposable_transport_scope(self):
        self.assertIn("--network=none", self.harness)
        self.assertIn("--security-opt=no-new-privileges", self.harness)
        self.assertIn("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1", self.harness)
        self.assertIn("smoke_doh_tls.pl", self.harness)
        self.assertIn("smoke_dot_tls.pl", self.harness)
        self.assertIn("smoke_doh_tls.pl', $header_path", self.auth)
        self.assertIn("smoke_dot_tls.pl", self.auth)
        self.assertNotIn("--network=host", self.harness)

    def test_doh_requires_verified_tls_and_exact_dns_answers(self):
        self.assertIn("dnsOverHttpsPort=18443", self.doh)
        self.assertIn("enableDnsOverHttps=true", self.doh)
        self.assertIn("dnsTlsCertificatePassword@/work/doh-pfx-password", self.doh)
        self.assertIn("'--cacert'", self.doh)
        self.assertIn("https://localhost:18443/dns-query", self.doh)
        self.assertIn("'--data-binary'", self.doh)
        self.assertIn("'--get'", self.doh)
        self.assertIn("application/dns-message", self.doh)
        self.assertIn("wrong-host.invalid:18443:127.0.0.1", self.doh)
        self.assertIn("pack('C4', 192, 0, 2, 42)", self.doh)
        self.assertNotIn("'--insecure'", self.doh)
        self.assertNotIn("'-k'", self.doh)

    def test_doh_rejects_wrong_echoed_question_and_truncated_response(self):
        self.assertIn("my $expected_question = substr($query, 12);", self.doh)
        self.assertIn("my $actual_question = substr($wire, 12, $offset - 12);", self.doh)
        self.assertIn("$actual_question eq $expected_question", self.doh)
        self.assertIn("$owner_matches_query && $type == 1", self.doh)
        self.assertIn("$owner_wire eq pack('C2', 0xc0, 12)", self.doh)
        self.assertIn("($flags & 0x7800) == 0", self.doh)
        self.assertIn("($flags & 0x0200) == 0", self.doh)

    def test_doh_rejects_bad_requests_without_disabling_valid_queries(self):
        self.assertIn("expect_http_error('doh-missing-dns', 400)", self.doh)
        self.assertIn("expect_http_error('doh-invalid-dns-base64', 400", self.doh)
        self.assertIn("expect_http_error('doh-invalid-post-media', 415", self.doh)
        self.assertIn("'Content-Type: text/plain'", self.doh)
        self.assertIn("run_doh('doh-valid-after-errors', 'POST')", self.doh)
        self.assertIn("check_response('doh-valid-after-errors')", self.doh)

    def test_dot_requires_hostname_validation_and_framed_dns(self):
        self.assertIn("enableDnsOverTls=true", self.doh)
        self.assertIn("dnsOverTlsPort=1853", self.doh)
        self.assertIn("use IPC::Open2;", self.dot)
        self.assertIn("'-verify_return_error'", self.dot)
        self.assertIn("'-verify_hostname'", self.dot)
        self.assertIn("pack('n', length($query))", self.dot)
        self.assertIn("wrong-host.invalid", self.dot)
        self.assertIn("pack('C4', 192, 0, 2, 42)", self.dot)
        self.assertNotIn("'-k'", self.dot)

    def test_ci_syntax_checks_both_tls_helpers(self):
        ci = (ROOT / ".github/workflows/goreecloud-static-checks.yml").read_text(encoding="utf-8")
        self.assertIn("perl -c tests/smoke_doh_tls.pl", ci)
        self.assertIn("perl -c tests/smoke_dot_tls.pl", ci)


if __name__ == "__main__":
    unittest.main()
