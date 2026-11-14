"""Static safety contracts for the opt-in synthetic AdvancedBlockingApp runtime lab.

These checks do not start containers, DNS, external processes, or network access.
The executable runtime harness is opt-in and requires a disposable DNS image.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHELL = ROOT / "tests" / "run_advanced_runtime.sh"
PERL = ROOT / "tests" / "smoke_advanced_runtime.pl"


class AdvancedRuntimeHarnessContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sh = SHELL.read_text(encoding="utf-8")
        cls.perl = PERL.read_text(encoding="utf-8")

    def test_hash_pinned_synthetic_plugin_package(self):
        self.assertIn("AdvancedBlocking-v2.zip", self.sh)
        self.assertIn("sha256sum", self.sh)
        self.assertIn(
            "74dcaad61ec3ab3835d3d56528fc74bb827efe4b9073a7bd51db26c6f68e75b2",
            self.sh
        )
        self.assertIn("synthetic app checksum mismatch", self.sh)

    def test_guarded_nonroot_container_and_loopback(self):
        self.assertIn('[ "$(id -u)" = 1654 ]', self.sh)
        self.assertIn("/sys/class/net/*", self.sh)
        self.assertIn("/sys/class/net/lo", self.sh)
        self.assertIn("external interface", self.sh)
        self.assertIn("$> == 1654", self.perl)
        self.assertIn("'/sys/class/net'", self.perl)
        self.assertIn("@ifs==1 && $ifs[0] eq 'lo'", self.perl)

    def test_ephemeral_files_and_secret_file_auth(self):
        self.assertIn("mkdir /work/config /work/.dotnet", self.sh)
        self.assertIn("umask 077", self.sh)
        self.assertIn("/dev/urandom", self.sh)
        self.assertIn("DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password", self.sh)
        self.assertIn("pass@/work/admin-password", self.perl)
        self.assertIn("chmod 0600,'/work/session-header'", self.perl)
        self.assertIn("undef $login", self.perl)

    def test_runtime_service_is_only_loopback(self):
        self.assertIn("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1", self.sh)
        self.assertIn("DNS_SERVER_RECURSION=Deny", self.sh)
        self.assertIn("--stop-if-bind-fails --portable-app /work/config", self.sh)
        self.assertIn("http://127.0.0.1:5380", self.sh)
        self.assertIn("http://127.0.0.1:5380", self.perl)

    def test_live_service_ownership_untouched(self):
        for script in (self.sh, self.perl):
            for forbidden in ("sudo ", "systemctl ", "iptables ", "nft ", "rm -rf",
                              "ssh ", "scp ", "172.56.", "goreecloud.com"):
                self.assertNotIn(forbidden, script)

    def test_no_nonloopback_domain_requests(self):
        urls = re.findall(r"https?://[^\s'\"<>]+", self.sh + self.perl)
        self.assertTrue(urls)
        for url in urls:
            self.assertTrue(url.startswith("http://127.0.0.1:5380"), url)
        self.assertIn("policy-block-1.example", self.perl)
        self.assertNotIn("8.8.8.8", self.perl)

    def test_exact_app_install_path(self):
        self.assertIn("/api/apps/install?name=AdvancedBlocking", self.perl)
        self.assertIn("file=@/work/AdvancedBlocking.zip", self.perl)
        self.assertIn("AdvancedBlocking.App", self.perl)
        self.assertIn("isRequestBlockingHandler", self.perl)

    def test_built_in_blocking_not_combined(self):
        self.assertIn("enableBlocking=false", self.perl)
        self.assertIn("builtin still enabled", self.perl)
        self.assertIn("built-in blocking disabled only in lab", self.perl)

    def test_two_client_udp_tcp_wire_checks(self):
        self.assertIn("127.0.0.2", self.perl)
        self.assertIn("127.0.0.3", self.perl)
        self.assertIn("for my $tcp(0,1)", self.perl)
        self.assertIn("NOERROR", self.perl)
        self.assertIn("0\\.0\\.0\\.0", self.perl)
        self.assertIn("app per-client wire enforcement", self.perl)

    def test_disposable_forwarder_created_only_on_loopback(self):
        stub = (ROOT / "tests" / "synthetic_offline_dns_upstream.pl").read_text("utf-8")
        self.assertIn("127.0.0.4", stub)
        self.assertIn("5301", stub)
        self.assertIn("192,0,2,53", stub)
        self.assertIn("network egress interface present", stub)
        self.assertIn("synthetic_offline_dns_upstream.pl", self.sh)
        self.assertIn("forwarders=127.0.0.4:5301", self.perl)
        self.assertNotIn("/api/zones/create", self.perl)
        self.assertIn("pre-plugin offline forwarded answer unavailable", self.perl)
        self.assertIn("loopback-forwarded answer", self.perl)

    def test_bypass_requires_successful_local_answer(self):
        self.assertIn("$b->[0] eq 'NOERROR'", self.perl)
        self.assertIn("$b->[3]", self.perl)
        self.assertIn("&& !$b->[1]", self.perl)
        self.assertIn("distinct successful loopback-forwarded UDP and TCP answers", self.perl)

    def test_filtered_and_bypass_records_are_distinct(self):
        self.assertIn("192\\.0\\.2\\.53", self.perl)
        self.assertIn("0\\.0\\.0\\.0", self.perl)
        self.assertIn("$f->[1] && !$f->[3]", self.perl)

    def test_synthetic_upstream_is_killed_on_exit(self):
        self.assertIn('kill "$pid" "$upstream_pid"', self.sh)
        self.assertIn('wait "$pid" "$upstream_pid"', self.sh)
        self.assertIn("DNS_SERVER_RECURSION=Deny", self.sh)
        self.assertIn("forwarderTimeout=1500", self.perl)

    def test_dnssec_validation_disabled_only_in_disposable_lab(self):
        self.assertIn("dnssecValidation=false", self.perl)
        self.assertIn("DNS_SERVER_RECURSION=Deny", self.sh)
        self.assertIn("forwarderProtocol=Udp", self.perl)
        self.assertIn("forwarderTimeout=1500", self.perl)

    def test_upstream_uses_only_reserved_example_name_and_testnet(self):
        stub = (ROOT / "tests" / "synthetic_offline_dns_upstream.pl").read_text("utf-8")
        self.assertIn("policy-block-1.example", stub)
        self.assertIn("192,0,2,53", stub)
        self.assertIn("127.0.0.4", stub)
        self.assertIn("LocalPort=>5301", stub)
        self.assertNotIn("0.0.0.0", stub)
        self.assertNotIn("http://", stub)
        self.assertNotIn("https://", stub)

    def test_forwarder_endpoint_and_cache_safety_checked(self):
        self.assertIn("configured_local_forwarder_match", self.perl)
        self.assertIn("recursion_allow", self.perl)
        self.assertIn("/api/cache/flush", self.perl)
        self.assertIn("offline forwarded answer unavailable", self.perl)

    def test_authoritative_domain_not_used_to_claim_blocking(self):
        self.assertNotIn("/api/zones/create", self.perl)
        self.assertNotIn("/api/zones/records/add", self.perl)
        self.assertIn("distinct successful loopback-forwarded UDP and TCP answers", self.perl)

    def test_privacy_reporting_opt_out_verified(self):
        self.assertIn("allowTxtBlockingReport", self.perl)
        self.assertIn("blocking report enabled", self.perl)
        self.assertIn("source=advanced-blocking-app", self.perl)
        self.assertIn("blocking report leaked", self.perl)
        self.assertIn("TXT/EDNS", self.perl)

    def test_clean_shutdown(self):
        self.assertIn("trap 'kill", self.sh)
        self.assertIn("wait", self.sh)
        self.assertIn("/api/user/logout", self.perl)
        self.assertIn("session logged out", self.perl)

    def test_fail_closed_limits_are_explicit(self):
        self.assertIn("other protections NOT VERIFIED", self.perl)
        self.assertNotIn("production_cutover_authorized=true", self.perl)
        self.assertNotIn("parental_protection_verified=true", self.perl)
        self.assertNotIn("safe_browsing_verified=true", self.perl)
        self.assertIn("die \"FAIL:", self.perl)


if __name__ == "__main__":
    unittest.main()
