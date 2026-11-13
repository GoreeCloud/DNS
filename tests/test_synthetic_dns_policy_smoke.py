"""Static, host-safe contracts for opt-in synthetic DNS policy probes.

This module never starts DNS, opens network connections or runs a container.
The two Perl probes refuse to run outside an isolated disposable test.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "tests" / "smoke_synthetic_filter_client_policy.pl"
LISTS = ROOT / "tests" / "smoke_synthetic_blocklist_subscriptions.pl"


class SyntheticPolicyContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = POLICY.read_text(encoding="utf-8")
        cls.lists = LISTS.read_text(encoding="utf-8")

    def test_perl_syntax_only(self):
        if shutil.which("perl") is None:
            self.skipTest("Perl is not installed")
        for program in (POLICY, LISTS):
            with self.subTest(program=program.name):
                result = subprocess.run(
                    ["perl", "-c", str(program)],
                    capture_output=True, text=True, timeout=7, check=False
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_host_execution_rejected_before_api_access(self):
        if shutil.which("perl") is None:
            self.skipTest("Perl is not installed")
        for program in (POLICY, LISTS):
            with self.subTest(program=program.name):
                result = subprocess.run(
                    ["perl", str(program), "/work/session-header"],
                    capture_output=True, text=True, timeout=5, check=False
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "requires disposable rootless container", result.stderr
                )

    def test_fail_closed_isolation(self):
        for program in (self.policy, self.lists):
            with self.subTest(script=program[:38]):
                self.assertIn("$> == 1654", program)
                self.assertIn("'/work/admin-password'", program)
                self.assertIn("'/run/.containerenv'", program)
                self.assertIn("'/sys/class/net'", program)
                self.assertIn("@interfaces == 1", program)
                self.assertIn("$interfaces[0] eq 'lo'", program)
                self.assertIn("requires network namespace containing loopback only", program)

    def test_ephemeral_authorization_only(self):
        for program in (self.policy, self.lists):
            self.assertIn("'/work/session-header'", program)
            self.assertIn("'--header','@'.$header", program)
            self.assertIn("http://127.0.0.1:5380", program)
            self.assertNotIn("Authorization: Bearer ", program)
            self.assertNotIn("pass=admin", program)

    def test_only_loopback_api_urls(self):
        for program in (self.policy, self.lists):
            urls = re.findall(r"https?://[^\s\'\"<>]+", program)
            self.assertTrue(urls)
            for url in urls:
                self.assertTrue(
                    url.startswith("http://127.0.0.1:"),
                    f"non-loopback URL present in synthetic probe: {url}"
                )
            self.assertNotIn("--insecure", program)
            self.assertNotIn("--network=host", program)

    def test_synthetic_reserved_names_only(self):
        for program in (self.policy, self.lists):
            self.assertIn(".example", program)
            self.assertNotIn("goreecloud.com", program)
            self.assertNotIn("adguard.com", program)
            self.assertNotIn("8.8.8.8", program)
        self.assertIn("'127.0.0.2'", self.policy)
        self.assertIn("'127.0.0.3'", self.policy)

    def test_explicit_blocked_address_not_nxdomain_only(self):
        self.assertIn("blockingType=AnyAddress", self.policy)
        self.assertIn("0\\.0\\.0\\.0", self.policy)
        self.assertIn("synthetic name blocked before policy creation", self.policy)
        self.assertIn("synthetic allow exception", self.policy)
        self.assertIn("bypass", self.policy.lower())
        self.assertNotIn("eq 'NXDOMAIN'", self.policy)

    def test_three_manual_blocks_and_both_transports(self):
        self.assertIn("for my $i (1..3)", self.policy)
        self.assertIn("for my $tcp (0,1)", self.policy)
        self.assertIn("'/api/blocked/add'", self.policy)
        self.assertIn("'/api/allowed/add'", self.policy)
        self.assertIn("blockingBypassList=127.0.0.2", self.policy)

    def test_ten_enabled_two_disabled_lists(self):
        self.assertIn("(1..10)", self.lists)
        self.assertIn("(11..12)", self.lists)
        self.assertIn("blockListUrls=", self.lists)
        self.assertIn("'/api/settings/forceUpdateBlockLists'", self.lists)
        self.assertIn("for my $i (1..10)", self.lists)
        self.assertIn("for my $i (11..12)", self.lists)
        self.assertIn("push @cmd,'+tcp' if $tcp;", self.lists)

    def test_local_only_list_fetcher_and_safe_cleanup(self):
        self.assertIn("LocalAddr=>'127.0.0.1'", self.lists)
        self.assertIn("my $listen_port=18081", self.lists)
        self.assertIn("HTTP/1.1 200 OK", self.lists)
        self.assertIn("HTTP/1.1 404 Not Found", self.lists)
        self.assertIn("END {", self.lists)
        self.assertIn("local $?;", self.lists)
        self.assertIn("waitpid($pid,0)", self.lists)
        self.assertIn("Content-Length:", self.lists)

    def test_failures_are_not_silenced(self):
        for program in (self.policy, self.lists):
            self.assertIn("or die", program)
            self.assertNotIn("|| true", program)
            self.assertNotIn("rm -rf", program)
            self.assertNotIn("system('sudo'", program)
            self.assertNotIn("127.0.0.1:443", program)


if __name__ == "__main__":
    unittest.main()
