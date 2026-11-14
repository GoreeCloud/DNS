"""Fail-closed DNS authoritative/recursive dispatch acceptance scope.

Pinned source review contract, not a live DNS test. A separate synthetic
rootless runtime run demonstrated non-enforcement on a local authoritative A
record and successful client-specific handling on forwarded DNS responses.
"""
import hashlib
import unittest
from pathlib import Path

DNS_CORE_BLOB = "315c9da00051e43b7412759d1e694423b971dc9e"
CORE_PATH = Path(__file__).resolve().parents[1] / "DnsServerCore/Dns/DnsServer.cs"


def reviewed_source():
    raw = CORE_PATH.read_bytes()
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if digest != DNS_CORE_BLOB:
        raise AssertionError("DNS dispatch source changed; re-qualify policy paths")
    return raw.decode("utf-8-sig")


def fragment(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise AssertionError("DNS source method boundary changed")
    left, right = text.index(start), text.index(end)
    if right <= left:
        raise AssertionError("DNS source method order changed")
    return text[left:right]


class ReviewedDnsDispatchContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = reviewed_source()
        cls.dispatch = fragment(cls.text,
            "private async Task<DnsDatagram> ProcessQueryAsync(",
            "private async Task<DnsDatagram> ProcessNotifyQueryAsync(")
        cls.authoritative = fragment(cls.text,
            "private async Task<DnsDatagram> ProcessAuthoritativeQueryAsync(",
            "private async Task<bool> IsAllowedAsync(")
        cls.allow = fragment(cls.text,
            "private async Task<bool> IsAllowedAsync(",
            "private async Task<DnsDatagram> ProcessBlockedQueryAsync(")
        cls.block = fragment(cls.text,
            "private async Task<DnsDatagram> ProcessBlockedQueryAsync(",
            "private async Task<DnsDatagram> ProcessRecursiveQueryAsync(")
        cls.recursive = cls.text.split(
            "private async Task<DnsDatagram> ProcessRecursiveQueryAsync(", 1)[1][:2500]

    def test_exact_source_reviewed(self):
        self.assertEqual(reviewed_source(), self.text)

    def test_authoritative_branch_runs_first(self):
        self.assertLess(self.dispatch.index("await ProcessAuthoritativeQueryAsync("),
                        self.dispatch.index("await ProcessRecursiveQueryAsync("))

    def test_authoritative_nonnull_response_returns_before_recursive(self):
        after = self.dispatch.split("await ProcessAuthoritativeQueryAsync(", 1)[1]
        before_recursion = after.split("if (!request.RecursionDesired || !isRecursionAllowed)", 1)[0]
        self.assertIn("if (response is not null)", before_recursion)
        self.assertIn("return response;", before_recursion)

    def test_recursive_fallback_requires_recursion_allowed(self):
        self.assertIn("if (!request.RecursionDesired || !isRecursionAllowed)", self.dispatch)
        self.assertIn("return await ProcessRecursiveQueryAsync(", self.dispatch)

    def test_recursive_path_invokes_policy_allow(self):
        self.assertIn("await IsAllowedAsync(request, remoteEP, protocol)", self.recursive)

    def test_recursive_path_invokes_policy_block(self):
        self.assertIn("await ProcessBlockedQueryAsync(request, remoteEP, protocol)", self.recursive)

    def test_app_handler_allow_invoked(self):
        self.assertIn("blockingHandler.IsAllowedAsync(request, remoteEP)", self.allow)

    def test_app_handler_block_invoked(self):
        self.assertIn("blockingHandler.ProcessRequestAsync(request, remoteEP)", self.block)

    def test_direct_authoritative_response_has_no_direct_block_handler(self):
        self.assertNotIn("blockingHandler.ProcessRequestAsync(", self.authoritative)
        self.assertNotIn("await ProcessBlockedQueryAsync(", self.authoritative)

    def test_authoritative_referral_may_enter_recursive_path(self):
        self.assertIn("DnsResourceRecordType.NS:", self.authoritative)
        self.assertIn("DnsResourceRecordType.FWD:", self.authoritative)
        self.assertIn("await ProcessRecursiveQueryAsync(", self.authoritative)

    def test_not_a_dnssec_equivalence_claim(self):
        self.assertIn("dnssecValidation", self.recursive)
        self.assertIn("await RecursiveResolveAsync(", self.recursive)


if __name__ == "__main__":
    unittest.main()
