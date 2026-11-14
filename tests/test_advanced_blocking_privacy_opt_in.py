"""Static, no-network privacy guard for GoreeCloud's Advanced Blocking draft.

This checks a proposed default and bundled sample, not installed DNS behavior.
Actual TXT/EDNS packet privacy needs a separate isolated runtime test.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "Apps/AdvancedBlockingApp/App.cs"
SAMPLE = ROOT / "Apps/AdvancedBlockingApp/dnsApp.config"
README = ROOT / "Apps/AdvancedBlockingApp/README.md"


class AdvancedBlockingPrivacyOptInContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SRC.read_text(encoding="utf-8-sig")
        cls.sample_text = SAMPLE.read_text(encoding="utf-8")
        cls.sample = json.loads(cls.sample_text)
        cls.docs = README.read_text(encoding="utf-8")

    def test_group_omission_defaults_not_disclosing(self):
        self.assertEqual(
            self.code.count('GetPropertyValue("allowTxtBlockingReport", false)'), 1
        )

    def test_no_default_true_fallback(self):
        self.assertNotIn('GetPropertyValue("allowTxtBlockingReport", true)', self.code)

    def test_group_has_stored_opt_in_field(self):
        self.assertIn('readonly bool _allowTxtBlockingReport;', self.code)
        self.assertIn('public bool AllowTxtBlockingReport', self.code)

    def test_blocking_txt_report_requires_explicit_group_flag(self):
        self.assertIn(
            'if (group.AllowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))',
            self.code
        )

    def test_blocking_edns_report_requires_explicit_group_flag(self):
        self.assertIn(
            'if (group.AllowTxtBlockingReport && (request.EDNS is not null))',
            self.code
        )

    def test_blocking_report_contains_group_and_list_context(self):
        self.assertIn('"source=advanced-blocking-app; group=" + group.Name', self.code)
        self.assertIn('GetBlockingReport()', self.code)

    def test_sample_json_valid(self):
        self.assertIsInstance(self.sample, dict)
        self.assertIsInstance(self.sample.get("groups"), list)

    def test_sample_groups_nonempty(self):
        self.assertGreaterEqual(len(self.sample["groups"]), 2)

    def test_sample_groups_opt_out_explicitly(self):
        for group in self.sample["groups"]:
            with self.subTest(group=group.get("name", "unnamed")):
                self.assertIn("allowTxtBlockingReport", group)
                self.assertIs(group["allowTxtBlockingReport"], False)

    def test_sample_document_has_no_true_flag(self):
        self.assertNotRegex(self.sample_text, r'"allowTxtBlockingReport"\s*:\s*true')

    def test_documentation_reports_default_false(self):
        self.assertIn('| `allowTxtBlockingReport` | boolean | `false`', self.docs)
        self.assertIn('missing `allowTxtBlockingReport` now defaults', self.docs)

    def test_documentation_preserves_explicit_true_opt_in(self):
        self.assertIn('explicitly set to `true`', self.docs)
        self.assertIn('unmerged development proposal', self.docs)

    def test_upstream_license_header_retained(self):
        self.assertIn('Copyright (C) 2026  Shreyas Zare', self.code)
        self.assertIn('GNU General Public License', self.code)

    def test_no_claim_of_production_enforcement(self):
        self.assertNotIn('production_cutover_authorized=true', self.docs)
        self.assertNotIn('production_policy_parity_verified=true', self.docs)


if __name__ == "__main__":
    unittest.main()
