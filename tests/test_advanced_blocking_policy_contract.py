"""Host-safe unit tests for an inert, intentionally incomplete DNS policy fixture."""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts" / "validate_synthetic_advanced_policy.py"
SPEC = importlib.util.spec_from_file_location("advanced_contract", PATH)
assert SPEC and SPEC.loader
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


class AdvancedSyntheticPolicyTests(unittest.TestCase):
    def setUp(self):
        self.doc = copy.deepcopy(contract.load_inert_fixture())

    def reject(self, name="invalid"):
        with self.assertRaises(contract.ContractError) as caught:
            contract.validate_synthetic_config(self.doc)
        self.assertNotIn("SECRET_CLIENT", str(caught.exception))
        self.assertNotIn("SECRET_URL", str(caught.exception))

    def test_fixture_valid_and_no_release_claim(self):
        result = contract.validate_synthetic_config(self.doc)
        self.assertEqual(result["status"], "STATIC_SYNTHETIC_CONTRACT_PASS")
        self.assertEqual(result["group_count"], 2)
        self.assertEqual(result["client_selector_count"], 2)
        self.assertFalse(result["app_runtime_tested"])
        self.assertFalse(result["production_parity_verified"])
        self.assertFalse(result["cutover_authorized"])

    def test_supported_capability_is_only_static_group_contract(self):
        self.assertTrue(contract.require_capabilities(["per_client_domain_blocking_contract"]))

    def test_unsupported_critical_capabilities_fail_closed(self):
        for capability in contract.UNVERIFIED:
            with self.subTest(capability=capability):
                with self.assertRaises(contract.ContractError):
                    contract.require_capabilities([capability])
        with self.assertRaises(contract.ContractError):
            contract.require_capabilities(["per_client_domain_blocking_contract", "safe_browsing"])

    def test_empty_capability_or_nonlist_fails(self):
        for request in ([], None, "per_client_domain_blocking_contract", [3]):
            with self.subTest(request=repr(request)):
                with self.assertRaises(contract.ContractError):
                    contract.require_capabilities(request)

    def test_disallows_unrecognized_and_implied_parental_flags(self):
        for key in ("parentalEnabled", "safeBrowsingEnabled", "adguardImportantPrecedence", "clientProfiles"):
            with self.subTest(key=key):
                self.doc[key] = True
                self.reject()
                self.doc.pop(key)

    def test_disallows_disabling_master_blocking(self):
        self.doc["enableBlocking"] = False
        self.reject()

    def test_disallows_boolean_ttl_as_number(self):
        self.doc["blockingAnswerTtl"] = True
        self.reject()

    def test_disallows_out_of_bounds_ttl(self):
        for ttl in (-1, 301, 10000000):
            with self.subTest(ttl=ttl):
                self.doc["blockingAnswerTtl"] = ttl
                self.reject()

    def test_disallows_policy_refresh_change(self):
        self.doc["blockListUrlUpdateIntervalMinutes"] = 1
        self.reject()

    def test_disallows_endpoint_override(self):
        self.doc["localEndPointGroupMap"] = {"127.0.0.1": "bypass"}
        self.reject()

    def test_disallows_private_real_world_addresses(self):
        self.doc["networkGroupMap"] = {"192.168.1.50": "filtered", "127.0.0.2": "bypass"}
        self.reject()

    def test_disallows_broad_network_catchall(self):
        self.doc["networkGroupMap"] = {"0.0.0.0/0": "filtered", "::/0": "bypass"}
        self.reject()

    def test_disallows_swapped_client_group_binding(self):
        self.doc["networkGroupMap"]["127.0.0.2"] = "filtered"
        self.reject()

    def test_disallows_missing_group(self):
        self.doc["groups"] = self.doc["groups"][:1]
        self.reject()

    def test_disallows_duplicate_group(self):
        self.doc["groups"][1]["name"] = "filtered"
        self.reject()

    def test_disallows_unknown_group(self):
        self.doc["groups"][0]["name"] = "kids"
        self.reject()

    def test_disallows_group_switch_flip(self):
        self.doc["groups"][0]["enableBlocking"] = False
        self.reject()

    def test_disallows_silent_bypass_turned_on(self):
        self.doc["groups"][1]["enableBlocking"] = True
        self.reject()

    def test_disallows_blocking_metadata_leaks(self):
        for g in self.doc["groups"]:
            with self.subTest(name=g["name"]):
                g["allowTxtBlockingReport"] = True
                self.reject()
                g["allowTxtBlockingReport"] = False

    def test_disallows_missing_metadata_flag(self):
        self.doc["groups"][0].pop("allowTxtBlockingReport")
        self.reject()

    def test_disallows_external_lists(self):
        self.doc["groups"][0]["blockListUrls"] = ["https://SECRET_URL.example/list.txt"]
        self.reject()

    def test_disallows_production_rule_domains(self):
        self.doc["groups"][0]["blocked"] = ["SECRET_CLIENT.example.com"]
        self.reject()

    def test_disallows_undocumented_allow_exceptions(self):
        self.doc["groups"][0]["allowed"] = ["policy-block-1.example"]
        self.reject()

    def test_disallows_unknown_group_properties(self):
        self.doc["groups"][0]["safebrowsing"] = True
        self.reject()

    def test_disallows_block_type_drift(self):
        self.doc["groups"][0]["blockAsNxDomain"] = True
        self.reject()

    def test_disallows_block_address_drift(self):
        self.doc["groups"][0]["blockingAddresses"] = ["192.0.2.10"]
        self.reject()

    def test_rejects_duplicate_json_fields(self):
        with self.assertRaises(contract.ContractError):
            json.loads('{"enableBlocking":true,"enableBlocking":false}',
                       object_pairs_hook=contract._no_duplicate_keys)

    def test_fixture_size_limit(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "synthetic_advanced_blocking_policy.json"
            source.write_bytes(b"x" * 33000)
            with patch.object(contract, "FIXTURE", source):
                with self.assertRaises(contract.ContractError):
                    contract.load_inert_fixture()

    def test_refuses_symlink_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "private"
            target.write_text("{}")
            link = Path(td) / "fixture"
            link.symlink_to(target)
            with patch.object(contract, "FIXTURE", link):
                with self.assertRaises(contract.ContractError):
                    contract.load_inert_fixture()

    def test_cli_rejects_arbitrary_config_argument(self):
        p = subprocess.run([sys.executable, str(PATH), "/etc/real/private/dnsApp.config"],
                           text=True, capture_output=True, timeout=5)
        self.assertEqual(p.returncode, 3)
        self.assertIn("static fixture only", p.stderr)
        self.assertNotIn("real/private", p.stderr)

    def test_cli_output_has_only_static_status(self):
        p = subprocess.run([sys.executable, str(PATH)],
                           text=True, capture_output=True, timeout=5)
        self.assertEqual(p.returncode, 0, p.stderr)
        result = json.loads(p.stdout)
        self.assertFalse(result["app_runtime_tested"])
        self.assertFalse(result["cutover_authorized"])
        self.assertNotIn("127.0.0.", p.stdout)
        self.assertNotIn("policy-block-1.example", p.stdout)

    def test_module_does_not_import_runtime_or_network_tools(self):
        text = PATH.read_text(encoding="utf-8")
        self.assertNotIn("import socket", text)
        self.assertNotIn("import requests", text)
        self.assertNotIn("import subprocess", text)
        self.assertNotIn("os.system", text)
        self.assertNotIn("urlopen", text)

    def test_no_source_user_data_in_fixture(self):
        raw = contract.FIXTURE.read_text("utf-8")
        self.assertNotIn("goreecloud.com", raw)
        self.assertNotIn("adguard.com", raw)
        self.assertNotIn("192.168.", raw)
        self.assertNotIn("https://", raw)
        self.assertNotIn("http://", raw)


if __name__ == "__main__":
    unittest.main()
