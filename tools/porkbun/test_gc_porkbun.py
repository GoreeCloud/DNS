#!/usr/bin/env python3
"""Offline tests for the GoreeCloud Porkbun API wrapper.

Do not access the network, real credentials, or live DNS records.
"""
import importlib.machinery
import importlib.util
import io
import pathlib
import sys
import types
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).with_name("gc-porkbun")
loader = importlib.machinery.SourceFileLoader("gc_porkbun", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
client = importlib.util.module_from_spec(spec)
loader.exec_module(client)


class PorkbunCliTests(unittest.TestCase):
    def setUp(self):
        self.zone = {"records": [
            {"id": "123", "name": "www", "type": "A", "content": "192.0.2.15"},
            {"id": "456", "name": "mail", "type": "MX", "content": "mail.example.net"},
        ]}
        self.good_preflight = {
            "status": "SUCCESS", "safe": True,
            "checks": [{"id": "nameservers-ours", "ok": True},
                       {"id": "spf-lookups", "ok": True}],
            "blockers": [], "warnings": [],
        }

    def test_fingerprint_stable_when_record_order_changes(self):
        reverse = {"records": list(reversed(self.zone["records"]))}
        self.assertEqual(client.zone_fingerprint(self.zone), client.zone_fingerprint(reverse))

    def test_fingerprint_detects_value_change(self):
        changed = {"records": [dict(x) for x in self.zone["records"]]}
        changed["records"][0]["content"] = "192.0.2.99"
        self.assertNotEqual(client.zone_fingerprint(self.zone), client.zone_fingerprint(changed))

    def test_missing_zone_rejected(self):
        with self.assertRaises(SystemExit):
            client.zone_fingerprint({"status": "SUCCESS"})

    def test_good_preflight(self):
        with mock.patch.object(client, "api", return_value=self.good_preflight):
            self.assertTrue(client.preflight()["safe"])

    def test_unsafe_preflight_blocks(self):
        for variation in (
            {"safe": False},
            {"warnings": ["Delegation differs"]},
            {"blockers": ["Unsafe"]},
            {"checks": [{"id": "nameservers-ours", "ok": False}]},
            {"checks": [{"id": "different", "ok": True}]},
        ):
            with self.subTest(variation=variation):
                response = dict(self.good_preflight, **variation)
                with mock.patch.object(client, "api", return_value=response):
                    with self.assertRaises(SystemExit):
                        client.preflight()

    def test_redirects_rejected(self):
        handler = client.RefuseRedirects()
        with self.assertRaises(SystemExit):
            handler.redirect_request(None, None, 302, "redirect", {}, "https://attacker.example/")

    def test_preview_only_does_not_write(self):
        args = types.SimpleNamespace(mode="preview", action="create", record_id=None, payload="unused")
        with mock.patch.object(client, "load_payload", return_value={"name": "preview", "type": "TXT", "content": "safe"}), \
             mock.patch.object(client, "preflight", return_value=self.good_preflight), \
             mock.patch.object(client, "get_zone", side_effect=[self.zone, self.zone]) as get_zone, \
             mock.patch.object(client, "api", return_value={"status": "SUCCESS", "wouldSucceed": True}) as api, \
             mock.patch.object(client, "backup_zone") as backup:
            client.safe_dns_write(args)
            self.assertEqual(api.call_count, 1)
            self.assertTrue(api.call_args.args[2]["dryRun"])
            self.assertEqual(get_zone.call_count, 2)
            backup.assert_not_called()

    def test_preview_warnings_rejected(self):
        args = types.SimpleNamespace(mode="preview", action="create", record_id=None, payload="unused")
        with mock.patch.object(client, "load_payload", return_value={"name": "preview", "type": "TXT", "content": "safe"}), \
             mock.patch.object(client, "preflight", return_value=self.good_preflight), \
             mock.patch.object(client, "get_zone", return_value=self.zone), \
             mock.patch.object(client, "api", return_value={"status": "SUCCESS", "wouldSucceed": True, "warnings": ["bad"]}) as api:
            with self.assertRaises(SystemExit):
                client.safe_dns_write(args)
            self.assertEqual(api.call_count, 1)

    def test_preview_detects_concurrent_zone_change(self):
        args = types.SimpleNamespace(mode="preview", action="create", record_id=None, payload="unused")
        changed = {"records": [dict(x) for x in self.zone["records"]]}
        changed["records"][0]["content"] = "192.0.2.98"
        with mock.patch.object(client, "load_payload", return_value={"name": "preview", "type": "TXT", "content": "safe"}), \
             mock.patch.object(client, "preflight", return_value=self.good_preflight), \
             mock.patch.object(client, "get_zone", side_effect=[self.zone, changed]), \
             mock.patch.object(client, "api", return_value={"status": "SUCCESS", "wouldSucceed": True}) as api:
            with self.assertRaises(SystemExit):
                client.safe_dns_write(args)
            self.assertEqual(api.call_count, 1)

    def test_apply_refuses_noninteractive_without_live_write(self):
        args = types.SimpleNamespace(mode="apply", action="create", record_id=None, payload="unused")
        with mock.patch.object(client, "load_payload", return_value={"name": "preview", "type": "TXT", "content": "safe"}), \
             mock.patch.object(client, "preflight", return_value=self.good_preflight), \
             mock.patch.object(client, "get_zone", side_effect=[self.zone, self.zone]), \
             mock.patch.object(client, "api", return_value={"status": "SUCCESS", "wouldSucceed": True}) as api, \
             mock.patch.object(client, "backup_zone") as backup, \
             mock.patch.object(client.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(SystemExit):
                client.safe_dns_write(args)
            self.assertEqual(api.call_count, 1)
            backup.assert_called_once()

    def test_protected_record_rejected(self):
        args = types.SimpleNamespace(mode="preview", action="delete", record_id="123", payload=None)
        bad = {"records": [{"id": "123", "type": "NS", "name": "", "content": "ns1.example.net"}]}
        with mock.patch.object(client, "preflight", return_value=self.good_preflight), \
             mock.patch.object(client, "get_zone", return_value=bad), \
             mock.patch.object(client, "api") as api:
            with self.assertRaises(SystemExit):
                client.safe_dns_write(args)
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
