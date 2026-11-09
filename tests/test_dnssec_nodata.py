"""Synthetic, mathematically signed NSEC AAAA NODATA proof; no trust anchor."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

HAS_CRYPTO = all(importlib.util.find_spec(x) for x in ("dns", "cryptography"))


@unittest.skipUnless(HAS_CRYPTO, "optional offline DNSSEC crypto dependencies")
class OfflineSignedNodataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import dns.dnssec
        import dns.name
        import dns.rdata
        import dns.rdataclass
        import dns.rdatatype
        import dns.rrset
        from cryptography.hazmat.primitives.asymmetric import ec
        cls.zone = dns.name.from_text("smoke.invalid.")
        cls.host = dns.name.from_text("host.smoke.invalid.")
        cls.priv = ec.generate_private_key(ec.SECP256R1())
        cls.dnskey = dns.dnssec.make_dnskey(cls.priv.public_key(), "ECDSAP256SHA256")
        cls.keys = dns.rrset.from_rdata(cls.zone, 300, cls.dnskey)
        cls.key_sig = dns.dnssec.sign(cls.keys, cls.priv, cls.zone, cls.dnskey,
                                      lifetime=3600)
        cls.nsec = dns.rrset.from_text(
            str(cls.host), 300, "IN", "NSEC",
            "next.smoke.invalid. A RRSIG NSEC"
        )
        cls.nsec_sig = dns.dnssec.sign(cls.nsec, cls.priv, cls.zone, cls.dnskey,
                                       lifetime=3600)

    def response(self, kind, *, nsec=None, sign=None, rcode=None, owner=None):
        import dns.message
        import dns.flags
        import dns.rcode
        import dns.rdatatype
        import dns.rrset
        qname = (self.zone if kind == "dnskey" else self.host) if owner is None else owner
        qtype = dns.rdatatype.DNSKEY if kind == "dnskey" else dns.rdatatype.AAAA
        request = dns.message.make_query(qname, qtype, want_dnssec=True)
        reply = dns.message.make_response(request)
        reply.flags |= dns.flags.AA
        reply.use_edns(edns=0, ednsflags=dns.flags.DO)
        if rcode is not None:
            reply.set_rcode(rcode)
        if kind == "dnskey":
            reply.answer.extend([
                self.keys,
                dns.rrset.from_rdata(self.zone, 300, self.key_sig),
            ])
        else:
            reply.authority.extend([
                self.nsec if nsec is None else nsec,
                dns.rrset.from_rdata(self.host, 300,
                                    self.nsec_sig if sign is None else sign),
            ])
        return reply.to_wire()

    def bundles(self):
        return (
            {t: self.response("dnskey") for t in ("udp", "tcp")},
            {t: self.response("nodata") for t in ("udp", "tcp")},
        )

    def verify(self, keys=None, nodata=None, **kw):
        from verify_dnssec_nodata import verify_nodata_bundle
        k, n = self.bundles()
        return verify_nodata_bundle(k if keys is None else keys,
                                   n if nodata is None else nodata, **kw)

    def test_exact_owner_nsec_signature_and_type_absence_pass(self):
        result = self.verify()
        self.assertTrue(result["exact_owner_aaaa_nodata_proved_by_nsec"])
        self.assertTrue(result["udp_nsec_mathematical_signature_verified"])
        self.assertTrue(result["tcp_nsec_mathematical_signature_verified"])
        self.assertFalse(result["external_trust_anchor_verified"])
        self.assertFalse(result["nxdomain_and_wildcard_denial_verified"])
        self.assertFalse(result["production_dnssec_ready"])

    def test_modified_nsec_bitmap_fails_even_when_record_present(self):
        import dns.rrset
        _, packets = self.bundles()
        malicious = dns.rrset.from_text(
            str(self.host), 300, "IN", "NSEC",
            "next.smoke.invalid. A AAAA RRSIG NSEC"
        )
        packets["udp"] = self.response("nodata", nsec=malicious)
        with self.assertRaises(ValueError):
            self.verify(nodata=packets)

    def test_wrong_owner_and_nxdomain_are_not_nodata(self):
        import dns.name
        import dns.rcode
        _, packets = self.bundles()
        packets["tcp"] = self.response("nodata", rcode=dns.rcode.NXDOMAIN)
        with self.assertRaises(ValueError):
            self.verify(nodata=packets)
        packets["tcp"] = self.response(
            "nodata", owner=dns.name.from_text("unknown.smoke.invalid.")
        )
        with self.assertRaises(ValueError):
            self.verify(nodata=packets)

    def test_modified_signing_key_fails_nsec_signature(self):
        import dns.dnssec
        import dns.rrset
        from cryptography.hazmat.primitives.asymmetric import ec
        _, packets = self.bundles()
        other = ec.generate_private_key(ec.SECP256R1())
        other_dnskey = dns.dnssec.make_dnskey(other.public_key(), "ECDSAP256SHA256")
        bad_sig = dns.dnssec.sign(self.nsec, other, self.zone, other_dnskey,
                                  lifetime=3600)
        packets["udp"] = self.response("nodata", sign=bad_sig)
        with self.assertRaises(ValueError):
            self.verify(nodata=packets)

    def test_expired_signature_and_missing_packet_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(now=4102444800)
        keys, packets = self.bundles()
        del packets["udp"]
        with self.assertRaises(ValueError):
            self.verify(keys=keys, nodata=packets)

    def test_command_line_redaction_and_protected_file_requirement(self):
        from verify_dnssec_nodata import main
        keys, packets = self.bundles()
        with tempfile.TemporaryDirectory() as folder:
            paths = []
            for data in (keys["udp"], keys["tcp"], packets["udp"], packets["tcp"]):
                path = Path(folder) / f"private-packet-{len(paths)}.bin"
                path.write_bytes(data)
                path.chmod(0o600)
                paths.append(path)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(p) for p in paths]), 0)
            self.assertTrue(json.loads(output.getvalue())
                            ["exact_owner_aaaa_nodata_proved_by_nsec"])
            paths[-1].chmod(0o644)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(p) for p in paths]), 1)
            self.assertNotIn(folder, output.getvalue())
            self.assertFalse(json.loads(output.getvalue())["production_dnssec_ready"])


class OfflineNodataContractTests(unittest.TestCase):
    def test_runtime_is_only_isolated_offline_and_explicitly_narrow(self):
        root = Path(__file__).resolve().parents[1] / "tests"
        runtime = (root / "smoke_runtime.sh").read_text()
        perl = (root / "smoke_dnssec_nodata.pl").read_text()
        helper = (root / "verify_dnssec_nodata.py").read_text()
        self.assertIn("--network=none", runtime)
        self.assertIn("verify_dnssec_nodata.py", runtime)
        self.assertIn("smoke_dnssec_nodata.pl", runtime)
        self.assertIn("AAAA", perl)
        self.assertIn("dns.dnssec.validate", helper)
        self.assertIn("nxdomain_and_wildcard_denial_verified", helper)
        workflow = (root.parent / ".github/workflows/goreecloud-static-checks.yml").read_text()
        self.assertIn("perl -c tests/smoke_dnssec_nodata.pl", workflow)


if __name__ == "__main__":
    unittest.main()
