"""Mathematical validation using synthetic ephemeral DNSSEC keys, offline only."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

HAS_CRYPTO = all(importlib.util.find_spec(x) for x in ("dns", "cryptography"))


@unittest.skipUnless(HAS_CRYPTO, "optional offline DNSSEC crypto verifier dependencies")
class DNSSECSignatureMathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives.asymmetric import ec
        import dns.dnssec
        import dns.name
        import dns.rrset
        cls.zone = dns.name.from_text("smoke.invalid.")
        cls.host = dns.name.from_text("host.smoke.invalid.")
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.dnskey = dns.dnssec.make_dnskey(cls.key.public_key(), "ECDSAP256SHA256")
        cls.keys_rrset = dns.rrset.from_rdata(cls.zone, 300, cls.dnskey)
        cls.a_rrset = dns.rrset.from_text(
            str(cls.host), 300, "IN", "A", "192.0.2.42"
        )
        cls.signed = {
            48: dns.dnssec.sign(cls.keys_rrset, cls.key, cls.zone, cls.dnskey, lifetime=3600),
            1: dns.dnssec.sign(cls.a_rrset, cls.key, cls.zone, cls.dnskey, lifetime=3600),
        }

    def wire(self, typ, *, owner=None, rrset=None, sig=None):
        import dns.message
        import dns.flags
        import dns.rrset
        expected_owner = self.zone if typ == 48 else self.host
        owner = expected_owner if owner is None else owner
        rrset = (self.keys_rrset if typ == 48 else self.a_rrset) if rrset is None else rrset
        sig = self.signed[typ] if sig is None else sig
        q = dns.message.make_query(owner, typ, want_dnssec=True)
        r = dns.message.make_response(q)
        r.flags |= dns.flags.AA
        r.use_edns(edns=0, ednsflags=dns.flags.DO)
        r.answer.append(rrset)
        r.answer.append(dns.rrset.from_rdata(owner, 300, sig))
        return r.to_wire()

    def bundle(self):
        return {
            (transport, typ): self.wire(typ)
            for transport in ("udp", "tcp") for typ in (48, 1)
        }

    def verifier(self, bundle):
        from verify_dnssec_crypto import verify_dnssec_wire_bundle
        return verify_dnssec_wire_bundle(bundle)

    def test_four_independent_signature_checks_pass_without_trust_anchor(self):
        result = self.verifier(self.bundle())
        self.assertEqual(result["wire_signature_checks"], 4)
        self.assertTrue(result["crypto_mathematically_verified"])
        self.assertFalse(result["external_trust_anchor_verified"])
        self.assertFalse(result["production_dnssec_ready"])

    def test_tampered_signed_a_record_rejected_in_both_transports(self):
        import dns.rrset
        altered = dns.rrset.from_text(str(self.host), 300, "IN", "A", "192.0.2.43")
        for transport in ("udp", "tcp"):
            data = self.bundle()
            data[(transport, 1)] = self.wire(1, rrset=altered)
            with self.subTest(transport=transport), self.assertRaises(ValueError):
                self.verifier(data)

    def test_wrong_dnskey_and_mismatched_transport_keys_rejected(self):
        import dns.dnssec
        import dns.rrset
        from cryptography.hazmat.primitives.asymmetric import ec
        other = ec.generate_private_key(ec.SECP256R1())
        other_key = dns.dnssec.make_dnskey(other.public_key(), "ECDSAP256SHA256")
        other_rr = dns.rrset.from_rdata(self.zone, 300, other_key)
        other_sig = dns.dnssec.sign(other_rr, other, self.zone, other_key, lifetime=3600)
        data = self.bundle()
        data[("tcp", 48)] = self.wire(48, rrset=other_rr, sig=other_sig)
        with self.assertRaises(ValueError):
            self.verifier(data)
        data[("udp", 48)] = data[("tcp", 48)]
        with self.assertRaises(ValueError):
            self.verifier(data)

    def test_expired_signatures_rejected(self):
        data = self.bundle()
        from verify_dnssec_crypto import verify_dnssec_wire_bundle
        with self.assertRaises(ValueError):
            verify_dnssec_wire_bundle(data, now=4102444800)

    def test_short_truncated_missing_and_bad_dns_wire_rejected(self):
        for entry in ((("udp", 1), b"x"), (("tcp", 48), b"\0"*12)):
            with self.subTest(entry=entry[0]):
                data = self.bundle()
                data[entry[0]] = entry[1]
                with self.assertRaises(ValueError):
                    self.verifier(data)
        data = self.bundle()
        del data[("tcp", 1)]
        with self.assertRaises(ValueError):
            self.verifier(data)

    def test_cli_rejects_symlink_or_unprotected_wire_file(self):
        from verify_dnssec_crypto import _read_wire
        from verify_dnssec_crypto import DNSSECProofError
        with tempfile.TemporaryDirectory() as temp:
            protected = Path(temp) / "protected.bin"
            protected.write_bytes(self.bundle()[("udp", 48)])
            protected.chmod(0o600)
            linked = Path(temp) / "linked.bin"
            linked.symlink_to(protected)
            with self.assertRaises(DNSSECProofError):
                _read_wire(linked)
            protected.chmod(0o644)
            with self.assertRaises(DNSSECProofError):
                _read_wire(protected)

    def test_cli_is_redacted_and_rejects_corrupted_wire(self):
        from verify_dnssec_crypto import main
        data = self.bundle()
        with tempfile.TemporaryDirectory() as temp:
            paths = []
            for transport, typ in (("udp",48),("udp",1),("tcp",48),("tcp",1)):
                f = Path(temp) / f"synthetic-{transport}-{typ}.bin"
                f.write_bytes(data[(transport,typ)])
                f.chmod(0o600)
                paths.append(f)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(p) for p in paths]), 0)
            self.assertTrue(json.loads(output.getvalue())["crypto_mathematically_verified"])
            paths[1].write_bytes(b"corrupt private path fixture")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(p) for p in paths]), 1)
            reply = json.loads(output.getvalue())
            self.assertEqual(reply["error"], "verification_failed")
            self.assertNotIn(temp, output.getvalue())
            self.assertFalse(reply["production_dnssec_ready"])


if __name__ == "__main__":
    unittest.main()
