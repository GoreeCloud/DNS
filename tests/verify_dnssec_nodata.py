#!/usr/bin/env python3
"""Offline mathematical proof of one signed NODATA test case.

Validates the actual signed NSEC bitmap at an *existing* A-only owner:
host.smoke.invalid AAAA must not exist. Uses a disposable in-band DNSKEY,
NOT an external authenticated trust anchor. Not an NXDOMAIN/wildcard proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verify_dnssec_crypto import _read_wire, DNSSECProofError, ZONE_TEXT, HOST_TEXT


def _bitmap_has_type(nsec, rrtype: int) -> bool:
    """Read RFC 4034 NSEC type bitmaps, MSB-first per 256-type window."""
    window = rrtype // 256
    byte_index = (rrtype % 256) // 8
    mask = 1 << (7 - rrtype % 8)
    for number, bitmap in nsec.windows:
        if number == window and byte_index < len(bitmap):
            return bool(bitmap[byte_index] & mask)
    return False


def verify_nodata_bundle(
    keys_by_transport: dict[str, bytes],
    nodata_by_transport: dict[str, bytes],
    *, now: int | None = None,
) -> dict:
    try:
        import dns.dnssec
        import dns.flags
        import dns.message
        import dns.name
        import dns.rcode
        import dns.rdatatype
        import dns.rdataclass
    except ImportError:
        raise DNSSECProofError("crypto dependencies unavailable") from None
    if set(keys_by_transport) != {"udp", "tcp"} or set(nodata_by_transport) != {"udp", "tcp"}:
        raise DNSSECProofError("invalid offline packet inputs")
    if now is not None and (type(now) is not int or now < 0):
        raise DNSSECProofError("invalid offline verification time")
    zone = dns.name.from_text(ZONE_TEXT)
    host = dns.name.from_text(HOST_TEXT)
    proven_keys = {}
    for transport in ("udp", "tcp"):
        for kind, wire in (("key", keys_by_transport[transport]),
                           ("nodata", nodata_by_transport[transport])):
            if not isinstance(wire, bytes) or not 12 <= len(wire) <= 65535:
                raise DNSSECProofError("malformed offline packet")
            try:
                msg = dns.message.from_wire(wire, ignore_trailing=False)
            except Exception:
                raise DNSSECProofError("malformed offline packet") from None
            owner = zone if kind == "key" else host
            qtype = dns.rdatatype.DNSKEY if kind == "key" else dns.rdatatype.AAAA
            if (msg.rcode() != dns.rcode.NOERROR or not msg.flags & dns.flags.AA
                    or msg.flags & dns.flags.TC or msg.edns != 0
                    or not msg.ednsflags & dns.flags.DO
                    or len(msg.question) != 1
                    or msg.question[0].name != owner
                    or msg.question[0].rdtype != qtype
                    or msg.question[0].rdclass != dns.rdataclass.IN):
                raise DNSSECProofError("unexpected DNSSEC packet shape")
            if kind == "key":
                rr = next((x for x in msg.answer
                           if x.name == zone and x.rdtype == dns.rdatatype.DNSKEY), None)
                sig = next((x for x in msg.answer
                            if x.name == zone and x.rdtype == dns.rdatatype.RRSIG
                            and x.covers == dns.rdatatype.DNSKEY), None)
                if rr is None or sig is None:
                    raise DNSSECProofError("DNSKEY self proof unavailable")
                if any(k.algorithm != 13 or k.protocol != 3 or not k.flags & 256 for k in rr):
                    raise DNSSECProofError("invalid disposable DNSKEY")
                try:
                    dns.dnssec.validate(rr, sig, {zone: rr}, now=now)
                except Exception:
                    raise DNSSECProofError("DNSKEY signature invalid") from None
                proven_keys[transport] = rr
                continue
            # Parse NODATA after collecting the keys, below.
            if len(msg.answer) != 0:
                raise DNSSECProofError("unexpected positive answer")
    if {k.to_text() for k in proven_keys["udp"]} != {k.to_text() for k in proven_keys["tcp"]}:
        raise DNSSECProofError("transport DNSKEY disagreement")
    keys = {zone: proven_keys["udp"]}
    for transport, wire in nodata_by_transport.items():
        msg = dns.message.from_wire(wire, ignore_trailing=False)
        nsec_set = next((rr for rr in msg.authority
                         if rr.name == host and rr.rdtype == dns.rdatatype.NSEC), None)
        signatures = next((rr for rr in msg.authority
                           if rr.name == host and rr.rdtype == dns.rdatatype.RRSIG
                           and rr.covers == dns.rdatatype.NSEC), None)
        if nsec_set is None or signatures is None or not nsec_set or not signatures:
            raise DNSSECProofError("signed exact-owner NSEC absent")
        if any(sig.algorithm != 13 or sig.signer != zone
               or sig.labels != len(host.labels) - 1 for sig in signatures):
            raise DNSSECProofError("invalid exact-owner NSEC signer")
        for nsec in nsec_set:
            if (not _bitmap_has_type(nsec, dns.rdatatype.A)
                    or _bitmap_has_type(nsec, dns.rdatatype.AAAA)
                    or _bitmap_has_type(nsec, dns.rdatatype.CNAME)):
                raise DNSSECProofError("NSEC bitmap does not prove AAAA NODATA")
        try:
            dns.dnssec.validate(nsec_set, signatures, keys, now=now)
        except Exception:
            raise DNSSECProofError("NSEC signature invalid") from None
    return {
        "schema": "goreecloud.dns.offline-signed-nodata.v1",
        "exact_owner_aaaa_nodata_proved_by_nsec": True,
        "udp_nsec_mathematical_signature_verified": True,
        "tcp_nsec_mathematical_signature_verified": True,
        "in_band_dnskey_only": True,
        "external_trust_anchor_verified": False,
        "nxdomain_and_wildcard_denial_verified": False,
        "key_rollover_verified": False,
        "production_dnssec_ready": False,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Offline synthetic NSEC NODATA proof, not DNSSEC trust")
    p.add_argument("udp_dnskey", type=Path)
    p.add_argument("tcp_dnskey", type=Path)
    p.add_argument("udp_nodata", type=Path)
    p.add_argument("tcp_nodata", type=Path)
    args = p.parse_args(argv)
    try:
        report = verify_nodata_bundle(
            {"udp": _read_wire(args.udp_dnskey),
             "tcp": _read_wire(args.tcp_dnskey)},
            {"udp": _read_wire(args.udp_nodata),
             "tcp": _read_wire(args.tcp_nodata)},
        )
    except Exception:
        # Do not disclose local filenames, public response packets, or
        # implementation traceback to normal CLI consumers.
        print(json.dumps({"schema": "goreecloud.dns.offline-signed-nodata.v1",
                          "exact_owner_aaaa_nodata_proved_by_nsec": False,
                          "production_dnssec_ready": False,
                          "error": "nodata_proof_failed"}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
