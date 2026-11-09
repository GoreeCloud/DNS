#!/usr/bin/env python3
"""Verify disposable DNSSEC response signatures mathematically, entirely offline.

Requires separately installed dnspython and cryptography; no network calls.
The in-band DNSKEY is NOT an authenticated external trust anchor. This verifies
signature math in a disposable test zone, not the DNSSEC chain of trust.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat

MAX_WIRE_BYTES = 65535
ZONE_TEXT = "smoke.invalid."
HOST_TEXT = "host.smoke.invalid."


class DNSSECProofError(ValueError):
    """Fail-closed and generic so no wire data, public keys or paths leak."""


def _read_wire(path: Path) -> bytes:
    # No symlink-follow or FIFO/terminal read: only protected, regular,
    # already-materialized disposable DNS responses may enter the verifier.
    if not hasattr(os, "O_NOFOLLOW"):
        raise DNSSECProofError("safe fixture open unavailable")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise DNSSECProofError("unavailable input") from None
    try:
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_nlink != 1 or before.st_mode & 0o077
                    or not 12 <= before.st_size <= MAX_WIRE_BYTES):
                raise DNSSECProofError("unsafe fixture properties")
            data = stream.read(MAX_WIRE_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (len(data) != before.st_size or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns):
                raise DNSSECProofError("fixture changed during verification")
    except OSError:
        raise DNSSECProofError("unavailable input") from None
    if not 12 <= len(data) <= MAX_WIRE_BYTES:
        raise DNSSECProofError("invalid wire size")
    return data


def verify_dnssec_wire_bundle(
    wire_by_transport: dict[tuple[str, int], bytes], *, now: int | None = None
) -> dict:
    """Validate DNSKEY self-signature and A RRset signatures for UDP and TCP.

    Require exactly four wire answers and identical DNSKEY material across
    transports. Self-signature correctness is not independent trust of keys.
    """
    try:
        import dns.dnssec
        import dns.flags
        import dns.message
        import dns.name
        import dns.rcode
        import dns.rdatatype
    except ImportError:
        raise DNSSECProofError("crypto verification dependency unavailable") from None
    expected = {(transport, typ) for transport in ("udp", "tcp") for typ in (48, 1)}
    if set(wire_by_transport) != expected:
        raise DNSSECProofError("wrong wire inputs")
    if now is not None and (type(now) is not int or now < 0):
        raise DNSSECProofError("invalid verification time")
    zone = dns.name.from_text(ZONE_TEXT)
    host = dns.name.from_text(HOST_TEXT)
    replies = {}
    for (transport, qtype), raw in wire_by_transport.items():
        if not isinstance(raw, bytes) or not 12 <= len(raw) <= MAX_WIRE_BYTES:
            raise DNSSECProofError("invalid wire input")
        try:
            msg = dns.message.from_wire(raw, ignore_trailing=False)
        except Exception:
            raise DNSSECProofError("unparseable DNS response") from None
        owner = zone if qtype == 48 else host
        if (msg.rcode() != dns.rcode.NOERROR or not msg.flags & dns.flags.AA
                or msg.flags & dns.flags.TC or msg.edns != 0
                or not msg.ednsflags & dns.flags.DO
                or len(msg.question) != 1 or msg.question[0].name != owner
                or msg.question[0].rdtype != qtype
                or len(msg.answer) != 2):
            raise DNSSECProofError("unexpected signed answer properties")
        rrset = next((x for x in msg.answer if x.name == owner and x.rdtype == qtype), None)
        sigs = next((x for x in msg.answer if x.name == owner and x.rdtype == 46), None)
        if rrset is None or sigs is None or len(rrset) == 0 or len(sigs) == 0:
            raise DNSSECProofError("missing signed record set")
        if any(sig.covers() != qtype or sig.algorithm != 13 or sig.signer != zone for sig in sigs):
            raise DNSSECProofError("unexpected DNSSEC signature")
        if qtype == 48 and any(key.algorithm != 13 or key.protocol != 3
                               or not key.flags & 256 for key in rrset):
            raise DNSSECProofError("unexpected DNSKEY algorithm or flags")
        replies[(transport, qtype)] = (rrset, sigs)
    # Trust only in-band keys for this cryptographic fixture. They must agree
    # across transports. Production DNSSEC requires separate DS/trust anchors.
    udp_keys = replies[("udp", 48)][0]
    tcp_keys = replies[("tcp", 48)][0]
    if (udp_keys.name != zone or tcp_keys.name != zone
            or {key.to_text() for key in udp_keys} != {key.to_text() for key in tcp_keys}):
        raise DNSSECProofError("inconsistent DNSKEY responses")
    keys = {zone: udp_keys}
    try:
        for (transport, qtype), (rrset, sigs) in replies.items():
            dns.dnssec.validate(rrset, sigs, keys, now=now)
    except (Exception,):
        raise DNSSECProofError("DNSSEC signature verification failed") from None
    return {
        "schema": "goreecloud.dns.offline-dnssec-signature-math.v1",
        "wire_signature_checks": 4,
        "udp_dnskey_signature_verified": True,
        "udp_a_signature_verified": True,
        "tcp_dnskey_signature_verified": True,
        "tcp_a_signature_verified": True,
        "crypto_mathematically_verified": True,
        "external_trust_anchor_verified": False,
        "nsec_negative_proofs_verified": False,
        "key_rollover_verified": False,
        "external_dnssec_interoperability_verified": False,
        "production_dnssec_ready": False,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Offline-only disposable DNSSEC signature verification")
    p.add_argument("udp_dnskey", type=Path)
    p.add_argument("udp_a", type=Path)
    p.add_argument("tcp_dnskey", type=Path)
    p.add_argument("tcp_a", type=Path)
    args = p.parse_args(argv)
    try:
        data = {
            ("udp", 48): _read_wire(args.udp_dnskey),
            ("udp", 1): _read_wire(args.udp_a),
            ("tcp", 48): _read_wire(args.tcp_dnskey),
            ("tcp", 1): _read_wire(args.tcp_a),
        }
        result = verify_dnssec_wire_bundle(data)
    except DNSSECProofError:
        print(json.dumps({"crypto_mathematically_verified": False,
                          "production_dnssec_ready": False,
                          "error": "verification_failed"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
