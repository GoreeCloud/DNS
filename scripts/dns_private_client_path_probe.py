#!/usr/bin/env python3
"""Opt-in, minimal DNS-over-NetBird/client-path wire diagnostic.

Queries ONLY the explicitly supplied numeric private/CGNAT IPv4 resolver.
Never reads or changes system DNS, network routes, VPN state, or credentials.
Produces fixed-field, address-redacted JSON; not filtering or uptime proof.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import secrets
import socket
import struct

QUESTION = b"\x09localhost\x00\x00\x01\x00\x01"
ALLOWED = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"
))
MAX_DNS_RESPONSE = 4096
TIMEOUT_SECONDS = 2.0


def validate_server(value: str, *, allow_loopback: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("numeric resolver required")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError("numeric IPv4 resolver required") from exc
    # Reject alternate spellings and avoid accidental public DNS traffic.
    if str(address) != value:
        raise ValueError("canonical IPv4 spelling required")
    if address.is_loopback and allow_loopback:
        return value
    if not any(address in block for block in ALLOWED):
        raise ValueError("explicit private or CGNAT resolver required")
    return value


def parse_reply(reply: bytes, expected_id: int) -> int:
    if not isinstance(reply, (bytes, bytearray)) or len(reply) < 12 + len(QUESTION):
        raise ValueError("short DNS answer")
    if len(reply) > MAX_DNS_RESPONSE:
        raise ValueError("DNS answer exceeds limit")
    transaction, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", reply[:12])
    if (transaction != expected_id or flags & 0x8000 == 0
            or flags & 0x7800 or flags & 0x0200 or qdcount != 1
            or reply[12:12+len(QUESTION)] != QUESTION):
        raise ValueError("unexpected DNS answer")
    return flags & 15


def recv_exact(sock: socket.socket, size: int) -> bytes:
    pieces = bytearray()
    while len(pieces) < size:
        chunk = sock.recv(size - len(pieces))
        if not chunk:
            raise ValueError("incomplete framed DNS response")
        pieces.extend(chunk)
    return bytes(pieces)


def probe(server: str, transport: str, *, port: int = 53) -> dict:
    if transport not in ("udp", "tcp") or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid query parameters")
    number = secrets.randbelow(65536)
    payload = struct.pack("!HHHHHH", number, 0x0100, 1, 0, 0, 0) + QUESTION
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    try:
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            if transport == "udp":
                sock.sendto(payload, (server, port))
                response, sender = sock.recvfrom(MAX_DNS_RESPONSE + 1)
                if sender[0] != server or sender[1] != port:
                    raise ValueError("unexpected UDP source")
            else:
                sock.connect((server, port))
                sock.sendall(struct.pack("!H", len(payload)) + payload)
                size = struct.unpack("!H", recv_exact(sock, 2))[0]
                if size > MAX_DNS_RESPONSE:
                    raise ValueError("oversized TCP reply")
                response = recv_exact(sock, size)
        return {"status": "responded", "rcode": parse_reply(response, number)}
    except socket.timeout:
        return {"status": "timeout", "rcode": None}
    except (OSError, ValueError, struct.error):
        return {"status": "unverified", "rcode": None}


def inspect(server: str, *, allow_loopback: bool = False) -> dict:
    server = validate_server(server, allow_loopback=allow_loopback)
    results = {transport: probe(server, transport) for transport in ("udp", "tcp")}
    return {
        "schema": "goreecloud.dns-private-client-path-probe.v1",
        "query": "localhost. A IN",
        "target_address_disclosed": False,
        "dns_configuration_changed": False,
        "network_policy_changed": False,
        "dns_policy_verified": False,
        "encrypted_dns_verified": False,
        "transport": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Opt-in fixed-question private DNS wire probe; no configuration changes"
    )
    parser.add_argument("--server", required=True, help="numeric private/CGNAT IPv4 address")
    parser.add_argument("--allow-loopback-lab", action="store_true",
                        help="permit 127.0.0.1 only in a separately controlled test lab")
    args = parser.parse_args(argv)
    try:
        result = inspect(args.server, allow_loopback=args.allow_loopback_lab)
    except ValueError:
        print(json.dumps({"schema": "goreecloud.dns-private-client-path-probe.v1",
                          "error": "invalid_private_resolver", "executed": False}))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if all(row["status"] == "responded"
                    for row in result["transport"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
