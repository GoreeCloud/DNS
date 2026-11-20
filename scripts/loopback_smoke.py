#!/usr/bin/env python3
"""Synthetic localhost-only DNS-wire and authenticated API acceptance test.

Run against the DEVELOPMENT Docker Compose topology after it has started.
No external domain is queried, no network configuration is changed, and no
private client identifiers or credentials are printed.
"""
import ipaddress
import json
import os
import socket
import struct
from urllib.request import ProxyHandler, Request, build_opener

DNS_HOST = "127.0.0.1"
DNS_PORT = 1053
API_URL = "http://127.0.0.1:8080/api/v1/status"


def wire_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise AssertionError("unexpected EOF in DNS/TCP response")
        data += chunk
    return data


def exchange(transport: str, name: str, qtype: int) -> bytes:
    query = struct.pack("!HHHHHH", 0xC13A, 0x0100, 1, 0, 0, 0)
    query += wire_name(name) + struct.pack("!HH", qtype, 1)
    if transport == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            sock.sendto(query, (DNS_HOST, DNS_PORT))
            response, _ = sock.recvfrom(4096)
    else:
        with socket.create_connection((DNS_HOST, DNS_PORT), timeout=4) as sock:
            sock.settimeout(4)
            sock.sendall(struct.pack("!H", len(query)) + query)
            count = struct.unpack("!H", recv_exact(sock, 2))[0]
            response = recv_exact(sock, count)
    assert len(response) >= 12 and response[:2] == query[:2], "bad DNS wire identifier"
    return response


def check(response: bytes, rcode: int, count: int, local: bool = False) -> None:
    flags = struct.unpack("!H", response[2:4])[0]
    answers = struct.unpack("!H", response[6:8])[0]
    assert flags & 0x8000, "packet is not a DNS response"
    assert flags & 15 == rcode, f"wrong DNS rcode: {flags & 15}"
    assert answers == count, f"wrong DNS answer count: {answers}"
    if local:
        assert flags & 0x0400, "local record response missing AA flag"


def main() -> None:
    for transport in ("udp", "tcp"):
        check(exchange(transport, "blocked.example", 1), 3, 0)
        a = exchange(transport, "home.example", 1)
        check(a, 0, 1, local=True)
        assert a.endswith(ipaddress.IPv4Address("192.0.2.42").packed), "incorrect local A answer"
        aaaa = exchange(transport, "home.example", 28)
        check(aaaa, 0, 1, local=True)
        assert aaaa.endswith(ipaddress.IPv6Address("2001:db8::42").packed), "incorrect local AAAA answer"
        check(exchange(transport, "alias.example", 1), 0, 1, local=True)
        check(exchange(transport, "home.example", 15), 0, 0, local=True)

    token = os.environ.get("DNS_API_TOKEN")
    assert token and len(token) >= 16, "test API token must be configured"
    request = Request(API_URL, headers={"Authorization": "Bearer " + token})
    with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
        status = json.load(response)
    assert status["rules"] == 1
    assert status["local_records"] == 3
    assert status["local_answers"] >= 8
    assert status["blocked"] >= 2
    print("Verified synthetic loopback UDP/TCP, A/AAAA/CNAME/NODATA, filtering, and API counters")


if __name__ == "__main__":
    main()
