"""Loopback-only mock DNS wire tests; never starts or reconfigures a resolver."""
import os
import shutil
import socket
import struct
import subprocess
import threading
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("smoke_dns_protocol.pl")


def receive_exact(sock, length):
    payload = b""
    while len(payload) < length:
        part = sock.recv(length - len(payload))
        if not part:
            raise RuntimeError("Mock DNS connection ended early")
        payload += part
    return payload


def exercise(protocol, mutation=None):
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    server = socket.socket(socket.AF_INET, kind)
    server.settimeout(5)
    server.bind(("127.0.0.1", 0))
    if protocol == "tcp":
        server.listen(1)
    port = server.getsockname()[1]
    failures = []

    def serve():
        try:
            if protocol == "tcp":
                with server.accept()[0] as connection:
                    length = struct.unpack("!H", receive_exact(connection, 2))[0]
                    question = receive_exact(connection, length)
                    response = make_response(question, mutation)
                    connection.sendall(struct.pack("!H", len(response)) + response)
            else:
                question, address = server.recvfrom(512)
                server.sendto(make_response(question, mutation), address)
        except Exception as error:
            failures.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    env = dict(os.environ, GOREECLOUD_DNS_SMOKE_PORT=str(port))
    try:
        result = subprocess.run(["perl", str(SCRIPT), protocol], capture_output=True,
                                text=True, timeout=8, env=env)
    finally:
        server.close()
        thread.join(timeout=1)
    if failures:
        raise AssertionError("Mock DNS server failed: " + str(failures[0]))
    return result


def make_response(question, mutation):
    response = bytearray(question[:2] + struct.pack("!HHHHH", 0x8185, 1, 0, 0, 0) + question[12:])
    if mutation == "question":
        response[13] = ord("x")
    elif mutation == "id":
        response[0] ^= 1
    elif mutation == "answers":
        struct.pack_into("!H", response, 6, 1)
    elif mutation == "authority":
        struct.pack_into("!H", response, 8, 1)
    elif mutation == "additional":
        struct.pack_into("!H", response, 10, 1)
    elif mutation == "trailing":
        response.append(0)
    elif mutation == "truncated_question":
        response.pop()
    elif mutation == "wrong_opcode":
        response[2] |= 0x08
    elif mutation == "truncated_flag":
        response[2] |= 0x02
    elif mutation == "not_refused":
        response[3] &= 0xF0
    return bytes(response)


@unittest.skipUnless(shutil.which("perl"), "Perl is required for the protocol harness")
class DnsMockWireTests(unittest.TestCase):
    def test_mock_refused_response_works_for_udp_and_tcp(self):
        for protocol in ("udp", "tcp"):
            with self.subTest(protocol=protocol):
                reply = exercise(protocol)
                self.assertEqual(reply.returncode, 0, reply.stderr)
                self.assertIn("PASS:", reply.stdout)

    def test_mutated_response_is_rejected_by_wire_harness(self):
        for protocol, mutation, expected in (
            ("udp", "question", "question changed"),
            ("tcp", "id", "transaction ID mismatch"),
        ):
            with self.subTest(protocol=protocol, mutation=mutation):
                reply = exercise(protocol, mutation)
                self.assertNotEqual(reply.returncode, 0)
                self.assertIn(expected, reply.stderr)


if __name__ == "__main__":
    unittest.main()
