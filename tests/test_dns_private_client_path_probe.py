"""No external DNS access: deterministic response parser and local test sockets."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import dns_private_client_path_probe as dnsprobe  # noqa: E402


def answer(request: bytes, *, change_id=False, flags=0x8180, question=None) -> bytes:
    transaction = (int.from_bytes(request[:2], "big") + int(change_id)) % 65536
    body = dnsprobe.QUESTION if question is None else question
    return struct.pack("!HHHHHH", transaction, flags, 1, 0, 0, 0) + body


class ReadonlyDNSProbeTests(unittest.TestCase):
    def test_only_canonical_private_and_cgnat_targets_allowed(self):
        for server in ("10.2.1.1", "172.16.5.1", "192.168.1.2", "100.71.27.119"):
            self.assertEqual(dnsprobe.validate_server(server), server)
        for invalid in ("8.8.8.8", "127.0.0.1", "0.0.0.0", "169.254.1.1",
                        "224.0.0.1", "::1", "example.net", "010.1.1.1", "1.1.1.1"):
            with self.subTest(target=invalid), self.assertRaises(ValueError):
                dnsprobe.validate_server(invalid)
        self.assertEqual(dnsprobe.validate_server("127.0.0.1", allow_loopback=True),
                         "127.0.0.1")

    def test_invalid_target_never_initiates_network_io(self):
        with patch.object(dnsprobe, "probe") as sender:
            self.assertRaises(ValueError, dnsprobe.inspect, "8.8.8.8")
            sender.assert_not_called()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(dnsprobe.main(["--server", "8.8.8.8"]), 2)
        self.assertNotIn("8.8.8.8", output.getvalue())

    def test_wire_answer_requires_identity_question_and_response(self):
        request = struct.pack("!HHHHHH", 42, 0x0100, 1, 0, 0, 0) + dnsprobe.QUESTION
        self.assertEqual(dnsprobe.parse_reply(answer(request), 42), 0)
        for invalid in (answer(request, change_id=True),
                        answer(request, flags=0x0100),
                        answer(request, flags=0x8200),
                        answer(request, question=b"\x03bad\x00\x00\x01\x00\x01"),
                        b"invalid", answer(request) + b"x" * 5000):
            with self.subTest(length=len(invalid)), self.assertRaises(ValueError):
                dnsprobe.parse_reply(invalid, 42)

    def test_udp_and_tcp_wire_probes_use_local_synthetic_resolver(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("127.0.0.1", 0))
        tcp.listen(1)
        outcomes = []

        def udp_worker():
            try:
                query, client = udp.recvfrom(2048)
                udp.sendto(answer(query), client)
            except OSError as exc:
                outcomes.append(type(exc).__name__)

        def tcp_worker():
            try:
                peer, _ = tcp.accept()
                with peer:
                    length = peer.recv(2)
                    query = dnsprobe.recv_exact(peer, int.from_bytes(length, "big"))
                    response = answer(query)
                    peer.sendall(struct.pack("!H", len(response)) + response)
            except (OSError, ValueError) as exc:
                outcomes.append(type(exc).__name__)

        workers = [threading.Thread(target=udp_worker),
                   threading.Thread(target=tcp_worker)]
        for worker in workers:
            worker.start()
        try:
            self.assertEqual(dnsprobe.probe("127.0.0.1", "udp",
                                           port=udp.getsockname()[1]),
                             {"status": "responded", "rcode": 0})
            self.assertEqual(dnsprobe.probe("127.0.0.1", "tcp",
                                           port=tcp.getsockname()[1]),
                             {"status": "responded", "rcode": 0})
        finally:
            udp.close()
            tcp.close()
            for worker in workers:
                worker.join(timeout=2)
        self.assertFalse(outcomes)

    def test_unverified_reply_never_claims_success(self):
        with patch.object(dnsprobe, "probe", side_effect=[
            {"status": "responded", "rcode": 0},
            {"status": "timeout", "rcode": None},
        ]):
            report = dnsprobe.inspect("100.71.27.119")
        self.assertFalse(report["dns_policy_verified"])
        self.assertFalse(report["encrypted_dns_verified"])
        self.assertFalse(report["target_address_disclosed"])
        self.assertFalse(report["dns_configuration_changed"])
        self.assertEqual(report["transport"]["tcp"]["status"], "timeout")
        self.assertNotIn("100.71.27.119", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
