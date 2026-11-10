"""Read-only DNS host listener preflight: synthetic socket-output tests only."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from dns_host_port_preflight import classify_sockets, gather, main  # noqa: E402

SOCKETS = "\n".join((
    "tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*",
    "udp UNCONN 0 0 [::]:53 [::]:*",
    "tcp LISTEN 0 4096 127.0.0.1:5380 0.0.0.0:*",
    "tcp LISTEN 0 4096 127.0.0.1:15380 0.0.0.0:*",
))


class HostListenerPreflightTests(unittest.TestCase):
    def test_exact_ports_and_ipv6_are_recognized(self):
        results = classify_sockets(SOCKETS)
        observed = {name for name, state in results.items() if state == "observed"}
        self.assertEqual(observed, {
            "dns_tcp_53", "dns_udp_53", "management_tcp_5380",
        })
        self.assertEqual(len(results), 11)

    def test_encrypted_http_and_dhcp_surfaces_are_checked_separately(self):
        paths = (
            ("tcp", 853, "dot_tcp_853"),
            ("udp", 853, "doq_udp_853"),
            ("tcp", 443, "doh_tcp_443"),
            ("udp", 443, "doh_http3_udp_443"),
            ("tcp", 80, "dns_http_tcp_80"),
            ("tcp", 8053, "dns_http_tcp_8053"),
            ("tcp", 53443, "management_tls_tcp_53443"),
            ("udp", 67, "dhcp_udp_67"),
        )
        synthetic = "\n".join(
            f"{proto} {'UNCONN' if proto == 'udp' else 'LISTEN'} 0 4096 [::]:{port} [::]:*"
            for proto, port, _ in paths
        )
        result = classify_sockets(synthetic)
        self.assertEqual({label for label, status in result.items()
                          if status == "observed"}, {label for _, _, label in paths})
        self.assertEqual(result["dns_udp_53"], "not_observed")
        self.assertEqual(result["dns_tcp_53"], "not_observed")
        self.assertEqual(result["management_tcp_5380"], "not_observed")

    def test_suffix_matching_does_not_confuse_similar_port_numbers(self):
        synthetic = "\n".join(
            f"tcp LISTEN 0 4096 127.0.0.1:{port} 0.0.0.0:*"
            for port in (153, 1443, 1853, 15380, 18053, 54343)
        )
        result = classify_sockets(synthetic)
        self.assertEqual(set(result.values()), {"not_observed"})

    def test_unrelated_ports_never_prove_cutover(self):
        with patch("dns_host_port_preflight.subprocess.run",
                   return_value=SimpleNamespace(returncode=0, stdout="")):
            report = io.StringIO()
            with contextlib.redirect_stdout(report):
                self.assertEqual(main([]), 0)
            result = json.loads(report.getvalue())
            self.assertFalse(result["production_cutover_authorized"])
            self.assertEqual(result["conclusion"], "not_observed_not_proven_available")
            self.assertTrue(all(value == "not_observed" for value in result["listeners"].values()))

    def test_occupied_port_is_reported_without_addresses(self):
        secret = "private-host-token-never-in-output"
        with patch("dns_host_port_preflight.subprocess.run",
                   return_value=SimpleNamespace(returncode=0,
                                                stdout=SOCKETS + "\n" + secret)):
            report = io.StringIO()
            with contextlib.redirect_stdout(report):
                self.assertEqual(main([]), 1)
            result = json.loads(report.getvalue())
            self.assertEqual(result["conclusion"], "listener_present")
            self.assertNotIn("127.0.0.53", report.getvalue())
            self.assertNotIn(secret, report.getvalue())

    def test_malformed_tcp_row_fails_closed(self):
        with self.assertRaises(ValueError):
            classify_sockets("tcp LISTEN 0 4096 invalid")
        with patch("dns_host_port_preflight.subprocess.run",
                   return_value=SimpleNamespace(returncode=0, stdout="tcp BAD")):
            self.assertTrue(all(state == "unknown" for state in gather().values()))

    def test_missing_tool_nonzero_exit_timeout_and_oversized_rows(self):
        failures = (
            FileNotFoundError("secret-path"),
            subprocess.TimeoutExpired(["ss"], 4, output=b"secret"),
        )
        for failure in failures:
            with self.subTest(kind=type(failure).__name__), patch(
                "dns_host_port_preflight.subprocess.run", side_effect=failure
            ):
                self.assertEqual(set(gather().values()), {"unknown"})
        with patch("dns_host_port_preflight.subprocess.run",
                   return_value=SimpleNamespace(returncode=1, stdout=SOCKETS)):
            self.assertEqual(set(gather().values()), {"unknown"})
        with self.assertRaises(ValueError):
            classify_sockets("x" * 524289)

    def test_arguments_fail_closed_without_running_ss(self):
        with patch("dns_host_port_preflight.subprocess.run") as runner:
            report = io.StringIO()
            with contextlib.redirect_stdout(report):
                self.assertEqual(main(["--unsafe"]), 2)
            runner.assert_not_called()
            self.assertEqual(json.loads(report.getvalue())["conclusion"], "unknown")


if __name__ == "__main__":
    unittest.main()
