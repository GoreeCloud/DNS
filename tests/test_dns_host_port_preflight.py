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
        self.assertEqual(len(results), 12)

    def test_adguard_caddy_bridge_listener_is_reported_without_endpoint_disclosure(self):
        present = classify_sockets(
            "tcp LISTEN 0 4096 172.19.0.1:3001 0.0.0.0:*"
        )
        self.assertEqual(present["adguard_caddy_proxy_tcp_3001"], "observed")
        self.assertEqual(present["dns_tcp_53"], "not_observed")
        absent = classify_sockets(
            "tcp LISTEN 0 4096 172.19.0.1:13001 0.0.0.0:*"
        )
        self.assertEqual(absent["adguard_caddy_proxy_tcp_3001"], "not_observed")
        with patch("dns_host_port_preflight.subprocess.run",
                   return_value=SimpleNamespace(returncode=0, stdout=(
                       "tcp LISTEN 0 4096 172.19.0.1:3001 0.0.0.0:*"
                   ))):
            report = io.StringIO()
            with contextlib.redirect_stdout(report):
                self.assertEqual(main([]), 1)
            parsed = json.loads(report.getvalue())
            self.assertEqual(parsed["listeners"]["adguard_caddy_proxy_tcp_3001"], "observed")
            self.assertFalse(parsed["production_cutover_authorized"])
            self.assertNotIn("172.19.0.1", report.getvalue())

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
        with patch("dns_host_port_preflight.subprocess.run",
                   return_value=SimpleNamespace(returncode=0, stdout=SOCKETS)):
            report = io.StringIO()
            with contextlib.redirect_stdout(report):
                self.assertEqual(main([]), 1)
            result = json.loads(report.getvalue())
            self.assertEqual(result["conclusion"], "listener_present")
            self.assertNotIn("127.0.0.53", report.getvalue())
            self.assertFalse(result["production_cutover_authorized"])

    def test_unknown_socket_rows_fail_closed_without_leaking_their_text(self):
        private_text = "private-host-token-never-in-output"
        for listing in (
            private_text,
            SOCKETS + "\n" + private_text,
            "tcp ESTAB 0 0 127.0.0.1:53 127.0.0.1:10000",
            "udp INVALID 0 0 [::]:53 [::]:*",
        ):
            with self.subTest(listing_length=len(listing)), patch(
                "dns_host_port_preflight.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stdout=listing),
            ):
                report = io.StringIO()
                with contextlib.redirect_stdout(report):
                    self.assertEqual(main([]), 2)
                result = json.loads(report.getvalue())
                self.assertEqual(result["conclusion"], "unknown")
                self.assertTrue(all(x == "unknown" for x in result["listeners"].values()))
                self.assertFalse(result["production_cutover_authorized"])
                self.assertNotIn(private_text, report.getvalue())
                self.assertNotIn("127.0.0.1", report.getvalue())

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

    def test_two_stable_observations_are_required_for_listener_hints(self):
        sample = SimpleNamespace(returncode=0, stdout=SOCKETS)
        with patch("dns_host_port_preflight.subprocess.run",
                   return_value=sample) as runner:
            result = gather()
            self.assertEqual(runner.call_count, 2)
            self.assertEqual(result["dns_tcp_53"], "observed")
            self.assertEqual(result["dns_udp_53"], "observed")
            self.assertEqual(result["management_tcp_5380"], "observed")

    def test_listener_changes_between_reads_are_unknown_not_available(self):
        first = SimpleNamespace(returncode=0, stdout=SOCKETS)
        second = SimpleNamespace(returncode=0, stdout="")
        with patch("dns_host_port_preflight.subprocess.run",
                   side_effect=[first, second]) as runner:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([]), 2)
            self.assertEqual(runner.call_count, 2)
            record = json.loads(output.getvalue())
            self.assertEqual(record["conclusion"], "unknown")
            self.assertTrue(all(state == "unknown"
                                for state in record["listeners"].values()))
            self.assertNotIn("127.0.0.53", output.getvalue())
            self.assertFalse(record["production_cutover_authorized"])

    def test_zero_exit_with_diagnostics_is_unknown_and_redacted(self):
        for index in (0, 1):
            with self.subTest(diagnostic_snapshot=index):
                entries = [
                    SimpleNamespace(returncode=0, stdout=SOCKETS, stderr=""),
                    SimpleNamespace(returncode=0, stdout=SOCKETS, stderr=""),
                ]
                entries[index].stderr = "private-interface-token: partial results"
                with patch("dns_host_port_preflight.subprocess.run",
                           side_effect=entries) as runner:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(main([]), 2)
                    self.assertEqual(runner.call_count, index + 1)
                    report = json.loads(output.getvalue())
                    self.assertEqual(report["conclusion"], "unknown")
                    self.assertTrue(all(value == "unknown" for value
                                        in report["listeners"].values()))
                    self.assertFalse(report["production_cutover_authorized"])
                    self.assertNotIn("private-interface-token", output.getvalue())
                    self.assertNotIn("127.0.0.53", output.getvalue())

    def test_failure_of_second_read_never_keeps_first_port_snapshot(self):
        first = SimpleNamespace(returncode=0, stdout=SOCKETS)
        with patch("dns_host_port_preflight.subprocess.run",
                   side_effect=[first, FileNotFoundError("private")]) as runner:
            result = gather()
            self.assertEqual(runner.call_count, 2)
            self.assertTrue(all(x == "unknown" for x in result.values()))

    def test_arguments_fail_closed_without_running_ss(self):
        with patch("dns_host_port_preflight.subprocess.run") as runner:
            report = io.StringIO()
            with contextlib.redirect_stdout(report):
                self.assertEqual(main(["--unsafe"]), 2)
            runner.assert_not_called()
            self.assertEqual(json.loads(report.getvalue())["conclusion"], "unknown")


if __name__ == "__main__":
    unittest.main()
