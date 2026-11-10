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
        self.assertEqual(classify_sockets(SOCKETS), {
            "dns_tcp_53": "observed",
            "dns_udp_53": "observed",
            "management_tcp_5380": "observed",
        })

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

    def test_arguments_fail_closed_without_running_ss(self):
        with patch("dns_host_port_preflight.subprocess.run") as runner:
            report = io.StringIO()
            with contextlib.redirect_stdout(report):
                self.assertEqual(main(["--unsafe"]), 2)
            runner.assert_not_called()
            self.assertEqual(json.loads(report.getvalue())["conclusion"], "unknown")


if __name__ == "__main__":
    unittest.main()
