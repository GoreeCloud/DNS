#!/usr/bin/env python3
"""Read-only host socket collision hint for DNS migration planning.

No network queries, Docker access, DNS changes, config reads, privilege
escalation or production cutover. Never publish listener addresses.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

PORTS = (("dns_udp_53", "udp", 53), ("dns_tcp_53", "tcp", 53),
         ("management_tcp_5380", "tcp", 5380))
PORT_SUFFIX = re.compile(r":([0-9]{1,5})$")


def classify_sockets(output: str) -> dict[str, str]:
    """Parse fixed ss -H -lntu columns without retaining host addresses."""
    if not isinstance(output, str) or len(output.encode("utf-8")) > 524288:
        raise ValueError("unbounded socket listing")
    status = {label: "not_observed" for label, _, _ in PORTS}
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        protocol = fields[0].lower()
        if protocol not in ("tcp", "udp"):
            continue
        if len(fields) < 5:
            raise ValueError("incomplete socket row")
        found = PORT_SUFFIX.search(fields[4])
        if not found:
            raise ValueError("unrecognized socket address")
        port = int(found.group(1))
        for label, expected_protocol, expected_port in PORTS:
            if protocol == expected_protocol and port == expected_port:
                status[label] = "observed"
    return status


def gather() -> dict[str, str]:
    """Never allow a command or parse failure to be interpreted as free ports."""
    try:
        result = subprocess.run(
            ["ss", "-H", "-lntu"], capture_output=True, text=True,
            check=False, timeout=4,
        )
        if result.returncode:
            raise ValueError("socket inspection failed")
        return classify_sockets(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        return {label: "unknown" for label, _, _ in PORTS}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    states = ({label: "unknown" for label, _, _ in PORTS}
              if argv else gather())
    report = {
        "schema_version": "goreecloud.dns-host-port-preflight.v1",
        "inspection": "read_only",
        "listeners": states,
        "production_cutover_authorized": False,
        "conclusion": (
            "unknown" if "unknown" in states.values()
            else "listener_present" if "observed" in states.values()
            else "not_observed_not_proven_available"
        ),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    if "unknown" in states.values():
        return 2
    return 1 if "observed" in states.values() else 0


if __name__ == "__main__":
    raise SystemExit(main())
