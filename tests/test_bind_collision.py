"""Contracts for offline duplicate-listener startup failure checks."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class IsolatedListenerCollision(unittest.TestCase):
    def test_startup_failure_is_nonzero_and_does_not_disrupt_primary(self):
        code = (ROOT / "DnsServerApp/Program.cs").read_text(encoding="utf-8")
        harness = (ROOT / "tests/smoke_runtime.sh").read_text(encoding="utf-8")
        self.assertIn("Environment.ExitCode = 1;", code)
        self.assertIn("--network=none", harness)
        self.assertIn("mkdir -p /work/bind-collision-config", harness)
        self.assertIn("collision_status=0", harness)
        self.assertIn('timeout 12s env DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password', harness)
        self.assertIn("--stop-if-bind-fails --portable-app /work/bind-collision-config", harness)
        self.assertIn('collision_status" -eq 0', harness)
        self.assertIn('collision_status" -eq 124', harness)
        self.assertIn("address already in use|failed to bind|AddressInUse", harness)
        self.assertIn("primary DNS console died after bind collision", harness)
        self.assertIn("perl /work/smoke_dns_protocol.pl udp", harness)
        self.assertIn("perl /work/smoke_dns_protocol.pl tcp", harness)


if __name__ == "__main__":
    unittest.main()
