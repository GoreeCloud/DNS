"""Static contract for the opt-in, container-only release-image smoke probe.

This test checks shell syntax and safety boundaries only. It never starts DNS.
"""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "smoke_release_image.sh"


class ReleaseImageSmokeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_posix_shell_syntax(self):
        result = subprocess.run(
            ["/bin/sh", "-n", str(SCRIPT)], capture_output=True,
            text=True, timeout=4, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_container_only_network_isolation_guard(self):
        self.assertIn("id -u", self.source)
        self.assertIn('"1654"', self.source)
        self.assertIn("/.dockerenv", self.source)
        self.assertIn("/run/.containerenv", self.source)
        self.assertIn("/sys/class/net/lo", self.source)
        self.assertIn('for interface in /sys/class/net/*; do', self.source)
        self.assertIn('network interface other than loopback is present', self.source)

    def test_disposable_config_and_auth(self):
        self.assertIn("umask 077", self.source)
        self.assertIn("od -An -N24 -tx1 /dev/urandom", self.source)
        self.assertIn("DNS_SERVER_ADMIN_PASSWORD_FILE=/work/admin-password", self.source)
        self.assertIn("--stop-if-bind-fails --portable-app /work/config", self.source)
        self.assertIn("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1", self.source)
        self.assertIn("DNS_SERVER_RECURSION=Deny", self.source)
        self.assertIn('trap ', self.source)
        self.assertNotIn("admin:admin", self.source)

    def test_basic_dns_and_api_boundaries(self):
        self.assertIn("GoreeCloud DNS</title>", self.source)
        self.assertIn("status: REFUSED", self.source)
        self.assertIn("http://127.0.0.1:5380/api/settings/get", self.source)
        self.assertIn("invalid-token", self.source)


if __name__ == "__main__":
    unittest.main()
