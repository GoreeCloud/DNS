"""Fail-closed source contract for the upstream Docker Compose example.

The Compose example pulls the upstream Technitium image and must not expose
its default-credential HTTP management console on non-loopback host addresses.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ExampleComposeSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    def test_unsecured_management_console_is_host_loopback_only(self):
        admin_port = re.findall(r'^\s*-\s*["\']([^"\']*5380[^"\']*)["\']',
                                self.compose, flags=re.MULTILINE)
        self.assertEqual(admin_port, ["127.0.0.1:5380:5380/tcp"])
        self.assertNotIn('"0.0.0.0:5380:5380/tcp"', self.compose)

    def test_upstream_image_is_not_misrepresented_as_goreecloud(self):
        self.assertIn("Upstream Technitium sample", self.compose)
        self.assertIn("not GoreeCloud DNS", self.compose)
        self.assertIn("docker.io/technitium/dns-server:latest", self.compose)
        self.assertIn("not production-certified", self.compose)


if __name__ == "__main__":
    unittest.main()
