"""Contracts for an opt-in, disposable two-container persistent-volume restart test."""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "smoke_release_persistence.sh"


class NonrootPersistentVolumeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = SCRIPT.read_text(encoding="utf-8")

    def test_bash_syntax(self):
        proc = subprocess.run(["bash", "-n", str(SCRIPT)],
                              capture_output=True, text=True,
                              check=False, timeout=4)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_requires_rootless_isolated_local_image(self):
        self.assertIn("Rootless}}", self.src)
        self.assertIn('podman image exists "$image"', self.src)
        self.assertIn("--pull=never", self.src)
        self.assertIn("--network=none", self.src)
        self.assertIn("--user=1654:1654", self.src)
        self.assertIn("--cap-drop=ALL --cap-add=NET_BIND_SERVICE", self.src)
        self.assertIn("--security-opt=no-new-privileges", self.src)
        self.assertNotIn("--network=host", self.src)

    def test_disposable_volume_and_restart(self):
        self.assertIn("mktemp -d /tmp/goreecloud-dns-restart-check.", self.src)
        self.assertIn('podman unshare chown 1654:1654 "$root/volume"', self.src)
        self.assertIn("for phase in first second; do", self.src)
        self.assertIn("PHASE=$phase", self.src)
        self.assertIn("podman unshare rm -rf --", self.src)
        self.assertIn("find /work/config -type f -size +0c", self.src)

    def test_credentials_and_loopback_only(self):
        self.assertIn("od -An -N24 -tx1 /dev/urandom", self.src)
        self.assertIn("umask 077", self.src)
        self.assertIn("--stop-if-bind-fails --portable-app /work/config", self.src)
        self.assertIn("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1", self.src)
        self.assertIn("DNS_SERVER_RECURSION=Deny", self.src)
        self.assertIn("status: REFUSED", self.src)
        self.assertIn("/sys/class/net", self.src)
        self.assertNotIn("8.8.8.8", self.src)


if __name__ == "__main__":
    unittest.main()
