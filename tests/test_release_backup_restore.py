"""Static contracts for opt-in local raw-volume archive round-trip testing."""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "smoke_release_backup_restore.sh"


class RawVolumeRestoreContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = SCRIPT.read_text(encoding="utf-8")

    def test_bash_syntax(self):
        r = subprocess.run(["bash", "-n", str(SCRIPT)],
                           capture_output=True, text=True, timeout=4, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_rootless_no_network_and_disposable_path(self):
        self.assertIn("Rootless}}", self.src)
        self.assertIn('podman image exists "$image"', self.src)
        self.assertIn("mktemp -d /tmp/goreecloud-dns-restore.", self.src)
        self.assertIn("--pull=never --network=none", self.src)
        self.assertIn("--user=1654:1654", self.src)
        self.assertIn("--cap-drop=ALL --cap-add=NET_BIND_SERVICE", self.src)
        self.assertIn("--security-opt=no-new-privileges", self.src)
        self.assertNotIn("--network=host", self.src)
        self.assertNotIn("--publish", self.src)

    def test_archive_integrity_before_restore(self):
        self.assertIn('tar -C "$root/original" -cf "$root/backup.tar"', self.src)
        self.assertIn('sha256sum "$root/backup.tar"', self.src)
        self.assertIn('sha256sum -c --status backup.sha256', self.src)
        self.assertIn('printf \'x\' >> "$root/altered.tar"', self.src)
        self.assertIn('tar -C "$root/restored" -xf "$root/backup.tar"', self.src)
        self.assertIn('tar -C "$root/restored" -df "$root/backup.tar"', self.src)

    def test_two_nonroot_containers_use_distinct_volumes(self):
        self.assertIn('mkdir "$root/original" "$root/restored"', self.src)
        self.assertIn('run_phase original "$root/original"', self.src)
        self.assertIn('run_phase restored "$root/restored"', self.src)
        self.assertIn('find /work/config -type f -size +0c', self.src)
        self.assertIn('od -An -N24 -tx1 /dev/urandom', self.src)
        self.assertIn('DNS_SERVER_RECURSION=Deny', self.src)
        self.assertIn('status: REFUSED', self.src)
        self.assertIn('podman unshare rm -rf -- "$root"', self.src)


if __name__ == "__main__":
    unittest.main()
