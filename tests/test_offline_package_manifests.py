"""Offline package manifest parity: bounded, redacted, nonexecuting fixtures."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from compare_offline_package_manifests import (  # noqa: E402
    MAX_BYTES, UnsafeManifest, compare, main, read_owner_manifest,
)

BASE = (
    "libc6\t2.39-0ubuntu8.5\tamd64\n"
    "dotnet-runtime-10.0\t10.0.1-1\tamd64\n"
    "libmsquic\t2:2.6.0-1\tamd64\n"
)
DRIFT = BASE.replace("2.6.0-1", "2.6.1-1")


class PackageInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.first = self.mk("one.tsv", BASE)
        self.second = self.mk("two.tsv", BASE)

    def tearDown(self):
        self.temp.cleanup()

    def mk(self, name, data):
        p = self.dir / name
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        p.chmod(0o600)
        return p

    def run_cli(self, *args):
        buf = StringIO()
        with redirect_stdout(buf):
            status = main(list(args))
        return status, json.loads(buf.getvalue()), buf.getvalue()

    def test_identical_files_and_different_row_order_are_equal(self):
        self.second.write_text("".join(reversed(BASE.splitlines(keepends=True))))
        result = compare(self.first, self.second)
        self.assertEqual(result, {
            "status": "identical", "first_count": 3, "second_count": 3,
        })
        status, report, _ = self.run_cli(str(self.first), str(self.second))
        self.assertEqual(status, 0)
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["comparison"], "offline_read_only")

    def test_drift_detected_without_package_names_or_paths(self):
        self.second.write_text(DRIFT)
        status, report, raw = self.run_cli(str(self.first), str(self.second))
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "drift")
        self.assertEqual(report["first_count"], 3)
        self.assertEqual(report["second_count"], 3)
        self.assertNotIn("libmsquic", raw)
        self.assertNotIn(str(self.dir), raw)
        self.assertFalse(report["release_authorized"])

    def test_duplicates_bad_syntax_and_invalid_utf8_fail_closed(self):
        fixtures = (
            BASE + "libc6\t2.40\tamd64\n",
            BASE + "library\tnot-a-version\tamd64\n",
            BASE + "bad/name\t1.2\tamd64\n",
            BASE + "abc 1.2 amd64\n",
            BASE + "abc\t1\tamd64\r\n",
            BASE + "abc\t1\tamd64",
            BASE + "\n",
            BASE + "a\t1\t" + "x" * 100 + "\n",
            b"\xff\t1\tamd64\n",
        )
        for i, fixture in enumerate(fixtures):
            with self.subTest(i=i):
                candidate = self.mk("bad.tsv", fixture)
                with self.assertRaises(UnsafeManifest):
                    read_owner_manifest(candidate)
                status, report, raw = self.run_cli(str(self.first), str(candidate))
                self.assertEqual(status, 2)
                self.assertEqual(report["status"], "unverified")
                self.assertNotIn("bad.tsv", raw)

    def test_existing_symlink_hardlink_and_public_permissions_rejected(self):
        linked = self.dir / "linked.tsv"
        linked.symlink_to(self.first)
        hard = self.dir / "hard.tsv"
        os.link(self.first, hard)
        with self.assertRaises(UnsafeManifest):
            read_owner_manifest(linked)
        with self.assertRaises(UnsafeManifest):
            read_owner_manifest(hard)
        hard.unlink()
        self.first.chmod(0o644)
        with self.assertRaises(UnsafeManifest):
            read_owner_manifest(self.first)

    def test_empty_and_oversized_inputs_rejected(self):
        empty = self.mk("empty.tsv", "")
        too_big = self.mk("large.tsv", b"a" * (MAX_BYTES + 1))
        for candidate in (empty, too_big):
            with self.subTest(path=candidate), self.assertRaises(UnsafeManifest):
                read_owner_manifest(candidate)

    def test_nonexistent_file_reports_unknown_without_errors_or_paths(self):
        absent = self.dir / "owner-private-file.tsv"
        code, record, raw = self.run_cli(str(self.first), str(absent))
        self.assertEqual(code, 2)
        self.assertEqual(record["status"], "unverified")
        self.assertEqual(record["first_count"], None)
        self.assertNotIn(str(absent), raw)


if __name__ == "__main__":
    unittest.main()
