#!/usr/bin/env python3
"""Compare two trusted, already-exported dpkg inventories without executing code.

This nonpublishing development gate detects package-set/version drift between
two candidate builds. It cannot attest package origin or make a release safe.
No shell commands, image runtime, network requests or host package changes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 1 << 20
MAX_PACKAGES = 4096
NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}(?::[a-z0-9-]+)?\Z")
VERSION = re.compile(r"[0-9][A-Za-z0-9.+~:_-]{0,127}\Z")
ARCH = re.compile(r"[a-z0-9][a-z0-9-]{0,39}\Z")


class UnsafeManifest(ValueError):
    pass


def read_owner_manifest(path: Path) -> dict[tuple[str, str], str]:
    """Read one bounded owner-only regular file without following its final link."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise UnsafeManifest("secure file operations unavailable")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, "O_CLOEXEC", 0))
        item = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if not (stat.S_ISREG(item.st_mode) and item.st_uid == os.geteuid()
                and item.st_nlink == 1 and not (item.st_mode & 0o077)
                and (item.st_dev, item.st_ino) == (named.st_dev, named.st_ino)
                and 0 < item.st_size <= MAX_BYTES):
            raise UnsafeManifest("unsafe input file")
        payload = bytearray()
        while len(payload) <= MAX_BYTES:
            block = os.read(fd, min(65536, MAX_BYTES + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        if len(payload) > MAX_BYTES:
            raise UnsafeManifest("input exceeds limit")
    except OSError as exc:
        raise UnsafeManifest("unavailable input file") from exc
    finally:
        if fd is not None:
            os.close(fd)

    try:
        value = bytes(payload).decode("ascii")
    except UnicodeDecodeError as exc:
        raise UnsafeManifest("non-ASCII input") from exc
    if not value.endswith("\n") or "\r" in value:
        raise UnsafeManifest("invalid line terminator")
    records: dict[tuple[str, str], str] = {}
    rows = value.splitlines()
    if not rows or len(rows) > MAX_PACKAGES:
        raise UnsafeManifest("invalid record count")
    for line in rows:
        if len(line) > 512:
            raise UnsafeManifest("oversized record")
        columns = line.split("\t")
        if len(columns) != 3:
            raise UnsafeManifest("incorrect record shape")
        name, version, arch = columns
        if not (NAME.fullmatch(name) and VERSION.fullmatch(version)
                and ARCH.fullmatch(arch)):
            raise UnsafeManifest("invalid record field")
        key = (name, arch)
        if key in records:
            raise UnsafeManifest("duplicate package")
        records[key] = version
    return records


def compare(first: Path, second: Path) -> dict[str, object]:
    a, b = read_owner_manifest(first), read_owner_manifest(second)
    return {
        "status": "identical" if a == b else "drift",
        "first_count": len(a),
        "second_count": len(b),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two owner-controlled offline dpkg-query manifests"
    )
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args(argv)
    try:
        facts = compare(args.first, args.second)
    except (UnsafeManifest, ValueError):
        facts = {"status": "unverified", "first_count": None, "second_count": None}
    output = {
        "schema_version": "goreecloud.dns-package-parity.v1",
        "comparison": "offline_read_only",
        "release_authorized": False,
        **facts,
    }
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return {"identical": 0, "drift": 1, "unverified": 2}[str(facts["status"])]


if __name__ == "__main__":
    raise SystemExit(main())
