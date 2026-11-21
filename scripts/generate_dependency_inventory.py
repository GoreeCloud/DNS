#!/usr/bin/env python3
"""Deterministic, deliberately partial SPDX 2.3 dependency inventory.

Scope: Go module graph and ALL entries in the committed npm lockfile.
Android/Qt artifacts, OS system packages, vendored byte-level attribution,
license verification, signatures and vulnerability attestations are excluded.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import quote

_SHA = re.compile(r"^[0-9a-f]{40}$")
_SPDX = "SPDX-2.3"
_SUPPORTED_CHECKSUMS = {"sha512": ("SHA512", 64), "sha256": ("SHA256", 32)}


def decode_objects(text):
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        entry, end = decoder.raw_decode(text, index)
        if not isinstance(entry, dict):
            raise ValueError("Go module records must be objects")
        yield entry
        index = end


def _identifier(prefix, value):
    return "SPDXRef-" + prefix + "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def _package(spdx_id, name, version, purl, checksum=None):
    item = {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        }],
    }
    if checksum:
        item["checksums"] = [checksum]
    return item


def _npm_checksum(info):
    entry = info.get("integrity")
    if not isinstance(entry, str):
        return None
    algorithm, sep, content = entry.partition("-")
    expected = _SUPPORTED_CHECKSUMS.get(algorithm)
    if not sep or expected is None or " " in content:
        return None
    try:
        raw = base64.b64decode(content, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if len(raw) != expected[1]:
        return None
    return {"algorithm": expected[0], "checksumValue": raw.hex()}


def generate(go_json, npm_lock, sha, created):
    if not _SHA.fullmatch(sha):
        raise ValueError("source revision must be an exact, lowercase SHA-1 Git commit")
    if npm_lock.get("lockfileVersion") != 3 or not isinstance(npm_lock.get("packages"), dict):
        raise ValueError("expected complete npm package-lock v3")
    if not created.endswith("Z"):
        raise ValueError("creation time must be a reproducible UTC timestamp")
    packages = [{
        "SPDXID": "SPDXRef-GoreeCloud-DNS",
        "name": "GoreeCloud-DNS",
        "versionInfo": sha,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "MIT",
        "copyrightText": "Copyright (c) 2026 GoreeCloud",
    }]
    relations = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-GoreeCloud-DNS",
    }]
    used_ids = {"SPDXRef-GoreeCloud-DNS"}
    module_count = 0
    for item in decode_objects(go_json):
        path = item.get("Path")
        version = item.get("Version")
        if not isinstance(path, str) or not isinstance(version, str) or not path or not version:
            # Skip the root module; it has no version and is described above.
            continue
        if item.get("Replace"):
            raise ValueError("module replacements require separate provenance review")
        purl = "pkg:golang/" + quote(path, safe="/") + "@" + quote(version, safe="")
        spdx_id = _identifier("go", path + "@" + version)
        if spdx_id in used_ids:
            raise ValueError("duplicate Go module entry")
        used_ids.add(spdx_id)
        packages.append(_package(spdx_id, path, version, purl))
        relations.append({
            "spdxElementId": "SPDXRef-GoreeCloud-DNS",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id,
        })
        module_count += 1
    if module_count < 1:
        raise ValueError("empty Go dependency graph")
    npm_count = 0
    for path, item in sorted(npm_lock["packages"].items()):
        if path == "":
            continue
        if not isinstance(path, str) or not isinstance(item, dict):
            raise ValueError("invalid npm dependency lock entry")
        name = item.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = item.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
            raise ValueError("incomplete npm dependency metadata")
        purl = "pkg:npm/" + quote(name, safe="@/") + "@" + quote(version, safe="")
        spdx_id = _identifier("npm", path + ":" + name + "@" + version)
        if spdx_id in used_ids:
            raise ValueError("duplicate npm lock entry")
        used_ids.add(spdx_id)
        packages.append(_package(spdx_id, name, version, purl, _npm_checksum(item)))
        relations.append({
            "spdxElementId": "SPDXRef-GoreeCloud-DNS",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id,
        })
        npm_count += 1
    if npm_count < 1:
        raise ValueError("empty npm dependency graph")
    packages.sort(key=lambda package: package["SPDXID"])
    relations.sort(key=lambda r: (r["spdxElementId"], r["relatedSpdxElement"]))
    return {
        "spdxVersion": _SPDX,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "GoreeCloud-DNS-source-dependency-inventory",
        "documentNamespace": "https://goreecloud.com/spdx/dns/source/" + sha,
        "creationInfo": {
            "created": created,
            "creators": ["Tool: GoreeCloud DNS partial source-inventory 1.0"],
            "comment": "PARTIAL, unsigned source inventory: Go module graph and ALL npm lock entries only. This is NOT a complete binary SBOM, license audit, vulnerability scan or release attestation.",
        },
        "packages": packages,
        "relationships": relations,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not _SHA.fullmatch(args.commit):
        parser.error("provide an exact lowercase Git commit SHA")
    timestamp = subprocess.run(["git", "show", "-s", "--format=%ct", args.commit],
                               capture_output=True, text=True, check=True).stdout.strip()
    created = dt.datetime.fromtimestamp(int(timestamp), tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    go = subprocess.run(["go", "list", "-m", "-json", "all"], check=True,
                        capture_output=True, text=True).stdout
    npm_lock = json.loads(Path("web/package-lock.json").read_text(encoding="utf-8"))
    document = generate(go, npm_lock, args.commit, created)
    output = json.dumps(document, indent=2, sort_keys=True) + "\n"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(output, encoding="utf-8")
    print(f"Partial SPDX inventory: {len(document['packages'])} source/root packages; unsigned; no license audit")


if __name__ == "__main__":
    main()
