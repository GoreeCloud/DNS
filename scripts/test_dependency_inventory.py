import base64
import hashlib
import json
import unittest
from generate_dependency_inventory import generate


class TestDependencyInventory(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.go = json.dumps({"Path": "github.com/GoreeCloud/DNS"}) + "\n" + json.dumps({
            "Path": "github.com/miekg/dns", "Version": "v1.1.73"
        })
        self.integrity = base64.b64encode(b"a" * 64).decode()
        self.lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "@goreecloud/dns-web", "version": "0.1.0"},
                "node_modules/react": {"version": "19.2.0", "integrity": "sha512-" + self.integrity},
            },
        }

    def test_spdx_shape_and_deterministic_output(self):
        a = generate(self.go, self.lock, self.sha, "2026-11-21T00:00:00Z")
        b = generate(self.go, self.lock, self.sha, "2026-11-21T00:00:00Z")
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(a["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(a["packages"]), 3)
        self.assertEqual(a["packages"][0]["SPDXID"].startswith("SPDXRef-"), True)
        names = {p["name"]: p for p in a["packages"]}
        self.assertEqual(names["GoreeCloud-DNS"]["licenseDeclared"], "MIT")
        self.assertEqual(names["github.com/miekg/dns"]["licenseDeclared"], "NOASSERTION")
        self.assertEqual(names["react"]["checksums"][0]["algorithm"], "SHA512")
        self.assertEqual(names["react"]["checksums"][0]["checksumValue"], (b"a" * 64).hex())
        self.assertEqual(len(a["relationships"]), 3)

    def test_missing_metadata_and_provenance_are_rejected(self):
        with self.assertRaises(ValueError):
            generate(self.go, self.lock, "not-a-commit", "2026-11-21T00:00:00Z")
        bad = dict(self.lock)
        bad["lockfileVersion"] = 2
        with self.assertRaises(ValueError):
            generate(self.go, bad, self.sha, "2026-11-21T00:00:00Z")
        with self.assertRaises(ValueError):
            generate(json.dumps({"Path": "root"}), self.lock, self.sha, "2026-11-21T00:00:00Z")
        replaced = json.dumps({
            "Path": "github.com/example/replaced", "Version": "v1.0.0", "Replace": {"Path": "../other"}
        })
        with self.assertRaises(ValueError):
            generate(replaced, self.lock, self.sha, "2026-11-21T00:00:00Z")

    def test_bad_npm_integrity_is_not_asserted(self):
        self.lock["packages"]["node_modules/react"]["integrity"] = "sha512-not-base64!"
        document = generate(self.go, self.lock, self.sha, "2026-11-21T00:00:00Z")
        react = next(x for x in document["packages"] if x["name"] == "react")
        self.assertNotIn("checksums", react)


if __name__ == "__main__":
    unittest.main()
