"""Offline CI regression for owner-scoped DNS checkout authorization.

The static source check cannot audit upstream actions or dependency contents.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/goreecloud-static-checks.yml"
PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"
USES = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
BLOCKS = re.compile(
    r"(?m)^        uses: actions/checkout@[^\n]+\n"
    r"        with:\n"
    r"((?:          [^\n]+\n)+)"
)


def validate(contents: str) -> None:
    refs = USES.findall(contents)
    if refs != ["actions/checkout@" + PIN, "actions/checkout@" + PIN]:
        raise ValueError("unexpected or mutable DNS CI action")
    blocks = BLOCKS.findall(contents)
    if len(blocks) != 2:
        raise ValueError("DNS checkout permission blocks missing")
    for body in blocks:
        if body.splitlines().count("          persist-credentials: false") != 1:
            raise ValueError("DNS checkout credentials must not persist")
    if "          fetch-depth: 2\n" not in blocks[0]:
        raise ValueError("DNS source-contract checkout history requirement changed")


class DNSCheckoutSafetyTests(unittest.TestCase):
    def test_two_checked_out_jobs_are_pinned_and_ephemeral(self):
        validate(WORKFLOW.read_text(encoding="utf-8"))

    def test_unsafe_mutations_fail_closed(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        bad = [
            source.replace(PIN, "v4", 1),
            source.replace("persist-credentials: false",
                           "persist-credentials: true", 1),
            source.replace("persist-credentials: false\n", "", 1),
            source + "\n      - uses: other/action@v1\n",
            source.replace("fetch-depth: 2", "fetch-depth: 1", 1),
        ]
        for i, changed in enumerate(bad):
            with self.subTest(case=i), self.assertRaises(ValueError):
                validate(changed)


if __name__ == "__main__":
    unittest.main()
