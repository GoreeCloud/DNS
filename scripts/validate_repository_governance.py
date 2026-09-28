#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = (
    "README.md",
    "SPECIFICATIONS.md",
    "PROJECT-SPECIFICATIONS.md",
    "PROJECT-RECORD.md",
    "FEATURES.md",
    "IMPLEMENTED-FEATURES.md",
    "PLANNED-FEATURES.md",
    "CAPABILITIES.md",
    "BENEFITS.md",
    "COMPETITIVE-OBJECTIVES.md",
    "BRANDING.md",
    "USER-MANUAL.md",
    "CHANGELOGS.md",
    "ARCHITECTURE.md",
    "SECURITY.md",
    "PRIVACY.md",
    "PLATFORM-INTEGRATIONS.md",
    "BEACON.md",
    ".gitignore",
    ".editorconfig",
    "goreecloud.platform.yaml",
    "go.mod",
    "cmd/goreecloud-dns/main.go",
    "internal/app/server.go",
    "internal/app/server_test.go",
    "internal/config/config.go",
    "internal/config/config_test.go",
    "internal/dnscore/pipeline.go",
    "internal/dnscore/pipeline_test.go",
    ".github/workflows/ci.yml",
    ".github/workflows/vulnerability.yml",
    ".github/workflows/repository-governance.yml",
    "scripts/validate_repository_governance.py",
)

SYSTEMS = (
    "GoreeCloud Manager",
    "Privacy Shield",
    "Wardveil Security",
    "Everkeep",
    "Glaze UI",
    "GoreeCloud Mesh",
    "GoreeCloud Identity",
    "GoreeCloud Policy",
    "GoreeCloud Observability",
)

CORE_MARKERS = (
    "type Policy interface",
    "type Authority interface",
    "type Cache interface",
    "type Resolver interface",
    "case PolicyBlock:",
    "p.authority.Lookup",
    "p.cache.Lookup",
    "p.resolver.Resolve",
    "ErrPolicyAction",
)

CORE_TESTS = (
    "TestResolvePolicyBlockShortCircuits",
    "TestResolveRejectsUnknownPolicyAction",
    "TestResolveUsesAuthorityBeforeCacheAndResolver",
    "TestResolveUsesCacheAfterAuthorityMiss",
    "TestResolveFallsBackToResolver",
    "TestResolveStopsOnStageError",
)

def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)

def main() -> int:
    errors = 0

    for relative in REQUIRED:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            fail(f"required repository file is missing or invalid: {relative}")
            errors += 1

    if (ROOT / "FEATURE-ROADMAP.md").exists():
        fail("retired FEATURE-ROADMAP.md must remain absent")
        errors += 1

    integrations = (ROOT / "PLATFORM-INTEGRATIONS.md").read_text(encoding="utf-8")
    for system in SYSTEMS:
        if system not in integrations:
            fail(f"PLATFORM-INTEGRATIONS.md is missing {system}")
            errors += 1

    core = (ROOT / "internal/dnscore/pipeline.go").read_text(encoding="utf-8")
    for marker in CORE_MARKERS:
        if marker not in core:
            fail(f"DNS core pipeline is missing required marker: {marker!r}")
            errors += 1

    tests = (ROOT / "internal/dnscore/pipeline_test.go").read_text(encoding="utf-8")
    for marker in CORE_TESTS:
        if marker not in tests:
            fail(f"DNS core pipeline tests are missing: {marker}")
            errors += 1

    ignored = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    }
    for pattern in (".env", ".env.*", "secrets/", "*.key", "*.pem"):
        if pattern not in ignored:
            fail(f".gitignore is missing sensitive-file pattern: {pattern}")
            errors += 1

    manifest = (ROOT / "goreecloud.platform.yaml").read_text(encoding="utf-8")
    for marker in (
        'schema_version: "0.4"',
        "id: goreecloud-dns",
        "lifecycle: development",
        "status: nonconformant",
    ):
        if marker not in manifest:
            fail(f"goreecloud.platform.yaml is missing required marker: {marker!r}")
            errors += 1

    if errors:
        print(f"DNS repository governance validation failed with {errors} error(s).", file=sys.stderr)
        return 1

    print("DNS repository governance validation passed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
