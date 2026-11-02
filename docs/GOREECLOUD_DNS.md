# GoreeCloud DNS — development and provenance

GoreeCloud DNS is a development distribution of [Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer), not an official upstream product or a production-validated deployment.

- Baseline: upstream master commit 0dd592aad21eced4221a9a46204cb1a299972ca0 (tree 8e95e2d771683be67624f98a57098fbcef867407), version 15.6.2.
- Unmodified source preserved in branch upstream/technitium-master-20261102.
- GoreeCloud/DNS already existed as an independent public repository; this is not a GitHub-native fork relationship.
- Original headers, attribution, and GPL-3.0-or-later terms are preserved.

## Added in the GoreeCloud development branch

- Console, login, About and encrypted DNS setup page identify the GoreeCloud distribution; upstream credit and repository links remain visible.
- Skip-to-content navigation, focus-visible styles and login autofill hints.
- App assembly metadata, console startup/shutdown notices, and OCI image metadata identify GoreeCloud DNS while retaining upstream attribution.
- One-click copy of the displayed DNS-over-HTTPS endpoint, with accessible status messages and failure fallback instructions.
- Dependency-free static regression checks.

## Validation evidence — 2026-11-02

- Built in isolated rootless Podman using the official Microsoft .NET SDK 10.0.403 image. Recorded image digest: sha256:9c7b6b263d9d4c2e4718e16dae6d75cd8f4b5ccf206f1e7d48a98eb429981b03.
- Dependency checkout: TechnitiumLibrary commit 4a5a530ac6c4114e72216e0b9c74208a7a5e3fa0. The ByteTree, Net, Security.OTP and DnsServerApp Release builds each completed with zero build warnings and zero build errors.
- Runtime: started the build inside a network-disabled, temporary container with --portable-app and only the NET_BIND_SERVICE capability. GET / returned HTTP 200 with the GoreeCloud DNS title; GET /css/goreecloud.css returned the expected stylesheet.
- DNS protocol smoke: locally generated localhost A-record queries over UDP and TCP returned matching transaction IDs and RCODE 5 (REFUSED), expected with recursion configured Deny. The anonymous settings API returned a denial; an explicitly configured missing administrator password file prevented first-run startup. These are limited offline checks, not external recursion or comprehensive authentication acceptance.
- Tests: fifteen Python contract tests passed locally, both edited browser scripts passed Node syntax checks, project XML parses, and patch whitespace checks pass. GitHub source and .NET build CI are required for each merged change.
- No external network access, resolver changes, DNS/DHCP host configurations, VPS services or production deployment were involved in runtime testing. The container and temporary configuration were disposable.

## Repeatable, offline DNS runtime smoke tests

After building the Release application according to the upstream build.md and the pinned dependency in CI, run:

    bash tests/smoke_runtime.sh /absolute/path/to/DnsServerApp/bin/Release

This is an **explicit opt-in** test; it is not automatically invoked by the hosted GitHub Actions build. It requires rootless Podman and its pre-pulled, pinned Microsoft .NET SDK container image. The harness copies build output to a temporary directory; runs the DNS application with portable configuration, no network access, no host port mappings, minimal container bind capability and recursion disabled; verifies the branded HTTP console and stylesheet, localhost DNS UDP and DNS-over-TCP REFUSED responses, and denial of unauthenticated administrative settings API access; then stops the server and removes temporary files. The DNS response checks only basic protocol/service behavior, **not external recursion or DNSSEC correctness**.

Never substitute host networking, rootful Podman or a production DNS configuration to make this smoke test pass.

## First-run administrator credential safety

**This is a development distribution, not a hardened public deployment.** In a fresh upstream-derived configuration, the administrator account defaults to `admin/admin` when no administrator password configuration is provided. Do not expose the management console or API to an untrusted network with that default. Change credentials before any networked staging, restrict the management listener with `DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES` and network policy, and use trusted HTTPS when applicable.

For a *new* configuration, prefer a strong, access-restricted secret file specified by `DNS_SERVER_ADMIN_PASSWORD_FILE`. Confirm that it is readable **inside the container or service identity** and contains a nonempty first line. The GoreeCloud security change prevents an explicit missing, unreadable, or empty secret file from falling back to the known password; startup must fail closed instead. `DNS_SERVER_ADMIN_PASSWORD` remains an upstream-supported environment override, but the secret-file mechanism avoids unnecessarily placing the password directly in process environment. Existing persisted `auth.config` is loaded separately and is **not automatically reinitialized** from these first-run variables.

Do not place password contents in repository files, build logs, CI variables printed to output, command arguments, or documentation. Review upstream password-reset mechanisms before using them in an authorized, isolated recovery. The offline smoke test covers the missing-secret first-run failure path but not all authentication, SSO, TOTP, rate limiting, or privilege-management behaviors.

## Build and release gates

Build requires .NET 10 and the separate sibling TechnitiumLibrary source/build described in the upstream build.md. Basic isolated web, UDP/TCP DNS, and anonymous API boundary smoke tests pass; they are not substitutes for real-network DNS, encrypted DNS, DHCP, upgrade, package, browser, assistive-technology, or production deployment tests. DNS and DHCP system settings are deliberately untouched.

Next: real-network isolated DNS protocol tests, encrypted DNS/DNSSEC/DHCP/cluster acceptance, threat-model review, GC UI theme/responsive/assistive-technology acceptance, packaging and onboarding audit, dependency vulnerability checks, and privacy-preserving DNS capabilities as separate reviewable changes.
