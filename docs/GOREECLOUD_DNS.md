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
- DNS UDP smoke: a locally generated localhost A-record query returned a valid response with matching transaction ID and RCODE 5 (REFUSED), expected because recursion was explicitly configured Deny. This tests basic DNS transport and permission handling, not resolver correctness under external network access.
- Tests: six Python contract tests passed, both edited browser scripts passed Node syntax checks, XML project files parse, and patch whitespace checks pass.
- No external network access, resolver changes, DNS/DHCP host configurations, VPS services or production deployment were involved in runtime testing. The container and temporary configuration were disposable.

## Repeatable, offline DNS runtime smoke tests

After building the Release application according to the upstream build.md and the pinned dependency in CI, run:

    bash tests/smoke_runtime.sh /absolute/path/to/DnsServerApp/bin/Release

This is an **explicit opt-in** test; it is not automatically invoked by the hosted GitHub Actions build. It requires rootless Podman and its pre-pulled, pinned Microsoft .NET SDK container image. The harness copies build output to a temporary directory; runs the DNS application with portable configuration, no network access, no host port mappings, minimal container bind capability and recursion disabled; verifies the branded HTTP console and stylesheet, localhost DNS UDP and DNS-over-TCP REFUSED responses, and denial of unauthenticated administrative settings API access; then stops the server and removes temporary files. The DNS response checks only basic protocol/service behavior, **not external recursion or DNSSEC correctness**.

Never substitute host networking, rootful Podman or a production DNS configuration to make this smoke test pass.

## Build and release gates

Build requires .NET 10 and the separate sibling TechnitiumLibrary source/build described in the upstream build.md. Basic isolated web and UDP smoke tests now pass; they are not substitutes for real-network DNS, encrypted DNS, DHCP, upgrade, package, browser, assistive-technology, or production deployment tests. DNS and DHCP system settings are deliberately untouched.

Next: isolated .NET build and protocol verification, threat-model review, GC UI theme/responsive acceptance, packaging and onboarding audit, vulnerability checks, then privacy-preserving DNS capabilities as separate reviewable changes.
