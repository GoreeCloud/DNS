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
- DNS protocol smoke: locally generated localhost A-record queries over UDP and TCP returned matching transaction IDs and RCODE 5 (REFUSED), expected with recursion configured Deny. Additional regression assertions require the standard query opcode, an untruncated response, zero answer records, and an unchanged single localhost A/IN question; these remain limited wire-level checks. The anonymous settings API returned a denial; an explicitly configured missing administrator password file prevented first-run startup. These are limited offline checks, not external recursion or comprehensive authentication acceptance.
- Tests: fifteen Python contract tests passed locally, both edited browser scripts passed Node syntax checks, project XML parses, and patch whitespace checks pass. GitHub source and .NET build CI are required for each merged change.
- **New mock-wire CI coverage (pending exact-head verification):** `tests/test_dns_mock_wire.py` binds only ephemeral `127.0.0.1` ports and invokes the existing Perl UDP/TCP refusal assertions against synthetic valid and intentionally corrupted packets. It uses a strictly validated `GOREECLOUD_DNS_SMOKE_PORT` override; the rootless application-runtime test still targets port 53 by default. A passing mock test verifies the **test harness**, not live DNS resolver behavior, encrypted-DNS protocols, DNSSEC or production security.
- No external network access, resolver changes, DNS/DHCP host configurations, VPS services or production deployment were involved in runtime testing. The container and temporary configuration were disposable.

## Repeatable, offline DNS runtime smoke tests

After building the Release application according to the upstream build.md and the pinned dependency in CI, run:

    bash tests/smoke_runtime.sh /absolute/path/to/DnsServerApp/bin/Release

This is an **explicit opt-in** test; it is not automatically invoked by the hosted GitHub Actions build. It requires rootless Podman and its pre-pulled, pinned Microsoft .NET SDK container image. The harness copies build output to a temporary directory; runs the DNS application with portable configuration, no network access, no host port mappings, minimal container bind capability and recursion disabled; verifies the branded HTTP console and stylesheet, localhost DNS UDP and DNS-over-TCP REFUSED responses, and denial of unauthenticated administrative settings API access; then stops the server and removes temporary files. The harness now creates a strong random first-run administrator password in a disposable rootless container, confirms that the known default password fails, authenticates with the configured secret using a POST form read from a protected file, checks authorized settings access, logs out, and verifies session revocation. The secret, bearer token, and JSON responses remain in temporary container-mounted files and are not printed to the console; all are removed with the temporary workspace. The DNS response checks only basic protocol/service behavior, **not external recursion or DNSSEC correctness**. These session checks do not certify TLS, rate limiting, SSO, TOTP, or full authorization coverage.

Never substitute host networking, rootful Podman or a production DNS configuration to make this smoke test pass.

The isolated authoritative-zone smoke also creates the reserved test zone `smoke.invalid` and an A record `host.smoke.invalid → 192.0.2.42` through the authenticated local management API; the wire-level UDP and TCP tests verify AA, NOERROR, the expected answer address, and the configured TTL bound. These records exist only in disposable test configuration, never the host resolver or any networked deployment. This is authoritative local-zone correctness evidence, **not DNSSEC, recursive forwarding, negative caching, zone transfer, or external connectivity acceptance**.

The same opt-in isolated harness now verifies **negative authoritative responses** from the disposable zone on both UDP and TCP: `absent.smoke.invalid` A queries return NXDOMAIN (RCODE 3) with an SOA in the authority section, while `host.smoke.invalid` AAAA queries return NOERROR with no answers (NODATA) and an authoritative SOA. Both tests require the authoritative-answer flag and a matching transaction ID. This does not verify DNSSEC denial-of-existence proofs, recursive caching behavior, zone transfers, or external network interoperability.

## EDNS version rejection smoke

The rootless, network-disabled DNS protocol harness checks EDNS(0) error handling by sending a bounded valid DNS query with an unsupported **EDNS version 1** OPT record over UDP and TCP. The response must preserve the transaction ID, include exactly one OPT record, advertise EDNS version 0, and encode **BADVERS (extended DNS response code 16)**. Both wire checks passed locally against the disposable loopback DNS listener. This verifies one unsupported-version boundary, **not** broad EDNS option parsing, truncation, amplification resistance, malformed-packet fuzzing, DNSSEC validation, or public-network interoperability.

## First-run administrator credential safety

**This is a development distribution, not a hardened public deployment.** In a fresh upstream-derived configuration, the administrator account defaults to `admin/admin` when no administrator password configuration is provided. Do not expose the management console or API to an untrusted network with that default. Change credentials before any networked staging, restrict the management listener with `DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES` and network policy, and use trusted HTTPS when applicable.

For a *new* configuration, prefer a strong, access-restricted secret file specified by `DNS_SERVER_ADMIN_PASSWORD_FILE`. Confirm that it is readable **inside the container or service identity** and contains a nonempty first line. The GoreeCloud security change prevents an explicit missing, unreadable, empty, or whitespace-only secret file from falling back to the known password; startup must fail closed instead. The disposable runtime harness explicitly checks missing, zero-byte, and whitespace-only files, requires a nonzero process exit (not a timeout), and matches the first-run credential-initialization failure before running the healthy-server tests. `DNS_SERVER_ADMIN_PASSWORD` remains an upstream-supported environment override, but the secret-file mechanism avoids unnecessarily placing the password directly in process environment. Existing persisted `auth.config` is loaded separately and is **not automatically reinitialized** from these first-run variables.

Do not place password contents in repository files, build logs, CI variables printed to output, command arguments, or documentation. Review upstream password-reset mechanisms before using them in an authorized, isolated recovery. The upstream-derived login endpoint currently accepts both GET and POST and reads credentials from query or form parameters. **Use POST form bodies over trusted HTTPS for authenticated network deployments; never put passwords in URL query strings**, which may be retained in browser history, reverse-proxy access logs, or monitoring systems. The isolated loopback-only test uses a POST form read from a temporary protected file; this documents safer client behavior but does not disable the inherited GET route. The offline smoke test covers the missing-secret first-run failure path but not all authentication, SSO, TOTP, rate limiting, or privilege-management behaviors.

## Local administrator login lockout smoke

The opt-in, rootless, `--network=none` harness now checks the existing source-IP login limiter **after** all other authenticated API checks. Five bounded invalid password attempts against the disposable loopback server must fail; the subsequent correct password must also fail with the expected maximum-attempts message. This tests only the imported implementation's five-attempt, five-minute lockout in one temporary process, not distributed or reverse-proxied client identification, lockout persistence, denial-of-service resistance, SSO/TOTP, or complete authentication security. No real accounts or production users are targeted, and no secrets or bearer tokens are printed.

## Isolated duplicate-listener startup behavior

The optional smoke harness now launches a second DNS process with independent temporary configuration while the original process holds the container's loopback management/DNS listeners. Under `--stop-if-bind-fails`, the duplicate must exit unsuccessfully before timeout and log a bind/address-in-use error. The test then checks that the first console still responds and continues the UDP/TCP DNS and authentication suite. No host port mappings, production server instances, external networks or persisted configurations are involved. This is **not** proof of high availability, cluster failover or safe live production restarts.

## Docker Compose example — upstream image and safe management binding

The repository includes an **upstream Technitium sample** `docker-compose.yml` that pulls `docker.io/technitium/dns-server:latest`. Running that sample does **not** run GoreeCloud's source changes or regression tests. The image tag is mutable, and release-image provenance and dependency pinning remain open under [issue #8](https://github.com/GoreeCloud/DNS/issues/8). Do not represent this sample as a validated GoreeCloud deployment.

The example's plaintext HTTP management port 5380 is now **bound to the Docker host loopback address** (`127.0.0.1:5380:5380/tcp`) rather than all host interfaces. This limits direct external exposure on normal host networking, but is not a substitute for unique first-run credentials, least-privilege access, TLS and firewall review. Do not publish, reverse-proxy, or forward the management service to an untrusted network without a separately verified secure configuration. DNS port 53 is exposed by the upstream example for its intended resolver function; assess public recursion/ACL, application trust and network policy before any deployment. No running Compose service was modified.

## Build and release gates

Build requires .NET 10 and the separate sibling TechnitiumLibrary source/build described in the upstream build.md. Basic isolated web, UDP/TCP DNS, and anonymous API boundary smoke tests pass; they are not substitutes for real-network DNS, encrypted DNS, DHCP, upgrade, package, browser, assistive-technology, or production deployment tests. DNS and DHCP system settings are deliberately untouched.

Next: real-network isolated DNS protocol tests, encrypted DNS/DNSSEC/DHCP/cluster acceptance, threat-model review, GC UI theme/responsive/assistive-technology acceptance, packaging and onboarding audit, dependency vulnerability checks, and privacy-preserving DNS capabilities as separate reviewable changes.
