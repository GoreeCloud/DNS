# GoreeCloud DNS security guidance

**Development preview only.** This code is not a hardened public DNS recursive resolver or authoritative DNS server.

DNS listener traffic is unauthenticated by DNS protocol design. The gateway now has a default-loopback CIDR allowlist and rejects an unrestricted 0/0 wildcard; unauthorized client IPs receive REFUSED. Keep the daemon on loopback until a deliberately scoped LAN ACL, firewall rules, rate limiting, recursive amplification defenses, malicious-packet testing and safe deployment procedures are independently verified. The ACL is not a full DoS defense.

The administrative HTTP API requires a unique bearer token of at least 16 characters and binds to loopback by default. For remote access, use a trusted HTTPS proxy and independent access controls. Token rotation, user accounts, RBAC and certificate lifecycle management are not implemented. Environment variables and container inspection may expose token material to local administrators.

The daemon does not collect client identities, per-query histories or network telemetry. Upstream transport can be auto UDP/TCP, forced TCP, or certificate-verified DNS-over-TLS with an explicit server identity and optional custom root CA. The default auto mode remains unencrypted. DNSSEC validation and cache behavior are delegated to the separately deployed Unbound service, whose operational guarantees have not been independently verified. A bounded concurrent-upstream budget limits overload. The first explicit CIDR allowlist restricts client networks but does **not** implement per-client query rate limits or a complete DNS-amplification defense.

The local policy engine recognizes limited syntax, including explicit allow exceptions, but not arbitrary AdGuard options or regex filter logic. File and rule-count limits apply and invalid reloads preserve old policy. Review allow exceptions carefully since they override matching blocks. The authenticated policy-check API is POST-only to avoid domains entering ordinary URL logs.

For security reports, use GitHub private vulnerability reporting when enabled or an authorized private channel; never publish real credentials, query logs or private network data.

Production gates include broader protocol fuzzing, DNS-wire acceptance, per-client rate limits and firewall acceptance, supply-chain and image pins, signed builds, full TLS lifecycle, backups and restore rehearsal, and an explicitly rehearsed DNS cutover rollback. None is yet certified complete.

Local DNS override files are host-controlled, strictly parsed, size-limited (2 MiB), and atomically reloaded. Do not write real internal hostnames, IP topology, API secrets, or private DNS data into public GitHub. The API cannot create records or fetch remote rule sources. Locally configured records override upstream responses by exact name but never bypass block policy or the DNS client CIDR ACL. CNAME loops and resolver behavior are not yet fully evaluated; maintain a cautious staging-only rollout and avoid production use.

## Container build privacy

The Docker build context has an explicit source-code allowlist. Only Go compilation inputs, the two Dockerfiles and the Unbound development configuration are sent to the builder; local environment values, host policies and DNS record files are excluded. The runtime container never embeds private local policy files. Compose supplies config/rules.txt and config/local-records.txt as read-only bind mounts. Treat any locally edited, sensitive hostnames as private; do not commit or publish them to the public repository. This build policy mitigates inadvertent disclosure but does not replace container image or builder security reviews.

## Aggregate query-rate protection

The daemon now uses a bounded global token bucket (default 500 queries per second and burst 1000). After CIDR access checks, excess packets receive REFUSED. This protects upstream capacity without storing per-IP state or query history. Global throttling does not prevent one allowed host from starving other LAN clients; production rollouts require independently validated firewall and abuse controls.


## DNS wire validation and privacy

Outbound recursive traffic now strips client-provided EDNS options (including ECS and DNS Cookies), unsigned additional records, and TSIG before forwarding, while retaining only the EDNS UDP-size (up to 1232 bytes) and DNSSEC DO parameters. This does not prevent a chosen upstream from observing the original requested name or the gateway's egress address. Operators must evaluate their upstream resolver's privacy and transport configuration under GoreeShield policies. Upstream DNS response correlation validates the original question and rejects malformed/mismatched replies rather than forwarding them to clients. Only standard IN-class queries are processed, and UDP truncation is retried using TCP. DNSSEC cryptographic validation remains delegated to a separately operated resolver.

## Optional Porkbun API CLI — credential and DNS-change isolation

`tools/porkbun/` contains an optional Python CLI for the upstream Porkbun registrar. This integration is separate from the local DNS resolver and exposes no HTTP listener. It requires a per-domain API opt-in and a tightly scoped key. Use owner-only configuration directories (`0700`) and credentials (`0600`); neither credentials nor private zone snapshots belong in this public repository. The client refuses HTTP redirects, validates DNS delegation/preflight before guarded write paths, and requires an interactive operator confirmation for `dns-apply`. **Do not** treat successful offline tests, provider `dryRun` or a token's `dns` scope as production authorization or proof of rollback capability. A local `0600` DNS backup is plaintext and requires an independent encryption, retention and restore policy. No actual production DNS change or recovery rehearsal has been performed. See [`tools/porkbun/README.md`](tools/porkbun/README.md).

## Management API HTTPS and listener guard

The API fails closed when configured to bind outside localhost without a TLS certificate/private key or an explicit isolated-container opt-in. Direct HTTPS loads its certificate from owner-managed PEM files, checks private key file permissions, and requires TLS 1.2+. HTTP request header, read/write and idle timeouts are bounded. The opt-in DNS_API_ALLOW_INSECURE_REMOTE=true is a development escape hatch only for independently verified localhost-published container or trusted reverse-proxy topologies; it must never be treated as network encryption or a general permission to expose the API. External ingress, certificate management and role-based operator identities require separate staging and production acceptance.

## Qt Linux API credential handling

The native Linux management client now uses QUrl strict validation and QtNetwork requests with manual redirect refusal, default TLS certificate verification, bounded five-second transfer timeout, 64 KiB maximum JSON response, and canceled stale sessions. Its authenticated requests are not sent through the previous QML XMLHttpRequest mechanism. The API token is held in memory and never intentionally persisted by the client. Sensitive API values are still visible to the local authorized process user, and the app does not yet implement full GoreeCloud Identity, encrypted credential vaulting, or physical desktop security certification. The URL-validation offline CLI is a development and operator preflight; no network request occurs in that mode.

## Android management session minimization

The Android client now rejects non-HTTPS or credential-bearing URL origins and requires the API origin to have no path/query/fragment before making a request. It continues to reject HTTP redirects and to rely on platform TLS certificate validation. The activity uses FLAG_SECURE to reduce token exposure through screen capture, and it resets Compose session state when backgrounded rather than retaining bearer input intentionally. These controls are source-level changes until they pass the relevant build and device evidence; they do not replace GoreeCloud Identity, token revocation, secure key storage or independent mobile security testing.

## Inbound encrypted DNS listener

A separate DoT listener may be configured only with an explicit address and validated TLS certificate/key pair; it is inert without all required variables. Keys must be regular owner-only files and the service requires TLS 1.2+. A non-loopback DoT bind also needs an explicit DNS_DOT_ALLOW_REMOTE opt-in; CIDR ACL, global query budget and policy restrictions still apply. TLS client certificate validation is performed by the operator's client (no mutual TLS user identities or per-client authentication are implemented). The service is not exposed in the sample Compose topology. Do not mistake encryption for DNSSEC validation, firewall enforcement, certificate lifecycle or protection from public recursive DNS amplification. Dedicated acceptance and rollback are required before any real network configuration.

## Inbound DoH privacy and trust boundary

Inbound DoH binds only with explicit HTTPS TLS credentials. A remote listener requires a separate opt-in; actual DNS client ACLs and the global query budget apply identically over HTTPS. The handler never trusts X-Forwarded-For, sends no permissive CORS headers, uses no query cache, does not record per-client query history, and constrains content types, wire payload and connection times. TLS errors are not logged with client IP addresses. It deliberately uses the existing DNS/Unbound security model: DoH encrypts the client-to-gateway hop but does NOT validate DNSSEC signatures or imply privacy of any forwarded unencrypted resolver connection. Do not expose the preview on a public network without tested firewall policy, real certificate lifecycle, signed release, network isolation and rollback.

## Encrypted policy recovery trust boundary

The new dns-config CLI requires independently trusted age recipient encryption, validates each allowlisted policy/local-record file with the daemon's parsers, and writes only owner-only encrypted archives without overwriting existing backups. Decryption requires a separate owner-only private identity file. The dry-run is the default; an explicit apply action stages verified policy only in a new empty private directory, never on active service paths. Tests cover ciphertext tampering and accidental overwrite. Key escrow, production-volume restore, complete backup replication, application rollback, service continuity and TLS credentials remain separate acceptance gates.

## Protocol fuzz and DNSSEC validation limitations

Native fuzz harnesses stress the DNS wire parser, minimum-data upstream message construction, upstream question identity comparison, filter-list parser and local-record parser using synthetic, bounded inputs. Short CI fuzz runs can catch regressions, but cannot certify parser safety or DNSSEC trust. A mocked upstream AD (authenticated data) bit can be forwarded unchanged by the gateway; actual DNSSEC chain validation and its trust anchors belong to a separately tested Unbound runtime. Production acceptance requires DNSSEC positive/negative cases, malicious backend testing, high-throughput load and independently tested resolver failure behavior.

## Supply-chain source inventory and action pinning

First-party GitHub Actions workflows use immutable commit SHA references for checkout, language setup, Gradle/Android installation and artifact upload, based on verified upstream tag-to-commit objects. The Go development artifact carries a deterministic SPDX 2.3 partial source inventory of the resolved Go module graph and npm lockfile packages, checksum-verified alongside the compiled development binaries. It does not cover all Android/Qt native runtime dependencies, OS/container image layers, cryptographic signing, independent license attribution or vulnerability attestation. Unknown dependency licenses are NOASSERTION rather than guessed. Production publication requires full-platform dependency closure, reviewed upstream action updates, artifact authenticity and signed release provenance.
