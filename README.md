# GoreeCloud DNS

Open-source, self-hosted DNS filtering and resolver management, currently an **early development preview**. It is not yet a production-ready Technitium DNS, AdGuard Home, Pi-hole or Unbound replacement.

## Implemented source

- First-party Go DNS gateway for UDP and TCP, using the BSD-licensed miekg/dns library; forwarding to a configurable recursive resolver.
- Local deny rules using domain names, hosts-file lines, simple AdGuard domain patterns, and explicit `@@||domain^` allow exceptions. Invalid policy reloads preserve the last good policy; parsing rejects oversized or unsupported files rather than partially loading them.
- Optional local A, AAAA, and CNAME DNS record overrides loaded from a validated local file. Exact-name matches never contact the upstream; block rules take precedence. Unsupported record syntax or failed reload preserves the prior working records.
- Protected administrator API using an environment-injected bearer token; aggregate counters include queries, blocked requests, upstream errors, overload refusals, rules, and exception counts. A private authenticated POST endpoint previews a domain's policy without creating a DNS query.
- React + TypeScript web management dashboard, including connect, refresh, local policy preview, DNS record reload, rule reload, and disconnect.
- Native Qt Quick 6.12.0 Linux management UI source with aggregate counters and local policy preview.
- Native Kotlin + Jetpack Compose Android management UI source with aggregate counters, local policy preview and strict HTTPS-only transport without redirects.
- Separately packaged Unbound recursive resolver configuration for Docker Compose local development.
- Unit tests, CI workflows, build manifests, Dockerfiles, security documentation and third-party attribution.

The gateway currently retains no per-client addresses or query history. Supported filtering is domain suffix blocking and explicit allow exceptions, not full AdGuard syntax or regex. It has optional certificate-verified DNS-over-TLS upstream forwarding and a separately configured **inbound** DNS-over-TLS listener, disabled by default. It does not provide inbound DoH or DoQ. Authoritative zone administration, DNSSEC validation in the gateway, DHCP, advanced ACLs, scheduled blocklist updates and production-grade filtering remain unimplemented.

## Local development

Prerequisites: Go 1.25, an available upstream recursive resolver on localhost port 5335, and a unique API token of at least 16 characters. For convenience use an installed Unbound service, or the included local-only Docker Compose development topology.

1. Copy the example environment file to a private environment file and generate a strong token. Never commit secrets.
2. Set the DNS_API_TOKEN environment variable in your shell, then execute: go run ./cmd/dnsd
3. By default the DNS gateway binds to 127.0.0.1:1053, the admin API to 127.0.0.1:8080, and the upstream to 127.0.0.1:5335. `DNS_MAX_CONCURRENT` defaults to 128; excess upstream requests receive SERVFAIL while local-policy blocks remain responsive.
4. Query with: dig @127.0.0.1 -p 1053 example.com A
5. For the React client, change into the web directory, execute npm install and npm run dev, then open http://127.0.0.1:5173. The local Vite development proxy connects to the local API.

Alternatively, set DNS_API_TOKEN in the shell and run docker compose up --build at the repository root. The Compose configuration starts the gateway and a separate Unbound resolver, publishing DNS port 1053 and admin port 8080 to **localhost only**. This configuration is development-only and is not an approved production DNS migration.

## Native applications

**Linux:** Requires Qt 6.12.0 with Quick and Quick Controls 2, CMake and a C++17 compiler. Commands: cmake -S linux -B build/linux, then cmake --build build/linux. A tested Linux package or device acceptance is not yet available.

**Android:** Requires JDK 17, Android platform SDK 35 and Gradle 8.13. From the android directory, use gradle :app:assembleDebug. Source is included but an installable, independently verified APK is not yet available.

**Web:** Run npm run build within the web directory for a static build. The static frontend must be deployed behind a same-origin trusted HTTPS proxy to the administrator API for remote operation. The current server API is unencrypted loopback HTTP only; never publish it directly to untrusted networks or send the bearer token via remote HTTP.

## API

| Method | Path | Auth | Result |
| --- | --- | --- | --- |
| GET | /healthz | None | Process HTTP response only; does not test DNS upstream |
| GET | /api/v1/status | Bearer | JSON with product, state, queries, blocked, upstream_errors and rules |
| POST | /api/v1/rules/reload | Bearer | Reload the configured local rules file, preserving the prior set if invalid |
| POST | /api/v1/policy/check | Bearer | JSON request `{ "name": "example.org" }`; returns normalized name and `allowed`, `blocked` or `unmatched` decision without generating DNS traffic |
| POST | /api/v1/local/reload | Bearer | Reload bounded local A/AAAA/CNAME overrides atomically; invalid files retain previous records, disabled configuration returns 409 |

## Upstream projects and licenses

The Go DNS package miekg/dns (BSD-3-Clause) is a module dependency and Unbound (BSD-3-Clause) is integrated as a separate runtime. Technitium DNS (GPL-3.0), AdGuard Home (GPL-3.0) and Pi-hole FTL (EUPL-1.2) are identified compatibility targets; their source is **not yet copied, bundled or integrated**. Full source import requires revision-specific license and dependency review. See third_party/README.md.

Original GoreeCloud source is MIT-licensed (see LICENSE); third-party components retain their own terms.

## Verification and limitations

Suggested checks: go mod tidy, go test -race ./..., go vet ./..., go build ./cmd/dnsd, npm ci and npm run build inside web, Android Gradle assembleDebug, and the Qt native Linux build. The initial CI baseline has passed Go tests, React, Android debug assembly, native Qt Quick 6.12.0 compilation and headless launch, and a containerized loopback DNS-wire NXDOMAIN smoke. This is **development test evidence only**: actual Android installation, physical Linux device testing, broad DNS protocol security, recovery, and LAN cutover remain unverified.

Read SECURITY.md, docs/architecture.md and docs/roadmap.md before using this project beyond localhost. Do not change LAN port 53, production DNS routing or firewall rules based on this preview.


## GoreeCloud UI token provenance

The web client includes a pinned copy of the official alpha GoreeCloud UI semantic token stylesheet in `web/src/gc-tokens.css`. The Android Compose color scheme and Linux QML colors map to the same source: [GoreeCloud/gc-ui](https://github.com/GoreeCloud/gc-ui) commit `be6fdda0dfa9ca509c01bafb9ed483a272fa821b` (MIT license). This pins verifiable design values without making an unreviewed live dependency. The alpha colors remain provisional, and visual/device acceptance remains outstanding.

## DNS-over-TLS upstream forwarding (development)

Set `DNS_UPSTREAM_MODE=tls`, `DNS_UPSTREAM_ADDR=203.0.113.10:853` (replace the documentation IP with the **real** server), and `DNS_UPSTREAM_TLS_NAME=resolver.example.org` (replace with the expected TLS certificate identity). The resolver must validate a trusted server certificate matching this name; the daemon never enables insecure certificate verification. Optionally supply a trusted PEM CA file using `DNS_UPSTREAM_TLS_CA_FILE`. The custom CA file must be explicitly readable by the daemon and is not mounted by the sample Compose topology. Use `DNS_UPSTREAM_MODE=tcp` to force conventional upstream TCP or `auto` (default) for client-aware UDP/TCP with TCP retry on UDP truncation.

These controls configure outbound encrypted queries only; **they do not protect the inbound DNS listener or management HTTP API**. Keep the API bound to localhost or behind trusted HTTPS. DNS-over-TLS does not itself eliminate upstream metadata or replace GoreeShield privacy controls. Verify resolver identity, reachable port, certificate validity and trusted network egress before activation.

Rules files accept one blocked domain per line, hosts-file `0.0.0.0`/ `127.0.0.1`/ `::` entries, `||blocked.example^`, and `@@||allowed.blocked.example^`. Exceptions override matching blocks. The file limit is 16 MiB and 250,000 distinct rules, with at most 256 KiB per line. Unsupported syntax rejects the entire reload and retains the prior active policy. No remote blocklist fetching occurs.

## Network client access control (development)

The daemon refuses DNS queries unless the client IP belongs to `DNS_ALLOWED_CIDRS`. Without an explicit override, only `127.0.0.0/8` and `::1/128` are accepted—even if someone configures the listener to bind to all interfaces. For an isolated home network, explicitly configure only the actual local prefixes you intend to serve (for example `DNS_ALLOWED_CIDRS=127.0.0.0/8,192.168.50.0/24`). Invalid CIDRs and unrestricted `0.0.0.0/0` or `::/0` are rejected at startup. Unauthorized DNS clients receive REFUSED and increment a non-identifying aggregate counter. Client IPs are not stored or logged.

The development Docker Compose topology explicitly permits RFC1918 bridge clients, while still publishing DNS and the admin API on **host loopback only**. The bundled Unbound recursive backend also refuses non-private-network clients. These are defense-in-depth development controls, not a substitute for firewall rules, rate limits, safe authoritative configuration or a tested public resolver deployment. Do **not** expose port 53 or the internal Unbound service to the Internet.

## Local DNS record overrides (development)

The new `DNS_LOCAL_RECORDS_FILE` setting points to a file of optional **exact-name** DNS overrides. The default repository path is `config/local-records.txt`; all entries are commented, so no local responses are generated until the operator adds records. Supported formats are:

```text
A printer.example 192.0.2.42
AAAA host.example 2001:db8::42
CNAME alias.example host.example
```

These are **documentation addresses**, not real network destinations. Each non-comment line requires precisely `TYPE NAME VALUE`. The resolver uses 60-second TTL for local records and only serves explicit exact matches; an unknown name still forwards to Unbound. The same local name with a different requested record type receives NOERROR with no answers (NODATA). A CNAME cannot coexist with A/AAAA for the same name. The code does **not** implement general authoritative zone hosting, DNS record management via the API, SOA/NS records, DNSSEC signing, wildcards, live service discovery, or DHCP. The gateway's deny-policy rules take precedence even for configured local records.

The parser rejects invalid IPs/names, unsupported types, files larger than 2 MiB, or more than 10,000 distinct overrides. Edit records on the host and call authenticated `POST /api/v1/local/reload` or the equivalent management-client control to atomically refresh; errors leave the prior active set intact. The API never accepts raw record values, file paths, shell commands, or remote downloads. Local record aggregate metrics contain counts only; the API does not expose private hostnames. The development Compose topology mounts this file read-only and publishes DNS ports to loopback only.

## Container image data-minimization

The Go image build uses a source allowlist and copies only compilation inputs. It does not include private policy files or local-record overrides in image layers. The development Compose topology mounts both configuration files read-only at runtime; a standalone container started without the required rule file will fail closed. Never commit real internal hostnames or secrets into public source, and never publish an image containing private runtime configuration.

## Process-wide privacy-preserving rate limit (development)

A token-bucket query budget now caps the total number of DNS packets processed by a gateway instance. DNS_RATE_QPS defaults to 500 accepted queries per second, with DNS_RATE_BURST=1000 allowing short spikes. The permitted ranges are 1 to 20,000 requests per second and 1 to 50,000 burst tokens. Invalid negative or over-limit values stop startup; zero values resolve to the defaults. The budget runs after the client CIDR ACL but before policy matching and upstream forwarding. Exhausted capacity returns DNS REFUSED without contacting the upstream resolver and increments an aggregate rate_limited counter. The counter is visible in the authenticated API and web/Linux/Android clients.

This is a global limit only: the implementation does not keep per-client IP identifiers, query histories or rolling personal profiles. A single abusive LAN client can still consume the shared budget, so proper router/firewall controls and per-source throttling require a separate privacy review. The mechanism is not a comprehensive amplification or DoS defense and is not a production capacity guarantee.


## DNS wire protocol and client metadata minimization (development)

Upstream recursive requests now remove all client-supplied DNS additional records and EDNS options, including EDNS Client Subnet and client cookies, before forwarding. The gateway keeps only EDNS UDP payload-size (capped at 1232 bytes) and DNSSEC DO preference when a client supplied EDNS0; the original client message remains unchanged. This reduces accidental leakage of client subnet and opaque identifiers, but it does not hide the DNS question, the gateway egress IP, or upstream timing from the chosen resolver.

Upstream responses must be DNS replies to exactly the original question, matching query ID, opcode, case-insensitive name, type and class. Invalid or still-truncated upstream responses are rejected as SERVFAIL and counted as upstream errors. UDP truncation triggers a TCP retry on the same configured upstream, where supported. Incoming DNS UPDATE and non-IN class questions receive NOTIMP instead of being forwarded.

The isolated tests cover synthetic EDNS Client Subnet/Cookie stripping, DNSSEC DO pass-through, UDP truncation plus TCP retry, unrelated response rejection, and non-query opcode handling. Do not interpret these tests as production DNSSEC validation, a complete RFC compliance test suite, client anonymity, or a production-grade authoritative DNS service.

## Optional Porkbun registrar API tooling

The repository now includes an independently operated, **development-stage** Python Porkbun CLI under [`tools/porkbun/`](tools/porkbun/README.md). It performs scoped account/domain reads, private zone backups, DNS safety preflights, non-mutating restore previews, and guarded `dryRun` previews. The executable is not used by the DNS resolver service or native clients, is not a public management API, and has not performed a production DNS mutation. Unit tests run without credentials. See [security guidance](SECURITY.md) before enabling it on a host.

## Management API transport security (development)

By default, the administrative HTTP listener only accepts a loopback bind address. A non-loopback bind is rejected on startup unless the administrator supplies a matching TLS certificate and key, or explicitly opts into a restricted development proxy/bridge. For direct HTTPS, configure DNS_API_TLS_CERT_FILE and DNS_API_TLS_KEY_FILE together. The private key must be a regular file readable by the daemon owner and inaccessible to group/other users. TLS 1.2 or later is required. Clients must independently verify server identity.

For a development-only container bridge with a separately protected loopback host mapping, DNS_API_ALLOW_INSECURE_REMOTE=true permits an HTTP bind to the container interface. The bundled Docker Compose example uses that exception specifically because it exposes the management port on 127.0.0.1 of the host. This exception does not create a secure remote management service and must NEVER be used for direct Internet/LAN exposure without a trusted HTTPS proxy, firewall rules, and operator-controlled credentials.

The HTTP server has header, read, write and idle timeouts and a bounded header size. The static bearer-token authentication remains a development-only management method; token rotation, Identity integration, MFA, audit policy and production TLS lifecycle are not yet implemented. No running host or router DNS listener was changed as part of these source changes.

## Temporary development build artifacts

GitHub CI now retains four short-lived development-only artifacts for the Go Linux daemon, React static web bundle, Android debug APK and non-standalone Qt 6.12 Linux executable. Each includes checksums and exact source-commit context. Consult docs/development-artifacts.md for verification and platform limitations. These artifacts are not signed installers, Stable releases or production deployments.

## Native Linux management transport safeguards

The Qt Quick 6.12 Linux client now uses a first-party C++ QtNetwork bridge instead of QML XMLHttpRequest. It validates complete HTTP/HTTPS URLs, rejects embedded credentials or query/fragment/path segments, and only permits plaintext HTTP for actual loopback hosts. Redirects are disabled before bearer authorization headers are sent; TLS verification stays enabled. Responses have a 64 KiB ceiling, connections use a five-second timeout, and changing the endpoint or token cancels pending requests to prevent stale session results.

The Linux binary supports a non-network endpoint validation preflight: goreecloud-dns-linux --validate-endpoint URL. This accepts trusted HTTPS origins or localhost HTTP and returns exit code 2 for rejected endpoints, without connecting or reading credentials. The CI test checks deceptive localhost-prefix URLs and other invalid cases. Native Qt build/headless acceptance is not evidence of correct operation on every physical Linux desktop.

## Android device and session safeguards

A previous debug APK was independently checksum-verified, temporarily installed, cold-launched on an authorized Android 17 ARM64 handset, and uninstalled without altering any DNS configuration. See docs/ANDROID-PHYSICAL-SMOKE.md. This is limited first-run evidence, not authentication, device accessibility or a release certification.

The updated native Android Compose client validates only trusted HTTPS origins without embedded credentials, path, query or fragments before attaching its management bearer token. Unit tests reject deceptive URLs. The token-bearing screen now requests Android FLAG_SECURE screenshot protection and clears remembered session state when the activity moves to the background. Those newly implemented behaviors require their own exact-commit CI and physical test evidence before being marked physically accepted.

## Optional inbound DNS-over-TLS listener (development)

The gateway supports a separate encrypted DNS-over-TLS listener using the same local policy, CIDR allowlist, global query-rate limit, and upstream recursive forwarding path as its normal UDP/TCP DNS listener. It is **disabled by default**. Operators must explicitly set all three environment values:

- DNS_DOT_LISTEN_ADDR=127.0.0.1:8853 (synthetic/local example; not standard public port 853)
- DNS_DOT_TLS_CERT_FILE=/path/to/owner-managed/server.crt
- DNS_DOT_TLS_KEY_FILE=/path/to/owner-only/server.key

An invalid or missing certificate/key, group/world-readable private key, port conflict, or incomplete configuration fails startup. The server requires TLS 1.2+ and supports the DNS-over-TLS ALPN identifier when negotiated. Client applications must independently verify the certificate identity; DoT is **not** an anonymous or authenticated-user management protocol.

Only explicitly configured non-loopback binds are permitted with DNS_DOT_ALLOW_REMOTE=true. This opt-in does not override DNS_ALLOWED_CIDRS: the existing DNS client ACL still defaults to loopback-only, and operators must separately scope the exact trusted LAN networks. Apply firewall rules and owner-controlled TLS identity before any LAN access. No Compose host port, VPS listener, router DNS, or firewall change is made by this source feature. Never publish this preview resolver on a public network or use it for production cutover.

Synthetic loopback tests exercise valid certificate trust, real encrypted A-record queries, filtered NXDOMAIN replies, invalid/unsafe configuration rejection, and client rejection of an untrusted certificate. They do not establish broad DNSSEC/DoH compatibility, certificate renewal, signed releases, real-device secure DNS settings, operational capacity or production readiness.

## Recipient-encrypted policy backup and staged recovery

The first-party cmd/dns-config companion tool uses independently installed age X25519 encryption for bounded backups of only rules.txt and local-records.txt. It validates with the same Go source parsers, includes integrity checks, rejects overwrites, and never writes a plaintext backup. Restores default to dry-run; an explicit apply flag creates a NEW, private staging directory without modifying running DNS or system resolver settings. This intentionally excludes API tokens and TLS keys. See docs/config-recovery.md for commands and the unaccepted full-disaster-recovery requirements.
