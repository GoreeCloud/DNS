# GoreeCloud DNS

Open-source, self-hosted DNS filtering and resolver management, currently an **early development preview**. It is not yet a production-ready Technitium DNS, AdGuard Home, Pi-hole or Unbound replacement.

## Implemented source

- First-party Go DNS gateway for UDP and TCP, using the BSD-licensed miekg/dns library; forwarding to a configurable recursive resolver.
- Local deny rules using domain names, hosts-file lines, simple AdGuard domain patterns, and explicit `@@||domain^` allow exceptions. Invalid policy reloads preserve the last good policy; parsing rejects oversized or unsupported files rather than partially loading them.
- Protected administrator API using an environment-injected bearer token; aggregate counters include queries, blocked requests, upstream errors, overload refusals, rules, and exception counts. A private authenticated POST endpoint previews a domain's policy without creating a DNS query.
- React + TypeScript web management dashboard, including connect, refresh, local policy preview, reload, and disconnect.
- Native Qt Quick 6.12.0 Linux management UI source with aggregate counters and local policy preview.
- Native Kotlin + Jetpack Compose Android management UI source with aggregate counters, local policy preview and strict HTTPS-only transport without redirects.
- Separately packaged Unbound recursive resolver configuration for Docker Compose local development.
- Unit tests, CI workflows, build manifests, Dockerfiles, security documentation and third-party attribution.

The gateway currently retains no per-client addresses or query history. Supported filtering is domain suffix blocking and explicit allow exceptions, not full AdGuard syntax or regex. It has optional authenticated DNS-over-TLS **upstream forwarding** but does not offer inbound DoT/DoH listeners. Authoritative zone administration, DNSSEC validation in the gateway, DHCP, advanced ACLs, scheduled blocklist updates and production-grade filtering remain unimplemented.

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

## Upstream projects and licenses

The Go DNS package miekg/dns (BSD-3-Clause) is a module dependency and Unbound (BSD-3-Clause) is integrated as a separate runtime. Technitium DNS (GPL-3.0), AdGuard Home (GPL-3.0) and Pi-hole FTL (EUPL-1.2) are identified compatibility targets; their source is **not yet copied, bundled or integrated**. Full source import requires revision-specific license and dependency review. See third_party/README.md.

Original GoreeCloud source is MIT-licensed (see LICENSE); third-party components retain their own terms.

## Verification and limitations

Suggested checks: go mod tidy, go test -race ./..., go vet ./..., go build ./cmd/dnsd, npm run build inside web, Android Gradle assembleDebug, and the Qt native Linux build. A CI workflow runs Go, web and Android checks, but until successful run evidence is available these are **unverified**. Linux device testing and DNS-wire isolated acceptance are pending.

Read SECURITY.md, docs/architecture.md and docs/roadmap.md before using this project beyond localhost. Do not change LAN port 53, production DNS routing or firewall rules based on this preview.


## GoreeCloud UI token provenance

The web client includes a pinned copy of the official alpha GoreeCloud UI semantic token stylesheet in `web/src/gc-tokens.css`. The Android Compose color scheme and Linux QML colors map to the same source: [GoreeCloud/gc-ui](https://github.com/GoreeCloud/gc-ui) commit `be6fdda0dfa9ca509c01bafb9ed483a272fa821b` (MIT license). This pins verifiable design values without making an unreviewed live dependency. The alpha colors remain provisional, and visual/device acceptance remains outstanding.

## DNS-over-TLS upstream forwarding (development)

Set `DNS_UPSTREAM_MODE=tls`, `DNS_UPSTREAM_ADDR=203.0.113.10:853` (replace the documentation IP with the **real** server), and `DNS_UPSTREAM_TLS_NAME=resolver.example.org` (replace with the expected TLS certificate identity). The resolver must validate a trusted server certificate matching this name; the daemon never enables insecure certificate verification. Optionally supply a trusted PEM CA file using `DNS_UPSTREAM_TLS_CA_FILE`. The custom CA file must be explicitly readable by the daemon and is not mounted by the sample Compose topology. Use `DNS_UPSTREAM_MODE=tcp` to force conventional upstream TCP or `auto` (default) for client-aware UDP/TCP with TCP retry on UDP truncation.

These controls configure outbound encrypted queries only; **they do not protect the inbound DNS listener or management HTTP API**. Keep the API bound to localhost or behind trusted HTTPS. DNS-over-TLS does not itself eliminate upstream metadata or replace GoreeShield privacy controls. Verify resolver identity, reachable port, certificate validity and trusted network egress before activation.

Rules files accept one blocked domain per line, hosts-file `0.0.0.0`/ `127.0.0.1`/ `::` entries, `||blocked.example^`, and `@@||allowed.blocked.example^`. Exceptions override matching blocks. The file limit is 16 MiB and 250,000 distinct rules, with at most 256 KiB per line. Unsupported syntax rejects the entire reload and retains the prior active policy. No remote blocklist fetching occurs.
