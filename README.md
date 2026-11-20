# GoreeCloud DNS

Open-source, self-hosted DNS filtering and resolver management, currently an **early development preview**. It is not yet a production-ready Technitium DNS, AdGuard Home, Pi-hole or Unbound replacement.

## Implemented source

- First-party Go DNS gateway for UDP and TCP, using the BSD-licensed miekg/dns library; forwarding to a configurable recursive resolver.
- Local deny rules using domain names, hosts-file lines and simple AdGuard domain patterns. Invalid policy reloads preserve the last good policy.
- Protected administrator API using an environment-injected bearer token, reporting aggregate query, blocked-query, upstream-error and rule counts.
- React + TypeScript web management dashboard, including connect, refresh, reload, and disconnect.
- Native Qt Quick 6.12.0 Linux management UI source.
- Native Kotlin + Jetpack Compose Android management UI source, requiring trusted HTTPS.
- Separately packaged Unbound recursive resolver configuration for Docker Compose local development.
- Unit tests, CI workflows, build manifests, Dockerfiles, security documentation and third-party attribution.

The gateway currently retains no per-client addresses or query history. It implements a domain-suffix blocking policy only; regex, exceptions, authoritative zone administration, DNSSEC validation in the gateway, DoH, DoT, DHCP, advanced ACLs and production-grade filtering features remain unimplemented.

## Local development

Prerequisites: Go 1.25, an available upstream recursive resolver on localhost port 5335, and a unique API token of at least 16 characters. For convenience use an installed Unbound service, or the included local-only Docker Compose development topology.

1. Copy the example environment file to a private environment file and generate a strong token. Never commit secrets.
2. Set the DNS_API_TOKEN environment variable in your shell, then execute: go run ./cmd/dnsd
3. By default the DNS gateway binds to 127.0.0.1:1053, the admin API to 127.0.0.1:8080, and the upstream to 127.0.0.1:5335.
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

## Upstream projects and licenses

The Go DNS package miekg/dns (BSD-3-Clause) is a module dependency and Unbound (BSD-3-Clause) is integrated as a separate runtime. Technitium DNS (GPL-3.0), AdGuard Home (GPL-3.0) and Pi-hole FTL (EUPL-1.2) are identified compatibility targets; their source is **not yet copied, bundled or integrated**. Full source import requires revision-specific license and dependency review. See third_party/README.md.

Original GoreeCloud source is MIT-licensed (see LICENSE); third-party components retain their own terms.

## Verification and limitations

Suggested checks: go mod tidy, go test -race ./..., go vet ./..., go build ./cmd/dnsd, npm run build inside web, Android Gradle assembleDebug, and the Qt native Linux build. A CI workflow runs Go, web and Android checks, but until successful run evidence is available these are **unverified**. Linux device testing and DNS-wire isolated acceptance are pending.

Read SECURITY.md, docs/architecture.md and docs/roadmap.md before using this project beyond localhost. Do not change LAN port 53, production DNS routing or firewall rules based on this preview.
