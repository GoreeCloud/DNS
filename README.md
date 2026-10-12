# GoreeCloud DNS

**Status: Fork-to-Native, initial source-import stage. Not a verified production DNS release.**

GoreeCloud DNS is a self-hosted, privacy-focused DNS resolver, filtering, and network protection project. Its initial source foundation is [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome). The aim is to progressively replace the inherited product architecture and interface with an independently maintained, GoreeCloud-native implementation.

**Implemented in the source baseline:** the inherited DNS service, filtering engine, user interfaces, build tooling, tests, and GPL-3.0 license. The existing Go module path, runtime settings, and upstream-specific identifiers remain unchanged until their compatibility impact is tested.

**Not verified yet:** a fully GoreeCloud-native DNS service, complete Glaze UI, GoreeCloud platform integrations, deployment, hardened security configuration, or migration from previous installations. Do not treat this branch as a production release.

## Coordinated networking platform

On October 12, 2026, the GoreeCloud owner designated **GoreeCloud Gateway, GoreeCloud VPN, and GoreeCloud DNS** as the **GoreeCloud Coordinated Networking Platform**. Within that coordinated family, DNS owns name resolution, filtering, and DNS policy; [VPN](https://github.com/GoreeCloud/VPN) owns encrypted private connectivity and approved remote/device access; and [Gateway](https://github.com/GoreeCloud/gateway) owns HTTP/HTTPS ingress and controlled service publication. Coordination must preserve independent policy authority, protect private network names, and never imply automatic public publication of discovered services.

This is an owner-defined architectural relationship, not evidence of completed integration, independently validated native DNS behavior, deployment, or production readiness.

## Product documentation

- [Beacon comprehensive product specifications](docs/PROJECT-SPECIFICATIONS.md) — proposed 34-area capability catalog, scope boundaries, and acceptance criteria.
- [Planned features](docs/PLANNED-FEATURES.md) — proposed workstreams and verification dependencies.
- [Implemented features](docs/IMPLEMENTED-FEATURES.md) — inherited source baseline versus demonstrated implementation.
- [Project record](docs/PROJECT-RECORD.md) — significant project history and decisions.

The Beacon catalog is a proposal; documentation alone does not establish that the described capabilities are operational.

## Development

See [Fork-to-Native roadmap](docs/FORK_TO_NATIVE.md) and [upstream source provenance](UPSTREAM.md). Original upstream documentation is retained in [docs/upstream/README.md](docs/upstream/README.md). The upstream GitHub Actions configuration, including its publishing and mirroring workflows, was not imported as executable automation.

The implementation remains subject to the [GNU General Public License v3.0](LICENSE.txt), including appropriate source availability and attribution. GoreeCloud DNS is an independent derivative project, not an official AdGuard product or an affiliated service.
