# GoreeCloud DNS

GoreeCloud DNS is a privacy-first, self-hosted DNS platform under active Development.

The target product combines recursive resolution, authoritative DNS, encrypted DNS, network-wide filtering, policy, DHCP integration, observability, automation, and resilient multi-node operation while preserving administrator ownership and GoreeCloud privacy/security boundaries.

> **Current implementation status:** This repository contains a bounded Go Development service foundation plus a first-party in-process DNS request pipeline. The pipeline defines Policy, Authority, Cache, and Resolver contracts with deterministic fail-closed coordination, but it is not connected to DNS wire traffic. The repository does **not** yet serve DNS traffic or establish a production deployment, release, or Stable status.

## Product identity

- **Product:** GoreeCloud DNS
- **Capability umbrella:** GoreeCloud Beacon
- **Lifecycle:** Development
- **Repository:** `GoreeCloud/DNS`
- **Repository ID:** `1391515788`
- **Default branch:** `main`

## Development foundation

The first executable slice intentionally does not open DNS UDP/TCP sockets. It provides:

- `cmd/goreecloud-dns`;
- loopback-only operational binding through `GOREECLOUD_DNS_ADMIN_LISTEN`;
- `/healthz` and `/readyz`;
- bounded HTTP server limits and graceful shutdown;
- unit tests, exact-source CI, and reachable-vulnerability scanning;
- architecture, security, privacy, Platform Contract, and nine-system integration boundaries;
- `internal/dnscore`, a non-network request-processing core ordered policy → authority → cache → resolver, with short-circuit and failure-path tests.

The default Development control-plane address is `127.0.0.1:8853`.

## Documentation

- [Project specifications](PROJECT-SPECIFICATIONS.md) — authoritative target product specification.
- [Project record](PROJECT-RECORD.md) — current repository state and historical lineage boundary.
- [Architecture](ARCHITECTURE.md), [security](SECURITY.md), and [privacy](PRIVACY.md).
- [Platform integrations](PLATFORM-INTEGRATIONS.md).
- [Beacon capability taxonomy](BEACON.md).
- [Features](FEATURES.md), [implemented features](IMPLEMENTED-FEATURES.md), and [planned features](PLANNED-FEATURES.md).
- [Capabilities](CAPABILITIES.md), [competitive objectives](COMPETITIVE-OBJECTIVES.md), [benefits](BENEFITS.md), [branding](BRANDING.md), [user manual](USER-MANUAL.md), and [changelogs](CHANGELOGS.md).

## Current boundary

The predecessor DNS implementation is not present in this recreated repository lineage. Historical evidence remains historical. New DNS capabilities must be implemented and verified in this repository before they are promoted from planned to implemented state.
