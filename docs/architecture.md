# Architecture

## Development data path

DNS clients --> GoreeCloud UDP/TCP DNS gateway :1053 --> local policy decision --> Unbound recursive service :5335 --> DNS hierarchy.

Clients outside the explicit CIDR allowlist receive REFUSED before domain policy is checked. Without an override, only loopback-source addresses may use the resolver. After CIDR authorization, a process-global, identity-free token bucket bounds the aggregate DNS request rate; exhausted clients receive REFUSED. Blocked domains return NXDOMAIN without contacting upstream. Explicit `@@||domain^` allow exceptions override blocked suffixes. For an explicit exact-name local A/AAAA/CNAME override, the gateway answers from a validated, immutable local record set without upstream traffic. The local file is atomically swapped after validation; there is no general authoritative zone engine. Other requests forward to the configured resolver: client-aware UDP/TCP with TCP fallback, forced TCP, or authenticated upstream DNS-over-TLS. Failed upstream exchanges or bounded-concurrency refusals return SERVFAIL. The daemon exposes separate authenticated aggregate statistics, atomic on-disk rule reload, and private policy preview through the management API.

React web, native Qt Quick Linux and native Compose Android clients access the same versioned management API. The clients do not execute host commands or process DNS packets.

## MIPS responsibilities

- GoreeShield governs privacy, retention, consent and minimization. The current daemon stores only process-local aggregate counters.
- Wardveil governs cybersecurity and network defense. Token authentication, loopback-only default CIDR restrictions, aggregate query-rate limiting and bounded upstream work exist; per-client rate limiting, role-based security policies, hardening and detection are pending.
- GoreeCloud Mesh governs opt-in integrations and API coordination. No live Mesh integration is verified.
- GoreeCloud Identity governs authentication and authorization. Current bearer-token MVP is not an Identity integration.
- GoreeCloud UI governs production design language. The web client includes pinned canonical alpha semantic tokens and the native clients map the matching palette. The shared token bridge is source-aligned but does not establish visual, accessibility, device, or Stable release acceptance.

## Limits

The gateway does not serve authoritative zones, issue dynamic DNS changes, validate DNSSEC itself, provide encrypted DNS listeners, inspect individual clients, or support complete ad-block rules. Upstream DoT is outbound only and requires certificate identity validation; the inbound management API is still HTTP on loopback by default. The Unbound service is an independent runtime dependency; its security and recursive validation configuration must be tested separately.

No DNS routing, router configuration, external ingress or host deployment is performed by this repository.
