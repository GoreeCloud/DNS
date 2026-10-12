# GoreeCloud DNS — Planned Features

> **Lifecycle classification:** Proposed / not yet implementation-verified  
> **Catalog recorded:** 2026-10-12  
> **Authoritative scope:** [PROJECT-SPECIFICATIONS.md](PROJECT-SPECIFICATIONS.md)  
> **Execution context:** [FORK_TO_NATIVE.md](FORK_TO_NATIVE.md)

This record tracks lifecycle disposition of the **Beacon** target capabilities. The comprehensive requirements are maintained once in PROJECT-SPECIFICATIONS.md; this file is the implementation planning and verification index. Every line below is **proposed**. The presence of related behavior inherited from AdGuard Home is not proof that a GoreeCloud-native implementation, release or deployable configuration has met its acceptance criteria. Source evidence and acceptance test links must be added before promotion.

| ID | Proposed capability workstream | Scope in specification | Principal dependency / validation |
| --- | --- | --- | --- |
| DNS-01 | Resolution and forwarding | §1 | resolver API, transport, E2E lookups, IPv4/v6 |
| DNS-02 | Independent recursive server | §2 | root hints, DNSSEC, open-resolver prevention, performance |
| DNS-03 | Authoritative DNS | §3 | separate authoritative role, zones, AXFR/IXFR, signing |
| DNS-04 | Resource-record administration | §4 | RR parser, record correctness, history/audit |
| DNS-05 | Encrypted client and upstream DNS | §5 | protocol-by-direction matrix, TLS/cert lifecycle |
| DNS-06 | Privacy and metadata controls | §6 | local-first, log-off, redaction, retention verification |
| DNS-07 | DNSSEC validation and signing | §7 | keys, trust anchors, validation failure and rollover |
| DNS-08 | Advertisement filtering | §8 | client/group/VLAN rules, list compatibility, false positives |
| DNS-09 | Tracker/telemetry filtering | §9 | categorized lists, exceptions, statistics privacy |
| DNS-10 | Blocklists and rule engine | §10 | precedence, import, reproducible response semantics |
| DNS-11 | Malware and DNS anomaly protection | §11 | threat feed provenance, bounded heuristic claims |
| DNS-12 | Parental controls | §12 | device profiles, category/schedule test suite |
| DNS-13 | DNS policy engine and RPZ | §13 | deterministic evaluation, simulations and auditing |
| DNS-14 | Client/device administration | §14 | identity accuracy, permissions, dynamic IP behavior |
| DNS-15 | Network/VLAN-aware policies | §15 | subnet ACL, resolver selection, firewall boundary |
| DNS-16 | Optional DHCP and IP coordination | §16 | no competing DHCP, lease recovery, DHCPv6 scope |
| DNS-17 | Private DNS and service discovery | §17 | split-horizon, VPN ACLs, delegated zones |
| DNS-18 | Advanced caches/performance | §18 | TTL correctness, stale behavior, load benchmarks |
| DNS-19 | Multi-node availability | §19 | sync integrity, data-plane independence, failover tests |
| DNS-20 | Analytics/monitoring | §20 | privacy-safe aggregated metrics and alert validation |
| DNS-21 | Query logs and reports | §21 | logging disabled by default, retention and RBAC |
| DNS-22 | Glaze web administration | §22 | accessible responsive UI and operational workflows |
| DNS-23 | RBAC/admin security | §23 | MFA/OIDC where implemented, scopes, audit and secrets |
| DNS-24 | REST API, CLI and automation | §24 | versioning, rate limits, token scopes and schemas |
| DNS-25 | Modules/plugins/extensions | §25 | sandbox/trust boundary, isolation, permissions |
| DNS-26 | Advanced resolver behaviors | §26 | DNS64, CNAME, proxies, RPZ, response integrity |
| DNS-27 | Router, firewall, VPN, OS and cloud integrations | §27 | documented external contracts, compatibility |
| DNS-28 | GoreeCloud platform integrations | §28 | Wardveil, Privacy Shield, Monitor and Glaze contracts |
| DNS-29 | Cross-platform deployment | §29 | packaging, per-platform support matrix and release tests |
| DNS-30 | Backups/disaster recovery | §30 | restored configuration validity and rollback |
| DNS-31 | Maintenance diagnostics | §31 | operator-safe testing, errors and troubleshooting |
| DNS-32 | Reliability and resilience | §32 | outage handling, failover and management isolation |
| DNS-33 | Security/privacy architecture | §33 | threat model, encryption, least privilege, safe defaults |
| DNS-34 | Product breadth and acceptance | §34 | complete catalog coverage and explicit release gates |

## Delivery sequencing (proposed, not committed dates)

- **Stage 0:** verify inherited upstream baseline and license/source provenance, build/test reproducibility, automation isolation; tracked by FORK_TO_NATIVE.md.
- **Stage 1:** identity, onboarding, exposure hardening, update lockout and privacy-safe defaults; retain inherited licensing notices. Existing work must be verified against the actual repository.
- **Stage 2:** establish DNS resolution, filtering, privacy, transport and optional DHCP interoperability with benchmark and negative-path tests. Broader recursion, authoritative serving and signing require distinct design reviews.
- **Stage 3:** build and validate Glaze administration and accessibility.
- **Stage 4:** integrate other GoreeCloud services and network infrastructure through documented, authorized contracts.
- **Stage 5:** progressively replace inherited product-defining modules, provide schema-versioned migration and rollback.
- **Stage 6:** independent validation of source, security, runtime DNS, platform support, backups and rollbacks before any Native/Stable or production claim.

This sequencing is architectural guidance, not proof of completion or a delivery promise. Workstreams may be developed concurrently when they have compatible dependencies and tests.

## Non-negotiable acceptance

- Resolve supported record types correctly across claimed IPv4/IPv6 and transport paths.
- No inadvertent open resolver, insecure admin exposure, competing DHCP server or plaintext secret leakage.
- DNSSEC and encrypted DNS claims independently conform to their implemented protocol mode and direction.
- Logging, telemetry and retention behavior match disclosed defaults; provide deletion/export workflows where promised.
- No published support for integration, OS, authoritative serving, clustering or protocol without verified target evidence.
- Test negative paths, conflicting policies, upstream loss, stale caches, failover, migration and rollback.
- Keep the repository [IMPLEMENTED-FEATURES.md](IMPLEMENTED-FEATURES.md) tied to actual commits and tests; maintain [PROJECT-RECORD.md](PROJECT-RECORD.md) for significant milestones.

## Open design decisions

- Native recursive and authoritative engine strategy versus explicitly bounded dependencies.
- Separation of resolver, authoritative, DHCP, management and optional clustering roles.
- Privacy-safe data model for devices, history, analytics and policy audit.
- Cryptographic key management, state replication and zone-signing authority.
- Deployment/OS compatibility matrix and extension isolation model.
- Rollout priorities and measured success criteria per workstream.

**Status of all DNS-01 through DNS-34: proposed/unverified until individually reclassified from concrete implementation evidence.**
