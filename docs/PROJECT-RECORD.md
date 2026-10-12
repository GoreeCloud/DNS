# GoreeCloud DNS — Project Record

> **Owner:** GoreeCloud  
> **Repository:** GoreeCloud/DNS  
> **Product:** GoreeCloud DNS — Beacon  
> **Purpose:** Significant decisions, historical milestones and authoritative evidence  
> **Current status:** Fork-to-Native / not a verified production release

## 2026-10-12 — Coordinated networking platform owner designation

- The owner designated **GoreeCloud Gateway**, **GoreeCloud VPN**, and **GoreeCloud DNS** as the three complementary products of the **GoreeCloud Coordinated Networking Platform**.
- DNS retains independent authority for name resolution, filtering, DNS policy, and DNS-based discovery; VPN retains private connectivity and remote-access authority; Gateway retains ingress, TLS, reverse-proxy, and service-publication authority.
- Integration boundaries must preserve private-by-default behavior and must not imply automatic exposure, access-policy bypass, or product authority transfer.
- This is an architectural classification and coordination objective, **not** an implementation, release, deployment, or acceptance claim. Current Fork-to-Native status remains unchanged.
- Cross-product records: [GoreeCloud Gateway architecture](https://github.com/GoreeCloud/gateway/blob/main/docs/architecture.md) and [GoreeCloud VPN](https://github.com/GoreeCloud/VPN).

## 2026-10-12 — Beacon product vision registered

- The owner provided a proposed comprehensive **34-part product feature catalog**, including recursive and authoritative DNS, encrypted protocols, DNSSEC, policy, filtering, security, DHCP, clients, Glaze administration, extensions, high availability, ecosystem integrations, deployment and recovery.
- The source-derived product remains in an initial Fork-to-Native stage. The catalog is not to be mistaken for implemented or certified features.
- The catalog is persisted as [PROJECT-SPECIFICATIONS.md](PROJECT-SPECIFICATIONS.md) with lifecycle dispositions in [PLANNED-FEATURES.md](PLANNED-FEATURES.md).
- The prior inherited implementation and its existing documented validation boundaries remain governed by [FORK_TO_NATIVE.md](FORK_TO_NATIVE.md), [README](../README.md), [UPSTREAM.md](../UPSTREAM.md) and licensing.
- No production deployment, feature implementation or protocol-certification event is claimed as a result of this documentation change.

## Source baseline and governance context

- The repository is a derivative of AdGuard Home, and must preserve GPL-3.0 and applicable copyright and upstream attribution.
- Existing repository documentation records that an earlier PR #2 merged inherited auto-update lockout and new-install query-logging defaults; the canonical PR and commit remain GitHub's authoritative evidence.
- Runtime readiness, full Glaze implementation, GoreeCloud integrations, configuration migration and native acceptance are not yet established by this record.

## Evidence and record maintenance

Capture each major architecture decision, migration, source acceptance, security/privacy shift, release-state transition, incident and deployment with dates and GitHub commit/PR/release or test evidence. Maintain specific requirements only in [PROJECT-SPECIFICATIONS.md](PROJECT-SPECIFICATIONS.md) and current feature lifecycle in [IMPLEMENTED-FEATURES.md](IMPLEMENTED-FEATURES.md) / [PLANNED-FEATURES.md](PLANNED-FEATURES.md); this history must not become a second specification or changelog.
