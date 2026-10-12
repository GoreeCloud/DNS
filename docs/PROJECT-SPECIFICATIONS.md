# GoreeCloud DNS — Project Specifications

> **Capability identity:** Beacon  
> **Specification:** Comprehensive Product Feature Catalog  
> **Classification:** Proposed product requirements and target architecture  
> **Recorded:** 2026-10-12  
> **Repository:** GoreeCloud/DNS  
> **Product category:** DNS infrastructure, network security, privacy, filtering, and management  
> **Lifecycle:** Fork-to-Native, initial source-import / safety-hardening stage; **not an accepted native or production release**  
> **Product vision:** *Secure Resolution. Private Networking. Intelligent DNS Management.*

## 0. Purpose, authority, and interpretation

GoreeCloud DNS (Beacon) aims to unify secure recursive and authoritative DNS, DNSSEC, encrypted transport, network-wide filtering, threat protection, private naming, DHCP coordination, caching, observability, administrative policy, extension modules, and high availability for individuals, families, businesses, and distributed infrastructure. It must operate independently while integrating with approved routers, firewalls, switches, access points, VPNs, operating systems, cloud infrastructure, and monitoring.

**This is a proposed scope catalog, not a verified implementation inventory.** An entry here does not establish availability, protocol compliance, security certification, operational deployment, or release readiness. Each capability requires implementation design, dependency review, tests, target-platform validation and explicit lifecycle classification. The current source baseline is an AdGuard Home-derived Fork-to-Native project; inherited functionality is not proof of every Beacon target capability. Consult [Fork-to-Native execution plan](FORK_TO_NATIVE.md), [privacy disclosure](PRIVACY.md), [planned-feature disposition](PLANNED-FEATURES.md), [upstream provenance](../UPSTREAM.md), and [README](../README.md). The project must preserve GPL-3.0 obligations and relevant attribution. All policy and release decisions remain subordinate to GoreeCloud governance.

### Lifecycle and acceptance contract

- **Proposed:** product ambition only; do not label implemented or released.
- **Planned:** accepted work item with dependencies and proposed testable design.
- **Implemented in source:** confirmed code at a named revision with tests where applicable.
- **Verified:** evidence for relevant protocols, interfaces, security boundaries, OS/platform matrix, negative paths, privacy behavior, and recovery.
- **Production-ready/released/stable:** separate gated determinations requiring documented deployment evidence and release authorization.

## 1. Core DNS resolution

- Full recursive and iterative DNS; independent, forwarded, stub, conditional, domain-specific, local/private/public/hybrid and split-horizon/split-brain resolution.
- Forward/reverse lookups; internal/external hostname handling; IPv4, IPv6, dual-stack and DNS64.
- Network-, client-, group-, device-, and policy-aware query processing; intelligent routing and response policy selection.
- Multiple configurable upstream resolvers, parallel querying, balancing, fastest-response selection, failover, health checks, bootstrap resolution, retries and timeouts.
- DNS response validation, rewriting, redirection, custom answers and response codes.
- EDNS(0), optional EDNS Client Subnet, Extended DNS Errors, DNS query optimization and resolution diagnostics.

## 2. Recursive DNS server

- Standalone recursion without mandatory public forwarder; root-hint management and root/TLD/authoritative nameserver discovery.
- Delegation processing; asynchronous, concurrent and multithreaded recursive query execution; caching and DNSSEC-validating recursion.
- Access-control lists, permitted-recursion configuration, retry/timeout settings, nameserver selection and hardening.
- QNAME minimization, QNAME case randomization, DNS Cookies, response validation, rate limiting and amplification safeguards.
- Resolver statistics, health monitoring, performance tuning, configuration validation and troubleshooting.

## 3. Authoritative DNS hosting

- Authoritative serving with primary, secondary, forward, reverse, public, private, internal and catalog zones; stub/conditional forwarding zone administration where applicable.
- Zone create/edit/delete/clone/import/export/template workflows, delegation, validation, versioning, logs, backup and restore.
- Zone replication and synchronization; AXFR, IXFR, NOTIFY, TSIG, authenticated and optionally encrypted transfer pathways.
- RFC 2136 dynamic updates, wildcard records, record enable/disable, record aging and expiration.
- DNSSEC zone signing, NSEC/NSEC3, ZONEMD, zone permissions and administrative auditing.
- Separate recursive, authoritative and management roles; no assumption that the current inherited resolver is an authoritative server.

## 4. DNS record management

**Standard record types:** A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA.

**Advanced record types:** DNAME, TLSA, SSHFP, SVCB, HTTPS, URI, NAPTR, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY, CSYNC, ZONEMD, and further standards-compliant RRs.

**Administration:** custom, wildcard and dynamic records; aliases; rewrites; CNAME flattening/ANAME-equivalent behavior where defensible; custom TTLs; bulk operations, search, import/export, validation, history and record-level audits. Record parsing, authoritative zone serving and synthesized answer behavior must be tested separately.

## 5. Encrypted DNS protocols

- DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNS-over-QUIC (DoQ), optional DNSCrypt, conventional DNS-over-UDP and DNS-over-TCP.
- Separately declared **client-facing listeners** and **upstream forwarding transports**; do not infer symmetric protocol support.
- HTTPS endpoints, HTTP/2 and HTTP/3 where supported, TLS version policy, certificate issuance/renewal, bootstrap and endpoint configuration.
- Per-client and per-network encrypted-DNS policy, resolver selection, failover, endpoint/encryption monitoring and diagnostics.

## 6. DNS privacy protection

- Local-first processing, independent recursion, transport encryption and reduced exposure to third-party resolvers.
- Minimized DNS metadata; client IP anonymization; individually configurable logging, retention, expiration and query-history deletion.
- Privacy profiles per client, group or network; privacy-oriented upstream selection and routing, constrained telemetry, visibility controls and privacy-aware statistics.
- Document whether logs and analytics are persistent, aggregated, anonymized or disabled; never equate transport encryption with anonymity.
- Potential GoreeCloud Privacy Shield integration only after approved contract verification.

## 7. DNSSEC and DNS integrity

- DNSSEC validating recursion; trust-anchor provisioning and automatic updates; DNSKEY, DS, RRSIG and chain-of-trust verification.
- Validation failures, diagnostics, configuration checks, error reports and statistics.
- Authoritative DNSSEC signing; key generation, secure key storage, rollover; NSEC/NSEC3; aggressive DNSSEC caching and key prefetching.
- Zone integrity monitoring and verification; fail closed on authenticity failures according to defined policies.

## 8. Network-wide advertisement blocking

- DNS-domain blocking of browser, mobile-app, smart-TV, streaming device and IoT advertising endpoints; third-party ad networks and malicious-ad domains.
- Managed/custom subscription lists, automated refresh, exceptions and temporary disablement.
- Client-, group-, network- and VLAN-specific filtering; schedules, activity reports and blocked-query statistics.
- Domain-layer limitations must be disclosed: first-party content, same-domain ads and non-DNS content are not guaranteed blockable.

## 9. Tracker and telemetry blocking

- Website/app/IoT tracking, measurement, behavioral analytics, tracking-pixel, telemetry and advertising attribution domains.
- Custom allow/deny lists, subscriptions, automatic refresh, device/group filtering and reporting.
- User-aware exceptions and false-positive recovery paths.

## 10. DNS blocklists and filtering rules

- Allow/deny/block lists and hosts-file input; exact domains, wildcards and regex rules.
- Local/remote subscriptions, multiple list sources, scheduled/manual updates, validation, deduplication, consolidation, versioning, history, enable/disable and conflict diagnostics.
- Deterministic precedence across domain, client, group, network and time policies; exceptions and temporary bypass.
- Response methods: NXDOMAIN, NODATA, REFUSED, null addresses, sinkholes, custom redirects and responses.
- Rule effectiveness reporting without requiring intrusive query-history retention.

## 11. Malware, phishing and threat protection

- Malware, phishing, spyware, malicious-ad, command-and-control and botnet domain filtering; reputation and threat-intelligence feeds.
- Suspicious/new domain heuristics, anomalous DNS patterns, tunneling and potential exfiltration indicators, query-flood detection.
- Rebinding prevention, cache-poisoning/spoofing and amplification mitigations, rate limiting, response policies and ACLs.
- Severity-classified security events, alerting, export, per-client controls, statistics and optional Wardveil integration.
- Heuristic flags are indicators, not proof of compromise; avoid unsupported detection guarantees.

## 12. Parental controls and family protection

- Family-safe profiles; adult/explicit content, gambling, harmful sites, social, gaming, streaming and application-service domain categories.
- Supported Safe Search and video restricted-mode enforcement with explicit provider compatibility limits.
- Profiles by child, family group, age and device; templates, managed allow/deny lists and temporary exceptions.
- Time-of-day/week schedules, access windows, category policies, configurable family statistics and privacy-respecting child-data retention.

## 13. DNS policy management

- Centralized policy evaluation by domain, device, client, group, subnet, network, VLAN, application service and time.
- Policy-based forwarding, blocking, rewriting, redirection, conditional behavior, RPZ and custom responses.
- Precedence/inheritance, exceptions, conflict detection, priorities, scheduling, templates, import/export, versioning and audit trail.
- Simulation, dry-run policy tests and programmable execution with deterministic, testable semantics.

## 14. Client and device management

- Automatic discovery only where network visibility permits; IP/hostname identification including IPv4 and IPv6.
- Friendly device names, labels, tags, groups, assignments and inventory import/synchronization through authorized integrations.
- Per-client DNS, filtering, upstream selection, parental, security, query-logging, history and statistical settings.
- Profile types: known/unknown, trusted/untrusted, administrator, personal, family, child, IoT, guest, infrastructure and remote.
- Device-specific access restrictions and policy exceptions, with accurate handling of address churn and identity uncertainty.

## 15. Network- and VLAN-aware DNS

- Profiles and policies per subnet, VLAN, network, guest, IoT, family, administrator or infrastructure segment.
- Private/public split-horizon answers, conditional forwarding, per-network upstream routing and private names across specifically approved segments.
- Client/network ACLs and managed allowed/blocked ranges; router, firewall, switch, wireless AP and VPN coordination.
- DNS bypass monitoring and unauthorized resolver signals where observability allows.
- **Boundary:** DNS filtering does not implement firewall isolation or network authorization.

## 16. DHCP and IP address coordination

- Optional DHCP server: IPv4 DHCP, supported DHCPv6, dynamic allocation, pools/scopes, static reservations, lease renewal/expiry/history and diagnostics.
- Device-hostname registration, DHCP-to-local-DNS updates, search domains/DNS options where supported.
- Router/firewall/external DHCP and IPAM integration; statistics, configuration import/export.
- **Safety gate:** do not activate a competing DHCP authority on a segment where another service assigns addresses.

## 17. Private DNS and internal service discovery

- Private/internal zones, hostnames, service aliases, dynamic registrations, SRV/service records, reverse-proxy mappings and local service lookup.
- Distinct internal/external answers; split-horizon resolution; private forwarding across approved subnets, VLANs, sites and VPN links.
- Search-domain configuration, authenticated access rules, approved remote name resolution and diagnostics.

## 18. DNS caching and performance

- Recursive/forwarded positive and negative caching; message, RR and infrastructure caches.
- Cache memory sizing, TTL minimums/maximums, expiry, flush and domain-specific invalidation; inspection and metrics.
- Prefetch, DNSSEC key prefetch, serve-stale, optimistic or persistent caching where safely supported.
- Query deduplication, parallel/concurrent/multithreaded execution; network/socket/memory tuning; optional external cache.
- Cache hit/miss, latency, utilization, benchmark and performance diagnostics.

## 19. DNS clustering and high availability

- Multiple independently processing DNS instances; node enrollment, membership, primary/secondary roles where meaningful, health and maintenance modes.
- Configuration, filtering, blocklist, policy and authoritative zone synchronization with version consistency and recovery behavior.
- Redundant endpoints, automated or operator-coordinated failover, service resynchronization and disaster recovery.
- Continue independently serving DNS if the management plane is unavailable; recovery tests and alerts.
- Clustering must not make DNS resolution depend on an always-online central control service.

## 20. DNS monitoring and analytics

- Glaze real-time dashboards: total/allowed/blocked queries, QPS, timeline, top domains/clients/upstreams, record types and response codes.
- Latency, timeouts, cache hit/miss, DNSSEC validation, recursion, authoritative zones, filters, threats, node/cluster and upstream health.
- Per-client/group/network/VLAN and historical reporting, metrics export and potential GoreeCloud Monitor integration.
- Aggregated analytics should respect configured logging disablement, anonymization and retention.

## 21. DNS query logging and reporting

- Opt-in detailed or real-time queries, historical records, domain/client/network/status/time/rule/upstream search and filters.
- Allowed/blocked, security, violation, performance, DNSSEC and availability reports.
- Configurable retention, expiration, disablement, IP anonymization, role-restricted access, structured output and external log collectors.
- Optional dnstap-compatible integration when implemented; separate administrative audit logs from DNS query data.

## 22. Web administration interface

- Responsive desktop/mobile web console following the approved GoreeCloud Glaze design system; light/dark modes and accessible states.
- Server overview; resolver, encrypted endpoint, DNSSEC, certificate, forwarding, authoritative zone, record, blocklist, filtering, device/group, policy, parental, cache, DHCP and cluster editors.
- Diagnostics, query inspection, dashboards, logs, alerts, configuration/backup import-export, activity/version history, users/roles and service health.
- Security-sensitive edits require validation, appropriate permissions, understandable consequences and recoverability.

## 23. Authentication and administrative security

- Named administrators and least-privilege RBAC including read-only, configuration, zone, security and policy roles.
- Scoped API tokens; authenticated service-to-service APIs; optional OIDC, LDAP, SSO, MFA/TOTP integrations.
- HTTPS management, session protections, network restrictions, credential/certificate/key protection and authentication/change audit logs.
- Minimize public exposure; ensure DNS service operation remains separate from management privileges and access.

## 24. APIs and automation

- Versioned REST management API covering resolver, configuration, zones/records, filtering/lists, devices/groups/policies, statistics/events, cluster and optional DHCP.
- Authenticated and rate-limited administration with scoped tokens; documented endpoints and error models.
- CLI, scripting, DDNS/RFC 2136 automation, blocklist refresh, config validation, policy tests, event/webhook delivery, metrics, backups, restores and cache management.
- Infrastructure-as-code and extension interfaces only through approved contracts.

## 25. DNS apps, plugins and extensibility

- Modular request/response processing and permission-controlled extension lifecycle with plugin configuration, diagnostics and failure isolation.
- Optional policy, filtering, forwarding, rebinding, DNS64, split-horizon, geolocation, CNAME cloaking, reputation, threat intelligence, rewrite, analytics and cache modules.
- Controlled Python scripting/external scripts and third-party integrations where supported.
- Explicit trust boundaries, resource limits, sandboxing or other appropriate constraints before enabling arbitrary custom code.

## 26. Advanced DNS capabilities

- RPZ; answer/response-IP rewriting; DNS64; client/network/geolocation-dependent answers.
- CNAME-chain inspection and cloaking defense, rebinding, anomaly/reputation checks, Extended DNS Errors, QNAME minimization/case randomization, DNS Cookies and ACLs.
- Rate limits, advanced forwarding paths and encrypted proxy routes; HTTP/SOCKS proxy support where available; appropriate PROXY protocol handling.
- Authenticated dynamic updates and zone transfers; integrity validation; pre/post-processing stages, scripted policies and tuning.

## 27. Network infrastructure integrations

**Routers and firewalls:** router DNS assignment, firewall DNS policy coordination, conditional forwarding, DHCP option delivery, bypass restriction, segmentation awareness; OPNsense, pfSense, OpenWrt, GL.iNet and compatible systems.

**Networks and remote access:** VLAN/subnet-aware coordination, managed switches/APs, WireGuard, OpenVPN, NetBird, Tailscale, remote private DNS, site-to-site and multi-network policies.

**Infrastructure and apps:** Proxmox, Docker, Kubernetes, Linux, Windows, macOS, mobile OS DNS configuration, Caddy/reverse proxies, home automation, monitoring, external DHCP and IPAM.

All integrations use documented protocols or published APIs; none may depend on unauthorized changes to another service.

## 28. GoreeCloud ecosystem integration

- **Wardveil Security:** threat feeds, malware domain indicators, tunneling/rebinding observations, anomalies and security events.
- **GoreeCloud Privacy Shield:** privacy and telemetry policies, minimization, client anonymization, retention and reporting preferences.
- **GoreeCloud Monitor:** service/endpoint availability, latency, recursive resolver, cache and cluster health, alerts and metrics.
- **Shared platform:** consistent Glaze UX, approved identity/RBAC, authenticated APIs, versioned contracts, health/event visibility.
- These are **potential** integrations, not statements that functional connections currently exist.

## 29. Deployment and operating system support

- Target deployment candidates: Linux, Windows, macOS, Docker, bare metal, VM, Proxmox, ARM, x86-64, Raspberry Pi, home servers, homelabs, SMB, enterprise, private cloud, distributed and multi-site installations.
- IPv4/IPv6/dual-stack, multiple interfaces/listeners and configurable DNS port endpoints.
- Environment/configuration files, containers, service install/lifecycle, health probes, deployment automation, rolling updates where architecture allows, backup and rollback.
- **The support matrix remains proposed until packaging, architecture, dependencies and release testing verify each target.**

## 30. Backup and disaster recovery

- Back up configurations, policies, filters/lists, DNS zones/records, client settings, DHCP reservations and cluster state.
- Manual/scheduled backup, export/import, versioning, restoration by subsystem or whole service, rollback and validated restore drills.
- Resolver/node failover, re-synchronization, independent DNS continuity and recovery diagnostics.
- Protect secrets in exports, backups and key material with appropriate access control and encryption.

## 31. System maintenance and diagnostics

- Health, recursive, authoritative, DNSSEC, encryption, upstream connectivity, query, record, reverse-lookup, response and latency tests.
- Configuration, zone, filter and policy validation; DNS cache inspect/flush; statistics/log inspection; error and timeout investigation.
- Certificate, node, cluster/failover checks, configuration consistency, updates, maintenance logs and downloadable troubleshooting reports.
- Diagnostic operations should be safely scoped and avoid accidental exposure of sensitive query content.

## 32. Reliability, availability and resilience

- Robust independent recursion, upstream redundancy, retries/timeouts, serve-stale caching, persisted cache where practical, health checks and redundant endpoints.
- Fault detection, failure logs and alerts, continuity across management-plane outages, recoverable cluster configuration and service resynchronization.
- Safe controlled updates, tested rollback, offline/tolerant behavior and disaster recovery planning.

## 33. Security and privacy architecture

- Secure defaults; no unintended open resolver; resolver ACLs and rate/amplification defenses; least-privilege administration.
- Separate management plane, recursive data plane, authoritative DNS and optional DHCP control; strict public/private DNS boundaries.
- Encrypt supported DNS transports and management connections; validate DNSSEC where relevant; protect transfers, APIs, secrets, certificates and signing keys.
- Minimize identifiable query data, make retention explicit, audit privileged changes and use documented authenticated integration channels.
- Preserve DNS availability independently of management service failure.
- **Limits:** DNS filtering is not a firewall, endpoint defense, or browser content-blocking replacement. Encrypted DNS is not anonymity. DHCP authority must be unique per segment.

## 34. Product capability matrix

| Capability area | Target scope | Lifecycle |
| --- | --- | --- |
| Resolution | Recursive, forwarding, conditional, local/private and policy-driven | Proposed |
| Authoritative DNS | Zones, records, AXFR/IXFR, dynamic updates, DNSSEC signing | Proposed |
| Encryption | DoH, DoT, DoQ, optional DNSCrypt; separate client/upstream support | Proposed |
| Security | DNSSEC, malicious-domain filtering, rebinding and threat indicators | Proposed |
| Ad/tracker filtering | Network-wide ad, tracker and telemetry domain policies | Proposed |
| Family protection | Profiles, categories, Safe Search, schedules | Proposed |
| Policy | Client/group/network/VLAN/domain/time/RPZ rules | Proposed |
| Cache | TTL, prefetch, serve-stale, diagnostic tuning | Proposed |
| DHCP | Optional scoped DHCP and DNS coordination | Proposed |
| Private DNS | Split-horizon naming and service discovery | Proposed |
| Monitoring | Analytics, log controls, health and threat reporting | Proposed |
| Administration | Glaze console, RBAC, APIs and automation | Proposed |
| Extensions | Modules, scripts and lifecycle controls | Proposed |
| High availability | Nodes, sync, failover, recoverable autonomous data plane | Proposed |
| Infrastructure | Router/firewall/VPN/cloud/OS/container integrations | Proposed |
| Operations | Validation, backups, restoration and diagnostics | Proposed |

## Implementation boundaries and verification

The complete product vision is intentionally broad and modular. Recursive DNS, authoritative hosting, DHCP, policy, threat intelligence, caching, UI and clustering may require independently maintained engines or services. For each target capability:

1. Specify ownership, interfaces, protocol conformance and failure behavior.
2. Distinguish in-process modules, external engine dependencies, optional service roles and integrations.
3. Define secure defaults, privacy/retention choices, access scopes and migration behavior.
4. Design positive/negative tests, relevant RFC interoperability, security and load testing.
5. Verify deployment and target OS capabilities, monitoring, backup/rollback and failover.
6. Record implementation with commit/test evidence in IMPLEMENTED-FEATURES.md, planned disposition in PLANNED-FEATURES.md, and major decisions/milestones in PROJECT-RECORD.md.
7. Do not call the complete catalog operational until all claimed features have independent implementation and acceptance evidence.

### Product vision

GoreeCloud DNS — **Beacon** is intended to replace fragmented DNS management tools with a cohesive, modular, standards-aligned, privacy-conscious solution for domain resolution, security, network privacy, content filtering, private discovery, performance and infrastructure administration.

**Specification status: Proposed comprehensive feature catalog.**