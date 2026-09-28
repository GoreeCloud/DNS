# Planned Features — GoreeCloud DNS

## Status

All product capabilities in this file are planned or required target scope unless separately moved to `IMPLEMENTED-FEATURES.md` after implementation and verification.

The full behavioral specification is maintained in `PROJECT-SPECIFICATIONS.md`.

## DNS Resolution and Protocols

- Full recursive resolution from the DNS root hierarchy.
- Upstream forwarding, conditional forwarding, forwarding zones, and stub zones.
- Local and split-horizon DNS.
- Reverse DNS.
- IPv4 and IPv6.
- UDP and TCP DNS.
- Configurable listeners and multiple interfaces.

## Authoritative DNS

- Primary and secondary authoritative zones.
- Catalog zones.
- AXFR and IXFR.
- DNS NOTIFY.
- TSIG-authenticated transfers.
- Dynamic DNS updates.
- Wildcards, TTL controls, aging, refresh, and expiration.
- DNSSEC-signed zones, automated key management, NSEC/NSEC3, and ZONEMD.
- Modern and traditional record families including A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, SOA, CAA, NAPTR, DNAME, SSHFP, TLSA, URI, SVCB, HTTPS, and DNSSEC-related records.

## Encrypted DNS

- DNS-over-HTTPS.
- DNS-over-TLS.
- DNS-over-QUIC.
- DNSCrypt.
- Encrypted upstream selection and client endpoints.

## Privacy and Security

- QNAME minimization.
- EDNS Client Subnet controls.
- Privacy-aware logging and client anonymization.
- DNS rebinding protection.
- Query and response-rate controls.
- Access-control lists.
- Malware, phishing, botnet, command-and-control, fraud, telemetry, tracker, advertising, and cryptomining protections.
- Response Policy Zones and threat-intelligence feeds.
- CNAME cloaking protection.

## Filtering and Policy

- Remote and local blocklists.
- Global, client, and group allowlists.
- Exact, wildcard, regular-expression, hosts-file, and adblock-style rules.
- Per-device and per-group policy.
- Safe Search and Restricted Mode enforcement.
- Service blocking.
- Custom DNS rewrites.
- Configurable blocking responses.

## Cache and Resilience

- Positive and negative caching.
- Configurable TTL policy and cache sizing.
- Prefetch and popular-record prefetch.
- Persistent cache where appropriate.
- Serve-stale.
- Selective invalidation and cache inspection.
- Concurrent resolution and latency-aware upstream selection.

## DHCP and Local Network Integration

- DHCPv4.
- IPv6-related network configuration where supported.
- Multiple address pools.
- Static reservations.
- Lease visibility and configurable durations.
- Gateway, DNS, and search-domain assignment.
- DHCP-to-DNS client identity integration.
- Host discovery and local-name resolution.

## Administration and Observability

- Responsive Glaze UI administration.
- Multi-user administration and role-based access.
- Query logs, filtering decisions, cache state, transports, response times, and DNSSEC status.
- Search, filtering, export, statistics, dashboards, and historical analytics.
- DNS lookup, trace, cache, DNSSEC, resolver, upstream, zone, response-time, and transport diagnostics.

## Identity, API, and Automation

- GoreeCloud Identity integration.
- OpenID Connect.
- LDAP where interoperability requires it.
- TOTP multi-factor authentication.
- Secure sessions and revocable credentials.
- Comprehensive management API.
- Configuration as code.
- Automated blocklist, record, certificate, backup, health, monitoring, and infrastructure workflows.
- Secure Dynamic DNS.

## High Availability and Multi-Server Operation

- Multiple redundant DNS nodes.
- Replicated authoritative zones.
- Redundant recursive and encrypted DNS endpoints.
- Configuration and policy synchronization.
- Cluster-aware administration.
- Health monitoring and controlled failover.
- Centralized multi-server management.

## Programmability and Networking

- Custom DNS response logic.
- Geographic and network-aware responses.
- Application-specific routing.
- Dynamic service discovery.
- Extensible filtering and security-policy engines.
- External data-source integration.
- Optional HTTP, HTTPS, SOCKS5, privacy-network, and explicitly configured Tor proxy routing.

## Deployment and Recovery

- Physical server, virtual machine, Linux, container, homelab, edge, single-board-computer, and private-cloud deployment targets where resources permit.
- Exportable configuration without proprietary lock-in.
- Everkeep-aligned backup and recovery for zones, records, policies, lists, clients, groups, DHCP, authentication, certificates, cluster configuration, and application metadata.

## GoreeCloud Platform Integration

- GoreeCloud Manager.
- GoreeCloud Identity.
- Privacy Shield.
- Wardveil Security.
- Everkeep.
- GoreeCloud Notify.
- GoreeCloud API.
- Glaze UI.
- Applicable current Integral Platform System contracts must be evaluated and documented before conformance is claimed.

## Data Ownership and Independence

- No advertising.
- No sponsorship-driven DNS behavior.
- No mandatory external account.
- No required third-party DNS provider.
- Local ownership of configuration, statistics, and logs.
- Replaceable upstream providers.
- Recursive operation without a commercial DNS intermediary.

## Performance

- Asynchronous DNS processing.
- Concurrent resolution.
- Efficient high-performance caching.
- Efficient filtering.
- Bounded resource usage.
- Optimized upstream selection.
- Fast local responses.
