# GoreeCloud DNS — Features and Capabilities

> **Authority and status:** This file is the repository-local product specification for GoreeCloud DNS target features and capabilities. Unless a section explicitly cites separate verified implementation evidence, statements below describe intended, required, or planned product behavior and must not be interpreted as proof that a capability is implemented, deployed, validated, production-ready, or Stable.
>
> **Documentation date:** September 27, 2026
>
> **Verified repository boundary at documentation time:** before this documentation change, the repository contained only its initial README. This specification records intended scope and does not convert planned capability into implemented capability.


GoreeCloud DNS is designed as a comprehensive, privacy-first, self-hosted DNS platform combining recursive resolution, authoritative DNS, network-wide filtering, encrypted DNS, advanced policy controls, observability, automation, and high availability in a single integrated service.

## Core DNS Resolution

GoreeCloud DNS provides a complete DNS resolution stack capable of operating as both a recursive resolver and a forwarding DNS server.

Key capabilities include:

- Full recursive DNS resolution directly from the DNS root hierarchy.
- Configurable upstream DNS forwarding.
- Conditional forwarding.
- Stub zones.
- Local DNS zones.
- Split-horizon and split-brain DNS.
- Forwarding zones.
- Reverse DNS resolution.
- IPv4 and IPv6 resolution.
- Custom local DNS records.
- Flexible resolver behavior for local, private, and public networks.

GoreeCloud DNS can operate without requiring a third-party public resolver when full recursive resolution is enabled.

## Authoritative DNS

GoreeCloud DNS is designed to provide full authoritative DNS hosting alongside recursive DNS services.

Capabilities include:

- Primary authoritative zones.
- Secondary authoritative zones.
- Forward zones.
- Stub zones.
- Catalog zones.
- Primary and secondary zone replication.
- AXFR and IXFR zone transfers.
- DNS NOTIFY.
- TSIG-authenticated zone transfers.
- Dynamic DNS updates.
- Wildcard DNS records.
- Zone record aging.
- Zone expiration and refresh management.
- DNSSEC-signed authoritative zones.
- ZONEMD zone verification.
- Automated DNSSEC key management.
- Custom TTL controls.

Supported record families are intended to include modern and traditional DNS records such as:

- A
- AAAA
- CNAME
- MX
- TXT
- SRV
- PTR
- NS
- SOA
- CAA
- NAPTR
- DNAME
- SSHFP
- TLSA
- URI
- SVCB
- HTTPS
- DNSSEC-related records

GoreeCloud DNS is intended to support both internal/private authoritative DNS and publicly delegated Internet domains.

## Encrypted DNS

GoreeCloud DNS provides encrypted DNS for both clients and upstream communications.

Target protocols include:

- DNS-over-HTTPS (DoH).
- DNS-over-TLS (DoT).
- DNS-over-QUIC (DoQ).
- DNSCrypt.
- Traditional encrypted HTTPS-based resolver communication.

GoreeCloud DNS can expose encrypted DNS endpoints to trusted clients while independently selecting encrypted or recursive resolution for upstream queries.

This allows laptops, mobile devices, remote systems, and applications to securely communicate with GoreeCloud DNS without exposing DNS queries as plaintext across untrusted networks.

## DNSSEC

GoreeCloud DNS provides comprehensive DNSSEC support for validating and authoritative DNS operations.

Capabilities include:

- DNSSEC validation.
- DNSSEC authoritative zone signing.
- Automated key management.
- NSEC support.
- NSEC3 support.
- Signature validation.
- Trust-anchor management.
- DNSSEC failure diagnostics.
- Secure handling of authenticated denial of existence.

DNSSEC validation protects clients from forged or manipulated DNS responses when the requested domain supports DNSSEC.

## Resolver Privacy

GoreeCloud DNS is designed to minimize unnecessary disclosure of DNS activity.

Privacy capabilities include:

- QNAME minimization.
- Reduced upstream disclosure.
- Optional suppression or control of EDNS Client Subnet.
- Configurable query logging.
- Client-address anonymization.
- Local recursive resolution.
- Encrypted DNS.
- Private local zones.
- Configurable retention of DNS statistics and logs.
- Fine-grained privacy controls for individual clients.

When recursive resolution is used, GoreeCloud DNS can resolve domains without sending a user's complete DNS activity to a single third-party resolver.

## High-Performance DNS Caching

GoreeCloud DNS includes an advanced DNS caching layer designed to improve performance, availability, and upstream independence.

Capabilities include:

- Positive response caching.
- Negative response caching.
- Configurable cache sizes.
- Configurable minimum and maximum TTLs.
- Cache prefetching.
- Popular-record prefetching.
- Serve-stale support.
- Persistent caching where appropriate.
- Cache statistics.
- Cache inspection.
- Manual cache clearing.
- Selective cache invalidation.
- Concurrent upstream resolution.
- Latency-aware upstream selection.

Frequently requested domains can be served locally without repeatedly querying upstream infrastructure.

## Serve-Stale and Failure Resilience

GoreeCloud DNS is designed to continue resolving previously known domains during temporary upstream DNS failures.

Serve-stale capabilities can allow cached records to remain temporarily usable when:

- An upstream DNS provider becomes unavailable.
- Internet connectivity is degraded.
- Root or authoritative servers are temporarily unreachable.
- A forwarding resolver experiences an outage.

This improves DNS availability during partial network failures.

## Network-Wide Ad and Tracker Blocking

GoreeCloud DNS provides DNS-level filtering across an entire network without requiring filtering software on every device.

Filtering can protect:

- Desktop computers.
- Laptops.
- Phones.
- Tablets.
- Smart televisions.
- Streaming devices.
- Game consoles.
- IoT devices.
- Smart-home systems.
- Servers.
- Virtual machines.
- Containers.

Filtering capabilities include:

- Advertising-domain blocking.
- Tracking-domain blocking.
- Telemetry blocking.
- Malware-domain blocking.
- Phishing-domain blocking.
- Known malicious-domain blocking.
- Cryptomining-domain blocking.
- Unwanted-content filtering.
- Custom organization or household filtering policies.

## Blocklists and Allowlists

GoreeCloud DNS supports centrally managed DNS filtering sources.

Capabilities include:

- Remote blocklist subscriptions.
- Automatic list updates.
- Local blocklists.
- Global allowlists.
- Per-client allowlists.
- Per-group allowlists.
- Exact-domain rules.
- Wildcard rules.
- Regular-expression rules.
- Hosts-file compatible lists.
- Adblock-style filtering syntax.
- Custom filtering rules.
- Response Policy Zones.
- Policy-based domain overrides.

Administrators can override third-party lists without modifying the source lists themselves.

## Threat Intelligence and RPZ

GoreeCloud DNS can incorporate DNS Response Policy Zones and other threat-intelligence sources.

This allows organizations to automatically enforce policies against domains associated with:

- Malware.
- Phishing.
- Botnets.
- Command-and-control infrastructure.
- Known malicious hosts.
- Fraud.
- Tracking.
- Unwanted services.

Multiple policy feeds can be combined with local administrator policies.

## CNAME Cloaking Protection

GoreeCloud DNS is designed to detect filtering bypass techniques in which tracking providers hide behind first-party CNAME records.

Filtering decisions can inspect CNAME resolution chains and apply policy to the actual destination domain rather than only the original hostname requested by the client.

## Per-Device DNS Policies

Each network client can have its own DNS behavior.

Clients may be identified using information such as:

- IP address.
- IPv6 address.
- CIDR network.
- DHCP lease.
- Hostname.
- MAC-associated DHCP information.
- Reverse DNS.
- Manually assigned client identity.

Individual clients can receive custom:

- Filtering policies.
- Blocklists.
- Allowlists.
- Upstream resolvers.
- Safe Search policies.
- Parental controls.
- Service restrictions.
- Logging policies.
- DNS rewrites.
- Security policies.

## Client Groups

GoreeCloud DNS supports centrally managed device and user groups.

Example groups can include:

- Adults.
- Children.
- Guests.
- Servers.
- IoT devices.
- Smart-home devices.
- Work devices.
- Development systems.
- Infrastructure.
- Trusted administrators.

Policies can be assigned to groups instead of being individually configured for every device.

## Parental Controls

GoreeCloud DNS provides configurable family-oriented DNS controls.

Capabilities include:

- Adult-content filtering.
- Malware protection.
- Phishing protection.
- Search-engine Safe Search enforcement.
- YouTube Restricted Mode enforcement.
- Service blocking.
- Device-specific restrictions.
- Group-specific restrictions.
- Schedule-aware filtering where configured.

Policies can differ between family members, guests, infrastructure, and shared devices.

## Service Blocking

Administrators can block specific Internet services independently of general domain filtering.

Examples can include:

- Social networks.
- Video-streaming platforms.
- Gaming services.
- Messaging platforms.
- Advertising networks.
- Tracking networks.
- Known telemetry services.

Service controls can be applied globally or selectively to clients and groups.

## Custom DNS Rewrites

GoreeCloud DNS can override normal DNS resolution through administrator-defined DNS rewrites.

Uses include:

- Internal services.
- Homelab applications.
- Development environments.
- Private cloud services.
- Split-horizon DNS.
- Service migrations.
- Temporary maintenance redirects.
- Local aliases.

Administrators can define custom responses for selected domains without operating a separate authoritative server.

## Configurable Blocking Responses

Blocked requests can return configurable DNS responses.

Supported policy behavior can include:

- NXDOMAIN.
- REFUSED.
- Null IPv4 address.
- Null IPv6 address.
- Custom IP address.
- Local blocking page.
- Administrator-defined DNS responses.

Different responses can be selected for different filtering scenarios where appropriate.

## DHCP Services

GoreeCloud DNS is designed to provide integrated DHCP services for networks that do not require an external DHCP platform.

Capabilities can include:

- DHCPv4.
- IPv6-related network configuration where supported.
- Multiple address pools.
- Static DHCP reservations.
- Configurable lease durations.
- Gateway configuration.
- DNS server assignment.
- Domain search configuration.
- Client hostname discovery.
- DHCP lease visibility.
- Integration between DHCP leases and DNS client identities.

## Local DNS and Host Discovery

GoreeCloud DNS automatically integrates network-device information into DNS administration.

Hostnames can be learned or resolved through:

- DHCP leases.
- Reverse DNS.
- Local hosts files.
- Router DNS.
- Conditional forwarding.
- Administrator-defined local records.
- Network neighbor information where available.

This provides readable device names throughout logs, statistics, and policy controls.

## Reverse DNS

GoreeCloud DNS supports reverse DNS zones and configurable reverse lookup behavior.

It can:

- Host authoritative reverse zones.
- Resolve local client names.
- Forward reverse queries to routers.
- Forward reverse queries to another DHCP/DNS server.
- Resolve private network addresses.
- Maintain PTR records.

## DNS Rebinding Protection

GoreeCloud DNS can protect clients from DNS rebinding attacks by detecting suspicious public-domain responses that unexpectedly point to private or local network addresses.

Administrators can create exceptions for legitimate internal services and split-horizon configurations.

## Query Rate Limiting

GoreeCloud DNS provides rate controls designed to protect DNS infrastructure from abusive clients and amplification attacks.

Controls can include:

- Per-client query limits.
- Global query limits.
- Response-rate controls.
- Access restrictions.
- Abuse detection.
- Restrictions on potentially abusive query types.

## Access Control

Administrators can control which networks and clients may use GoreeCloud DNS.

Policies can be based on:

- IPv4 networks.
- IPv6 networks.
- Individual addresses.
- Trusted network ranges.
- Interface bindings.
- Authentication where supported.
- Encrypted DNS client configuration.

This helps prevent a private DNS resolver from becoming an unintended public resolver.

## Advanced DNS Security

GoreeCloud DNS combines multiple layers of DNS security, including:

- DNSSEC.
- DNS-over-HTTPS.
- DNS-over-TLS.
- DNS-over-QUIC.
- DNSCrypt.
- DNS rebinding protection.
- Query-rate controls.
- Access-control lists.
- Malware filtering.
- Phishing filtering.
- Threat-intelligence feeds.
- RPZ.
- Secure zone transfers.
- TSIG.
- Least-privilege service operation.
- Protected administrative access.

## Query Logging

GoreeCloud DNS provides detailed DNS query visibility.

Logs can include:

- Timestamp.
- Client.
- Client group.
- Requested domain.
- Query type.
- DNS response.
- Response code.
- Upstream resolver.
- Response time.
- Cache status.
- Filtering decision.
- Rule responsible for blocking.
- DNS transport.
- DNSSEC validation status.

Administrators can search, filter, export, and analyze query activity.

## Privacy-Aware Logging

DNS logging is configurable rather than mandatory.

Controls can include:

- Disable query logging.
- Limit log retention.
- Anonymize client addresses.
- Exclude selected clients.
- Exclude selected domains.
- Store only aggregate statistics.
- Configure independent statistics and query-log retention periods.

This allows observability requirements to be balanced against privacy requirements.

## DNS Statistics and Analytics

GoreeCloud DNS provides dashboards and historical analytics for DNS activity.

Metrics can include:

- Total DNS queries.
- Queries per second.
- Blocked queries.
- Allowed queries.
- Cache-hit rate.
- Cache-miss rate.
- DNSSEC validation activity.
- Queries by client.
- Queries by group.
- Queries by protocol.
- Queries by record type.
- Top requested domains.
- Top blocked domains.
- Top clients.
- Upstream resolver performance.
- Filtering effectiveness.
- Response latency.
- Error rates.

## DNS Diagnostics

Built-in diagnostic tools can help administrators troubleshoot DNS behavior.

Capabilities can include:

- DNS lookup testing.
- DNSSEC diagnostics.
- Resolver testing.
- Cache inspection.
- Trace resolution.
- Upstream testing.
- Zone validation.
- Query-log inspection.
- Response-time analysis.
- DNS transport testing.

## Web Administration

GoreeCloud DNS is designed to provide a modern responsive administrative interface for desktop, tablet, and mobile use.

Administrators can manage:

- DNS server settings.
- Recursive resolution.
- Authoritative zones.
- DNS records.
- Encrypted DNS.
- DNSSEC.
- Filtering.
- Clients.
- Groups.
- DHCP.
- Blocklists.
- Allowlists.
- Query logs.
- Statistics.
- Security.
- Users.
- API access.
- Cluster nodes.
- Backups.
- Updates.

The interface should follow the applicable GoreeCloud Glaze UI design contract.

## Role-Based Administration

GoreeCloud DNS is designed for multi-user administration rather than requiring one shared administrator account.

Administrative capabilities can include:

- Multiple administrator accounts.
- Role-based access control.
- Read-only roles.
- DNS-management roles.
- Filtering-management roles.
- Infrastructure administration.
- API-specific permissions.
- Auditable administrative actions.

## Authentication and Single Sign-On

Target administrative authentication capabilities include:

- GoreeCloud Identity integration.
- OpenID Connect.
- LDAP where interoperability requires it.
- TOTP-based multi-factor authentication.
- Secure session management.
- API tokens.
- Revocable access credentials.

## API

GoreeCloud DNS exposes a comprehensive API for automation and external management.

API capabilities can cover:

- DNS records.
- Zones.
- Filtering rules.
- Blocklists.
- Allowlists.
- Clients.
- Groups.
- DHCP.
- Statistics.
- Query logs.
- Cache management.
- Server configuration.
- Cluster administration.
- Health monitoring.

This allows GoreeCloud Manager and other authorized GoreeCloud applications to administer DNS without requiring direct interaction with the web interface.

## Automation

GoreeCloud DNS is designed for automated deployment and administration.

Automation can include:

- REST API management.
- Configuration-as-code.
- Automated blocklist updates.
- Automated DNS record management.
- Dynamic DNS.
- Certificate automation.
- Zone synchronization.
- Backup automation.
- Health checks.
- Monitoring integration.
- Infrastructure orchestration.

## Dynamic DNS

GoreeCloud DNS can support secure automated updates to DNS records when host addresses change.

This is useful for:

- Home Internet connections.
- Remote GoreeCloud nodes.
- Dynamic public IP addresses.
- VPN endpoints.
- Self-hosted services.
- Mobile infrastructure.

## High Availability

GoreeCloud DNS is designed to operate as a redundant multi-server DNS platform.

High-availability capabilities can include:

- Multiple DNS nodes.
- Redundant recursive resolvers.
- Redundant encrypted DNS endpoints.
- Replicated authoritative zones.
- Primary and secondary DNS.
- Cluster-aware administration.
- Configuration synchronization.
- Filtering-policy synchronization.
- Health monitoring.
- Automatic or administrator-controlled failover.
- Serve-stale operation during upstream failures.

Clients can be configured with multiple GoreeCloud DNS instances to avoid a single DNS-server dependency.

## Centralized Multi-Server Management

Multiple GoreeCloud DNS instances can be managed as one logical DNS environment.

Central management can cover:

- DNS configuration.
- Zones.
- Filtering.
- Client groups.
- Security policies.
- Blocklists.
- Certificates.
- Statistics.
- Server health.
- Updates.
- Backup status.

## Programmable DNS

GoreeCloud DNS is designed to support programmable DNS behavior for advanced environments.

Potential use cases include:

- Custom DNS response logic.
- Geographic responses.
- Network-aware responses.
- Split-horizon policy.
- Application-specific routing.
- Dynamic service discovery.
- Custom filtering engines.
- Security-policy extensions.
- External data-source integration.

## Proxy Support

Upstream DNS traffic can optionally use network proxies where required.

Supported architectures can include:

- HTTP proxies.
- HTTPS proxies.
- SOCKS5 proxies.
- Privacy-network routing.
- Tor-routed DNS where explicitly configured.

Proxy usage remains administrator-controlled and visible.

## Modern Networking

GoreeCloud DNS is designed for modern dual-stack networks.

Capabilities include:

- IPv4.
- IPv6.
- UDP DNS.
- TCP DNS.
- DNS-over-TLS.
- DNS-over-HTTPS.
- DNS-over-QUIC.
- Multiple network interfaces.
- Configurable listening addresses.
- Multiple network segments.
- Private networks.
- Remote-access networks.

## Flexible Deployment

GoreeCloud DNS is intended to support deployment across a wide range of GoreeCloud environments, including:

- Physical servers.
- Virtual machines.
- Linux servers.
- Containers.
- Homelab systems.
- Edge systems.
- Single-board computers where resources permit.
- Private cloud infrastructure.

Deployment should remain portable and avoid unnecessary dependence on a single infrastructure vendor.

## Backup and Recovery

GoreeCloud DNS is designed to preserve configuration and operational state through the applicable Everkeep recovery architecture.

Recoverable data can include:

- DNS zones.
- DNS records.
- Filtering rules.
- Blocklists.
- Allowlists.
- Client definitions.
- Groups.
- DHCP configuration.
- Server configuration.
- Authentication configuration.
- Certificates where appropriate.
- Cluster configuration.
- Application metadata.

Configuration should be exportable and restorable without proprietary lock-in.

## Privacy Shield Integration

GoreeCloud DNS is intended to integrate with GoreeCloud Privacy Shield as a central privacy-enforcement layer.

DNS signals and policies can contribute to:

- Tracker blocking.
- Telemetry reduction.
- Advertising-domain blocking.
- Privacy threat identification.
- Per-device privacy controls.
- Central privacy reporting.

## Wardveil Security Integration

GoreeCloud DNS is intended to participate in the Wardveil Security architecture.

DNS capabilities can contribute to:

- Malicious-domain blocking.
- Phishing protection.
- Threat-intelligence enforcement.
- Suspicious DNS detection.
- DNS infrastructure hardening.
- Security-event visibility.
- Policy enforcement.
- Administrative auditing.

## GoreeCloud Platform Integration

GoreeCloud DNS is designed as a first-party GoreeCloud platform service rather than an isolated DNS appliance.

Integration targets include:

- GoreeCloud Identity for authentication and authorization.
- GoreeCloud Manager for centralized administration.
- GoreeCloud Privacy Shield for privacy controls.
- Wardveil Security for security enforcement and threat intelligence.
- Everkeep for backup and recovery.
- GoreeCloud Notify for operational notifications.
- GoreeCloud API for authorized automation and interoperability.
- Glaze UI for a consistent administrative experience.

## Data Ownership and Independence

GoreeCloud DNS is designed around self-hosting and administrator ownership.

The platform should provide:

- No advertising.
- No sponsorship-driven DNS behavior.
- No mandatory external account.
- No required third-party DNS provider.
- Local ownership of configuration.
- Local ownership of DNS statistics.
- Local ownership of query logs.
- Exportable configuration.
- Open and documented interfaces.
- Self-hosted operation.
- Replaceable upstream providers.
- Recursive operation without a commercial DNS intermediary.

## Performance and Efficiency

GoreeCloud DNS is designed to remain efficient enough for home and small-network deployments while scaling to substantially larger environments.

Performance-oriented capabilities include:

- Asynchronous DNS processing.
- Concurrent resolution.
- High-performance caching.
- Cache prefetching.
- Efficient filtering.
- Persistent state where beneficial.
- Bounded resource usage.
- Optimized upstream selection.
- Fast local DNS responses.
- Low-overhead network-wide filtering.

## GoreeCloud DNS Capability Vision

GoreeCloud DNS is intended to combine the major strengths traditionally spread across several separate DNS products into one first-party platform:

- A validating recursive DNS resolver.
- A full authoritative DNS server.
- A network-wide filtering engine.
- An encrypted DNS server.
- A DHCP and local-network DNS service.
- A DNS security and threat-enforcement platform.
- A per-device and group policy engine.
- A DNS analytics and diagnostics platform.
- A programmable and API-driven DNS service.
- A highly available multi-node DNS platform.

The objective is not merely to provide DNS-based ad blocking. GoreeCloud DNS is designed to become the authoritative, recursive, privacy, security, filtering, policy, observability, and administration layer for DNS throughout the GoreeCloud environment.