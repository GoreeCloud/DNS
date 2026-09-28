# Project Specifications — GoreeCloud DNS

## Document Status

- **Product:** GoreeCloud DNS
- **Repository:** `GoreeCloud/DNS`
- **Current repository ID:** `1391515788`
- **Default branch:** `main`
- **Lifecycle:** Development pending component-by-component reclassification under current release-lifecycle governance
- **Capability umbrella:** GoreeCloud Beacon
- **Authority:** This repository file is the authoritative project specification after verified migration.
- **Implementation boundary:** Requirements and historical implementation descriptions do not establish current implementation in the recreated repository.
- **Migrated source:** `Project Specification — DNS.docx`, Drive ID `1z5aDWcgxCls1alEXx8bj0RLhoPPrUELw`, source version v1.0, last updated September 15, 2026.
- **Reconciled:** September 27, 2026.

> The current `GoreeCloud/DNS` repository is a recreated lineage. Historical source milestones from the predecessor repository are preserved in `PROJECT-RECORD.md`; they are not inherited as current implementation or acceptance evidence.

## Reconciliation Notes

The migrated Drive specification remains the governing requirements baseline. Its original fork-first language is retained where historically or architecturally relevant, but its own later Section 34 controls the target architecture: GoreeCloud DNS is a first-party GoreeCloud-owned DNS platform, and AdGuard Home/Unbound paths are transitional migration, compatibility, testing, reference, and rollback sources rather than permanent product-level runtime dependencies.

The September 27, 2026 owner-supplied capability inventory is preserved as Appendix A because it adds concrete target requirements not stated explicitly in the September 15 source, including DNSCrypt, ZONEMD, CNAME-cloaking protection, SVCB/HTTPS records, additional administration interoperability, and optional proxy-routing capabilities.

## 1. Purpose
I will use GoreeCloud DNS as GoreeCloud’s client-facing DNS filtering, policy-enforcement, private service-discovery, and DNS security platform.
GoreeCloud DNS will become the complete GoreeCloud DNS platform and will replace the long-term production roles currently performed by both AdGuard Home and Unbound. Filtering, policy enforcement, private DNS, recursive resolution, forwarding, caching, DNSSEC validation, resolver resilience, privacy controls, statistics, and administration will become first-party GoreeCloud DNS capabilities within one service.
My objective is not to create a cosmetic rebrand of AdGuard Home. I will use AdGuard Home as a mature engineering foundation and progressively replace, redesign, or extend inherited components when doing so provides meaningful GoreeCloud ownership, security, usability, maintainability, interoperability, or independence benefits.

## 2. Strategic Decision
Current direction note — The fork-first strategy retained below records the project’s initial migration approach. Section 34 now controls the target architecture: GoreeCloud DNS is a first-party GoreeCloud-owned DNS platform, and inherited AdGuard Home or Unbound paths are transitional migration, compatibility, testing, reference, and rollback sources only—not permanent product-level runtime dependencies.
I will initially develop GoreeCloud DNS as a maintained open-source fork of AdGuard Home rather than implementing a DNS platform completely from scratch.
This approach provides a mature DNS foundation while allowing GoreeCloud to progressively gain direct control over the product architecture. It reduces the operational risk associated with immediately reimplementing DNS parsing, caching, filtering, upstream resolution, encrypted DNS, client identification, concurrency, network behavior, and failure handling.
The intended transition model is:
AdGuard Home → GoreeCloud-maintained fork → increasingly independent GoreeCloud DNS → future GoreeCloud-controlled architecture.
A complete native rewrite is not required as an initial milestone. Native replacement of inherited subsystems may occur incrementally when justified and validated.

## 3. Product Role
GoreeCloud DNS will provide:
- Network-wide advertisement and tracker blocking.
- Malicious-domain and threat-domain blocking.
- Client-specific DNS policies.
- Family and child DNS policy profiles.
- Private GoreeCloud DNS records and service discovery.
- Custom filtering and allow rules.
- Query visibility and privacy-aware diagnostics.
- Upstream DNS management.
- Encrypted DNS capabilities where approved.
- Integration with GoreeCloud Network for private connectivity and client identity.
- Integration with GoreeCloud Monitor for service health and observability.
- Integration with GoreeCloud Notify for operational and security notifications.
- Integration with Everkeep for configuration and state protection.
- Integration with GoreeCloud Manager for centralized administration and platform visibility.
- Wardveil Security capabilities for DNS security and policy enforcement.

## 4. DNS Architecture
The target architecture is a single-service GoreeCloud DNS responsibility model:
Approved Clients
→ GoreeCloud DNS
→ Internet DNS Authorities or explicitly configured upstream resolvers
GoreeCloud DNS responsibilities:
- Client-facing DNS service.
- DNS filtering.
- Advertisement and tracker blocking.
- Threat-domain blocking.
- Per-client and per-group policies.
- Private GoreeCloud DNS records.
- Service discovery.
- DNS query policy enforcement.
- Approved encrypted DNS endpoints.
- DNS administration and operational visibility.
Integrated GoreeCloud DNS resolver responsibilities:
- Recursive DNS resolution.
- DNS caching, negative caching, stale serving, and prefetching.
- DNSSEC validation.
- Privacy-oriented recursive resolution and query-name minimization.
GoreeCloud DNS will replace both the AdGuard Home and Unbound production roles.

## 5. Private GoreeCloud Service Discovery
Private GoreeCloud DNS must be treated as a first-class product capability rather than only as a generic DNS-rewrite feature.
The administration interface should provide a GoreeCloud Services area that identifies private service hostnames, destination addresses, service roles, access classifications, HTTPS routing relationships, and health information where integrations make that information available.
Examples include private service names such as manager.goreecloud.com, memos.goreecloud.com, search.goreecloud.com, and other approved GoreeCloud hostnames.
DNS resolution does not itself grant authorization. Network access, application authentication, authorization, Caddy routing, GoreeCloud Network policies, and other security controls remain independent enforcement boundaries.

## 6. Policy Profiles
GoreeCloud DNS should provide first-class policy profiles that simplify consistent DNS protection across device and user classes.
Initial planned profiles include:
- Administrator
- Personal
- Family
- Child
- IoT
- Guest
- Infrastructure
- Custom
Profiles may control filtering levels, SafeSearch behavior, blocked service categories, schedules, custom rules, access to private GoreeCloud names, logging and privacy levels, encrypted DNS behavior, threat protection, and other approved DNS capabilities.

## 7. Glaze UI
The GoreeCloud DNS administration interface will use the Glaze UI design language.
The interface should prioritize clarity, accessibility, responsive behavior, operational visibility, and consistent interaction patterns with other GoreeCloud applications.
Initial navigation may include:
- Overview
- Queries
- Protection
- Clients
- Services
- Policies
- Upstreams
- Security
- Settings
Inherited AdGuard Home interface elements may remain temporarily during early fork stabilization, but the long-term interface must become a coherent GoreeCloud-controlled product experience rather than a lightly reskinned upstream interface.
7.1 Beacon Insights Overview
The Overview page will be the default GoreeCloud DNS Beacon Console landing surface and will be powered by Beacon Insights. It must be a purpose-built Glaze UI operational dashboard rather than an inherited AdGuard-style statistics page.
Its signature visualization should be a DNS Resolution Path that makes the live request flow understandable at a glance: client/listener → identity and policy / Beacon Shield → authoritative or private DNS → Beacon Cache → Beacon Resolver or configured forwarder/upstream → DNSSEC/result processing → client response. Each applicable stage should expose health, throughput, latency, error or decision state, and a direct path to deeper diagnostics without implying that presentation is an enforcement boundary.
The Overview should surface, where implemented and applicable: DNS service and listener state and relevant IP addresses; active and known DNS clients; total query activity for the selected time range; allowed, blocked, filtered, rewritten, failed, and cached outcomes; top privacy-safe policy/filter categories and decisions; cache hit, miss, and stale behavior; recursive and forwarded resolution state; configured upstream and resolver health, success/failure, failover, and latency; DNSSEC secure, insecure, bogus, and indeterminate outcomes; and authoritative-zone, DHCP, or cluster state when those subsystems are enabled.
Overview cards and charts should support time-range selection and deep links into Queries, Clients, Protection, Upstreams, Security, and other authoritative detail pages. Responsive layouts must adapt composition rather than merely shrink it, and loading, empty, unknown, degraded, permission-denied, and error states must remain deliberate Glaze UI experiences.
Privacy-safe aggregate statistics are the default presentation. GoreeCloud DNS must not collect or retain raw query names, client identifiers, private IP inventories, or other sensitive activity merely to populate the Overview. Per-client, per-query, or raw-address detail may be available only inside the authorized GoreeCloud DNS administrative boundary when the relevant logging, access-control, minimization, masking, retention, deletion, and Privacy Shield requirements permit it.
This requirement belongs to Beacon Console presentation and Beacon Insights observability. It does not transfer DNS runtime authority to GoreeCloud Manager, Monitor, or any dashboard consumer, and it does not constitute production acceptance until the native implementation and applicable Glaze UI, Privacy Shield, security, accessibility, responsive, performance, and target-environment acceptance gates are verified.

## 8. Wardveil Security
Wardveil Security by GoreeCloud will identify security-focused DNS capabilities where appropriate.
Potential Wardveil DNS capabilities include:
- Malicious-domain protection.
- Threat intelligence integration.
- DNS bypass detection.
- Encrypted DNS policy enforcement.
- Suspicious query detection.
- DNS anomaly indicators.
- Client isolation indicators.
- Security event generation.
- Integration with GoreeCloud Notify and GoreeCloud Monitor.
Security capabilities must remain evidence-based and must not imply protections that the underlying implementation does not actually provide.

## 9. GoreeCloud Platform Integrations
GoreeCloud DNS should progressively integrate with the broader GoreeCloud platform.
GoreeCloud Manager may display DNS health, query activity, filtering status, protection status, configuration state, and other operational information.
GoreeCloud Network may provide approved client identity, private connectivity, remote DNS delivery, and network-policy context.
GoreeCloud Monitor may verify DNS availability, upstream resolution, filtering behavior, private service resolution, latency, and other health indicators.
GoreeCloud Notify may deliver DNS outage, configuration, security, or validation notifications.
Everkeep must protect the configuration, policy definitions, custom rules, private records, required persistent state, and recovery information necessary to restore GoreeCloud DNS.

## 10. Repository and Licensing
The planned repository is:
GoreeCloud/goreecloud-dns
The repository will originate from the approved AdGuard Home upstream repository.
The fork must preserve all applicable upstream licensing, copyright notices, attribution, source-availability obligations, and other license requirements. The exact upstream license and applicable obligations must be verified and recorded when the fork is created.
The repository must follow GoreeCloud source-control, code-structure, security-update, dependency-management, documentation, privacy, and continuous-improvement requirements.

## 11. Development Phases
Phase 0 — Fork Foundation
- Create the GoreeCloud fork.
- Establish repository identity and upstream provenance.
- Verify licensing.
- Establish protected development practices.
- Establish CI and build validation.
- Establish dependency and vulnerability scanning.
- Establish software bill of materials generation where appropriate.
- Establish reproducible release practices.
Phase 1 — GoreeCloud Product Foundation
- Introduce GoreeCloud DNS naming and product identity.
- Begin Glaze UI integration.
- Establish GoreeCloud configuration conventions.
- Preserve existing DNS functionality during UI and structural changes.
- Establish migration and compatibility testing.
Phase 2 — GoreeCloud DNS Features
- Implement GoreeCloud Services management.
- Implement policy profiles.
- Improve client and device organization.
- Improve private DNS management.
- Establish GoreeCloud APIs and integration boundaries.
Phase 3 — Platform Integration
- Integrate GoreeCloud Network.
- Integrate GoreeCloud Manager.
- Integrate GoreeCloud Monitor.
- Integrate GoreeCloud Notify.
- Integrate Everkeep.
- Expand Wardveil Security integration.
Phase 4 — Independence
- Identify inherited components that create unnecessary upstream dependence.
- Replace selected components when justified.
- Establish native GoreeCloud configuration and policy models where beneficial.
- Reduce upstream-specific assumptions.
- Maintain migration compatibility where practical.

## 12. Migration from AdGuard Home
GoreeCloud DNS must provide a controlled migration path from the current AdGuard Home deployment.
Migration scope should include, where technically possible and appropriate:
- DNS rewrites.
- Client definitions.
- Client groups.
- Filtering lists.
- Custom filtering rules.
- Allowlists.
- Upstream configuration.
- Bootstrap DNS configuration.
- Query and privacy settings.
- SafeSearch and family-protection settings.
- Other approved operational settings.
Migration must not expose credentials, secrets, API keys, private tokens, or other sensitive information through source control or ordinary documentation.

## 13. Production Safety and Cutover
The current AdGuard Home production service must remain operational during early GoreeCloud DNS development.
GoreeCloud DNS must initially operate in an isolated development or validation environment using a non-conflicting address, port, virtual machine, container environment, or other approved isolation mechanism.
Production DNS cutover is prohibited until the replacement has demonstrated acceptable behavior for:
- Local DNS clients.
- Remote GoreeCloud Network clients.
- Private GoreeCloud service resolution.
- Advertisement and tracker filtering.
- Threat-domain filtering.
- Policy profiles.
- Integrated recursive and forwarded resolution.
- DNSSEC-dependent behavior.
- Failure and restart behavior.
- Configuration backup.
- Restoration.
- Monitoring.
- Performance.
- Security.
The existing AdGuard Home deployment must remain available as a rollback option until GoreeCloud DNS has completed production acceptance and an approved stabilization period.

## 14. Availability and Failure Requirements
Because DNS is foundational infrastructure, GoreeCloud DNS must fail predictably and must not create an unrestricted public resolver.
The project must include validation for:
- Service startup and restart.
- Upstream resolver failure.
- Network interruption.
- Invalid configuration.
- Corrupted or missing persistent state.
- Backup restoration.
- Client timeout behavior.
- Private DNS resolution failure.
- Filter update failure.
- Resource exhaustion.
- Upgrade and rollback behavior.
Future high-availability or redundant DNS deployment may be added when the infrastructure supports it.

## 15. Privacy Requirements
GoreeCloud DNS must follow GoreeCloud privacy-by-default requirements.
DNS query data can reveal sensitive information about browsing, applications, devices, users, and behavior. Query logging must therefore be configurable, appropriately retained, access controlled, and minimized according to operational need.
Telemetry must not be introduced merely for product analytics. Any external communication must have a documented operational purpose and must comply with GoreeCloud privacy and data-protection requirements.

## 16. Security Requirements
GoreeCloud DNS must:
- Restrict administrative access to approved users and networks.
- Avoid unnecessary public exposure.
- Protect configuration and credentials.
- Separate secrets from source-controlled configuration.
- Validate updates and dependencies.
- Maintain auditable configuration changes where practical.
- Support secure backup and recovery.
- Avoid unrestricted recursive DNS exposure to the public Internet.
- Preserve network and application authorization boundaries.

## 17. Long-Term Direction
The long-term objective is not permanent dependence on AdGuard Home.
The upstream project is the initial foundation that allows GoreeCloud DNS to begin with mature DNS capabilities. Over time, GoreeCloud may replace inherited user-interface components, configuration models, policy engines, APIs, integration layers, and other subsystems when doing so improves platform ownership or maintainability.
The desired progression is:
AdGuard Home
→ GoreeCloud DNS maintained fork
→ GoreeCloud-native user experience and integrations
→ increasingly independent internal architecture
→ GoreeCloud-controlled DNS platform.
Technology independence remains more important than preserving any particular inherited implementation.

## 18. Initial Decision Record
Decision: Build GoreeCloud DNS as a GoreeCloud-maintained fork of AdGuard Home with a controlled fork-to-native transition strategy.
Product Name: GoreeCloud DNS
Repository: GoreeCloud/goreecloud-dns
Initial Upstream: AdGuard Home
DNS Role: Client-facing filtering, policy enforcement, private DNS, and service discovery
Recursive Resolver: Native GoreeCloud DNS first-party resolver engine
Design Language: Glaze UI
Security Identity: Wardveil Security by GoreeCloud
Production Migration: Controlled parallel validation followed by explicit acceptance and cutover
Current Production AdGuard Home: Remains operational until GoreeCloud DNS is proven stable and accepted for production.

## 19. Integrated First-Party Resolver Engine
I will develop GoreeCloud DNS as one complete DNS application and service that replaces both AdGuard Home and Unbound after controlled migration and production acceptance.
AdGuard Home is the initial maintained-fork engineering foundation. Unbound is a capability reference and current migration source. Neither is a permanent backend, sidecar, or required production dependency in the target architecture.
GoreeCloud DNS will natively provide recursive resolution, high-performance positive and negative caching, aggressive DNSSEC negative caching, configurable minimum and maximum cache TTL controls, stale-cache serving, prefetching, configurable forward zones, multiple upstream resolvers with redundancy and failover, DNSSEC validation and trust-anchor lifecycle management, query-name minimization where applicable, minimal responses, local zones and local DNS data, response-policy zones, private-address and DNS-rebinding protection, client and network access controls, multi-threaded processing, partitioned or sharded caches, comprehensive runtime statistics, authenticated runtime administrative controls, interface and query restrictions, privilege separation where supported, and resolver hardening.
The target request path is: Approved Client → GoreeCloud DNS listener → client and access policy → local/private DNS and policy evaluation → cache → recursive or forward resolver → DNSSEC validation → response policy → client response. Every stage is part of the GoreeCloud DNS runtime and uses one configuration, administration, observability, privacy, security, backup, release, and recovery lifecycle.
The migration will be incremental. GoreeCloud DNS will preserve inherited behavior while the native resolver subsystem is implemented behind explicit internal interfaces. Native resolver capabilities will then be validated for correctness, feature parity, DNSSEC behavior, cache performance, stale-cache behavior, upstream failover, privacy, access control, concurrency, observability, runtime administration, restart and recovery behavior, configuration migration, and rollback. Only after explicit acceptance will the separate AdGuard Home and Unbound production services be retired.
Initial source implementation status: draft pull request #3 now establishes the single-service first-party resolver capability contract, removes the previously introduced separate Unbound backend configuration, prohibits reintroduction of a sidecar Unbound backend through fail-closed source validation, and records that production_approved remains false until executable integration and target-environment acceptance are complete.

## 20. Integrated First-Party DNS Platform Capability Set
I will expand GoreeCloud DNS beyond the resolver engine into a complete first-party DNS platform while preserving the single-service architecture. Recursive DNS, authoritative DNS, encrypted DNS, filtering, DHCP, clustering, administration, identity, automation, observability, and extensible DNS processing will be owned by GoreeCloud DNS rather than delegated to permanent external DNS products.
Recursive and authoritative DNS requirements include full recursive resolution for independence from external DNS providers; authoritative hosting for internal and public zones; primary, secondary, forwarder, and stub zones; catalog-based zone provisioning and synchronization; zone transfer and notification; split-horizon responses based on client, subnet, or network identity; conditional forwarding for directory services, VPNs, branch offices, hybrid environments, private namespaces, and other internal DNS systems; DNSSEC validation for recursive resolution; and DNSSEC signing for authoritative zones.
Filtering and policy requirements include network-wide advertisement, tracker, malware, phishing, telemetry, and unwanted-domain blocking; blocklists and allowlists; wildcard and regular-expression rules; response-policy zones; client-specific policy; subnet-based groups; and controlled custom DNS processing. Filtering must remain integrated with the same access-control, privacy, observability, and administration model used by the resolver and authoritative engine.
Encrypted DNS requirements include DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC for approved downstream clients, plus secure encrypted forwarding to compatible upstream resolvers when forwarding is selected instead of direct recursion.
Performance and resilience requirements include positive, negative, aggressive-negative, persistent, serve-stale, prefetch, and auto-prefetch caching; configurable TTL controls; cache sharding or partitioning; concurrent recursive work; latency-based authoritative name-server selection; health-aware upstream failover; and multi-threaded processing.
DHCP requirements include an integrated DHCP server with automatic registration and lifecycle management of approved DNS records so leases, names, client identity, and policy can remain synchronized inside GoreeCloud DNS.
High-availability requirements include multi-instance clustering, centralized configuration and operational management, catalog and zone synchronization, health coordination, and redundant independent DNS-serving capability. Cluster control must not create a mandatory single point of DNS failure.
Administration and identity requirements include a browser-based administration console, comprehensive HTTP API, multiple administrative users, role-based access control, scoped API tokens, TOTP two-factor authentication, and OIDC single sign-on. Runtime administration must support safe configuration reloads, cache operations, statistics, zone management, upstream/resolver controls, service health, and other approved management functions.
Observability requirements include configurable detailed DNS query logging, audit logging, runtime statistics, dashboards, health information, metrics, resolver and authoritative latency, cache behavior, DNSSEC outcomes, forwarding and recursion health, failure information, DHCP state, and integration with approved GoreeCloud monitoring systems. Privacy-by-default controls must allow sensitive query data to be minimized, redacted, retained for limited periods, or disabled according to operational need.
The application framework must expose controlled extension points for advanced blocking, split-horizon processing, geolocation-based responses, DNS64, DNS rebinding protection, advanced forwarding, and custom DNS processing logic. Extensions must execute within explicit security, privacy, resource, policy, and observability boundaries and must not bypass core DNS safeguards.
Draft pull request #3 now records these capabilities in resolver/capabilities.json schema version 2, expands the first-party DNS platform architecture documentation, and fails closed if required capability declarations are removed or a separate Unbound backend is reintroduced. This remains an implementation contract and staged migration blueprint rather than a claim that every native subsystem is already production-complete.

## 21. Native Subsystem and Configuration Architecture
I will implement the integrated GoreeCloud DNS platform as one service with explicit internal subsystem boundaries rather than as a collection of permanent external DNS sidecars. The source-controlled subsystem contract defines listener, identity and policy, query pipeline, filtering, authoritative DNS, cache, recursive resolver, DHCP, clustering, administration, observability, configuration, runtime security, and extension responsibilities.
The listener subsystem will own DNS over UDP and TCP plus optional DoH, DoT, and DoQ endpoints. Identity and policy will own client identification, subnet grouping, administrator roles, API tokens, TOTP, and OIDC. The query pipeline will coordinate split-horizon decisions and approved custom processing before selecting authoritative, filtering, cache, recursive, forwarder, or stub behavior.
The authoritative subsystem will own internal and public authoritative zones, primary and secondary operation, forwarder and stub zone definitions, catalog zones, zone transfer, notify, and DNSSEC signing. The cache subsystem will own volatile and persistent caches, negative and aggressive-negative caching, TTL controls, stale responses, prefetch, auto-prefetch, and cache partitioning. The resolver subsystem will own recursion, concurrent resolution, latency-based name-server selection, conditional and normal forwarding, encrypted forwarding, DNSSEC validation, trust anchors, QNAME minimization, and minimal responses.
The DHCP subsystem will integrate address assignment with DNS registration. The cluster subsystem will coordinate approved configuration, policy, and zone state across multiple independent GoreeCloud DNS nodes without making central management a mandatory single point of DNS failure. Administration and observability remain separate internal responsibilities so APIs, the Glaze UI console, audit records, metrics, query logs, health data, and statistics can be independently secured and tested.
The first-party configuration model will fail safe. The source example restricts recursive DNS to loopback networks, explicitly prohibits public recursive-resolver mode, enables DNSSEC validation and DNS rebinding protection, and keeps encrypted DNS listeners, authoritative serving, DHCP, clustering, and extensions disabled until explicitly configured. Administration and API listeners also default to loopback. Public authoritative service is treated as a distinct exposure class from public recursive DNS.
The source validator must fail closed if required native subsystems disappear, required capability ownership becomes incomplete, unsafe example defaults are introduced, production approval is asserted by source configuration, or a separate Unbound backend is reintroduced. These contracts guide implementation and review but do not substitute for executable subsystem code or production acceptance.

## 24. GoreeCloud Beacon Feature Identity
I will use GoreeCloud Beacon as the official umbrella identity for the first-party capabilities of GoreeCloud DNS. GoreeCloud DNS remains the application and service name; Beacon organizes and presents the integrated feature families inside that single application and runtime.
Beacon represents trusted DNS guidance, discovery, resolution, security, routing, authoritative data, resilience, administration, and operational visibility. The identity does not create a separate daemon, backend, sidecar, or permanent dependency. Every Beacon capability remains part of GoreeCloud DNS and follows the same configuration, access-control, privacy, security, observability, backup, release, recovery, and production-acceptance requirements.
The official feature-family vocabulary is:
- Beacon Resolver — recursive resolution, forwarding, conditional and stub resolution, concurrency, latency-aware name-server selection, DNSSEC validation, QNAME minimization, upstream failover, encrypted forwarding, and resolver hardening.
- Beacon Cache — positive, negative, and aggressive-negative caching; TTL controls; serve-stale; prefetch and auto-prefetch; persistent cache state; sharding; statistics; and recovery behavior.
- Beacon Zones — internal and public authoritative DNS, primary and secondary zones, forwarder and stub zones, local zones and data, split-horizon DNS, transfers and notify, catalog zones, and DNSSEC signing.
- Beacon Shield — DNS advertisement, tracker, malware, phishing, telemetry, and unwanted-domain blocking; blocklists and allowlists; wildcard and regular-expression rules; response-policy zones; client/subnet policies; query restrictions; private-address protections; and DNS-rebinding protection. Beacon Shield is a DNS capability family and does not replace Wardveil Security as GoreeCloud’s broader security identity.
- Beacon Policy Profiles — reusable identity-, device-, client-, subnet-, network-, group-, family-, and infrastructure-scoped DNS policy profiles; deterministic inheritance and composition; schedules; temporary overrides; privacy settings; family controls; application/service controls; SafeSearch; rewrites; and explainable precedence.
- Beacon Secure DNS — DoH, DoT, DoQ, encrypted forwarding, secure listener policy, certificate-aware encrypted-DNS configuration, and transport restrictions.
- Beacon DHCP — integrated DHCP, lease lifecycle, automatic DNS registration, and coordinated local DNS state.
- Beacon Horizon — split-horizon responses, client/subnet/network-specific answers, private-domain routing, VPN and branch-office DNS behavior, hybrid conditional forwarding, geolocation-based responses where approved, and DNS64 processing.
- Beacon Cluster — multi-instance coordination, centralized management, approved configuration and zone synchronization, catalog-based provisioning, redundancy, health-aware operation, and controlled recovery.
- Beacon Console — the Glaze UI browser administration experience for configuration, troubleshooting, query inspection, zone and policy management, DHCP, clustering, health visibility, and runtime control.
- Beacon API — the first-party HTTP API, scoped API tokens, scripting, automation, orchestration, integrations, configuration management, runtime administration, cache control, and statistics retrieval.
- Beacon Identity — multi-user administration, role-based access control, scoped permissions, API-token identity, TOTP two-factor authentication, OIDC single sign-on, and administrative authorization boundaries.
- Beacon Insights — privacy-aware query logging, auditing, statistics, health data, resolver/upstream health, cache utilization, DNSSEC outcomes, authoritative-zone state, DHCP state, cluster status, metrics, and dashboards.
- Beacon Extensions — controlled first-party extension points for advanced blocking, split-horizon logic, DNS64, geolocation responses, forwarding logic, policy extensions, and custom DNS processing.
The preferred relationship is: Product — GoreeCloud DNS; Feature Umbrella — GoreeCloud Beacon; Design Language — Glaze UI; Security Identity — Wardveil Security where applicable; Privacy Identity — Privacy Shield where applicable; Runtime Authority — GoreeCloud DNS.
Beacon naming may appear in source documentation, Glaze UI navigation, settings, dashboards, APIs, release notes, and public explanations when it improves clarity. New Beacon family names must describe durable capability domains, must not imply separate executables unless the architecture explicitly establishes them, and must not conflict with existing GoreeCloud identities such as Glaze UI, Wardveil Security, Privacy Shield, Everkeep, Waypoint, or Quill.
Naming does not constitute implementation or production acceptance. A Beacon capability may be described as production-ready only after its executable implementation passes the applicable correctness, security, privacy, performance, recovery, migration, and target-environment acceptance requirements.

## 34. Expanded Capability Requirements — GoreeCloud DNS + GoreeCloud Beacon
Normative status — This section records the approved target capability and architecture requirements for GoreeCloud DNS. It does not claim that every capability is implemented or production-ready. Where target-language elsewhere in this specification conflicts with this section, this section controls. Earlier implementation and validation entries remain historical evidence of the state actually verified at the time.
I require GoreeCloud DNS to become a complete first-party DNS, privacy, security, filtering, policy-control, analytics, administration, and service-discovery platform. It must combine advanced DNS filtering and policy capabilities with native recursive DNS, authoritative DNS, DNSSEC, encrypted DNS, DHCP, private service discovery, high availability, privacy controls, administration, automation, and deep GoreeCloud ecosystem integration.
GoreeCloud DNS must remain first-party, GoreeCloud-owned, self-hostable, privacy-by-default, operator-controlled, independent of third-party hosted control planes, and capable of local operation without mandatory cloud dependencies. The objective is not simple feature parity or checklist-driven imitation; capabilities are to be added because they make GoreeCloud DNS better, safer, more private, easier to operate, more resilient, or more useful.
34.1 Product Principles
- First-party GoreeCloud ownership of the DNS product, policy model, administration experience, privacy model, security boundaries, and runtime architecture.
- Self-hostable and operator-controlled deployment, with no mandatory third-party hosted control plane.
- Local-first operation and continued DNS service when optional centralized management or external connectivity is unavailable.
- Privacy-by-default processing, explicit operational purpose, data minimization, and no required external analytics telemetry.
- First-party implementation of capabilities that properly belong inside GoreeCloud DNS instead of depending on another complete DNS product.
- Clear lifecycle separation between planned capability, Development implementation evidence, release acceptance, production deployment, and Stable qualification.
34.2 GoreeCloud Beacon Capability Umbrella
GoreeCloud Beacon remains the official capability umbrella inside GoreeCloud DNS. Beacon organizes durable capability families but must not become a separate product, daemon, backend, sidecar, hosted dependency, or independent runtime authority.
- Beacon Shield
- Beacon Policy Profiles
- Beacon Resolver
- Beacon Cache
- Beacon Zones
- Beacon Secure DNS
- Beacon Horizon
- Beacon DHCP
- Beacon Cluster
- Beacon Console
- Beacon API
- Beacon Identity
- Beacon Insights
- Beacon Extensions
34.3 Beacon Shield — DNS Filtering and Policy Enforcement
- Network-wide advertisement, tracker, telemetry-domain, malware-domain, phishing-domain, malicious-domain, and unwanted-domain blocking.
- Threat-intelligence integration with controlled provenance and privacy boundaries.
- Configurable blocklists and allowlists; wildcard and regular-expression filtering; response-policy rules; custom domain rules; category-based filtering; application and service controls.
- Private-address protections and DNS-rebinding protection.
- Client-, device-, network-, subnet-, group-, and profile-specific policy.
- Deterministic, explainable rule actions, where valid within DNS semantics: Allow, Block, Refuse, NXDOMAIN, Bypass, Override, DNS Rewrite, A Rewrite, AAAA Rewrite, CNAME Rewrite, and Private-Domain Rewrite.
Beacon Shield is the primary DNS filtering and policy-enforcement family and does not replace Wardveil Security as GoreeCloud’s broader security authority.
34.4 Beacon Policy Profiles
Policy Profiles must be reusable, composable, explainable, and assignable by approved identity and network context.
Assignment scopes
- User
- Administrator
- Device
- Client identity
- IP address
- Subnet
- Network
- Device group
- Family member
- Infrastructure role
Initial profile types
- Administrator
- Personal
- Family
- Child
- IoT
- Guest
- Infrastructure
- Custom
Profile controls
- DNS filtering levels; advertisement, tracker, telemetry, and threat protection.
- Content categories, applications, online services, SafeSearch, and restricted-content behavior where DNS-level enforcement is technically appropriate.
- Custom DNS rules, private DNS access, DNS rewrites, and encrypted-DNS behavior.
- Schedules, query logging, analytics, data retention, and privacy levels.
Profile inheritance and composition are permitted only when precedence remains deterministic and understandable. A Child profile may, for example, inherit a Family baseline while applying additional restrictions.
34.5 Scheduled Policies and Temporary Overrides
Scheduled policy requirements
- Selected weekdays and explicit time ranges.
- Overnight schedules.
- Local IANA time zones.
- Recurring schedules.
- School-hour, work-hour, bedtime, recreation-period, and maintenance-window policies.
- Deterministic evaluation with an explanation of which schedule made a rule active or inactive.
Temporary override requirements
- Temporarily allow a blocked application or service.
- Temporarily disable a filtering category.
- Temporarily block a service.
- Temporarily relax a Child profile or temporarily increase protection.
- Temporarily override a DNS rule.
- Automatically expire exceptions without manual cleanup.
Each override must record who created it, what it changes, activation and expiration times, affected profile, affected client/device when applicable, and the original policy or rule being overridden. Expired overrides must stop affecting DNS behavior automatically.
34.6 Family and Child Controls
- Adult-content, gambling, violence-related, piracy-related, and other configurable category filtering.
- Social-network, gaming, application, and online-service controls.
- SafeSearch enforcement and restricted-content enforcement where DNS-level enforcement is technically appropriate.
- Scheduled access, bedtime policies, recreation periods, and temporary exceptions.
Family and Child controls must use the existing Beacon Policy engine rather than creating a separate parallel parental-control system.
34.7 Application, Service, Category, and SafeSearch Catalogs
GoreeCloud DNS must maintain controlled first-party catalogs so administrators can govern recognizable applications, services, platforms, protocols, destinations, content categories, SafeSearch mappings, restricted-content mappings, and threat classifications without manually enumerating every associated domain.
- Policy actions such as blocking a social platform, allowing a video service, restricting gaming or streaming services, blocking cloud-storage services, and applying time- or profile-scoped service access.
- Documented provenance, integrity validation, signed metadata where applicable, versioning, controlled updates, rollback, offline availability, privacy protection, change history, expiration, recovery, and administrator review when appropriate.
- SafeSearch enforcement per profile, device, client, and schedule, with target-domain exemptions, deterministic mappings, rewrite-loop protection, ambiguous-mapping protection, controlled updates, and rollback.
- Catalog behavior must never depend on silently downloaded mutable data whose integrity cannot be established.
SafeSearch and restricted-content mappings must be GoreeCloud-controlled configuration data and must not require a third-party hosted control plane.
34.8 Beacon Secure DNS
- DNS-over-HTTPS (DoH).
- DNS-over-TLS (DoT).
- DNS-over-QUIC (DoQ).
- Encrypted forwarding to approved upstream resolvers when forwarding is selected.
- Per-profile encrypted-DNS policy.
- Certificate-aware endpoint configuration and transport restrictions.
- Approved-client enforcement and client authentication where appropriate.
- Encrypted-DNS bypass detection where technically possible and appropriately scoped.
- Integration with Wardveil Security without transferring DNS runtime authority away from GoreeCloud DNS.
34.9 Beacon Insights — Privacy-Aware Analytics and Explainability
- Total, allowed, blocked, rewritten, failed, cached, and stale-cache DNS queries.
- Policy decisions, filter categories, rule matches, and permitted client activity.
- DNSSEC outcomes, cache performance, resolver performance, upstream health, latency, and failures.
- Authoritative-zone state, DHCP state, cluster state, encrypted-DNS usage, and service health.
Explainable decisions
- Which policy profile applied and which assignment caused it to apply.
- Which rule, category, or recognizable service matched.
- Which action occurred and why that rule had precedence.
- Whether a schedule changed the decision.
- Whether a temporary override changed the decision.
Privacy-safe aggregate statistics are the default. Raw DNS activity must not be retained merely to populate dashboards.
34.10 Privacy Shield Logging and Data Controls
- Completely disabled query logging.
- Configurable retention and automatic expiration.
- Domain redaction and client redaction.
- IP masking and pseudonymous client identifiers.
- Per-profile privacy settings.
- Export and deletion controls.
- Role-based access to sensitive data.
- Configurable diagnostic detail.
- Privacy-safe aggregate statistics.
DNS data must remain under the operator’s control. GoreeCloud DNS must not require external analytics telemetry, and sensitive DNS activity must be collected only for an explicit operational purpose consistent with Privacy Shield.
34.11 DNS Rewrites, Overrides, and Responsibility Boundaries
- Custom A and AAAA records.
- Custom CNAME responses.
- Private hostname mappings.
- DNS rewrites and response overrides.
- Split-horizon responses.
- Client-, subnet-, and network-specific answers.
- Internal GoreeCloud service names.
- Conditional forwarding and private namespaces.
- Location-aware DNS responses where appropriate.
These capabilities must be assigned among Beacon Horizon, Beacon Zones, Beacon Shield, and the Policy system according to responsibility so filtering, authoritative data, routing context, and policy decisions remain understandable and independently testable.
34.12 Beacon Horizon — Context-Aware DNS
- Split-horizon DNS.
- Client-, subnet-, and network-specific responses.
- Private-domain routing and private-namespace handling.
- VPN-aware, branch-network, and hybrid-network DNS behavior.
- Conditional forwarding and stub zones.
- DNS64.
- Location-aware responses where appropriate.
- Network-context-aware DNS decisions.
34.13 Traffic Routing Boundary
GoreeCloud DNS is the DNS authority, not GoreeCloud’s general-purpose network proxy or Internet-egress platform.
GoreeCloud DNS may control
- DNS responses and DNS routing.
- DNS forwarding.
- DNS rewrites and DNS overrides.
- Split-horizon DNS.
- Location-aware DNS answers.
- Conditional resolution.
- Resolver selection.
Capabilities that belong primarily to GoreeCloud Network
- Transparent proxying.
- Geographic Internet exits.
- IP-level traffic routing.
- Application traffic tunneling.
- General network tunneling.
- Non-DNS traffic steering.
- Selective Internet egress.
- Proxy-location selection.
GoreeCloud DNS may provide policy signals or DNS context to GoreeCloud Network, Wardveil Security, Privacy Shield, and GoreeCloud Identity, but GoreeCloud DNS must remain the DNS authority rather than becoming the general network-routing authority.
34.14 Beacon Resolver
- Full recursive DNS resolution plus forwarding, conditional forwarding, stub resolution, and iterative resolution.
- Root-server iteration, referral processing, and authoritative nameserver discovery.
- DNSSEC validation and authenticated denial of existence.
- QNAME minimization and resolver hardening.
- Concurrent resolution, deterministic failover, health-aware target selection, and latency-aware resolver selection.
- Encrypted forwarding and trust-anchor management.
- CNAME and DNAME processing.
- Recursion limits, loop detection, and response validation.
Beacon Resolver must allow GoreeCloud DNS to operate independently without requiring an external public recursive resolver.
34.15 Beacon Cache
- Positive and negative caching, including aggressive negative caching.
- Configurable TTL limits and TTL aging.
- Persistent caching.
- Serve-stale.
- Prefetch and automatic prefetch.
- Cache sharding, statistics, and recovery.
- Explicit cache clearing.
- Bounded memory usage.
- Policy-aware cache partitioning and client-aware partitioning where necessary.
- Cache-persistence controls.
34.16 Beacon Zones
- Authoritative DNS for internal and public zones.
- Primary, secondary, forward, stub, local, catalog, and split-horizon zones.
- Zone transfers using AXFR and IXFR, plus NOTIFY.
- DNSSEC signing and validation.
- Local and private DNS records.
- Automatic zone synchronization.
34.17 Private GoreeCloud DNS and Service Discovery
Private GoreeCloud service discovery remains a first-class DNS capability. GoreeCloud DNS should understand approved relationships among service names, destination addresses, network accessibility, service roles, HTTPS routing, health information, GoreeCloud Network, GoreeCloud Identity, and availability state.
Authorization boundary — DNS resolution must never automatically imply authorization. Application authentication, network authorization, GoreeCloud Identity, Wardveil policies, Privacy Shield authorization, and service-level authorization remain independent enforcement boundaries.
34.18 Beacon DHCP
- DHCP leases and device identification.
- Automatic DNS registration and hostname lifecycle.
- Lease-to-client mapping and policy assignment.
- Local DNS integration and DNS synchronization.
- Lease expiration handling.
- Static reservations.
DHCP and DNS may share approved client identity and device context but must avoid unnecessarily duplicating sensitive information.
34.19 Beacon Identity
- Multiple administrators.
- Role-based access control and scoped permissions.
- Scoped API tokens.
- TOTP two-factor authentication.
- OIDC single sign-on.
- GoreeCloud Identity integration.
- Device identity and administrative identity.
- Delegated administration.
- Session controls.
- Auditable administrative actions.
Identity context should support approved relationships among users, devices, administrators, networks, policy profiles, and infrastructure systems without making DNS the authoritative identity provider.
34.20 Beacon API
- Configuration, policies, profiles, filtering, clients, devices, and zones.
- Resolver and cache controls.
- Statistics and logs.
- DHCP and clustering.
- Service discovery and Secure DNS.
- Security controls and privacy controls.
- Automation and backup/recovery integration.
- Health information.
The API must use scoped credentials and produce auditable administrative actions.
34.21 Beacon Cluster
- Multiple DNS nodes with independent DNS-serving capability.
- Synchronized configuration, policy, zones, service catalogs, and catalog data.
- Health coordination and node-health visibility.
- Controlled failover and controlled recovery.
- Disaster recovery.
Central administration must never become a mandatory single point of DNS failure. Each approved node must be able to continue serving DNS independently when central management is unavailable.
34.22 Beacon Console
The administration experience must use the current authoritative Glaze UI design language and expose complex DNS behavior through progressive, explainable controls.
Primary areas
- Overview
- Queries
- Protection
- Clients
- Devices
- Services
- Policies
- Family
- Zones
- Resolver
- Cache
- Secure DNS
- DHCP
- Cluster
- Insights
- Security
- Privacy
- Settings
Experience requirements
- Clear status visualization and purposeful color coding.
- Glaze UI translucency and contextual emphasis without sacrificing readability.
- Responsive layouts and accessible controls.
- Useful dashboards and explainable policy views.
- Health indicators and progressive disclosure.
- Clear warnings and deliberate degraded, unavailable, permission-denied, and failure states.
34.23 Managed Filter-List Lifecycle
- Source identity and content-integrity verification.
- Cryptographic metadata verification and trusted signing keys.
- Issue timestamps, expiration timestamps, and sequence numbers.
- Scheduled updates with bounded retries.
- Offline grace periods.
- Rollback and immutable snapshot history.
- Multiple-list composition.
- Required and optional list behavior.
- Controlled activation.
- Privacy-minimized status information.
- Recovery through Everkeep.
Unverified or malformed list content must fail closed rather than being silently trusted.
34.24 Managed Service and Category Catalog Lifecycle
- Controlled first-party catalogs for categories, applications, services, SafeSearch mappings, restricted-content mappings, and threat classifications.
- Provenance, versioning, integrity validation, signed metadata, rollback, offline availability, scheduled updates, review workflows, expiration, and recovery.
- No policy behavior may depend on silently downloaded mutable data whose integrity cannot be established.
34.25 Beacon Extensions
- Advanced filtering.
- Custom policy evaluation.
- Split-horizon logic.
- DNS64.
- Location-aware DNS behavior.
- Forwarding logic.
- Service discovery.
- Custom DNS processing.
Extensions must run within explicit security, privacy, resource, policy, observability, and authorization boundaries and must not be able to silently bypass core DNS safeguards.
34.26 GoreeCloud Ecosystem Integrations
34.27 Canonical Product Boundary
34.28 Development Direction
GoreeCloud DNS must continuously evaluate useful advances in DNS, filtering, privacy, network protection, family controls, encrypted DNS, policy management, observability, administration, and resolver technology.
- Privacy
- Security
- Filtering
- Policy control
- Family protection
- Administration
- Usability
- Resilience
- Observability
- Interoperability
- Independence
- Self-hosting
- Recoverability
A capability should be implemented first-party when it materially improves one or more of these outcomes and fits the product boundary. The program must not be driven by checklist imitation or by copying another DNS platform’s architecture.
34.29 Long-Term Target
- Advanced DNS filtering and policy enforcement.
- Family controls and application/service controls.
- Encrypted DNS and privacy-aware analytics.
- Native recursive DNS and authoritative DNS.
- DNSSEC, private DNS, split-horizon DNS, and service discovery.
- DHCP, clustering, and high availability.
- APIs, automation, and identity-aware administration.
- Backup, recovery, and continuity through Everkeep.
- Controlled extensibility.
- Local-first operation.
- Complete GoreeCloud ecosystem integration.
GoreeCloud DNS must not depend on another complete DNS product or hosted DNS control plane for capabilities that properly belong inside GoreeCloud DNS. The long-term objective is complete GoreeCloud ownership of the DNS platform, its policy model, its administration experience, its privacy model, its security boundaries, and its runtime architecture.

## Appendix A — September 27, 2026 Owner-Supplied Capability Expansion

> This appendix is cumulative target scope. It does not assert implementation. Where it overlaps earlier requirements, the requirements are complementary unless an explicit conflict is documented and resolved.

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
