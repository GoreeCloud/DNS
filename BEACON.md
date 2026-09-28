# GoreeCloud Beacon

> **Status:** Capability taxonomy and product vocabulary for GoreeCloud DNS.
>
> **Product authority:** GoreeCloud DNS remains the application, service, and runtime authority. Beacon is not a separate daemon, server, repository, network service, or deployment boundary.
>
> **Migrated source:** `Reference — GoreeCloud Beacon`, Drive ID `1PRzFFDDyfxLk3R-hk812pJwC0b-sovbC2tWeAaFzZNg`, source version v0.1.
>
> **Implementation boundary:** Naming and taxonomy do not prove that a capability is implemented, tested, production-ready, enabled, or deployed.

## 1. Purpose
I use GoreeCloud Beacon as the official umbrella identity for the first-party feature system inside GoreeCloud DNS. Beacon gives the DNS platform a coherent vocabulary for its resolver, cache, authoritative DNS, encrypted DNS, filtering, DHCP, split-horizon behavior, clustering, administration, identity, observability, automation, and extensibility capabilities.

GoreeCloud DNS remains the application and service. GoreeCloud Beacon is not a separate daemon, server, repository, network service, or deployment boundary. It is the feature framework and product vocabulary that organizes capabilities owned by GoreeCloud DNS.

## 2. Identity Statement
GoreeCloud Beacon is the unified intelligence, resolution, security, routing, authoritative DNS, DHCP, administration, and network-discovery framework within GoreeCloud DNS.

The Beacon name represents guidance, discovery, dependable direction, visibility, and the infrastructure role DNS performs for every dependent service and client. It is intentionally broad enough to represent both present and future native DNS capabilities without tying the identity to one protocol, one resolver implementation, or one upstream project.

## 3. Product Relationship
The approved relationship is:

GoreeCloud DNS → powered by GoreeCloud Beacon → presented through Glaze UI → protected or complemented by Wardveil Security and Privacy Shield where their respective capability boundaries apply.

GoreeCloud DNS is the product and runtime authority. Beacon is its feature umbrella. Glaze UI remains the interface design language. Wardveil Security remains the broader GoreeCloud security identity. Privacy Shield remains the broader GoreeCloud privacy identity.

## 4. Beacon Capability Families
Beacon Resolver
Beacon Resolver covers full recursive DNS resolution, recursive delegation walking, forwarding and stub resolution, conditional forwarding, upstream selection, failover, concurrency, cancellation, query-name minimization, minimal responses, DNSSEC validation, trust-anchor lifecycle management, and resolver hardening.

Beacon Cache
Beacon Cache covers positive, negative, and aggressive-negative caching; TTL controls; sharded cache structures; serve-stale behavior; prefetch and auto-prefetch; persistent cache state; cache recovery; cache statistics; and future cache-warming and scope controls.

Beacon Zones
Beacon Zones covers authoritative DNS for internal and public namespaces, primary and secondary zones, forwarder and stub zones, catalog zones, local DNS data, zone transfer and notification, DNSSEC signing, and authoritative-zone lifecycle management.

Beacon Shield
Beacon Shield covers DNS-layer filtering and response policy, including advertisement, tracker, malware, phishing, telemetry, and unwanted-domain blocking; blocklists; allowlists; wildcard rules; regular expressions; response-policy zones; client and subnet policies; and DNS rebinding protection.

Beacon Secure DNS
Beacon Secure DNS covers encrypted DNS transport and approved encrypted forwarding, including DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC, certificate and key lifecycle integration, endpoint policy, and secure upstream transport.

Beacon DHCP
Beacon DHCP covers integrated address assignment, leases, reservations, client identity linkage, automatic DNS registration, DNS record lifecycle management, and policy coordination between DHCP and DNS.

Beacon Horizon
Beacon Horizon covers split-horizon DNS, conditional namespace routing, client-, subnet-, and network-dependent responses, branch and hybrid DNS routing, geolocation-aware responses where approved, DNS64, and advanced routing or response-selection logic.

Beacon Cluster
Beacon Cluster covers multi-instance coordination, configuration and zone synchronization, node identity and trust, redundancy, health-aware operation, catalog distribution, failover coordination, and high-availability management without making a central control plane a mandatory DNS-serving dependency.

Beacon Console
Beacon Console is the browser-based administrative experience for GoreeCloud DNS. It uses Glaze UI and provides configuration, troubleshooting, runtime administration, zone management, client and policy management, health information, dashboards, and operational controls.

Beacon API
Beacon API covers the comprehensive HTTP API, scoped automation endpoints, scripting and orchestration interfaces, runtime controls, statistics access, configuration operations, zone administration, integrations, and other machine-to-machine management capabilities.

Beacon Identity
Beacon Identity covers administrative users, role-based access control, scoped API tokens, TOTP two-factor authentication, OpenID Connect single sign-on, session and authorization policy, and auditable administrative identity.

Beacon Insights
Beacon Insights covers query logging, audit logging, runtime statistics, cache statistics, DNSSEC outcomes, resolver and upstream health, authoritative-zone health, DHCP state, cluster state, dashboards, metrics, privacy-aware diagnostics, and integrations with approved GoreeCloud observability systems.

Beacon Extensions
Beacon Extensions covers the controlled first-party extension framework for advanced filtering, split-horizon processors, geolocation responses, DNS64, custom forwarding, custom DNS processing logic, and future approved modules. Extensions must remain inside explicit security, privacy, resource, policy, observability, and disable-control boundaries.

## 5. Security and Privacy Identity Boundaries
Beacon Shield does not replace Wardveil Security. Beacon Shield names the DNS-native filtering and response-policy family inside GoreeCloud DNS, while Wardveil Security remains the broader GoreeCloud security identity and may surface, coordinate, or contextualize verified DNS security capabilities.

Beacon privacy features do not replace Privacy Shield. Privacy Shield remains the broader GoreeCloud privacy identity, while GoreeCloud DNS implements DNS-specific privacy controls such as minimized logging, local-first processing, encrypted DNS, query-name minimization, retention controls, and privacy-aware observability.

A feature must not receive Wardveil, Privacy Shield, or Beacon security or privacy claims unless the underlying implementation actually provides and validates that behavior.

## 6. Architecture Boundary
Every Beacon feature is implemented as a first-party GoreeCloud DNS capability within the single-service target architecture. Beacon does not authorize permanent Unbound, AdGuard Home, or other external DNS sidecars as required runtime dependencies.

AdGuard Home remains the initial maintained-fork engineering foundation during the transition. Unbound remains a migration and capability reference while current production dependencies still exist. The long-term target is a GoreeCloud-controlled DNS runtime in which Beacon capabilities are native and independently testable inside GoreeCloud DNS.

## 7. Naming Rules
I use the format “Beacon <Capability>” for feature-family names when a distinct family improves navigation, documentation, administration, or product understanding.

I do not create a Beacon sub-name merely for decorative branding. A family name must correspond to a stable functional boundary that users and administrators can understand.

I keep GoreeCloud DNS as the application name. I do not rename the application itself to GoreeCloud Beacon. User-facing language may state that GoreeCloud DNS is powered by GoreeCloud Beacon when that wording improves product clarity.

## 8. Implementation and Acceptance Boundary
Beacon naming describes approved feature identity and capability ownership. It does not by itself prove that a capability is implemented, tested, production-ready, enabled, or deployed.

Each Beacon subsystem must continue to follow GoreeCloud source-control, security, privacy, configuration, observability, backup, recovery, migration, release, and production-acceptance requirements.

Features inherited from the current fork foundation may retain compatibility implementations during migration, but long-term Beacon capability ownership belongs to GoreeCloud DNS.

## 9. Long-Term Direction
I will use Beacon as the consistent vocabulary for GoreeCloud DNS as the product transitions from a maintained fork into an increasingly independent first-party DNS platform.

The desired progression is:

Inherited DNS capability → GoreeCloud-controlled interface and contract → native Beacon subsystem → isolated validation → production-equivalent acceptance → controlled cutover.

Beacon should make the platform easier to understand without fragmenting it. The final objective remains one coherent GoreeCloud DNS service with first-party recursive DNS, authoritative DNS, encrypted DNS, filtering, DHCP, clustering, administration, automation, identity, observability, and extensibility.

## 10. Decision Record
Decision: Adopt GoreeCloud Beacon as the official umbrella identity for GoreeCloud DNS first-party features.
Application Name: GoreeCloud DNS
Feature Umbrella: GoreeCloud Beacon
Design Language: Glaze UI
Security Identity: Wardveil Security
Privacy Identity: Privacy Shield
Architecture: Single-service GoreeCloud DNS runtime with modular first-party Beacon capabilities
Production Effect: Naming and documentation decision only; implementation and production acceptance remain separate requirements
