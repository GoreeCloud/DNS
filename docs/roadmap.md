# Priority development roadmap

1. Continue CI acceptance and dependency review; independently compile and run Linux Qt 6.12 and the Android app in an appropriate isolated environment. Reproducible Go and web dependencies, Android builds, and synthetic Go DNS-wire tests exist in the foundation, but a prior Android 17 ARM64 cold launch/uninstall smoke passed; full physical-device authentication, background-session security, accessibility and Linux acceptance remain outstanding.
2. Expand the now-implemented isolated EDNS privacy, DNSSEC DO pass-through, UDP truncation/TCP retry, and malformed-upstream-question tests to comprehensive fuzzing, DNS-wire load testing, broad protocol compliance and signed DNSSEC validation. Parser fuzz seeds, a concurrent upstream work budget, explicit client CIDR restrictions, a stateless global token bucket and a synthetic DoT certificate test exist; per-client rate limits (subject to GoreeShield data minimization) and firewall acceptance remain outstanding.
3. Review/up-pin third-party source, container images and build actions. Generate SBOM and audit licensing, vulnerabilities, access controls and reproducible builds.
4. Extend the initial explicit allowlist exception syntax and strict local A/AAAA/CNAME override loading into complete validated filter policy, safe record management, per-device rules, curated list updates, restoreable versioning, local privacy controls and a fully verified management TLS lifecycle and Identity integration (an opt-in direct TLS listener and default-loopback API bind guard now exist).
5. Implement separate, documented, licensed API adapters for Technitium, AdGuard Home and Pi-hole rather than mixing incompatible licenses in one binary.
6. Add opt-in GoreeCloud Mesh integration, Identity authentication, Wardveil security controls, GoreeShield privacy policy and official GoreeCloud UI design tokens.
7. Expand toward inbound DoH/DoT, DNSSEC management, authoritative zones, DHCP and DNS-over-QUIC according to verified needs and protocol test coverage. Authenticated outbound DoT is an early first step, not an inbound encrypted DNS listener.
8. Package signed Linux and Android releases, validate hardware behavior, and stage a controlled LAN deployment with backups and rollback.

All items are proposed future work, not active running capabilities.
