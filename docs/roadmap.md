# Priority development roadmap

1. Run all CI checks and add dependency lockfiles; fix build failures before any merge. Independently compile and run Linux Qt 6.12 and the Android app in an appropriate isolated environment.
2. Add isolated end-to-end DNS-wire tests for UDP, TCP, EDNS, truncation, malformed packets, and DNSSEC pass-through. Add fuzz tests, rate limits, ACLs and safety budgets.
3. Review/up-pin third-party source, container images and build actions. Generate SBOM and audit licensing, vulnerabilities, access controls and reproducible builds.
4. Add allowlists, per-device policies, exceptions, curated blocklist updates, restoreable policy versioning, local privacy controls and a hardened HTTPS management API.
5. Implement separate, documented, licensed API adapters for Technitium, AdGuard Home and Pi-hole rather than mixing incompatible licenses in one binary.
6. Add opt-in GoreeCloud Mesh integration, Identity authentication, Wardveil security controls, GoreeShield privacy policy and official GoreeCloud UI design tokens.
7. Only then expand toward DoH, DoT, DNSSEC management, authoritative zones, DHCP and DNS-over-QUIC according to verified needs and protocol test coverage.
8. Package signed Linux and Android releases, validate hardware behavior, and stage a controlled LAN deployment with backups and rollback.

All items are proposed future work, not active running capabilities.
