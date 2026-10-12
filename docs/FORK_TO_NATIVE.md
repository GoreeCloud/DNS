# GoreeCloud DNS — Fork-to-Native execution plan

**Current stage: 0, source foundation imported.** All subsequent stages are planned, not completed. This plan is subordinate to GoreeCloud governance and release gates.

## Architecture and staged delivery

1. **Stage 0 — Source baseline.** Import licensed foundation in the GoreeCloud repository, pin source SHA, retain GPL-3.0, inventory Go, frontend, DNS, DHCP, REST APIs and dependencies, and establish reproducible baseline testing. Contain upstream release/mirror automation.
2. **Stage 1 — Safety and identity.** Replace product branding and onboarding without removing legal attribution. Review installer, listeners, admin setup, network exposure, inherited updates, outbound contacts, query logging and packaging.
3. **Stage 2 — DNS core and privacy.** Test UDP/TCP DNS, filtering, allowlists, rewrites, caching, encrypted upstreams, DHCP where supported, adverse paths and recovery. Review log retention, redaction, secrets, TLS, authentication and least privilege.
4. **Stage 3 — User experience.** Replace administrative UI and onboarding progressively using the current approved stable Glaze contract. Verify accessibility, localization, mobile responsive states and error handling.
5. **Stage 4 — Platform interoperability.** Evaluate then implement applicable GoreeCloud Privacy Shield, Wardveil, identity, policy, observability and recovery contracts with verified API boundaries; do not represent planned integrations as implemented.
6. **Stage 5 — Native modules and migration.** Replace product-defining upstream code with GoreeCloud-owned components, while retaining justified bounded libraries. Preserve prior configuration via schema-versioned export/import, tests and rollback.
7. **Stage 6 — Native acceptance.** Verify independent builds, tests, licensing, security, upgrades, rollback, full Glaze UX and release authorization. Only then consider Native status.

## Non-negotiable quality gates

- No production deployment until network-infrastructure security and release gates pass.
- Preserve GPL license, copyright attribution, third-party notices, and provenance.
- Never copy unreviewed upstream release, mirroring, signing, auto-update or deployment workflows into executable CI.
- No credentials, sensitive network configurations or real DNS query logs in commits or CI artifacts.
- No breaking config migration without a tested converter and recovery path.
- Verify protocol support and operating-system compatibility separately, with runtime evidence.
- Native acceptance means measurable removal of the upstream product shell, not just a renamed UI.

## Initial independent workstreams

- Reproducible Go and frontend builds, tests, dependency/license inventory and supply-chain review.
- Audit upstream update/network behaviors, admin security, query-log retention and defaults.
- Transition product identity, localized copy, imagery and Glaze user experience.
- Integrate GoreeCloud security/privacy contracts after validating the actual interfaces.
- Add backward-compatible config import/export and DNS end-to-end tests.

Authoritative implementation state lives in versioned repository commits, not this roadmap.
