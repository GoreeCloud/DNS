# Changelogs — GoreeCloud DNS

This changelog records verified changes to the **current** `GoreeCloud/DNS` repository lineage. Historical predecessor implementation history is preserved separately in `PROJECT-RECORD.md` and authoritative GoreeCloud records.

## 2026-09-27

### Native DNS Cache 0.3 candidate

- Added a concrete in-memory implementation of the native DNS Cache contract.
- Added normalized DNS question keys partitioned by client ID.
- Added successful-result-only storage, minimum-TTL expiry, per-record TTL aging, lookup-time expiry cleanup, bounded deterministic oldest-entry eviction, flush support, context cancellation, and defensive copy isolation.
- Added deterministic tests for capacity validation, name normalization, client partitioning, expiry/aging, non-cacheable results, eviction, copy isolation, flush, and cancellation.
- Extended repository governance to require the cache implementation and negative-path tests.
- No DNS listener, persistent/distributed cache, recursive network resolver, DNSSEC validation, production traffic, or production authority is introduced.


### Native DNS Core 0.2

- Added first-party Request, Result, Record, Policy, Authority, Cache, and Resolver contracts under `internal/dnscore`.
- Added deterministic policy → authoritative lookup → cache → resolver coordination.
- Added fail-closed request validation, required-stage validation, unknown-policy rejection, error propagation, stage-source attribution, and result-record copy isolation.
- Added unit tests for stage ordering, short-circuiting, invalid requests, policy blocking, unknown policy actions, resolver fallback, and stage errors.
- Added repository-governance validation for the native core and mandatory DNS repository records.
- No DNS wire parser, UDP/TCP DNS listener, recursive network resolver, production filtering, production authoritative zone, or cutover authority is introduced.


### Development service foundation

- Added the first executable Go source foundation for the recreated repository.
- Added loopback-only operational configuration, health/readiness endpoints, bounded HTTP server limits, and graceful shutdown.
- Added unit tests plus exact-source formatting, test, vet, build, and reachable-vulnerability CI.
- Added architecture, security, privacy, Platform Contract, and nine-system integration baselines.
- No DNS listener or production/Stable claim is established by this foundation.


### Current repository initialization

- Current `GoreeCloud/DNS` repository initialized with repository ID `1391515788`.
- Initial commit `2bbf847a42a0a88bd058d646abddf37586882629` created the minimal repository.

### DNS product specification documentation

- Pull request #1 documented the owner-supplied GoreeCloud DNS features and capability vision.
- Added the initial repository specification.
- Updated README navigation.
- Squash-merged as `e1ff5e39004f623a5d8fb89a478805b0a7db4e3c`.
- No runtime implementation, release, production deployment, or Stable claim was established.

### Repository documentation reconciliation

- Rebuilt repository-native current-state documentation for the recreated repository lineage.
- Established separate project specification, project record, implemented-feature, planned-feature, capability, competitive-objective, benefit, and changelog records.
- Preserved predecessor implementation and Platform Contract history as historical evidence only.


### Drive project-specification migration reconciliation

- Migrated and normalized the active `Project Specification — DNS.docx` into repository-local `PROJECT-SPECIFICATIONS.md`.
- Preserved predecessor implementation milestones in `PROJECT-RECORD.md` instead of representing them as current recreated-repository implementation.
- Preserved the September 27 owner-supplied capability expansion as cumulative target scope.
- Migrated the GoreeCloud Beacon capability taxonomy into `BEACON.md`.
- Recorded that connected Drive and GitHub searches did not expose a recoverable predecessor source archive; local/offline recovery remains unresolved rather than assumed absent.
