# Changelogs — GoreeCloud DNS

This changelog records verified changes to the **current** `GoreeCloud/DNS` repository lineage. Historical predecessor implementation history is preserved separately in `PROJECT-RECORD.md` and authoritative GoreeCloud records.

## 2026-09-27

### Native Local Authority 0.6 candidate

- Added `MemoryAuthority` as the first concrete implementation of the native DNS Authority contract.
- Added normalized exact-request keys with global default results and client-scoped overrides; a client override takes precedence only for that client, while other clients continue using the global result.
- Added exact-partition deletion, full flush, and entry count for controlled Development use.
- Added fail-closed result validation, defensive record-slice copies, and clearing of caller-supplied source attribution.
- Preserved zero-TTL authoritative records because authoritative TTL is response metadata, not authority-store lifetime.
- Added deterministic tests for global/override precedence, client isolation, deletion behavior, copy isolation/source clearing, invalid results, zero-TTL records, flush, cancellation, and invalid requests.
- Extended repository governance to require the local-authority source and negative-path tests.
- No authoritative zone engine, DNS listener, zone transfer/NOTIFY, dynamic update protocol, persistence, DNSSEC signing, authenticated client identity, production traffic, or production authority is introduced.


### Native DNS Cache Administration 0.5 candidate

- Added exact-key `MemoryCache.Inspect` for a caller-supplied DNS question/client partition.
- Inspection returns only presence, record count, and remaining TTL; it does not enumerate cache keys, expose cached record data or client identifiers, or increment normal hit/miss counters.
- Added exact-key `MemoryCache.Invalidate` with client-partition isolation.
- Missing entries are unchanged; expired entries are cleaned and counted as expirations rather than successful invalidations.
- Added aggregate invalidation counting without query or client detail.
- Added deterministic tests for privacy-minimized inspection, partition isolation, expiry cleanup, selective invalidation, missing/expired behavior, cancellation, and invalid requests.
- Extended repository governance to require the cache-administration source contract and tests.
- No administrative network API, authentication/authorization surface, cache enumeration, DNS listener, negative caching, persistent/distributed cache, recursive network resolver, production traffic, or production authority is introduced.


### Native DNS Cache Controls 0.4 candidate

- Added `CacheConfig` with bounded-entry and optional minimum/maximum TTL controls.
- Invalid negative capacity and inverted TTL ranges fail closed.
- Zero-TTL records remain non-cacheable even when a minimum TTL is configured.
- Added process-local aggregate cache counters for entries, hits, misses, stores, evictions, and expirations without query names, client identifiers, record data, or raw errors.
- Added deterministic tests for TTL-range rejection, TTL clamping/expiry, zero-TTL preservation, aggregate statistics, and overwrite-versus-eviction behavior.
- Extended repository governance to require the cache-control source contract and tests.
- No DNS listener, persistent/distributed cache, negative-cache semantics, recursive network resolver, DNSSEC validation, production traffic, or production authority is introduced.


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
