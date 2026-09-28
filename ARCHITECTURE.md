# Architecture — GoreeCloud DNS

## Status

Development architecture baseline. The current source includes a loopback-only operational control-plane foundation plus a first-party in-process request pipeline. It does not listen for DNS traffic and does not implement concrete recursive networking, authoritative-zone persistence, durable cache persistence, filtering catalogs, DHCP, encrypted-DNS transports, or production policy enforcement.

## Current source boundary

Development 0.1 contains:

- one Go entry point at `cmd/goreecloud-dns`;
- configuration that accepts only explicit loopback addresses for the operational HTTP listener;
- `/healthz` and `/readyz`;
- bounded HTTP timeouts and header size;
- graceful shutdown;
- automated formatting, test, vet, build, and reachable-vulnerability validation;
- `internal/dnscore`, which defines Request/Result records and Policy, Authority, Cache, and Resolver interfaces;
- a deterministic pipeline ordered policy → authority → cache → resolver, with fail-closed handling of unknown policy actions and stage errors.

No DNS UDP/TCP socket is opened by this foundation. No production listener, client routing, resolver authority, filtering authority, query log, credentials, zone data, DHCP state, or network configuration is changed.

## Native DNS core 0.2

The in-process core is deliberately independent of DNS sockets and external resolver libraries. Policy can block a request before later stages execute. Authoritative and cache hits short-circuit subsequent stages. Missing stages are rejected at construction, invalid requests are rejected before stage execution, and stage errors stop resolution rather than silently falling through. The pipeline overwrites result source attribution so callers can distinguish the authoritative stage that produced a result.

This is coordination/domain implementation, not a recursive resolver or DNS protocol implementation. No stage currently owns production DNS state or network I/O.

## Native DNS cache 0.3

`MemoryCache` is the first concrete implementation behind the core Cache contract. Cache keys normalize DNS names case-insensitively, preserve question type/class, and partition entries by trimmed ClientID so one client partition cannot read another partition's cached result. Only successful results with records and non-zero TTLs are stored.

Entries expire at the minimum record TTL. Returned record TTLs age with elapsed time, expired entries are removed on lookup, caller-owned record slices are defensively copied on insertion and lookup, cancelled contexts fail immediately, and bounded caches evict the oldest stored entry deterministically when inserting a new key at capacity. A zero capacity means unbounded Development capacity; negative capacity is rejected.

The cache is in-memory and process-local only. It is not persistent, distributed, DNSSEC-aware, production-sized, or connected to DNS wire traffic.

## Native DNS cache controls 0.4

`CacheConfig` adds explicit Development controls for maximum entries and optional minimum/maximum TTL bounds. Invalid negative capacity and inverted TTL ranges are rejected. Zero-TTL records remain non-cacheable even when a minimum TTL is configured, preventing the control from silently converting an explicit zero lifetime into cacheable state. TTL bounds are applied before the minimum-record expiry is computed.

`CacheStats` exposes only aggregate entry, hit, miss, store, eviction, and expiration counts. It contains no query names, record data, client identifiers, addresses, or raw errors. The counters are process-local operational evidence and are not wired to external telemetry or persistence.

## Native DNS cache administration 0.5

`MemoryCache.Inspect` provides exact-key Development inspection for a caller-supplied DNS question and client partition. It returns only whether that exact entry is present, its record count, and its remaining cache TTL. It does not enumerate cache keys, reveal cached record data, return client identifiers, or increment normal lookup hit/miss counters. Expired entries encountered by inspection are removed and counted as expirations.

`MemoryCache.Invalidate` removes only the exact normalized question/type/class/client-partition key supplied by the caller. Missing entries return false, expired entries are treated as expirations rather than successful administrative invalidations, and successful removals increment an aggregate invalidation counter. Neither method is exposed through an administrative network endpoint in this Development slice; authentication, authorization, audit, Privacy Shield policy, and production administration remain future requirements.

## Planned runtime layers

Future implementation should preserve explicit boundaries between DNS transports, client context, policy/filtering, authoritative zones, cache, recursive/forwarding resolution, DNSSEC, privacy-minimized observability, administration APIs, and GoreeCloud platform integrations.

Each layer must be independently testable and must fail closed where security, privacy, policy, or authority evidence is missing or invalid.

## Authority boundary

GoreeCloud DNS will own DNS behavior only after corresponding implementation and cutover are explicitly validated. Repository source alone does not displace an existing production resolver. DNS resolution also does not grant authorization to a private service; network, Gateway, application Identity, and policy controls remain separate enforcement boundaries.

## Exposure boundary

The current operational listener is loopback-only. Broader administrative or DNS exposure requires separately reviewed authentication, authorization, transport security, abuse/resource controls, privacy/security integration, recovery, and target-environment validation.

## Evidence rule

Source presence, documentation, unit tests, and CI are Development evidence. They do not establish production deployment, production acceptance, DNS correctness under production traffic, or Stable status.
