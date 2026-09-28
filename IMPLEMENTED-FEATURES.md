# Implemented Features — GoreeCloud DNS

## Verified Development foundation

The repository currently implements:

- a Go service entry point;
- loopback-only operational listener validation;
- health and readiness endpoints;
- bounded HTTP server limits and graceful shutdown;
- unit tests and exact-source CI;
- reachable-vulnerability scanning;
- architecture, security, privacy, and platform-integration baselines;
- a first-party in-process DNS request pipeline with required Policy, Authority, Cache, and Resolver stages;
- deterministic policy → authority → cache → resolver ordering, short-circuit behavior, fail-closed unknown policy handling, and stage-error propagation;
- a process-local in-memory cache with client-partitioned keys, name normalization, minimum-TTL expiry, record TTL aging, configurable minimum/maximum TTL clamps, bounded deterministic eviction, flush support, context cancellation, copy isolation, and privacy-safe aggregate hit/miss/store/eviction/expiration statistics.

## Product boundary

The request-processing core is verified as Development source logic, but no DNS-serving product feature is verified as implemented yet. The current foundation does not open DNS listeners, answer DNS queries, alter client DNS settings, or establish production or Stable status.
