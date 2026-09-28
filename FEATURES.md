# GoreeCloud DNS — Features

## Current verified Development features

The current repository provides:

- a loopback-only operational Development service with health/readiness endpoints;
- fail-closed operational listener configuration;
- a first-party in-process DNS request pipeline with explicit Policy, Authority, Cache, and Resolver contracts;
- deterministic stage order: policy → authoritative lookup → cache → resolver;
- policy blocking and unknown-policy-action fail-closed behavior;
- short-circuiting on authoritative and cache hits;
- stage-error propagation without silently falling through;
- a first-party in-memory cache with DNS-name normalization, question/client partitioning, minimum-TTL expiry, TTL aging, configurable minimum/maximum TTL clamps, bounded deterministic eviction, flush support, cancelled-context handling, defensive copies, and aggregate-only cache counters;
- unit tests, exact-source CI, and reachable-vulnerability scanning.

## Product boundary

The request pipeline and in-memory cache are Development domain/runtime primitives only. It does not parse DNS wire messages, open UDP/TCP DNS listeners, perform recursive network resolution, host authoritative zones, validate DNSSEC, filter production traffic, or change any production DNS authority.

See [PLANNED-FEATURES.md](PLANNED-FEATURES.md) for the target product backlog.
