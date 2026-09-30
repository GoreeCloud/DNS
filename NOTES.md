# GoreeCloud DNS — Development Notes

## Current stabilization context

- Lifecycle remains Development. The current repository lineage is GoreeCloud/DNS (repository ID `1391515788`); predecessor DNS implementation and Platform Contract evidence belong to an earlier repository lineage and are historical only.
- Authoritative `main` currently contains the native request-coordination pipeline, process-local cache and bounded cache inspection/invalidation work. This source does not establish DNS wire serving, production migration, Release Candidate/Seal, Anchor, or replacement of the governed AdGuard Home/Unbound production path.
- PR #9 adds a bounded process-local exact-request `MemoryAuthority` behind the current native Authority contract. Its records are in-memory only and are not an authoritative zone engine or durable DNS data store.
- Repository documentation must distinguish implemented Development source from planned DNS capability scope and from predecessor historical evidence.

## Active implementation and acceptance gates

- Preserve exact request validation, client-partition isolation, global fallback behavior, defensive record copies, and pipeline-owned source attribution as the local authority evolves.
- Add durable authoritative data, DNS wire serving, zone/SOA ownership, wildcard/delegation behavior, transfer/update protocols, synchronization, DNSSEC signing, and authenticated client policy only through separately reviewed implementation slices with negative-path tests.
- Complete Platform Contract 2.0 migration and evidence for all applicable Integral Platform Systems before lifecycle promotion.
- Validate privacy-minimized DNS logging, retention, masking, query/client access control, security boundaries, recovery, and runtime behavior before any production migration proposal.
- Preserve the existing AdGuard Home/Unbound production authority until an exact GoreeCloud DNS candidate satisfies governed migration, rollback, runtime, and production-acceptance gates.
- Protect the default branch and enforce applicable exact-head DNS CI before integrating new candidates; GitHub issue #10 tracks that repository-governance blocker.

## Safety and evidence boundary

Do not place DNS query payloads, client-identifying data, reusable credentials, private keys, production configuration secrets, or other sensitive operational data in this notes file. Source implementation, unit tests, and repository CI are Development evidence only and must not be represented as production runtime acceptance.
