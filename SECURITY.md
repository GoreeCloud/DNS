# Security Policy — GoreeCloud DNS

## Project maturity

GoreeCloud DNS is in active Development and is not production-ready or Stable. The current executable foundation exposes only loopback operational health/readiness endpoints and does not serve DNS traffic.

## Reporting vulnerabilities

Report vulnerabilities privately through GitHub Security Advisories for this repository when available. Do not publish active exploitation details, reusable credentials, private network inventories, raw DNS activity, or unrelated personal information in public issues.

## Current security boundary

- The Development operational listener must remain loopback-only.
- Wildcard, LAN, private-network, and public administrative listen addresses are rejected.
- No DNS UDP/TCP listener is implemented in the current foundation.
- No authentication or authorization endpoint is implemented yet.
- No raw DNS query logging is implemented.
- No production network exposure is authorized by this source.

Broader listeners or administration must not be enabled merely for convenience. They require explicit authentication/authorization, transport protection, rate/resource controls, network placement, privacy/security review, and target-environment validation.

## Required engineering principles

- fail closed on invalid security-sensitive configuration;
- least privilege and explicit authorization at trusted boundaries;
- no reusable credentials or key material in source, logs, fixtures, or ordinary diagnostics;
- bounded input, resource use, timeouts, and retries;
- privacy-minimized operational evidence;
- dependency and vulnerability review;
- exact-revision validation for release-critical evidence;
- negative tests for denied behavior as well as permitted behavior.

## Production boundary

Passing source tests or vulnerability scanning does not authorize production DNS service, listener ownership, client DNS changes, firewall changes, public exposure, Release Candidate status, or Stable status.
