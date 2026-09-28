# Architecture — GoreeCloud DNS

## Status

Development architecture baseline. The current executable source is intentionally limited to a loopback-only operational control-plane foundation. It does not listen for DNS traffic and does not implement recursive, forwarding, authoritative, filtering, DHCP, encrypted-DNS, or policy behavior.

## Current source boundary

Development 0.1 contains:

- one Go entry point at `cmd/goreecloud-dns`;
- configuration that accepts only explicit loopback addresses for the operational HTTP listener;
- `/healthz` and `/readyz`;
- bounded HTTP timeouts and header size;
- graceful shutdown;
- automated formatting, test, vet, build, and reachable-vulnerability validation.

No DNS UDP/TCP socket is opened by this foundation. No production listener, client routing, resolver authority, filtering authority, query log, credentials, zone data, DHCP state, or network configuration is changed.

## Planned runtime layers

Future implementation should preserve explicit boundaries between DNS transports, client context, policy/filtering, authoritative zones, cache, recursive/forwarding resolution, DNSSEC, privacy-minimized observability, administration APIs, and GoreeCloud platform integrations.

Each layer must be independently testable and must fail closed where security, privacy, policy, or authority evidence is missing or invalid.

## Authority boundary

GoreeCloud DNS will own DNS behavior only after corresponding implementation and cutover are explicitly validated. Repository source alone does not displace an existing production resolver. DNS resolution also does not grant authorization to a private service; network, Gateway, application Identity, and policy controls remain separate enforcement boundaries.

## Exposure boundary

The current operational listener is loopback-only. Broader administrative or DNS exposure requires separately reviewed authentication, authorization, transport security, abuse/resource controls, privacy/security integration, recovery, and target-environment validation.

## Evidence rule

Source presence, documentation, unit tests, and CI are Development evidence. They do not establish production deployment, production acceptance, DNS correctness under production traffic, or Stable status.
