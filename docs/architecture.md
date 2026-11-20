# Architecture

## Development data path

DNS clients --> GoreeCloud UDP/TCP DNS gateway :1053 --> local policy decision --> Unbound recursive service :5335 --> DNS hierarchy.

Blocked domains return NXDOMAIN without contacting upstream. Other requests forward to the configured resolver, attempting TCP when UDP is truncated. Failed upstream exchanges return SERVFAIL. The daemon exposes separate authenticated aggregate statistics and atomic on-disk rule reload through the management API.

React web, native Qt Quick Linux and native Compose Android clients access the same versioned management API. The clients do not execute host commands or process DNS packets.

## MIPS responsibilities

- GoreeShield governs privacy, retention, consent and minimization. The current daemon stores only process-local aggregate counters.
- Wardveil governs cybersecurity and network defense. Token authentication exists; rate limiting, advanced ACLs, hardening and detection are pending.
- GoreeCloud Mesh governs opt-in integrations and API coordination. No live Mesh integration is verified.
- GoreeCloud Identity governs authentication and authorization. Current bearer-token MVP is not an Identity integration.
- GoreeCloud UI governs production design language. The web client includes pinned canonical alpha semantic tokens and the native clients map the matching palette. The shared token bridge is source-aligned but does not establish visual, accessibility, device, or Stable release acceptance.

## Limits

The gateway does not serve authoritative zones, issue dynamic DNS changes, validate DNSSEC itself, provide encrypted DNS listeners, inspect individual clients, or support complete ad-block rules. The Unbound service is an independent runtime dependency; its security and recursive validation configuration must be tested separately.

No DNS routing, router configuration, external ingress or host deployment is performed by this repository.
