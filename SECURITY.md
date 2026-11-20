# GoreeCloud DNS security guidance

**Development preview only.** This code is not a hardened public DNS recursive resolver or authoritative DNS server.

DNS listener traffic is unauthenticated by DNS protocol design. Keep the daemon on loopback until access controls, rate limiting, recursive amplification defenses, firewall policy, malicious-packet testing and safe deployment procedures are implemented and verified.

The administrative HTTP API requires a unique bearer token of at least 16 characters and binds to loopback by default. For remote access, use a trusted HTTPS proxy and independent access controls. Token rotation, user accounts, RBAC and certificate lifecycle management are not implemented. Environment variables and container inspection may expose token material to local administrators.

The daemon does not collect client identities, per-query histories or network telemetry. Upstream DNS transport may be unencrypted. DNSSEC validation and cache behavior are delegated to the separately deployed Unbound service, whose operational guarantees have not been independently verified.

The local policy engine recognizes limited syntax and does not interpret allowlist exceptions or regex filter logic. Invalid reloads preserve old policy. Review changes to blocklist files before reloading.

For security reports, use GitHub private vulnerability reporting when enabled or an authorized private channel; never publish real credentials, query logs or private network data.

Production gates include protocol fuzzing, DNS-wire acceptance, rate limits, ACLs, supply-chain and image pins, signed builds, TLS, backups and restore rehearsal, and an explicitly rehearsed DNS cutover rollback. None is yet certified complete.
