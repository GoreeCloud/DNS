# GoreeCloud DNS security guidance

**Development preview only.** This code is not a hardened public DNS recursive resolver or authoritative DNS server.

DNS listener traffic is unauthenticated by DNS protocol design. The gateway now has a default-loopback CIDR allowlist and rejects an unrestricted 0/0 wildcard; unauthorized client IPs receive REFUSED. Keep the daemon on loopback until a deliberately scoped LAN ACL, firewall rules, rate limiting, recursive amplification defenses, malicious-packet testing and safe deployment procedures are independently verified. The ACL is not a full DoS defense.

The administrative HTTP API requires a unique bearer token of at least 16 characters and binds to loopback by default. For remote access, use a trusted HTTPS proxy and independent access controls. Token rotation, user accounts, RBAC and certificate lifecycle management are not implemented. Environment variables and container inspection may expose token material to local administrators.

The daemon does not collect client identities, per-query histories or network telemetry. Upstream transport can be auto UDP/TCP, forced TCP, or certificate-verified DNS-over-TLS with an explicit server identity and optional custom root CA. The default auto mode remains unencrypted. DNSSEC validation and cache behavior are delegated to the separately deployed Unbound service, whose operational guarantees have not been independently verified. A bounded concurrent-upstream budget limits overload. The first explicit CIDR allowlist restricts client networks but does **not** implement per-client query rate limits or a complete DNS-amplification defense.

The local policy engine recognizes limited syntax, including explicit allow exceptions, but not arbitrary AdGuard options or regex filter logic. File and rule-count limits apply and invalid reloads preserve old policy. Review allow exceptions carefully since they override matching blocks. The authenticated policy-check API is POST-only to avoid domains entering ordinary URL logs.

For security reports, use GitHub private vulnerability reporting when enabled or an authorized private channel; never publish real credentials, query logs or private network data.

Production gates include broader protocol fuzzing, DNS-wire acceptance, per-client rate limits and firewall acceptance, supply-chain and image pins, signed builds, full TLS lifecycle, backups and restore rehearsal, and an explicitly rehearsed DNS cutover rollback. None is yet certified complete.

Local DNS override files are host-controlled, strictly parsed, size-limited (2 MiB), and atomically reloaded. Do not write real internal hostnames, IP topology, API secrets, or private DNS data into public GitHub. The API cannot create records or fetch remote rule sources. Locally configured records override upstream responses by exact name but never bypass block policy or the DNS client CIDR ACL. CNAME loops and resolver behavior are not yet fully evaluated; maintain a cautious staging-only rollout and avoid production use.
