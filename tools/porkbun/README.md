# Porkbun registrar and authoritative-DNS operator CLI

This optional, dependency-free Python utility helps authorized GoreeCloud operators inspect and carefully manage a **Porkbun-hosted domain** from a trusted Linux host. It is distinct from GoreeCloud DNS's local recursive resolver. It **does not** serve DNS, change delegation automatically, configure Caddy, or integrate with the resolver's development API.

The first deployment targets `goreecloud.com`. It was installed on an authorized VPS and authenticated read operations were verified there in November 2026. These are host-specific observations; a public checkout is **not** an operational or production deployment. No production DNS record write was performed.

## Install and authenticate

Requirements: Python 3.11+ with the standard library, an authorized Linux user account, Porkbun API key with minimal scopes (`read`, `dns` only if changes are authorized), and explicit domain API opt-in at Porkbun. Do **not** put API keys or other sensitive domain records into GitHub, a shell command, a URL, chat, or the repo.

Deploy the script as `~/.local/bin/gc-porkbun`, mode `0700`, from a reviewed pinned commit. Store credentials in `~/.config/goreecloud/porkbun.json`, accessible only to the running user (`0600`); its containing directory must be `0700`. The JSON object uses two secret fields: `api_key` and `secret_api_key`. Provision them **directly into the secure host** through a trusted terminal or secret manager; never stage a credential file in this repository. Credential installation should avoid shell history and process arguments. The host's credential file is intentionally excluded from version control.

Host-side setup, authentication and operational command references are maintained in the private GoreeCloud Drive registry at `GoreeCloud/CLI Commands/Third-Party/Porkbun.md` (the canonical command reference). For secret setup, the separate host-local `gc-porkbun-setup` helper is currently available on the verified VPS but has **not** been imported into this repository; reconcile its tested source separately before relying on a fresh installation.

## Commands

```sh
gc-porkbun status
gc-porkbun ping
gc-porkbun domain
gc-porkbun nameservers
gc-porkbun dns-summary
gc-porkbun dns-preflight
gc-porkbun dns-history
gc-porkbun dns-backup
```

The read-only commands redact DNS values and account contacts. `dns-backup` stores a private, timestamped local JSON export of the zone with mode `0600` in a `0700` backup directory; this backup contains potentially sensitive DNS records, is **not encrypted**, and has **not been restore-rehearsed**. Encrypt, protect, and manage its retention under a separately approved backup/recovery system before treating it as a disaster-recovery artifact.

```sh
# A preview requires an on-host JSON payload with name/type/content, not credentials.
gc-porkbun dns-preview create --payload /path/to/private-preview.json

# High impact: do not run on production without target-specific authorization,
# current baseline, rollback rehearsal and an interactive confirmation.
gc-porkbun dns-apply create --payload /path/to/approved-payload.json
```

The preview sends `dryRun: true` to Porkbun. It **must not** be confused with actually creating a DNS record. `dns-apply` performs an API preflight, preview, snapshot and stale-zone check; it fails closed if a required check fails, then requires a human-entered confirmation phrase before attempting any write. DNS queries must be checked at authoritative nameservers after a real change; a Porkbun-success response alone does not prove effective public routing. Changes to DNSSEC, nameservers, email records, root routing or live certificates require separate change control.

Current restrictions: the script intentionally targets one domain, supports only record-level create/edit/delete by numeric ID, and has no restore command, managed secret-store integration, or automated change approval. A zone-level update is not transactional; review concurrency and idempotency behavior before use. No running automation has been configured.

## Validation

```sh
python3 -m unittest discover -s tools/porkbun -p 'test_gc_porkbun.py' -v
python3 -m py_compile tools/porkbun/gc-porkbun
```

The offline unit tests stub all API requests and do not touch credentials or live DNS. The public CI workflow uses those tests. Live validation on November 20, 2026 confirmed Porkbun `SUCCESS`, `read,dns,domains` token scopes, verified Porkbun nameserver delegation, six successful DNS-preflight checks, a non-mutating DNS-create dry run with `wouldSucceed: true`, 29 unchanged DNS records, and available zone history. No live mutation, sandbox credential testing, or restore procedure was completed.

## Sources and licensing

This folder contains original GoreeCloud Python source under the repository's MIT license; no third-party Python packages or copied Porkbun source are included. Porkbun is an external API provider, not an embedded component. Refer to its [official API reference](https://porkbun.com/llms/dns) and [security guidance](https://kb.porkbun.com/article/308-ai-agent-safety) before changing commands or permissions.
