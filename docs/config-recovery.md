# Encrypted DNS policy backup and staging-only recovery

**Maturity:** developer preview. This is not a production disaster-recovery certification, and the running DNS daemon is not changed by the recovery CLI.

## Ownership and data scope

The Go companion CLI in cmd/dns-config validates and archives **only** two specifically selected resolver configuration files: rules.txt (filtering and allow exceptions) and local-records.txt (local A, AAAA and CNAME overrides). It never opens API tokens, TLS private keys, environment secrets, host system DNS configuration, logs or a database. **A policy-only backup is not a complete service or host recovery**. The policy can still contain private DNS names, so it must always remain encrypted.

Encryption is delegated to the separately installed open-source **age** tool from https://github.com/FiloSottile/age using a public age X25519 recipient. The CLI does not vendor or execute arbitrary remote code. The age identity file is a private key that must be owner-only and kept separately from its archive; only the public recipient appears on a CLI argument.

## Command reference

Use reviewed versions of age, age-keygen, and the matching GoreeCloud DNS source/binary. These examples are placeholders; do not paste private identities into terminal history or GitHub. Generate your real identity privately:

    age-keygen -o /private/dns-recovery-identity.txt
    age-keygen -y /private/dns-recovery-identity.txt

Create an encrypted archive in a private destination that does not exist yet:

    go run ./cmd/dns-config backup --rules config/rules.txt --records config/local-records.txt --recipient age1REPLACE_WITH_PUBLIC_KEY --out /private/backups/dns-policy.age

Verify with the private identity. This decrypts only in process memory and validates the two Go policy/record parsers and checksums:

    go run ./cmd/dns-config verify --archive /private/backups/dns-policy.age --identity /private/dns-recovery-identity.txt

The first restore command is a **dry-run** that creates no files:

    go run ./cmd/dns-config restore --archive /private/backups/dns-policy.age --identity /private/dns-recovery-identity.txt --target /private/isolated-staging-policy

The second command only creates a **new, nonexistent staging directory** with 0700 permissions and two validated 0600 files. It refuses any existing target and does not reload the live DNS service:

    go run ./cmd/dns-config restore --archive /private/backups/dns-policy.age --identity /private/dns-recovery-identity.txt --target /private/isolated-staging-policy --apply

## Boundary and failure handling

The backup validates both files with the exact production Go parsers before calling age. It refuses symlink source files, malformed policy, files exceeding bounded limits, invalid age recipient syntax, symlink destination parents, and replacing any existing archive. Ciphertext is written atomically via a new owner-only temporary file and an exclusive hard-link operation. Decryption and integrity checks occur in memory and never write a plaintext archive. Staged restore refuses existing target directories; the CLI does not restart or reload services.

The GitHub CI Go job installs age in a disposable Ubuntu runner and tests a real X25519 synthetic encryption, verification, dry-run, staged restore, tampered ciphertext, private-key permissions, and overwrite rejection. Independent disaster recovery requires separately protected recovery keys, offsite retention, complete host/app configuration and key backups, restoration drills, monitoring, and an approved cutover/rollback. Do not point this CLI at active VPS DNS files without a separate reviewed operator plan.
