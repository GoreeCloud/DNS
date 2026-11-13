# Opt-in synthetic DNS filtering and client-policy smoke

**Status:** Development-only test fixture; not deployed DNS policy or production migration acceptance.

These two Perl programs exercise Technitium-derived GoreeCloud DNS blocking APIs and wire-level responses **only inside an explicitly isolated, rootless, network-disabled test container**:

- `tests/smoke_synthetic_filter_client_policy.pl`: three reserved `.example` names added to the blocked zone; their `0.0.0.0` A responses over UDP/TCP; an allowed-zone override; and two distinct loopback-source IP addresses, one with a blocking bypass.
- `tests/smoke_synthetic_blocklist_subscriptions.pl`: ten synthetic loopback-served hosts-format blocklist subscriptions, two deliberately excluded subscriptions, forced refresh and actual blocked A responses over UDP/TCP. A temporary HTTP server is bound to `127.0.0.1:18081` **inside the isolated container** and terminated after testing.

## Preconditions and invocation

These are **session-level test modules, not standalone executables**. Run them only as an opt-in extension of an already authenticated, disposable GoreeCloud DNS image smoke:

1. The enclosing runner must verify rootless Podman, `--network=none`, UID 1654, loopback as the **sole** network interface, a read-only image filesystem, zero host port mappings, resource limits, and a temporary writable `/work` mount.
2. Start the **development** DNS application on loopback with a randomly generated, temporary administrator password stored in `/work/admin-password`. Never use a production token, client address, rule, blocklist URL, or configuration file.
3. The runner must authenticate using the temporary password, create `/work/session-header` mode 0600, and copy the two test scripts into `/work`. Perl JSON::PP and IO::Socket::INET, `curl` and `dig` must be available in the container (a minimal runtime image may require independently reviewed test-only Perl modules).
4. **While that temporary session is active**, invoke, in order:

   ```sh
   perl /work/smoke_synthetic_filter_client_policy.pl /work/session-header
   perl /work/smoke_synthetic_blocklist_subscriptions.pl /work/session-header
   ```

5. Require exit code zero from each. Afterward invalidate the temporary session, stop the test DNS instance, and remove the disposable container. The tests refuse invocation on the host, under an unexpected UID, or with a non-loopback network interface.

The existing repository smoke runners are not implicitly changed by these new files. No unattended deployment, privileged host operation, public port opening, production DNS mutation or external blocklist download is requested. A portable opt-in rootless runner can be considered in a separate reviewed integration step.

## Scope and limitations

The **counts** were selected to resemble an owner-verified aggregate source AdGuard Home configuration: 12 subscriptions with 10 enabled, three blocked hosts, and two persistent clients. These are **new synthetic entries, not imports, copies, conversions or views** of the owner's actual private policies.

The tests do **not** establish: source custom-rule syntax/precedence equivalence, client identity/profile mapping, actual external filter subscription format/refresh and availability, upstream or bootstrap resolver parity, DNSSEC chain validation, logging/retention parity, publicly reachable encrypted DNS, or operational cutover readiness. In particular, an allowed synthetic query can yield `SERVFAIL` with no outside network: the assertion proves **suppression of the distinctive blocked A address**, not successful recursive resolution.

Never use `.invalid`-domain `NXDOMAIN` alone as evidence of a blocking rule: that result can arise without blocking. This fixture deliberately verifies `0.0.0.0` A answers against an unblocked baseline.

**Local validation (November 13, 2026):** On a previously cached development image (`sha256:84ec3f4a8085686a101cf174c5a3350de95c78c51f1688cdb600bd5ef710ba3b`), both guarded programs passed syntax checks, refused host execution, and passed together with the existing synthetic authentication, DNS-over-TLS/HTTPS and DNSSEC-publication smoke in a network-disabled rootless Podman runtime. The combined run exited zero; no test containers remained. This does not verify a fresh image rebuild or the current GitHub head implementation.

**Release decision:** Experimental surrogate coverage only. Real AdGuard-to-GoreeCloud policy comparison and destination service acceptance remain open.
