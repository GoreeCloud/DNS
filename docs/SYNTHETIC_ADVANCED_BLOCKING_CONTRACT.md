# Synthetic Advanced Blocking policy contract

**Status: static, non-production compatibility research.** This fixture is inert JSON and a fail-closed checker. It is not an installed DNS app, a service configuration, a production policy converter, or evidence of parity with any live AdGuard Home deployment.

## Why this is separate from built-in blocking

The upstream Advanced Blocking App (`Apps/AdvancedBlockingApp/`) selects groups by client network or local DNS endpoint and provides independent per-group blocking switches. Its own README explicitly warns that it does **not** reuse lists or settings from the server's built-in Blocking page. Mixing built-in blocking with this app can produce unexpected behavior. The separate [draft PR #44](https://github.com/GoreeCloud/DNS/pull/44) built-in blocking smoke must therefore **not** be interpreted as an Advanced Blocking runtime test.

The reviewed `App.cs` source also defaults `allowTxtBlockingReport` to `true`. Blocking reports can include group, blocked domain/regex, and blocklist URL metadata in TXT responses or extended DNS errors. **This synthetic fixture explicitly sets it to `false` for both groups.** That privacy setting should be separately verified in any eventual runtime acceptance and designed under GoreeShield privacy governance.

## What the fixture represents

`tests/fixtures/synthetic_advanced_blocking_policy.json` describes two **fictitious** loopback clients, using `127.0.0.2` and `127.0.0.3`, with distinct groups named `bypass` and `filtered`. One group has blocking enabled; the other does not. The sole blocked DNS name is `policy-block-1.example`. No real endpoints, credentials, private rules, filter subscription URLs, client identifiers, or production settings are included. There are no host-port mappings or network operations.

`scripts/validate_synthetic_advanced_policy.py` checks exactly this synthetic schema, fails closed for unknown keys, unsafe address mappings, external URLs, changed policy switches, missing privacy flags, unsupported capabilities and accidental inclusion of real-world client data. It accepts no external file argument and reads only its fixed in-repository fixture. It never launches DNS, installs the app, binds a port, changes a host, or communicates over the network.

Use its static checks:

```sh
python3 -m unittest discover -s tests -p test_advanced_blocking_policy_contract.py -v
python3 scripts/validate_synthetic_advanced_policy.py
```

The validator returns a JSON status containing `app_runtime_tested:false`, `production_parity_verified:false` and `cutover_authorized:false`. It deliberately refuses any capability request for parental protection, safe browsing, AdGuard `$important` exception precedence, and production client identity mapping.

## Opt-in offline application runtime acceptance (November 13, 2026)

The separately tested `tests/run_advanced_runtime.sh` and `tests/smoke_advanced_runtime.pl` **actually loaded the compiled Advanced Blocking plugin** into a disposable GoreeCloud DNS server image. This is different from the inert JSON/static CI contract above. The runtime harness is committed for review, **not invoked by default CI**.

The owner-controlled laptop lab used a previously cached GoreeCloud DNS image identified by `sha256:84ec3f4a8085686a101cf174c5a3350de95c78c51f1688cdb600bd5ef710ba3b`, a cached .NET SDK 10 image, the exactly reviewed `Apps/AdvancedBlockingApp/App.cs` source blob `97e13a467937c02221394d9ab8fac93377c4e094`, and library DLLs extracted from that cached image. The source compiled successfully **offline**, with no network interface, zero warnings and zero errors. The emitted DLL SHA-256 was `4d9132209088a65d996131010c0888a7bd34266d5c4b2cea9fa3faa6bfd346d4`.

**Packaging is required:** The DNS application loader scans `*.deps.json` to discover plugin assemblies. A first intentionally observed package containing only the DLL and JSON config was accepted by the installer but had **zero loaded handlers**. The corrected **test-only** ZIP contains only `AdvancedBlockingApp.dll`, `AdvancedBlockingApp.deps.json` (SHA-256 `f5a23fd1eaa1b00c8885a85dbed4606e8551c81bcf00a62696c601829951f796`), and the static JSON fixture as `dnsApp.config`. The exact tested ZIP SHA-256 is **`74dcaad61ec3ab3835d3d56528fc74bb827efe4b9073a7bd51db26c6f68e75b2`**. No binary ZIP is committed to this repository. The opt-in shell refuses any differently hashed payload.

The successful rootless Podman run used `--network=none --read-only --user 1654:1654 --cap-drop=all --cap-add=NET_BIND_SERVICE --security-opt=no-new-privileges`, bounded PIDs, CPU, and RAM, no published host ports, read-only mounts for the reviewed tests, the ZIP, and Perl JSON::PP dependencies, and a disposable 96 MiB `/work` tmpfs. It generated a temporary administrator password, used authenticated localhost-only API calls, disabled **built-in** blocking only in the container, and installed the Advanced Blocking App only in its disposable filesystem.

**Actual test observations (exit 0):** DNS app installation returned one module, class `AdvancedBlocking.App`, with a recognized blocking handler. The returned config preserved two synthetic loopback IP-group selectors and `allowTxtBlockingReport=false` for both groups. The filtered synthetic client received a distinctive blocked A response `0.0.0.0` over both UDP and TCP, while the other loopback client did not. The bypassed query returned `SERVFAIL` without outside recursion—**not** a successful unfiltered lookup. The tested blocked TXT/EDNS response contained no Advanced Blocking metadata report. Ephemeral admin logout completed. The final private lab evidence readback was mode 0600, SHA-256 `800d5eaeaeee5f065e7702ac47a5819d155e6ff2c063c32623b08d6f38e8d1df`; no test container remained running.

**Limits:** This validates synthetic **group-based domain blocking**, not parental protection, safe browsing, AdGuard `$important` precedence, real client identity mapping, real subscription downloads, DNSSEC trust, downstream resolver success, IPv6 clients, encrypted-DNS client attribution, broad metadata confidentiality, or operational compatibility with the destination VPS. The test package and scripts must never be run on any live service. They must not be mixed with the separate built-in blocking policy of draft PR #44.

## What this does NOT establish

Hosted CI verifies the **static fixture** and independently **compiles the existing Advanced Blocking App source** against the repository's pinned dependency build. The compile step does not install, enable, or run `AdvancedBlockingApp`; it does not exercise network-group matching with actual DNS packets, fully audit app dependencies or license risks, test filter-list refresh, authenticate clients on encrypted transports, validate rule priority, or reproduce AdGuard client settings.

It especially does **not** establish safe-browsing or parental-protection equivalence. A client's filtering switch is not a replacement for the other protections. Nor can aggregate source counts establish which protection settings belong to which private client identity. The app's `allowed` and `blocked` lists are not a proven implementation of AdGuard's `$important` precedence. A privacy-controlled, independently reviewed runtime parity protocol would be required before any real client DNS cutover.


**Hosted verification:** [GitHub Actions run 43537823750](https://github.com/GoreeCloud/DNS/actions/runs/43537823750) passed its source-contract and pinned .NET build jobs. Its new `Compile Advanced Blocking App source (no install or runtime)` step completed successfully. These results apply to draft branch commit `31f38efa56d869fb6873c09bcf1d620be856d287`, not to a deployed application.

**Application availability:** The immutable cached DNS image did not show a preinstalled Advanced Blocking assembly in the inspected locations. The separately compiled app **was installed and executed successfully only in an ephemeral, isolated lab container**; its installation on any production or destination VPS remains unverified and unauthorized.

**Release decision:** Static contract and isolated synthetic runtime acceptance passed; **production feature and policy parity remain blocked**. Wardveil access controls, GoreeShield retention and reporting, GoreeCloud Identity, client encrypted transport, and GoreeCloud Mesh integration remain OPEN. No backups, production service configuration changes, DNS routing, or cutover are requested.
