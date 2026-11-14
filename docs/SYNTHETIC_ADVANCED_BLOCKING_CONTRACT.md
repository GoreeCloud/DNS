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

## What this does NOT establish

Even successful CI proves only that the **static fixture** meets a narrow policy contract. It does not install or run `AdvancedBlockingApp`, exercise network-group matching with actual DNS packets, independently verify app dependency or license risk, test filter list refresh, authenticate clients on encrypted transports, validate rule priority, or reproduce AdGuard client settings.

It especially does **not** establish safe-browsing or parental-protection equivalence. A client's filtering switch is not a replacement for the other protections. Nor can aggregate source counts establish which protection settings belong to which private client identity. The app's `allowed` and `blocked` lists are not a proven implementation of AdGuard's `$important` precedence. A privacy-controlled, independently reviewed runtime parity protocol would be required before any real client DNS cutover.

**Application availability:** The cached development DNS image was previously checked for an Advanced Blocking assembly in common application directories, without a verified hit. Its actual installation/running status remains **unverified**, not assumed available.

**Release decision:** Design contract only. Production DNS policy parity, Wardveil access controls, GoreeShield retention and reporting, GoreeCloud Identity, encrypted transport, and Mesh integration all remain OPEN. No backups, service configuration changes, DNS routing, or cutover are requested.
