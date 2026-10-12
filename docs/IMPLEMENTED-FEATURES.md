# GoreeCloud DNS — Implemented Features

> **Status as reviewed:** 2026-10-12  
> **Authority:** Live source and applicable test evidence in this repository.  
> **Not a release or production certification.**

## Existing inherited source baseline

The repository contains the AdGuard Home-derived Go DNS service, filtering code, user interfaces, build tooling, tests and GPL-3.0 license. This establishes **source presence** of inherited subsystems, not proof that all upstream variants, protocol features or deployment configurations are verified for GoreeCloud DNS.

The existing [README](../README.md), [Fork-to-Native plan](FORK_TO_NATIVE.md) and [privacy disclosure](PRIVACY.md) document the current limited transformation. In particular, existing project documentation states that PR #2 merged an inherited executable auto-update lockout and new-install query-log default changes. Existing configurations preserve their own logging settings; disabling logs does not remove historical data.

## Development candidate — IPv6 scoped-address access rules (October 12, 2026)

The unmerged network-hardening candidate normalizes IPv6 interface-zone identifiers before exact allow/block IP matching, including zone-qualified configured entries. It includes scoped regression tests that exercise allowed and blocked link-local addresses with different zones. Local Go 1.27.1 `go test ./internal/dnsforward -run 'TestAccessIPZones|TestIsBlockedIP' -count=1` passed. This is not a verified production DNS deployment or full filtering-path acceptance.

## Verification gaps / no unwarranted completion claims

The comprehensive Beacon feature catalog in [PROJECT-SPECIFICATIONS.md](PROJECT-SPECIFICATIONS.md) remains proposed and indexed in [PLANNED-FEATURES.md](PLANNED-FEATURES.md). Full independent recursion, authoritative zone hosting, DNSSEC signing, clustering, full protocol matrix, Glaze UI, GoreeCloud ecosystem interoperability and production readiness are **not verified by this inventory**.

A specific feature may only be promoted here after inspection of its implementing code, named revision, tests and appropriate negative-path/platform acceptance evidence. Document source implementation separately from runtime, production, released and Stable status.
