# GoreeCloud DNS — Implemented Features

> **Status as reviewed:** 2026-10-12  
> **Authority:** Live source and applicable test evidence in this repository.  
> **Not a release or production certification.**

## Existing inherited source baseline

The repository contains the AdGuard Home-derived Go DNS service, filtering code, user interfaces, build tooling, tests and GPL-3.0 license. This establishes **source presence** of inherited subsystems, not proof that all upstream variants, protocol features or deployment configurations are verified for GoreeCloud DNS.

The existing [README](../README.md), [Fork-to-Native plan](FORK_TO_NATIVE.md) and [privacy disclosure](PRIVACY.md) document the current limited transformation. In particular, existing project documentation states that PR #2 merged an inherited executable auto-update lockout and new-install query-log default changes. Existing configurations preserve their own logging settings; disabling logs does not remove historical data.

## Development candidate — private-zone name boundary

The isolated `internal/goreecloud/privatezone` Go package in branch
`feature/private-zone-boundary-20261013` provides a label-aware,
case-normalized matcher for explicitly configured private DNS suffixes such as
`.lan`, `.home.arpa`, and `.internal` and their delegated subzones. It
rejects malformed labels and invalid configurations and prevents false positive
matches such as `lan.evil.test` or `examplelan`. DNS-SD owner names with
leading underscore labels are recognized for matching without publishing them.
Unit tests cover negative and positive cases.

The package is not wired into the inherited resolver or any Gateway/VPN
service-discovery path. This source-level boundary does not authorize private
names, filtering, split-horizon routing, public exposure, or automatic service
publication. Scoped Go CI and runtime integration evidence are still required.

## Verification gaps / no unwarranted completion claims

The comprehensive Beacon feature catalog in [PROJECT-SPECIFICATIONS.md](PROJECT-SPECIFICATIONS.md) remains proposed and indexed in [PLANNED-FEATURES.md](PLANNED-FEATURES.md). Full independent recursion, authoritative zone hosting, DNSSEC signing, clustering, full protocol matrix, Glaze UI, GoreeCloud ecosystem interoperability and production readiness are **not verified by this inventory**.

A specific feature may only be promoted here after inspection of its implementing code, named revision, tests and appropriate negative-path/platform acceptance evidence. Document source implementation separately from runtime, production, released and Stable status.
