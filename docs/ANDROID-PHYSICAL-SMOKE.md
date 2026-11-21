# Android physical-device development smoke

Status: **partial physical-device acceptance; not a release**.

## Observed isolated test — November 21, 2026

- Source: GoreeCloud DNS PR #9 GitHub Actions run 44876873334, head eb516fbd4569b8e35012020e8bc3153a29f71973; the APK provenance file records Actions' synthesized pull-request checkout SHA 0aa3e769b33da7f0c9f816e2aad25ad5f77215ab. These are distinct refs and should not be conflated.
- Artifact: debug-signed goreecloud-dns-debug.apk, verified by SHA256SUMS. SHA-256 7763bc85e2bc11713cba5e28bd3d028604b9388ad6d141bd1d998f7385b409ae.
- Target: an authorized ARM64 handset running Android 17, connected over USB to the authorized Linux laptop. No device serial, personal data, network profile, or user credentials is recorded here.
- Before installing, the package com.goreecloud.dns was not installed.
- Verified APK package ID, version 0.1.0, minimum SDK 26, target SDK 35 and APK Signature Scheme v2.
- A temporary debug installation completed successfully; MainActivity cold-start completed and became the foreground resumed activity. The application process existed, with INTERNET as its sole declared runtime permission.
- No management token, DNS endpoint, client DNS profile, route, VPN, network setting or production service was modified.
- The temporary app was uninstalled, and a subsequent package-path query returned no installed copy.
- Laptop disk was nearly full (~1 GB available), so local Gradle compilation was stopped; the independently built GitHub Actions APK was verified from RAM-backed temporary storage instead. The phone test did not require a local Android build.

**Scope:** This verifies only package integrity, temporary install, cold launch, foreground activity and clean removal for that older artifact. It does not prove authenticated API function, live HTTPS, UI accessibility, background credential handling, key rotation, offline failure recovery, Android 17 release compatibility or production readiness.

## Next version safeguards

The development branch adds strict URI-origin parsing, debug unit tests for deceptive URLs, screenshot protection for the token-bearing UI, and session-state reset on backgrounding. These modifications **were not in the APK described above**. Rebuild and revalidate the exact new source before claiming their behavior on a physical device.
