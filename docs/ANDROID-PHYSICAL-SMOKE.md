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

## Follow-up Android 17 handset smoke — November 21, 2026

- **Source:** PR #11 exact feature head `00464a5c3cf8e56d8890b8018a3fc11d1b28a9c8` (subsequently squash-merged to protected main as `971e4b2f56d7fa842f0d9a610099ed64fde2abbe`). GitHub Actions run `44877484744` was successful, including Android JVM endpoint-validation tests. The artifact sidecar records a synthesized pull-request checkout SHA `90a953028da6755b0de57d9960858b5ffe516e50`, **not** the feature head or squash commit.
- **Debug APK:** verified the supplied SHA256SUMS; SHA-256 `8ff6dd48ce97d5b0abf037b43f2193c6830d448839c09757c15b0484eb7ac8d9`. APK Signature Scheme v2, package `com.goreecloud.dns`, version 0.1.0, minimum SDK 26, target SDK 35; no release or app-store signing.
- **Physical handset:** same authorized Android 17 ARM64 USB-connected device, with no preexisting GoreeCloud DNS installation at preflight.
- **Actions verified:** temporary install, successful cold launch with MainActivity foreground, Home/background transition, Activity resume, application process existence and complete uninstall. Final package-path query found no installed copy.
- **Privacy/safety:** no real DNS API credentials entered; no query-history, VPN profile, router, resolver settings or production network changed. All test APKs were staged only in temporary RAM-backed storage because the laptop root filesystem was nearly full.
- **Important limits:** the Android FLAG_SECURE intent was implemented in source and APK, but the read-only window dump was not conclusive proof that screenshots were blocked. No API credentials were present, so background token erasure, TLS failure paths, token revocation and remote API session handling were **not** exercised on the handset. UI accessibility, full lifecycle testing and Android release-signing remain open.

## Current source safeguards and remaining acceptance

Current Kotlin source includes strict HTTPS-origin parsing and JVM unit tests for deceptive URLs, screenshot protection requested on the token-bearing activity, and Compose session state reset on backgrounding. The follow-up test above verifies **install, cold-launch, background, resume and removal** on a physical handset, not the effectiveness of screenshot prevention or private-token lifecycle controls. Production security and release acceptance require dedicated negative-path, authenticated session, accessibility and rollback testing under an explicitly authorized isolated target.

