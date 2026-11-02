# GoreeCloud DNS — development and provenance

GoreeCloud DNS is a development distribution of [Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer), not an official upstream product or a production-validated deployment.

- Baseline: upstream master commit 0dd592aad21eced4221a9a46204cb1a299972ca0 (tree 8e95e2d771683be67624f98a57098fbcef867407), version 15.6.2.
- Unmodified source preserved in branch upstream/technitium-master-20261102.
- GoreeCloud/DNS already existed as an independent public repository; this is not a GitHub-native fork relationship.
- Original headers, attribution, and GPL-3.0-or-later terms are preserved.

## Added in the GoreeCloud development branch

- Console, login, About and encrypted DNS setup page identify the GoreeCloud distribution; upstream credit and repository links remain visible.
- Skip-to-content navigation, focus-visible styles and login autofill hints.
- App assembly product metadata identifies GoreeCloud DNS while retaining original authorship.
- One-click copy of the displayed DNS-over-HTTPS endpoint, with accessible status messages and failure fallback instructions.
- Dependency-free static regression checks.

## Build and release gates

Build requires .NET 10 and the separate sibling TechnitiumLibrary source/build described in the upstream build.md. A static test is not a DNS runtime, package, browser, assistive-technology, or production deployment test. DNS and DHCP system settings are deliberately untouched.

Next: isolated .NET build and protocol verification, threat-model review, GC UI theme/responsive acceptance, packaging and onboarding audit, vulnerability checks, then privacy-preserving DNS capabilities as separate reviewable changes.
