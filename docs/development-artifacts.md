# Development build artifacts and provenance

GoreeCloud DNS CI retains temporary, non-release build artifacts for seven days to support independent, authorized testing. Each artifact includes a SHA-256 checksum file and an exact source commit recorded by GitHub Actions. Compilation is not a cryptographic signature, production acceptance, software update policy or safe DNS cutover.

| GitHub Actions artifact | Contains | Limitations |
| --- | --- | --- |
| dns-go-resolver-dev | Static Linux AMD64 DNS daemon, encrypted-policy recovery CLI, and Go module/build info | Neither binary is a system service, signed package or deployed binary; the recovery CLI also requires an independently trusted age installation |
| dns-react-web-dev | React static web dist files | Must be deployed behind trusted HTTPS with a protected same-origin API |
| dns-android-debug-dev | Android debug APK | Debug-signed for temporary testing only; not a public release |
| dns-linux-qt612-dev | Qt Quick 6.12.0 Linux executable | Dynamically linked; Qt libraries and platform plugins are not bundled |

## Artifact acceptance

Download artifacts only from a reviewed exact-source GitHub Actions run. Verify SHA256SUMS before use, compare the source commit and build information, and review dependency provenance and package signature identity. Do not copy these binaries to the VPS, change router DNS, expose port 53, or overwrite any working service.

Android physical acceptance requires an authorized test handset, scoped first-run with no real API credentials, verified package identity and safe removal afterward. Linux physical acceptance requires runtime Qt compatibility, visual and keyboard/accessibility checks, installation/uninstallation, correct desktop integration, dependency closure, and controlled rollback.

Signing, release packaging, installer/update migration, SBOM, dependency-license audit, recovery and actual production support are future work. CI artifacts do not satisfy these gates.
