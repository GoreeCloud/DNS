# GoreeCloud DNS — Privacy and data handling

**Development disclosure, October 12, 2026.** This notice describes the current source baseline. It is not a statement that GoreeCloud DNS has completed independent security, privacy, or production acceptance testing.

## What the local server processes

GoreeCloud DNS processes DNS requests submitted by clients using the configured DNS listener and forwards requests to resolvers selected by the operator. DNS requests, response metadata, and network identifiers may be visible to the operator and to any selected upstream DNS provider. Plain DNS does not encrypt traffic; enable supported encrypted DNS transports where appropriate.

## Query history and diagnostics

For newly generated configurations, the default query-log settings now disable query history and file-backed query recording. **Previously existing configurations retain their configured settings**, including any enabled query logs and retention interval. Disabling logging does not automatically remove historical log files. Administrators must review retention, logs, backups, statistics, application logs, and client IP anonymization settings for their own installation.

## Other outbound connections

Depending on enabled features and administrator configuration, the inherited source can contact upstream DNS resolvers, filtering-list hosts, safe browsing/parental protection services, update endpoints for filter lists, and other configured providers. An inherited executable auto-update mechanism is disabled in GoreeCloud DNS pending a verified GoreeCloud-controlled release process. This does not imply that all application network communication is disabled. An outbound-domain and dependency audit remains an open release gate.

## Admin dashboard and external links

The administration UI operates against the local service. Its documentation, privacy, and issue-report links point to source-controlled GoreeCloud pages. Clicking an external link opens a third-party website and is subject to that website's practices. The original AdGuard license and attribution remain available in [UPSTREAM.md](../UPSTREAM.md).

## Operator responsibilities

Self-hosting operators control their network exposure, DNS upstreams, certificates, authentication settings, log access, retention, backups, and any disclosures to clients. Do not expose an unreviewed DNS administrative interface to the public Internet. Test your deployment's settings before handling production network traffic.

Report security concerns as described in [SECURITY.md](../SECURITY.md).
