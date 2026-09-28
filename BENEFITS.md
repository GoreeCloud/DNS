# Benefits — GoreeCloud DNS

## Current Verified Benefits

The current repository provides a clear, source-controlled product specification and truthful separation between planned capabilities, historical predecessor evidence, and current implementation state.

No operational DNS benefit is claimed yet because no DNS runtime is currently verified in this repository lineage.

## Intended User and Administrator Benefits

The planned product scope is intended to provide the following benefits after the corresponding capabilities are implemented and validated:

### Privacy

- Reduce unnecessary disclosure of DNS activity.
- Allow local recursive resolution without concentrating complete query history at one public resolver.
- Provide configurable logging, anonymization, retention, and per-client privacy controls.
- Keep DNS configuration and operational data under administrator control.

### Security

- Validate DNSSEC.
- Block malicious and phishing domains.
- Apply threat intelligence and RPZ policy.
- Protect against DNS rebinding and abusive query patterns.
- Use encrypted DNS where appropriate.
- Separate DNS use from administrative privilege.

### Ownership and Independence

- Operate without advertising or sponsorship-driven behavior.
- Avoid a mandatory external account.
- Avoid mandatory dependence on a commercial upstream DNS provider.
- Keep configuration, logs, statistics, zones, and policies exportable and self-hosted.

### Reliability and Performance

- Serve frequently requested records from local cache.
- Use serve-stale behavior during suitable upstream failures.
- Support redundant nodes and replicated DNS services.
- Select upstreams using health and latency signals where forwarding is used.

### Administration

- Centralize recursive, authoritative, filtering, DHCP, policy, diagnostics, and analytics administration.
- Apply policies by client and group.
- Automate configuration through APIs and configuration-as-code workflows.
- Manage multiple DNS nodes as one logical environment.

### GoreeCloud Integration

- Integrate with GoreeCloud Identity for authentication and authorization.
- Integrate with Manager for authorized administration.
- Integrate with Privacy Shield and Wardveil Security within their respective privacy and security boundaries.
- Integrate with Everkeep for recoverability.
- Use Glaze UI for a consistent administrative experience.

These are intended benefits, not current runtime claims.
