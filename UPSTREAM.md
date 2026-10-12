# Upstream provenance and import ledger

- Source project: AdGuard Home, https://github.com/AdguardTeam/AdGuardHome
- Source owner: AdguardTeam
- Source branch: master
- Pinned source commit: 8dedd3278542b45ea21994e24422f5cc53e14b8f
- Source snapshot import date: 2026-10-12
- Source license: GNU GPL-3.0, original LICENSE.txt retained
- Destination repository: https://github.com/GoreeCloud/DNS
- Development approach: Fork-to-Native in an independent repository, not a GitHub fork relationship

The import retains upstream application source and build files. The upstream README, SECURITY and CONTRIBUTING documents are retained in docs/upstream; the root versions are GoreeCloud-specific. Upstream .github configuration and workflows, including release and mirror actions, were deliberately excluded from executable GitHub configuration pending independent review.

This source import is not a claim of independent invention. Copyright headers and required notices must remain. Changes to source modules, runtime identity, update channels, management API and configuration schemas require compatibility and licensing review.
