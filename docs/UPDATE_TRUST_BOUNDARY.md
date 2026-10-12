# GoreeCloud DNS update trust boundary

The source baseline inherits an update client that references the AdGuard Home release service. This dependency is not approved as a GoreeCloud binary distribution or update authority.

Until a GoreeCloud-controlled release channel has independently verified manifests, cryptographic integrity, rollback, and service upgrade tests, builds must not treat the inherited release feed as a trusted source for executable replacement. Both the administrative API and command-line update paths require explicit fail-closed controls and tests.

This is a development risk record, not a release attestation.
