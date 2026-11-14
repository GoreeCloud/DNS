"""Fail-closed contract for an *inert*, synthetic Advanced Blocking fixture.

No network, subprocess, service, secret, host-config or privileged operations.
This deliberately does not implement parental controls, safe browsing, or
AdGuard's $important precedence. It MUST NOT be used for production migration.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic_advanced_blocking_policy.json"
GROUPS = {"filtered", "bypass"}
CLIENTS = {"127.0.0.2": "bypass", "127.0.0.3": "filtered"}
LIST_FIELDS = ("allowed", "blocked", "allowListUrls", "blockListUrls",
               "allowedRegex", "blockedRegex", "regexAllowListUrls",
               "regexBlockListUrls", "adblockListUrls")
UNVERIFIED = ("parental_protection", "safe_browsing",
              "adguard_important_exception_precedence",
              "production_client_identity_mapping")


class ContractError(ValueError):
    """Generic error only: never include potentially sensitive input values."""


def _no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ContractError("duplicate_json_key")
        out[key] = value
    return out


def load_inert_fixture():
    """Load only the committed test fixture, never a caller-supplied path."""
    if FIXTURE.is_symlink() or not FIXTURE.is_file():
        raise ContractError("fixture_not_regular_file")
    if FIXTURE.stat().st_size > 32768:
        raise ContractError("fixture_too_large")
    try:
        return json.loads(FIXTURE.read_text(encoding="utf-8"),
                          object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError("invalid_fixture_json") from None


def validate_synthetic_config(document):
    """Validate narrowly-scoped test semantics without running the DNS app."""
    if type(document) is not dict:
        raise ContractError("invalid_document_type")
    keys = {"enableBlocking", "blockingAnswerTtl",
            "blockListUrlUpdateIntervalHours",
            "blockListUrlUpdateIntervalMinutes",
            "localEndPointGroupMap", "networkGroupMap", "groups"}
    if set(document) != keys:
        raise ContractError("unexpected_root_properties")
    if document["enableBlocking"] is not True:
        raise ContractError("master_blocking_disabled")
    if type(document["blockingAnswerTtl"]) is not int or not 0 <= document["blockingAnswerTtl"] <= 300:
        raise ContractError("unsafe_ttl")
    if document["blockListUrlUpdateIntervalHours"] != 24 or document["blockListUrlUpdateIntervalMinutes"] != 0:
        raise ContractError("unexpected_update_interval")
    if document["localEndPointGroupMap"] != {}:
        raise ContractError("endpoint_override_not_allowed")
    mapping = document["networkGroupMap"]
    if type(mapping) is not dict or mapping != CLIENTS:
        raise ContractError("non_synthetic_client_mapping")
    for address in mapping:
        if not ipaddress.ip_address(address).is_loopback:
            raise ContractError("non_loopback_client")
    groups = document["groups"]
    if type(groups) is not list or len(groups) != 2:
        raise ContractError("incorrect_group_count")
    seen = set()
    allowed_group_keys = {"name", "enableBlocking", "allowTxtBlockingReport",
                          "blockAsNxDomain", "blockingAddresses", *LIST_FIELDS}
    for group in groups:
        if type(group) is not dict or set(group) != allowed_group_keys:
            raise ContractError("unexpected_group_properties")
        name = group["name"]
        if type(name) is not str or name not in GROUPS or name in seen:
            raise ContractError("unexpected_group_name")
        seen.add(name)
        if group["enableBlocking"] is not (name == "filtered"):
            raise ContractError("incorrect_group_blocking_switch")
        # This setting defaults true upstream and may disclose rule/list metadata
        # in TXT and Extended DNS Error responses. Deny in all synthetic groups.
        if group["allowTxtBlockingReport"] is not False:
            raise ContractError("blocking_metadata_disclosure")
        if group["blockAsNxDomain"] is not False:
            raise ContractError("unexpected_block_type")
        if group["blockingAddresses"] != ["0.0.0.0", "::"]:
            raise ContractError("unexpected_blocking_addresses")
        for field in LIST_FIELDS:
            v = group[field]
            if type(v) is not list:
                raise ContractError("invalid_rule_list_type")
            if field == "blocked" and name == "filtered":
                if v != ["policy-block-1.example"]:
                    raise ContractError("non_synthetic_blocked_name")
            elif v != []:
                raise ContractError("unexpected_rule_or_remote_url")
    if seen != GROUPS:
        raise ContractError("missing_policy_group")
    return {
        "schema": "gc.synthetic-advanced-blocking-contract.v1",
        "status": "STATIC_SYNTHETIC_CONTRACT_PASS",
        "group_count": 2,
        "client_selector_count": 2,
        "metadata_reporting_disabled": True,
        "real_client_data_loaded": False,
        "external_urls_configured": False,
        "per_client_domain_blocking_contract": True,
        "unverified_capabilities": list(UNVERIFIED),
        "app_runtime_tested": False,
        "production_parity_verified": False,
        "cutover_authorized": False,
    }


def require_capabilities(capabilities):
    """Fail closed if a caller asks for safety features not evidenced here."""
    if type(capabilities) is not list or any(type(x) is not str for x in capabilities):
        raise ContractError("invalid_capability_request")
    allowed = {"per_client_domain_blocking_contract"}
    if not capabilities or set(capabilities) - allowed:
        raise ContractError("capability_not_evidenced")
    return True


def main():
    # No CLI path argument: cannot inspect actual source or production settings.
    import sys
    if len(sys.argv) != 1:
        print("BLOCKED: static fixture only", file=sys.stderr)
        return 3
    try:
        result = validate_synthetic_config(load_inert_fixture())
    except ContractError as exc:
        # These error labels are constants, never raw config data.
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
