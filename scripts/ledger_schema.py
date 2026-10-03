"""The conformance ledger's row schema and its readers (#1208, #1209).

A row in docs/conformance/bacnet-135-2020.json is moving to a lean schema:
`summary` replaces `requirement_summary`, `gaps` holds open work, and the
one-off keys fold into notes and gaps. Rows convert in batches, so readers
accept both forms until every row is lean: `summary()` falls back to
`requirement_summary`, and `gaps()` reads a missing `gaps` as empty.
docs/conformance/README.md describes the schema for writers.
"""

from __future__ import annotations

# The keys a lean row may hold.
LEAN_KEYS = frozenset(
    {
        "id",
        "standard_anchor",
        "priority",
        "summary",
        "status",
        "code_anchors",
        "positive_tests",
        "negative_tests",
        "benchmarks",
        "public_claims",
        "notes",
        "gaps",
    }
)

# Keys of the old schema, allowed only on rows the style checker still skips
# (scripts/ledger_style_pending.txt). `evidence` is #1191's temporary table
# source; the rest are one-off keys of two rows that the condense batches fold
# into notes and gaps.
LEGACY_KEYS = frozenset(
    {
        "requirement_summary",
        "evidence",
        # BACNET-13-AUDIT-WIRE-MODELS
        "object_owned_av_bv_policy",
        "python_static_target_reporter",
        "python_direct_parent_forwarding",
        "python_receiver_query_parity",
        "audit_log_forwarding_boundary_evidence",
        "audit_log_forwarding_immediate",
        "target_create_delete_immediate",
        "target_list_immediate",
        "target_atomic_write_file_immediate",
        "target_resource_admission_failure",
        "target_write_immediate",
        "target_write_monitored_objects",
        "target_device_recipient",
        "target_multiple_reporters",
        # BACNET-AB-SC-CONNECTION-STATE
        "address_resolution_accepting_capability",
        "hub_resolution_transit",
        "hub_unknown_transit",
        "rejection_nak_budget",
        "unknown_function_admission",
        "mu_rejection_liveness",
        "unsolicited_response_admission",
        "zero_limit_admission",
        "empty_npdu_admission",
    }
)

# Statuses that need no gaps: the row is either fully evidenced or out of scope.
NO_GAP_STATUSES = frozenset({"supported-with-clause-evidence", "unsupported-by-design"})


def summary(row: dict) -> str:
    """A row's one-sentence summary, from `summary` or the older `requirement_summary`."""
    text = row.get("summary", row.get("requirement_summary"))
    return text if isinstance(text, str) else ""


def gaps(row: dict) -> list[str]:
    """A row's open-work entries; a row without `gaps` has none."""
    value = row.get("gaps", [])
    if not isinstance(value, list):
        raise TypeError(f"{row.get('id')}: gaps must be an array, not {value!r}")
    return value
