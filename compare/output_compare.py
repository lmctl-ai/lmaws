"""Small, explicit numeric comparison for native CSV and OpenTofu outputs.

This module deliberately does not guess that unrelated labels are equivalent.
Only fields listed here (or directly shared by both sides) are compared; missing
provider fields are reported as unsupported instead of becoming a false pass.
"""
from __future__ import annotations

import csv
import io
from decimal import Decimal, InvalidOperation
from typing import Any


# Native examples use labels that describe the display category, while the
# provider configuration uses the corresponding AWS-domain field name.
ALIASES = {
    "security_groups": {"true": "public", "false": "private"},
    "tag_compliance": {"true": "tagged", "false": "untagged"},
    "resource_graph": {"stores": "buckets"},
    "secrets": {"[redacted]": "secrets"},
}


def _number(value: Any) -> Decimal | None:
    if isinstance(value, bool):
        return Decimal(int(value))
    if isinstance(value, (int, float, Decimal)):
        return Decimal(str(value))
    if isinstance(value, str):
        try:
            return Decimal(value.strip())
        except (InvalidOperation, ValueError):
            return None
    return None


def native_values(native: dict[str, Any], example: str | None = None) -> dict[str, Decimal]:
    """Extract numeric rows from stored ``outputs_csv``/``outputs_count``."""
    values: dict[str, Decimal] = {}
    raw = native.get("outputs_csv", "")
    if raw:
        rows = list(csv.reader(io.StringIO(raw)))
        if len(rows) >= 2 and len(rows[0]) >= 2:
            for row in rows[1:]:
                if len(row) < 2:
                    continue
                number = _number(row[1])
                if number is not None and row[0].strip():
                    label = row[0].strip()
                    label = ALIASES.get(example or "", {}).get(label, label)
                    values[label] = number
    raw_count = native.get("outputs_count", "")
    if raw_count:
        for item in str(raw_count).split(","):
            if "=" not in item:
                continue
            label, raw_value = item.split("=", 1)
            number = _number(raw_value)
            if number is not None:
                values[ALIASES.get(example or "", {}).get(label.strip(), label.strip())] = number
    # The category split in these examples represents one inventory count.
    # Expose an aggregate only when the provider reports the aggregate field.
    if example in {"tables"}:
        values["tables"] = sum(values.values(), Decimal(0))
    return values


def _comparison_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    if isinstance(value.get("comparison"), dict):
        candidate = value["comparison"]
        if isinstance(candidate.get("value"), dict):
            return candidate["value"]
        return candidate
    for item in value.values():
        found = _comparison_object(item)
        if found:
            return found
    return {}


def cloud_values(cloud: dict[str, Any]) -> dict[str, Decimal]:
    """Extract numeric ``comparison`` outputs from OpenTofu state output."""
    result: dict[str, Decimal] = {}
    for key, value in _comparison_object(cloud.get("outputs", {})).items():
        number = _number(value)
        if number is not None:
            result[key] = number
    return result


def compare_outputs(native: dict[str, Any], cloud: dict[str, Any], write_mode: bool,
                    example: str | None = None) -> str:
    """Return ``same``/``differs``/``unsupported`` with field-level detail."""
    if native.get("status") != "passed" or cloud.get("status") != "passed":
        return "unsupported: an engine was blocked"
    left = native_values(native, example)
    right = cloud_values(cloud)
    if write_mode:
        observed = cloud.get("observed_resources", [])
        right = {"created": Decimal(sum(r.get("kind") in {
            "bucket", "queue", "topic", "parameter", "table", "log_group"
        } for r in observed))}
        right["cleaned"] = Decimal(cloud.get("leftover_count", 0))
        if any(r.get("kind") == "aws_s3_object" for r in observed):
            right["objects"] = Decimal(sum(r.get("kind") == "aws_s3_object" for r in observed))
        if any(r.get("kind") == "aws_dynamodb_table_item" for r in observed):
            right["items"] = Decimal(sum(r.get("kind") == "aws_dynamodb_table_item" for r in observed))
    shared = sorted(set(left) & set(right))
    missing = sorted(set(left) - set(right))
    if not shared:
        return "unsupported: no common numeric fields (native=%s provider=%s)" % (
            ",".join(sorted(left)) or "none", ",".join(sorted(right)) or "none")
    mismatched = [f for f in shared if left[f] != right[f]]
    if mismatched:
        return "differs: " + ", ".join(f + "=" + str(left[f]) + "/" + str(right[f]) for f in mismatched)
    if missing:
        return "same supported fields; unsupported native fields: " + ", ".join(missing)
    return "same: " + ", ".join(shared)
