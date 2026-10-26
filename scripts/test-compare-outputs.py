#!/usr/bin/env python3
"""Regression tests for numeric native/OpenTofu output comparisons."""
from decimal import Decimal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compare"))
from output_compare import compare_outputs, cloud_values, native_values


def check(condition, message):
    if not condition:
        raise AssertionError(message)


native = {"status": "passed", "outputs_csv": "service,count\ninstances,2\nvpcs,3\n"}
cloud = {"status": "passed", "outputs": {"comparison": {"value": {"instances": 2, "vpcs": 3}}}}
check(native_values(native) == {"instances": Decimal(2), "vpcs": Decimal(3)}, "CSV parser")
check(cloud_values(cloud) == {"instances": Decimal(2), "vpcs": Decimal(3)}, "cloud parser")
check(compare_outputs(native, cloud, False, "inventory") == "same: instances, vpcs", "multi-row same")

native = {"status": "passed", "outputs_csv": "category,count\ntrue,2\nfalse,1\n"}
cloud = {"status": "passed", "outputs": {"comparison": {"value": {"tagged": 2, "untagged": 1}}}}
check(compare_outputs(native, cloud, False, "tag_compliance") == "same: tagged, untagged", "aliases")

native = {"status": "passed", "outputs_csv": "service,count\nalarms,3\nlog_groups,2\n"}
cloud = {"status": "passed", "outputs": {"comparison": {"value": {"log_groups": 2}}}}
check(compare_outputs(native, cloud, False, "log_groups").startswith("same supported fields; unsupported native fields: alarms"), "unsupported field")

native = {"status": "passed", "outputs_csv": "service,count\ninstances,2\n"}
cloud = {"status": "passed", "outputs": {"comparison": {"value": {"instances": 3}}}}
check(compare_outputs(native, cloud, False, "instances").startswith("differs: instances=2/3"), "numeric mismatch")

native = {"status": "passed", "outputs_csv": "phase,count\ncreated,1\nobjects,1\ncleaned,0\n"}
cloud = {"status": "passed", "observed_resources": [{"kind": "bucket"}, {"kind": "aws_s3_object"}]}
check(compare_outputs(native, cloud, True, "bucket_objects") == "same: cleaned, created, objects", "observed write shape and verified cleanup")
check(compare_outputs({"status": "blocked"}, cloud, False).startswith("unsupported:"), "blocked")
print("PASS output comparison mappings and unsupported-field safeguards")
