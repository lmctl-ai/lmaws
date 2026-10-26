# Native AWS SDK versus lmcloud/OpenTofu

Every one of the 30 native examples has `compare/<name>/main.tf` and an
`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/<name>/<name>.lms`
equivalent. Generated scripts embed the HCL and directly call `tofu.init`,
`validate`, `plan`, `apply`, `show_state`, and `destroy` in separately checked phases.
The scripts pin released lmcloud v0.1.10. Python 3, curl and AWS CLI support the local safety ledger and independent checks.
No lmcloud checkout is needed or modified.

```sh
export TF_PLUGIN_CACHE_DIR="${TMPDIR:-/tmp}/lmaws-provider-cache"
mkdir -p "$TF_PLUGIN_CACHE_DIR"
LMAWS_LIVE=1 AWS_PROFILE=default AWS_REGION=us-east-1 timeout 1050 compare/run.sh inventory
LMAWS_LIVE=1 AWS_PROFILE=lmaws AWS_REGION=us-east-1 timeout 1050 compare/run.sh bucket_objects
# To reuse a completed SDK run instead of repeating a write:
# --native-evidence compare/runs/<example>/<run>/native/native-result.json
python3 compare/sweep.py --older-than-hours 0
```

Use `default` for read-only comparisons and `lmaws` for writes, always us-east-1.
IAM is skipped before either engine executes. No other identity is used. The native
evidence option reuses a completed live run; resource creation is not repeated.
Both profiles were independently verified to target the same account.

The runtime writes the own-resource ledger and plan before apply, refuses existing
resource names, validates allowed parent/child ownership, reserves cost headroom,
then always attempts destroy in a finally path. Provider state stays under ignored
`compare/runs/`; deletion is independently checked with default metadata calls.
Authorization failures never count as absence. The sweeper is local and dry-run only.
A blocked engine or partial comparison exits 3 (and records its finding); exit 0 requires both engines and comparable results to pass. A shared campaign file enforces the $0.25 ceiling; default example cap is $0.05.

Native SDK cost counts observed requests and resource lifetime/storage. lmcloud does
not expose SDK request counts, so its ledger explicitly uses a conservative
500-request maximum-price upper allowance of $0.0025 per attempted plan, including verification and tiny storage.
This is not observed traffic or an invoice measurement. The allowance is reserved before plan because data sources can issue charged
metadata requests there. It is not a measured provider API charge. Run campaigns
sequentially against the shared cost file, and reuse the scratch plugin cache.

[RESULTS.md](RESULTS.md) has one row per example: status, cost, parent resource
names/types/tags, outputs, wall time, cleanup and differences. Unique run IDs are
normalized for comparisons. The SDK ledger tracks the owning bucket/table while
OpenTofu additionally represents its object/item; these are explicit differences.
Unsupported provider list APIs and imperative message operations are documented in
[manifest.json](manifest.json), not silently replaced by unrelated data.

[PROVIDER_TEST.md](PROVIDER_TEST.md) records successful v0.1.10 provider use.
The [current campaign](../evidence/comparison-campaign-v0110.json) completed all
19 read-only pairs and bucket/object: seven matching comparisons, 13 supported-
output or local-state differences, six prior-denied writes not comparable, and
four IAM skips. Each engine's one bucket/object was deleted and independently
verified absent. Both sweepers report zero leftovers.

The driver compares observed post-apply resources, reconstructs confirmed SDK
child writes from its private ledger, and selects evidence by recording time.
A missing final provider record means cleanup is unknown, never assumed zero.
Only one owned parent and one bounded inline child are allowed; untracked
force-destroy, file uploads and known foreign parents are rejected.

Public CI runs `scripts/test-compare.py` against a fake schema endpoint and mocked
provider phases, covering all 30 script compilations, ownership rejection and finally
teardown without AWS credentials, OIDC, or AWS requests. Regenerate after HCL changes
with `python3 compare/generate.py`; private logs/state must never be committed.

AWS provider 5.100.0 is an external OpenTofu plugin (MPL-2.0), not linked or bundled
into lmaws. [Official source](https://github.com/hashicorp/terraform-provider-aws/tree/v5.100.0).
