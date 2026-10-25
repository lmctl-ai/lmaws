# Native AWS SDK versus lmcloud/OpenTofu

Every one of the 30 native examples has `compare/<name>/main.tf` and an
`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/<name>/<name>.lms`
equivalent. Generated scripts embed the HCL and directly call `tofu.init`,
`validate`, `plan`, `apply`, `show_state`, and `destroy` in separately checked phases.
Python 3, curl and AWS CLI support the local safety ledger and independent checks.
No lmcloud checkout is needed or modified.

```sh
LMAWS_LIVE=1 AWS_PROFILE=default AWS_REGION=us-east-1 timeout 900 compare/run.sh inventory
LMAWS_LIVE=1 AWS_PROFILE=lmaws AWS_REGION=us-east-1 timeout 900 compare/run.sh bucket_objects \
  --native-evidence evidence/live-cost-bucket_objects-<run-id>.json
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
500-request maximum-price allowance of $0.0025 per write, including tiny storage.
This is not observed traffic or an invoice measurement. Actual provider initialization
currently fails before apply, so provider creations and estimated charge are zero.

[RESULTS.md](RESULTS.md) has one row per example: status, cost, parent resource
names/types/tags, outputs, wall time, cleanup and differences. Unique run IDs are
normalized for comparisons. The SDK ledger tracks the owning bucket/table while
OpenTofu additionally represents its object/item; these are explicit differences.
Unsupported provider list APIs and imperative message operations are documented in
[manifest.json](manifest.json), not silently replaced by unrelated data.

[PROVIDER_TEST.md](PROVIDER_TEST.md) records the lmcloud 0.1.9 provider resolution
finding. Its init returns false for the pinned AWS provider; process exit zero alone
is not success. No lmcloud source was changed. Four IAM examples remain estimated
only; the other 26 attempted comparisons retain the real initialization failure.

Public CI runs `scripts/test-compare.py` against a fake schema endpoint and mocked
provider phases, covering all 30 script compilations, ownership rejection and finally
teardown without AWS credentials, OIDC, or AWS requests. Regenerate after HCL changes
with `python3 compare/generate.py`; private logs/state must never be committed.

AWS provider 5.100.0 is an external OpenTofu plugin (MPL-2.0), not linked or bundled
into lmaws. [Official source](https://github.com/hashicorp/terraform-provider-aws/tree/v5.100.0).
