# Live procedure and measured results

[docs/USER_TEST.md](../docs/USER_TEST.md) is the canonical READY FOR USER TEST
handoff: environment, exact autoruns, the scoped federated session policy, cap
harness, profile selection and sweepers. Do not change IAM, credentials or
profiles, and never use agentcore-poc, admin or another identity. `default` is
read-only; only `AWS_PROFILE=lmaws` may mutate, in us-east-1, with `LMAWS_LIVE=1`.
The session is re-issued by `~/.aws/session-tools/scripts/aws-profile-session.py`
from `~/.aws/session-tools/tasks/iam-snapshots/local-lmaws-session.json`. Its STS
session policy is limited to 2,048 characters and permits both `lmaws_` and
`lmaws-` names for SQS, SSM, DynamoDB, SNS and Logs, plus `lmaws-` names for S3;
all resources carry the `lmaws_test` ownership tag.
Independent deletion checks use default metadata calls. IAM examples are skipped
with the configured federated profiles; do not try to repair their access here.

The native v0.1.2 baseline is [the campaign record](../evidence/live-cost-campaign-v012.json)
and [per-example comparison results](../compare/RESULTS.md):

- Nineteen read-only examples passed live and display estimated cost `$0.00`.
- `bucket_objects` passed: one bucket and tiny object, estimated `$0.00001781`,
  both deleted and independently verified absent.
- Six lifecycle examples were subsequently re-run once under the re-issued
  `lmaws` session. Measured estimates were `before_after` $0.00000400,
  `queue_pipeline` $0.00000360, `sandbox_lifecycle` $0.00000000,
  `table_items` $0.00000063, `topic_publish` $0.00000450 and `log_retention`
  $0.00000000. Cleanup proofs are recorded in the corresponding
  `evidence/live-cost-*.json` files.
- Four IAM-dependent examples (`identity`, `read_only_audit`, `roles`,
  `service_matrix`) were skipped and remain estimated only.

The v0.1.3 six-example campaign measured `$0.00001272500021` for lifecycle
operations plus `$0.00000130` for independent verification passes. All recorded
leftovers are zero. This is estimated cost from measured activity, not an AWS
invoice; do not sum older/overlapping campaign snapshots.

For future authorized runs, use `scripts/test-live-examples.py` or the canonical
autoruns with the exact profile for each category. Save sanitized
`evidence/live-cost-<example>-<run-id>.json`, preserve private ledgers, check provider
absence independently, and fold both sweepers. Authorization errors never prove
absence. Reuse completed native evidence for comparisons to avoid repeating
writes. The legacy `scripts/test-live.py` hardcodes default-profile writes and is
incompatible with the current guard; do not use it. Updating/removing it is open.

The current comparison campaign reran all 19 read-only cases and bucket/object
successfully on both engines with zero leftovers. Its seven matching/13 partial
or semantic differences, provider bounds and retries are recorded in
[06-comparisons.md](06-comparisons.md); do not combine its totals with the older
native baseline. The six lifecycle comparisons are included in the v0.1.3
campaign evidence.
