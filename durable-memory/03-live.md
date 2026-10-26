# Live procedure and measured results

[docs/USER_TEST.md](../docs/USER_TEST.md) is the canonical READY FOR USER TEST
handoff: environment, exact autoruns, scoped service permissions, cap harness,
profile selection and sweepers. Do not change IAM, credentials or profiles, and
never use agentcore-poc, admin or another identity. `default` is read-only;
only `AWS_PROFILE=lmaws` may mutate, in us-east-1, with `LMAWS_LIVE=1`.
Independent deletion checks use default metadata calls. IAM examples are skipped
with the configured federated profiles; do not try to repair their access here.

The native v0.1.2 baseline is [the campaign record](../evidence/live-cost-campaign-v012.json)
and [per-example comparison results](../compare/RESULTS.md):

- Nineteen read-only examples passed live and display estimated cost `$0.00`.
- `bucket_objects` passed: one bucket and tiny object, estimated `$0.00001781`,
  both deleted and independently verified absent.
- Six lifecycle examples were attempted once and denied: `before_after` and
  `queue_pipeline` (SQS CreateQueue), `sandbox_lifecycle` (SSM PutParameter),
  `table_items` (DynamoDB CreateTable), `topic_publish` (SNS CreateTopic) and
  `log_retention` (Logs CreateLogGroup). Full lifecycle costs remain estimated;
  attempted-request costs are retained.
- Four IAM-dependent examples (`identity`, `read_only_audit`, `roles`,
  `service_matrix`) were skipped and remain estimated only.

Native baseline price-table estimate: `$0.00004640`, including independent verification
passes. All recorded leftovers are zero. This is estimated cost from measured
activity, not an AWS invoice; do not sum older/overlapping campaign snapshots.

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
native baseline. The six denied write cases remain unmeasured for full lifecycles.
