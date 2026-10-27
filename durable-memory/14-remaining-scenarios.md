# Remaining web scenarios

Main adds queue/Lambda mapping lifecycle, DLQ redrive, conditional DynamoDB writes
and bounded S3 SigV4 PUT signing for lmweblab scenarios 07–10. Scenario 12 reuses
the nano/static weighted-DNS engine for a 0/100 → 100/0 → 0/100 manual cutover.

`ServerlessExtras` extends the durable `ServerlessRun` journal. Teardown removes
mappings before workers and queues; worker recovery uses exact names and run tags.
Worker logs reuse the receipt-proven final-delivery reconciliation after both
functions and the mapping are removed. All Lambda logs use `lmaws_<slug>_logs_<run>`. Queue worker execution and SQS/log
bounds join the whole-run estimate. Static cache TTLs are bounded; API cache TTLs
stay zero. The generated schema and signatures are the API count authority.

New APIs and the exact IAM handoff are in [REMAINING_SCENARIOS](../docs/REMAINING_SCENARIOS.md).
`test.sh` runs real SDK loopback mapping/redrive/presign/conditional dispatch tests
and durable demo reopen/teardown checks. No cloud credentials are needed.

The lmweblab drivers are offline by default. Live work requires profile lmaws, fresh hexadecimal IDs, the general go flag and a current source build. Scenario 07 additionally requires LMWEBLAB_WORKER_LIVE_GO=1. The Lead authorized it under v7b: functional tests passed, initial cleanup hit a post-delete Get denial, and recovery plus independent inventory left both attempts empty. No functional rerun followed the denial. See [current results](https://github.com/lmctl-ai/lmweblab/blob/main/scenarios/RESULTS.md). No role, IAM or profile files were changed by this campaign. Main version 0.1.19 does not imply these changes are packaged; use current source until a containing artifact is verified.

Upload ownership accepts the exact web-stack bucket `lmaws-site-<run>` as well as legacy `lmaws-<run>-<suffix>` buckets. Either shape still requires the provider tag `lmaws_test=<run>`. Near-match web names and missing or foreign run tags are refused; SigV4 and environment setup share this check. SDK loopback regressions cover each branch.

Numeric upload limits from the SDK JSON reader are validated and emitted as canonical integer environment strings. Python `int()` cannot import values such as `10.0`; `RemainingChecks` covers actual parsed JSON, fractions and bounds. The gallery driver smoke-tests import before deploying CloudFront. Current source fixes are d7bb7bd and bdb7cfd; the version label alone does not prove those fixes are packaged.

Worker readiness persists the mapping ARN before a bounded Enabled wait. Creation sends only lmaws_test; no standalone mapping tagging/adoption is allowed. Run inventory includes foreign/untagged mappings rather than falsely returning zero. Redrive policy uses raw wire JSON so ARN accounts stay intact; clearing sends an empty attribute value.

Delete validates account/region, proves exact-ARN presence/absence through a bounded account-wide list, and checks tags/source/function before mutating a present mapping. Polling Get after deletion can return AccessDenied on resource * under tag-scoped EsmOwn; the client uses permitted list-based absence instead of expanding IAM or treating arbitrary denials as absence. SDK loopback tests reproduce this. Final log settlement uses max(API deletion, worker deletion), ignores rewritten finished_at, and skips a run without function deletion. Source fixes: 3ce8fb5, 5bb969b, 3b14634.
