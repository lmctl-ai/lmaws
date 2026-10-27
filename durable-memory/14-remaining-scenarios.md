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

The lmweblab drivers are offline by default. Live up/test/all require the Lead's
explicit go (`LMWEBLAB_REMAINING_LIVE_GO=1`), profile lmaws, a fresh explicit hex
run id and no fake endpoint. Scenario 07 additionally needs mapping permissions:
function-only `lambda:*` in the reviewed v6 snapshot does not cover them. No policy or profile files were changed by these scenarios. The authorized 08/09/10/12 live campaign is verified in [lmweblab RESULTS](https://github.com/lmctl-ai/lmweblab/blob/main/scenarios/RESULTS.md); 07 remains offline-only until separately granted and authorized. Native packaging and any
patch release are separate from this main-source work. Concurrent main version
metadata is 0.1.19. The historical v0.1.18 release proof does not cover these
additions; use the current source build until an artifact containing them is verified.

Upload ownership accepts the exact web-stack bucket `lmaws-site-<run>` as well as legacy `lmaws-<run>-<suffix>` buckets. Either shape still requires the provider tag `lmaws_test=<run>`. Near-match web names and missing or foreign run tags are refused; SigV4 and environment setup share this check. SDK loopback regressions cover each branch.

Numeric upload limits from the SDK JSON reader are validated and emitted as canonical integer environment strings. Python `int()` cannot import values such as `10.0`; `RemainingChecks` covers actual parsed JSON, fractions and bounds. The gallery driver smoke-tests import before deploying CloudFront. Current source fixes are d7bb7bd and bdb7cfd; the version label alone does not prove those fixes are packaged.
