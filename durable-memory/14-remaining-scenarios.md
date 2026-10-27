# Remaining web scenarios

Main adds queue/Lambda mapping lifecycle, DLQ redrive, conditional DynamoDB writes
and bounded S3 SigV4 PUT signing for lmweblab scenarios 07–10. Scenario 12 reuses
the nano/static weighted-DNS engine for a 0/100 → 100/0 → 0/100 manual cutover.

`ServerlessExtras` extends the durable `ServerlessRun` journal. Teardown removes
mappings before workers and queues; worker recovery uses exact names and run tags.
All Lambda logs use `lmaws_<slug>_logs_<run>`. Queue worker execution and SQS/log
bounds join the whole-run estimate. Static cache TTLs are bounded; API cache TTLs
stay zero. Main currently exposes 194 host signature lines including context.

New APIs and the exact IAM handoff are in [REMAINING_SCENARIOS](../docs/REMAINING_SCENARIOS.md).
`test.sh` runs real SDK loopback mapping/redrive/presign/conditional dispatch tests
and durable demo reopen/teardown checks. No cloud credentials are needed.

The lmweblab drivers are offline by default. Live up/test/all require the Lead's
explicit go (`LMWEBLAB_REMAINING_LIVE_GO=1`), profile lmaws, a fresh explicit hex
run id and no fake endpoint. Scenario 07 additionally needs mapping permissions:
function-only `lambda:*` in the reviewed v6 snapshot does not cover them. No policy
was applied and no live scenario was run in this work. Native packaging and any
patch release are separate from this main-source work. Concurrent main version
metadata is 0.1.19. The historical v0.1.18 release proof does not cover these
additions; use the current source build until an artifact containing them is verified.
