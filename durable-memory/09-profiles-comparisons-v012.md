# v0.1.2 profile and OpenTofu comparison work

User rule: default is read-only; only lmaws may mutate (us-east-1). No OIDC,
no other identity, no IAM/credential/profile changes. Four IAM examples are skipped.
AwsBackend activeProfile resolves AWS_PROFILE, AWS_DEFAULT_PROFILE, then default;
real create/put/delete require exact lmaws before SDK calls. Fake loopback/demo remain
credential-free. The CLI guard is tested independently of CI's real-backend guard.

All seven native writes were attempted ONCE with profile lmaws on the new native
candidate. S3 bucket/object passed, estimated $0.00001781, independently deleted.
Before/after and queue pipeline: sqs:CreateQueue denied. SSM: PutParameter denied.
DynamoDB: CreateTable denied. SNS: CreateTopic denied. Logs: CreateLogGroup denied.
All attempts have evidence/live-cost-* JSON and independent default-profile absence
checks; all zero leftovers. No IAM example was run. Nineteen read-only native
examples were also rerun for comparison and passed; original measured evidence kept.
Current campaign estimate $0.00004640 includes SDK requests/storage and both
independent verification passes. One bucket/tiny object created, both deleted.

Every example has compare/<name>/main.tf and a generated remote autorun .lms with
explicit tofu.* init/validate/plan/apply/inspect/destroy bytecode phases. Python runtime
retains a private own ledger/state, checks returned booleans/last_error, validates
fresh prefixed/tagged plan names and child ownership, reserves cost before creation,
always destroys after apply even on failure, then independently verifies absence.
The OpenTofu ledger uses an explicit conservative 500-request allowance, not observed
SDK counts. Drivers can reuse native evidence so writes are not run twice. Public
CI compiles all 30 scripts with a fake schema emitter and mocks failure teardown.

Published lmcloud 0.1.9 cannot resolve official AWS provider 5.100.0: init false,
'no available releases match'. All 26 non-IAM comparisons attempted init and stopped
before plan/apply; zero provider resources/cost. See compare/PROVIDER_TEST.md and
RESULTS.md. Four IAM comparisons skipped. No lmcloud repository changes were made.
Provider-source audit records unsupported list/message APIs as differences rather
than unrelated fallback data. Both local dry-run sweepers report zero leftovers.

A denied creation originally printed readonly-style $0.00 despite retaining charged
request estimates. The release corrects displayCost for rejected_creations with a
focused exact-unit regression check; this formatting change makes no AWS calls and
none of the seven native live creation cases was repeated. Cost files retain their
original emitted display text and exact unrounded request estimates.

Source was pushed early as d5c14c5; test isolation fix 294bb8d passed all five CI jobs
40198710670. Final comparison/cost formatting changes require final CI and release.
