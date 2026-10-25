# v0.1.1 release and user test handoff

Released https://github.com/lmctl-ai/lmaws/releases/tag/v0.1.1 from 507c545.
Main CI 40197519194 and tag CI 40197523188 both passed all five platforms,
including JVM/native fake endpoints, cost checks, schema/signatures, memory limits
and all 30 examples. Compiler 0.2.420 and main's implicit-std schema are validated.
The tag publication job passed. All five downloaded binaries match SHA256SUMS;
both Linux assets pass the dynamic glibc 2.35 policy (no other dynamic libraries).

All 30 main raw URLs ran from independent empty working directories with no lmaws
on PATH and an initially empty shared tool cache. Each installed the published
v0.1.1 host, matched its release SHA-256, printed estimated cost and generated its
PNG. See autorun-v011.json and release-v011.json.

READY FOR USER TEST. The user explicitly removed live completion as a publication
gate. Preserve the 19 measured read-only $0.00 ledgers. Eleven other examples are
labelled estimated from price table, not yet measured live. Tiny S3/DynamoDB/SQS/SNS
planning allowance is $0.0001 per example; SSM, empty logs and read-only flows use
$0.00 table pricing. Actual attempts/storage/lifetimes are charged in each ledger.

Prior session awsspot-local-default rejected SQS CreateQueue and ssm:PutParameter;
IAM ListRoles returned InvalidClientTokenId. No further live calls, IAM changes,
credential/profile edits or alternate identity were used during this resume.
The cost-patch campaign created zero resources and recorded zero leftovers.
The older evidence/validation-status-v011.json is a prepublication live snapshot;
this release record supersedes its publication-in-progress field.

README and docs/USER_TEST.md contain the default profile/us-east-1 environment,
all 30 exact autorun commands, expected estimates, aggregate-cap harness and dry-run
sweeper, plus action lists scoped to lmaws_ / lmaws- names and supported tag keys.
Global inventory calls require Resource:*; IAM needs only ListRoles plus repair of
the existing invalid federated session outside this host. No IAM writes or keys.
Public CI remains fake-only without cloud credentials or GitHub OIDC.
