# Purpose, architecture and API

lmaws is the MIT Java 21 AWS scripting host, separate from the older TypeScript
lmawscli wrapper. `sdk.lock` pins lmcode-java v0.1.1 by commit/archive hash;
`deps.lock` pins AWS SDK for Java v2 2.57.3 and every runtime JAR hash. SDK sources
are fetched under ignored `third_party/`. `CloudHost` registers the typed API;
`Main` derives the host-only `schema/lmaws.dsl.json` from its signatures. The
compiler resolves implicit standard declarations; schema parity is tested.

The `aws: Cloud` context exposes `demo()`, `region(string)` and `example(name)`.
Sixteen metadata inventories cover identity, buckets, instances, VPCs, security
groups, tables, queues, topics, functions, log groups, alarms, zones, secrets,
parameters, clusters and roles. `Rows` supports length, indexing, equality
count/filter, CSV and JSON; `Row` exposes string/integer fields.

`Run` creates only buckets, queues, topics, Standard String parameters,
on-demand pk/value tables and log groups. `put` handles their bounded payload or
retention updates; cleanup, remaining count and estimated cost are exposed.
There is no general AWS dispatcher, secret-value API or IAM user/key mutation.
Guarded Spot/Web APIs support owned nano and web-stack deployments; typed
Lambda/EventBridge and durable Serverless APIs are implemented and tested with
fake transports pending the explicit live rollout. Account IDs are masked in public
outputs; raw ownership identifiers stay in private recovery ledgers.

Masking (`Jsons.mask`, used by `Rows.json/csv`, spend exports and error messages) replaces the
account field of ARNs, values labelled account/owner (`account 123...`, `"OwnerId": "123..."`),
map/CSV fields named account/account_id/owner/owner_id, and the caller's own account id once
`identity()` has seen it; access-key ids are redacted. Plain numbers are never masked: before
v0.1.8 any standalone 12-digit run was replaced, which corrupted balances such as
`1233.123456789012` and 12-digit byte counts. Self-tests cover both directions.

`AwsBackend` uses the synchronous URLConnection transport. Real clients use
`ProfileCredentialsProvider` with the selected profile, not the unrestricted
default credential chain. Demo mode resolves no credentials; loopback HTTP fake
endpoints use dummy credentials. Region/mode and the cost ledger are shared
across a program's clients. See [safety/cost](07-example-costs.md).

`LMAWS_MAX_MEMORY_MB` is positive whole MiB, default 4096. VM allocations and
retained rows are charged, bytecode/inventories are bounded, and `RuntimeBudget`
restarts with a heap cap of approximately 75% when needed. Budgets below 16 MiB
fail execution. This bounds VM/Java heap allocation, not process RSS or OS memory;
the host does not set rlimits. Native and JVM error paths are tested.

The read-only Spend API adds nine own signatures:
CE costs/resources, SP/RI commitments, regional inventories, Pricing and batched
CloudWatch metrics. See [spend reports](09-spend-reports.md). From v0.1.5, EC2
compute inventory/spot sandbox methods (`Ec2Compute`) add 18 own signatures; from
v0.1.6, customer-managed `lmaws_` IAM policy management (`IamPolicies`) adds five
own signatures (`iam_policy_lint`, `iam_policy_get`, `iam_policy_versions`,
`iam_policy_put`, `iam_policy_delete`); `CredentialProcess` adds
`lmaws --credential-process <mode>` on the CLI and `session_doctor` on `Cloud`.
From v0.1.12, the fluent IAM Permission Builder (`PolicyBuilder`, `PolicyCatalog`,
`PolicyAnalyzer`, `PolicySimulator`) adds the `Policy` type (46 methods) and 12
policy analysis/simulation methods on `Cloud` (58 new own signatures).
Current main has 175 host signature lines including the implicit context,
and 247 lines including the 72 standard signatures. The new serverless API is
source-only until released; use `--dsl-signatures` to check the actual binary.
