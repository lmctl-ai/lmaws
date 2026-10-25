# lmaws
AWS read-only inventory and safely owned test resources for lmscript, powered by the AWS SDK for Java v2.

| Picture | Story and reproducible command | Measured local cost |
|---|---|---|
| ![Cloud inventory](docs/images/inventory.png) | Cloud inventory at a glance — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-inventory-r71d606a0xcaf04f53.json)).
| ![Network topology](docs/images/vpcs.png) | Network topology overview — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/vpcs.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-vpcs-r62eeb5c9x53334996.json)).
| ![Queue pipeline](docs/images/queue_pipeline.png) | Queue lifecycle simulation — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queue_pipeline.lms` | running this example costs about $0.0001 (estimated from price table, not yet measured live).
| ![Safety audit](docs/images/read_only_audit.png) | Read-only safety audit — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/read_only_audit.lms` | running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles).
| ![Resource graph](docs/images/resource_graph.png) | Resource relationship graph — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/resource_graph.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-resource_graph-r2511a45fxb4544623.json)).

## Install

Install the single native executable from the latest GitHub release:

```text
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms
```

Every example uses `aws.example("name")`: demo data by default, and real AWS only when `LMAWS_LIVE=1` with `default` for read-only calls or `lmaws` for writes, in us-east-1. Public CI forces `LMAWS_LIVE=0`, uses fakes only, and has no OIDC or cloud credentials. The live test ledger owns every mutation and tears it down on success or failure. S3 names use `lmaws-<run-id>-...` plus the `lmaws_test=<run-id>` tag; other resources use the `lmaws_<run-id>_` prefix.

The typed API covers inventory and owned test flows for buckets, EC2 instances, VPCs, security groups, DynamoDB tables, SQS queues, SNS topics, Lambda metadata, CloudWatch log groups and alarms, Route 53 zones, Secrets Manager metadata, SSM parameters, ECS clusters and IAM role metadata. Secret-value APIs, access-key APIs, and session-token APIs are not exposed. Lambda examples describe metadata and do not deploy functions.

The native release targets five platforms and uses a 4096 MB memory budget. Linux binaries require glibc 2.35 or newer; Windows requires the standard Microsoft Visual C++ runtime. The host and examples are MIT licensed; the AWS SDK for Java v2 is Apache-2.0.

## API

| Expression | Result |
|---|---|
| `aws.example("name")` | Demo deterministic Cloud; live AWS only with `LMAWS_LIVE=1` |
| `cloud.is_demo()`, `cloud.example_run()`, `run.estimated_cost()` | Select fixture assertions, create a capped ledger-owned run, inspect its estimate |
| `aws.region("us-east-1")`, `aws.region("")` | Live Cloud with an explicit region, or the default region chain |
| `cloud.buckets()`, `instances()`, `vpcs()`, `security_groups()` | Resource Rows |
| `cloud.tables()`, `queues()`, `topics()`, `functions()` | Data, messaging and function metadata Rows |
| `cloud.log_groups()`, `alarms()`, `zones()`, `secrets()`, `parameters()` | Operations and metadata Rows |
| `rows.len()`, `rows.at(i)`, `rows.count(key,value)`, `rows.filter(key,value)` | Inspect and aggregate Rows |
| `rows.csv(path)`, `rows.json()` | Masked tabular or JSON output |
| `cloud.run(runId, existingLedgerDir)` (legacy explicit form) | Owned writes with an automatically named ledger, tags and cleanup |
| `run.bucket(name)`, `queue(name)`, `topic(name)` | Create owned storage/messaging resources |
| `run.parameter(name,value)`, `table(name)`, `log_group(name)` | Create owned standard parameters, on-demand tables and log groups |
| `run.put(resource,key,value)`, `cleanup()`, `remaining()` | Update owned resources, tear down, inspect outstanding resources |

```lmscript
mkdir("data");
aws = _dsl_ cli="lmaws" install="github:lmctl-ai/lmaws@latest";
let cloud = aws.example("inventory");
let rows = cloud.instances();
check(rows.len() == 3);
rows.csv("data/instances.csv");
end _dsl_
savedsl(aws, "inventory.dslb");
r = system ${dsl_cli(aws)} --dsl "inventory.dslb";
assert(r.code == 0);
```

`--dry-run` uses demo data and makes no AWS requests, while still writing local reports and ledgers. `lmaws --sweep LEDGER_DIR --older-than-hours 24` is always a dry-run: it lists stale `lmaws-*.jsonl` ledger candidates and never deletes account resources. Create the ledger directory before opening a run; explicit ledger filenames should also use that prefix and extension. Errors use exit 2 for configuration and 3 for runtime failures.

For `run.put`, `key` is the S3 object key or DynamoDB `pk`; queue/topic/parameter writes use `value` as the message or parameter value, and log groups accept `key="retention_days"`.

v0.1.2 writes are limited to those six resource kinds. Compute, networking, IAM, ECS, Lambda, DNS and Secrets Manager are metadata-only.

## Cost per example

Every example prints a final `estimated cost: $...` line. Read-only examples use `$0.00`; write examples estimate each request and resource from a price table, exact request counts, fractional minutes alive and fractional GB-month storage. The table uses conservative us-east-1 prices as of 2026-10-25, ignores free-tier credits, and does not call Cost Explorer. Prices vary by region and change over time.

Each ledger refuses the next creation above the example cap of $0.05 or the whole-run hard ceiling of $0.25. Evidence is stored as `evidence/live-cost-<example>-<run-id>.json`; successful entries include the price table, requests, resources and leftover count. Nineteen read-only examples retain measured $0.00 evidence. In the v0.1.2 campaign, all seven write/lifecycle examples were attempted once using `AWS_PROFILE=lmaws`: S3 bucket/object passed at a measured estimated $0.00001781; SQS (two examples), SSM, DynamoDB, SNS and Logs creation were denied. Every attempted name was independently verified absent with the read-only `default` profile. Those six complete lifecycle costs remain price-table estimates, not successful live measurements. The four IAM-dependent examples are intentionally skipped and labelled **estimated, not measured live**.

Profiles: `default` is READ-ONLY; **only `AWS_PROFILE=lmaws` may mutate**, in `us-east-1`. The host rejects real create/update/delete calls under any other active profile. No OIDC, IAM edits, credential/profile edits or alternate identity are used. Denied requests can still have a request-price estimate; their evidence retains the actual failure and unrounded estimate.

The current campaign estimated total, including both independent deletion-check passes, is **$0.00004640**, with one S3 bucket and its tiny object created and deleted and **zero leftovers**. This is price-table accounting from observed native SDK requests and lifetimes, not an AWS invoice measurement. See [live campaign evidence](evidence/live-cost-campaign-v012.json).

All 30 examples also have [lmcloud/OpenTofu comparisons](compare/RESULTS.md), with small AWS-provider `.tf` files and autorunnable `.lms` scripts. All 26 non-IAM comparisons attempted provider initialization with published lmcloud v0.1.9; every attempt was blocked by its AWS-provider resolution failure, so no OpenTofu apply ran and no OpenTofu AWS resources were created. The [finding and reproduction](compare/PROVIDER_TEST.md) check `tofu.init`'s boolean and `tofu.last_error`, rather than treating process exit zero as success. The four IAM comparisons are skipped. Unsupported declarative inventory/message operations are explicit differences in the manifest, not substitute data.

The unmeasured write estimates are planning allowances: $0.0001 for tiny DynamoDB, SQS and SNS flows; Standard SSM and empty log-group/retention flows use $0.00 table pricing. Per-run ledgers include preflight/tag/verification requests, retries and storage. Prices vary by region and time. [Local test steps and permissions](docs/USER_TEST.md).

## Resource limits and build

`LMAWS_MAX_MEMORY_MB` accepts a positive whole number, defaults to 4096 MiB, and bounds both heap and VM inputs. Budgets below 16 MiB end with a runtime error. The minimum supported runtime is Java 21 for JVM development; releases are GraalVM native executables. Build and validate locally with:

```sh
bash scripts/sync-deps.sh
mvn -q verify
./test.sh
bash scripts/build-native.sh
LMAWS_NATIVE=1 ./test.sh
```

The native build uses the GraalVM distribution selected by `JAVA_HOME`; release CI builds Linux, macOS and Windows binaries. Windows users need the Microsoft Visual C++ runtime. macOS Intel uses GraalVM CE 25.0.1, the final upstream build for that architecture; other release builds use CE 25.0.2.

## Examples

Each example writes its image to `images/<name>.png` in the current directory and includes an assertion. Copy any command into an empty directory:

- **inventory** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-inventory-r71d606a0xcaf04f53.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/inventory/inventory.lms`
- **buckets** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/buckets.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-buckets-r957ab3d1xc5e247e7.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/buckets/buckets.lms`
- **instances** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/instances.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-instances-ra4a54d9fxb3054905.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/instances/instances.lms`
- **vpcs** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/vpcs.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-vpcs-r62eeb5c9x53334996.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/vpcs/vpcs.lms`
- **security_groups** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/security_groups.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-security_groups-r978c99a4x285a43fa.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/security_groups/security_groups.lms`
- **tables** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tables.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-tables-r0a638e82x6bb64168.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/tables/tables.lms`
- **queues** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queues.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-queues-rad2e44b3x2dcc4dd7.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/queues/queues.lms`
- **topics** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topics.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-topics-r3f3a6389xd6084890.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/topics/topics.lms`
- **functions** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/functions.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-functions-r8b53f0abx71fc40db.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/functions/functions.lms`
- **log_groups** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_groups.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-log_groups-r87934eb2x848e4203.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/log_groups/log_groups.lms`
- **alarms** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/alarms.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-alarms-r2f6f55b6x5be54f83.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/alarms/alarms.lms`
- **zones** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/zones.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-zones-r38602169x68ff4e86.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/zones/zones.lms`
- **secrets** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/secrets.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-secrets-r320f386bx9cea4ec7.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/secrets/secrets.lms`
- **parameters** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/parameters.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-parameters-r61d3586dx74ab4fa6.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/parameters/parameters.lms`
- **clusters** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/clusters.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-clusters-rc6e3bf8bx64b54aaf.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/clusters/clusters.lms`
- **roles** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/roles.lms` — running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/roles/roles.lms`
- **identity** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/identity.lms` — running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/identity/identity.lms`
- **resource_graph** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/resource_graph.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-resource_graph-r2511a45fxb4544623.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/resource_graph/resource_graph.lms`
- **tag_compliance** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tag_compliance.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-tag_compliance-r7cb07155x9d6941ad.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/tag_compliance/tag_compliance.lms`
- **queue_pipeline** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queue_pipeline.lms` — running this example costs about $0.0001 (estimated from price table, not yet measured live; lmaws profile SQS CreateQueue denied). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/queue_pipeline/queue_pipeline.lms`
- **sandbox_lifecycle** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sandbox_lifecycle.lms` — running this example costs about $0.000000 (estimated from price table, not yet measured live; lmaws profile ssm:PutParameter denied). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/sandbox_lifecycle/sandbox_lifecycle.lms`
- **before_after** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/before_after.lms` — running this example costs about $0.0001 (estimated from price table, not yet measured live; lmaws profile SQS CreateQueue denied). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/before_after/before_after.lms`
- **read_only_audit** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/read_only_audit.lms` — running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/read_only_audit/read_only_audit.lms`
- **regional_posture** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/regional_posture.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-regional_posture-r8c324e7dx1c334aa2.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/regional_posture/regional_posture.lms`
- **service_matrix** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/service_matrix.lms` — running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/service_matrix/service_matrix.lms`

- **bucket_objects** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/bucket_objects.lms` — running this example costs about $0.00001781 ([measured live estimate](evidence/live-cost-bucket_objects-raaa7c272xd3864f73.json); lmaws profile, independently verified deletion). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/bucket_objects/bucket_objects.lms`
- **table_items** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/table_items.lms` — running this example costs about $0.0001 (estimated from price table, not yet measured live; lmaws profile dynamodb:CreateTable denied). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/table_items/table_items.lms`
- **topic_publish** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topic_publish.lms` — running this example costs about $0.0001 (estimated from price table, not yet measured live; lmaws profile sns:CreateTopic denied). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/topic_publish/topic_publish.lms`
- **log_retention** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_retention.lms` — running this example costs about $0.000000 (estimated from price table, not yet measured live; lmaws profile logs:CreateLogGroup denied). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/log_retention/log_retention.lms`

The gallery contains 27 lmplot charts and 3 lmdraw diagrams generated from all 30 examples. `scripts/test-gallery.py` checks every URL, image and isolated demo run. Public CI forces `LMAWS_LIVE=0`, uses in-process fakes only, and never receives OIDC or cloud credentials. Live runs use the default AWS profile on this machine, with per-example ledgers, a dry-run sweeper and teardown.


- **sweeper** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sweeper.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-sweeper-rb06fb78dx83ba4d51.json)). · lmcloud: `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/sweeper/sweeper.lms`

Compiler minimum: lmscript 0.2.420. Host schema bytes omit built-in std; `--dsl-signatures` includes it and `--without-std` selects host declarations.
