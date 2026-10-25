# lmaws
AWS read-only inventory and safely owned test resources for lmscript, powered by the AWS SDK for Java v2.

| Picture | Story and reproducible command | Measured local cost |
|---|---|---|
| ![Cloud inventory](docs/images/inventory.png) | Cloud inventory at a glance — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-inventory-r71d606a0xcaf04f53.json)).
| ![Network topology](docs/images/vpcs.png) | Network topology overview — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/vpcs.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-vpcs-r62eeb5c9x53334996.json)).
| ![Queue pipeline](docs/images/queue_pipeline.png) | Queue lifecycle simulation — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queue_pipeline.lms` | live cost pending — default-profile authorization blocked.
| ![Safety audit](docs/images/read_only_audit.png) | Read-only safety audit — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/read_only_audit.lms` | live cost pending — default-profile authorization blocked.
| ![Resource graph](docs/images/resource_graph.png) | Resource relationship graph — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/resource_graph.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-resource_graph-r2511a45fxb4544623.json)).

## Install

Install the single native executable from the latest GitHub release:

```text
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms
```

Every example uses `aws.example("name")`: demo data by default, and real AWS only when `LMAWS_LIVE=1` with the default profile and one region. Public CI forces `LMAWS_LIVE=0`, uses fakes only, and has no OIDC or cloud credentials. The live test ledger owns every mutation and tears it down on success or failure. S3 names use `lmaws-<run-id>-...` plus the `lmaws_test=<run-id>` tag; other resources use the `lmaws_<run-id>_` prefix.

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

v0.1.0 writes are limited to those six resource kinds. Compute, networking, IAM, ECS, Lambda, DNS and Secrets Manager are metadata-only.

## Cost per example

Every example prints a final `estimated cost: $...` line. Read-only examples use `$0.00`; write examples estimate each request and resource from a price table, exact request counts, fractional minutes alive and fractional GB-month storage. The table uses conservative us-east-1 prices as of 2026-10-25, ignores free-tier credits, and does not call Cost Explorer. Prices vary by region and change over time.

Each ledger refuses the next creation above the example cap of $0.05 or the whole-run hard ceiling of $0.25. Evidence is stored as `evidence/live-cost-<example>-<run-id>.json`; successful entries include the price table, requests, resources and leftover count. Current authorization blocks several live examples, so the project is **NOT READY FOR USER TEST** until all 30 examples have a successful default-profile live run with zero leftovers.

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

- **inventory** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-inventory-r71d606a0xcaf04f53.json)).
- **buckets** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/buckets.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-buckets-r957ab3d1xc5e247e7.json)).
- **instances** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/instances.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-instances-ra4a54d9fxb3054905.json)).
- **vpcs** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/vpcs.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-vpcs-r62eeb5c9x53334996.json)).
- **security_groups** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/security_groups.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-security_groups-r978c99a4x285a43fa.json)).
- **tables** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tables.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-tables-r0a638e82x6bb64168.json)).
- **queues** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queues.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-queues-rad2e44b3x2dcc4dd7.json)).
- **topics** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topics.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-topics-r3f3a6389xd6084890.json)).
- **functions** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/functions.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-functions-r8b53f0abx71fc40db.json)).
- **log_groups** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_groups.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-log_groups-r87934eb2x848e4203.json)).
- **alarms** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/alarms.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-alarms-r2f6f55b6x5be54f83.json)).
- **zones** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/zones.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-zones-r38602169x68ff4e86.json)).
- **secrets** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/secrets.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-secrets-r320f386bx9cea4ec7.json)).
- **parameters** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/parameters.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-parameters-r61d3586dx74ab4fa6.json)).
- **clusters** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/clusters.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-clusters-rc6e3bf8bx64b54aaf.json)).
- **roles** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/roles.lms` — live cost pending — default-profile authorization blocked.
- **identity** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/identity.lms` — live cost pending — default-profile authorization blocked.
- **resource_graph** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/resource_graph.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-resource_graph-r2511a45fxb4544623.json)).
- **tag_compliance** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tag_compliance.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-tag_compliance-r7cb07155x9d6941ad.json)).
- **queue_pipeline** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queue_pipeline.lms` — live cost pending — default-profile authorization blocked.
- **sandbox_lifecycle** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sandbox_lifecycle.lms` — live cost pending — default-profile authorization blocked.
- **before_after** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/before_after.lms` — live cost pending — default-profile authorization blocked.
- **read_only_audit** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/read_only_audit.lms` — live cost pending — default-profile authorization blocked.
- **regional_posture** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/regional_posture.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-regional_posture-r8c324e7dx1c334aa2.json)).
- **service_matrix** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/service_matrix.lms` — live cost pending — default-profile authorization blocked.

- **bucket_objects** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/bucket_objects.lms` — live cost pending — default-profile authorization blocked.
- **table_items** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/table_items.lms` — live cost pending — default-profile authorization blocked.
- **topic_publish** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topic_publish.lms` — live cost pending — default-profile authorization blocked.
- **log_retention** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_retention.lms` — live cost pending — default-profile authorization blocked.

The gallery contains 27 lmplot charts and 3 lmdraw diagrams generated from all 30 examples. `scripts/test-gallery.py` checks every URL, image and isolated demo run. Public CI forces `LMAWS_LIVE=0`, uses in-process fakes only, and never receives OIDC or cloud credentials. Live runs use the default AWS profile on this machine, with per-example ledgers, a dry-run sweeper and teardown.


- **sweeper** — `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sweeper.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-sweeper-rb06fb78dx83ba4d51.json)).
