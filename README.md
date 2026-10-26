# lmaws
AWS read-only inventory and safely owned test resources for lmscript, powered by the AWS SDK for Java v2.

| Picture | Story and reproducible command | Measured local cost |
|---|---|---|
| ![Cloud inventory](docs/images/inventory.png) | Cloud inventory at a glance — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-inventory-r71d606a0xcaf04f53.json)).
| ![Network topology](docs/images/vpcs.png) | Network topology overview — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/vpcs.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-vpcs-r62eeb5c9x53334996.json)).
| ![Queue pipeline](docs/images/queue_pipeline.png) | Queue lifecycle simulation — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queue_pipeline.lms` | running this example costs about $0.00000360 (measured live; independently verified deletion).
| ![Safety audit](docs/images/read_only_audit.png) | Read-only safety audit — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/read_only_audit.lms` | running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles).
| ![Resource graph](docs/images/resource_graph.png) | Resource relationship graph — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/resource_graph.lms` | running this example costs about $0.00 ([live evidence](evidence/live-cost-resource_graph-r2511a45fxb4544623.json)).

## Install

Install the single native executable from the latest GitHub release:

```text
lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms
```

The original inventory and lifecycle examples use `aws.example("name")`: demo data by default, and real AWS only when `LMAWS_LIVE=1` with `default` for read-only calls or `lmaws` for writes, in us-east-1. The reusable recipe examples always force synthetic mode. Public CI forces `LMAWS_LIVE=0`, uses fakes only, and has no OIDC or cloud credentials. The live test ledger owns every mutation and tears it down on success or failure. S3 names use `lmaws-<run-id>-...` plus the `lmaws_test=<run-id>` tag; other resources use the `lmaws_<run-id>_` prefix. The federated `lmaws` session is re-issued by the existing local session tooling; its scoped policy permits both patterns (S3 uses the hyphen because bucket names cannot contain underscores).

The typed API covers inventory and owned test flows for buckets, EC2 instances, VPCs, security groups, DynamoDB tables, SQS queues, SNS topics, Lambda metadata, CloudWatch log groups and alarms, Route 53 zones, Secrets Manager metadata, SSM parameters, ECS clusters and IAM role metadata. Secret-value APIs, access-key APIs, and session-token APIs are not exposed. Lambda examples describe metadata and do not deploy functions.

The native release targets five platforms and uses a 4096 MB memory budget. Linux binaries require glibc 2.35 or newer; Windows requires the standard Microsoft Visual C++ runtime. The host and examples are MIT licensed; the AWS SDK for Java v2 is Apache-2.0.

## Recipes

<!-- RECIPES:START -->

![Review account spend detail and optimization signals](docs/images/recipe_spend_detail.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_spend_detail.lms`

![Find lmaws_ and lmaws- names across supported account inventories](docs/images/recipe_prefix_search.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_prefix_search.lms`

![Create and tear down one owned queue with its run ledger](docs/images/recipe_sandbox_queue.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_queue.lms`

Reusable LMScript recipes for audits, inventory, spend review and safely owned sandboxes.
The access column describes AWS permissions; local reports are written only when a recipe is called.
Each generated entry is self-contained and runnable directly. Import the paired library from its raw URL when composing recipes; entry scripts perform the execution step.
Use `lmaws`, never the `aws` CLI. Read-only recipes use `default`; writes require
`AWS_PROFILE=lmaws`, the ownership prefix/tag, a ledger and teardown.

All executable recipes default to synthetic fixtures. Use `--preview` for a no-call plan,
or the runner's `lmctl script --dry-run recipes/<name>.lms`. Live inventory needs `--live`;
live sandboxes also require `--apply --profile lmaws`. Prefix discovery and the sweeper
never authorize deletion of existing resources. The current sweeper is read-only.

Arguments override defaults. `AWS_PROFILE` / `AWS_REGION` and `LMAWS_RECIPE_PERIOD`,
`LMAWS_RECIPE_TOP`, `LMAWS_RECIPE_PREFIX` supply environment defaults. Period is used
by spend recipes; prefix filters inventory when explicitly supplied. All examples force
synthetic mode and their committed pictures contain no real account data.

Inventory/sandbox caps default to $0.05. Spend reports default to the explicit $0.25
spend cap; `--cap` or `LMAWS_MAX_COST_USD` overrides it. A script reserves each live
recipe's full cap against a shared $0.25 ceiling before dispatch. Compose recipes
sequentially and choose smaller individual caps for a multi-report live run.
Synthetic spend estimates model billable requests but make no AWS calls and spend no
real money. Read `metadata.status` in reports: missing, partial or budget-exhausted
data must not be read as an observed zero. Live spend costs have not been measured
as part of this recipe presentation work.

Price references: [Cost Explorer](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/)
and [CloudWatch GetMetricData](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/metrics-classic-getdata.html).

Import-only composition example (functions do not execute on import):

```javascript
import "https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms";
let report=recipe_inventory({task:"queues",top:5,output:"data/my-queues",live:false});
println("matched rows:",len(report.rows));
```


### Identity and access posture

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`inventory_identity.lms`](recipes/inventory_identity.lms) | Inspect bounded identity metadata (synthetic only; federated IAM cases skipped live) | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_identity [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_roles.lms`](recipes/inventory_roles.lms) | Inspect bounded roles metadata (synthetic only; federated IAM cases skipped live) | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_roles [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_security_groups.lms`](recipes/inventory_security_groups.lms) | Inspect bounded security groups metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_security_groups [--live] | $0.00 synthetic; live capped request estimate in ledger |

### Inventory

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`inventory.lms`](recipes/inventory.lms) | Review all supported inventories; IAM entries are skipped live | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory [--live] | $0.00 synthetic; live request cap $0.05 |
| [`inventory_alarms.lms`](recipes/inventory_alarms.lms) | Inspect bounded alarms metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_alarms [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_buckets.lms`](recipes/inventory_buckets.lms) | Inspect bounded buckets metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_buckets [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_clusters.lms`](recipes/inventory_clusters.lms) | Inspect bounded clusters metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_clusters [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_functions.lms`](recipes/inventory_functions.lms) | Inspect bounded functions metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_functions [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_instances.lms`](recipes/inventory_instances.lms) | Inspect bounded instances metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_instances [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_log_groups.lms`](recipes/inventory_log_groups.lms) | Inspect bounded log groups metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_log_groups [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_parameters.lms`](recipes/inventory_parameters.lms) | Inspect bounded parameters metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_parameters [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_queues.lms`](recipes/inventory_queues.lms) | Inspect bounded queues metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_queues [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_secrets.lms`](recipes/inventory_secrets.lms) | Inspect bounded secrets metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_secrets [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_tables.lms`](recipes/inventory_tables.lms) | Inspect bounded tables metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_tables [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_topics.lms`](recipes/inventory_topics.lms) | Inspect bounded topics metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_topics [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_vpcs.lms`](recipes/inventory_vpcs.lms) | Inspect bounded vpcs metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_vpcs [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_zones.lms`](recipes/inventory_zones.lms) | Inspect bounded zones metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_zones [--live] | $0.00 synthetic; live capped request estimate in ledger |

### Cost and spend

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`bandwidth.lms`](recipes/bandwidth.lms) | Break down billed transfer categories and network counters | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`dynamodb_spend.lms`](recipes/dynamodb_spend.lms) | Review DynamoDB usage and spend signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`ebs_audit.lms`](recipes/ebs_audit.lms) | Review EBS attachments and snapshot retention signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`ec2_spend.lms`](recipes/ec2_spend.lms) | Break down EC2 compute spend and current resource signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`eip_audit.lms`](recipes/eip_audit.lms) | Review idle public IPv4 allocations and estimated run-rate | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`lambda_spend.lms`](recipes/lambda_spend.lms) | Review Lambda usage and spend signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`savings_plans.lms`](recipes/savings_plans.lms) | Review Savings Plans and Reserved Instance utilization and coverage | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`spend_detail.lms`](recipes/spend_detail.lms) | Review account spend detail and optimization signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |

### Idle and waste detection

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`idle_instances.lms`](recipes/idle_instances.lms) | Flag stopped-instance state for further review; never delete | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/idle_instances [--live] | $0.00 synthetic; live request cap $0.05 |

### Tag and naming compliance

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`naming_compliance.lms`](recipes/naming_compliance.lms) | Check case-sensitive lmaws_ and lmaws- naming among prefix candidates | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/naming_compliance [--live] | $0.00 synthetic; live request cap $0.05 |
| [`tag_compliance.lms`](recipes/tag_compliance.lms) | Report missing and unknown tag presence without assuming compliance | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/tag_compliance [--live] | $0.00 synthetic; live request cap $0.05 |

### Leftover search and cleanup by prefix

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`leftover_report.lms`](recipes/leftover_report.lms) | Inspect aged active/pending records in the local run ledgers | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/leftover_report [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 0 | $0.00 synthetic; live request cap $0.05 |
| [`prefix_search.lms`](recipes/prefix_search.lms) | Find lmaws_ and lmaws- names across supported account inventories | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/prefix_search [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 0 | $0.00 synthetic; live request cap $0.05 |
| [`sweeper.lms`](recipes/sweeper.lms) | Dry-run leftover review; discovery never authorizes deletion | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/sweeper [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 0 | $0.00 synthetic; live request cap $0.05 |

### Safe lifecycle sandboxes

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`lifecycle.lms`](recipes/lifecycle.lms) | Select a disposable queue/topic/table/bucket/parameter/log-group lifecycle | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/lifecycle [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_bucket.lms`](recipes/sandbox_bucket.lms) | Create and tear down one owned bucket with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_bucket [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_log_group.lms`](recipes/sandbox_log_group.lms) | Create and tear down one owned log group with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_log_group [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_parameter.lms`](recipes/sandbox_parameter.lms) | Create and tear down one owned parameter with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_parameter [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_queue.lms`](recipes/sandbox_queue.lms) | Create and tear down one owned queue with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_queue [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_table.lms`](recipes/sandbox_table.lms) | Create and tear down one owned table with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_table [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_topic.lms`](recipes/sandbox_topic.lms) | Create and tear down one owned topic with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_topic [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |

### Picture-first examples

Each recipe points at an offline synthetic example so its output can be previewed safely.

#### inventory_identity

![Inspect bounded identity metadata (synthetic only; federated IAM cases skipped live)](docs/images/recipe_inventory_identity.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_identity.lms`

Example: [`examples/recipe_inventory_identity.lms`](examples/recipe_inventory_identity.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_roles

![Inspect bounded roles metadata (synthetic only; federated IAM cases skipped live)](docs/images/recipe_inventory_roles.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_roles.lms`

Example: [`examples/recipe_inventory_roles.lms`](examples/recipe_inventory_roles.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_security_groups

![Inspect bounded security groups metadata](docs/images/recipe_inventory_security_groups.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_security_groups.lms`

Example: [`examples/recipe_inventory_security_groups.lms`](examples/recipe_inventory_security_groups.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory

![Review all supported inventories; IAM entries are skipped live](docs/images/recipe_inventory.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory.lms`

Example: [`examples/recipe_inventory.lms`](examples/recipe_inventory.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_alarms

![Inspect bounded alarms metadata](docs/images/recipe_inventory_alarms.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_alarms.lms`

Example: [`examples/recipe_inventory_alarms.lms`](examples/recipe_inventory_alarms.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_buckets

![Inspect bounded buckets metadata](docs/images/recipe_inventory_buckets.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_buckets.lms`

Example: [`examples/recipe_inventory_buckets.lms`](examples/recipe_inventory_buckets.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_clusters

![Inspect bounded clusters metadata](docs/images/recipe_inventory_clusters.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_clusters.lms`

Example: [`examples/recipe_inventory_clusters.lms`](examples/recipe_inventory_clusters.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_functions

![Inspect bounded functions metadata](docs/images/recipe_inventory_functions.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_functions.lms`

Example: [`examples/recipe_inventory_functions.lms`](examples/recipe_inventory_functions.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_instances

![Inspect bounded instances metadata](docs/images/recipe_inventory_instances.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_instances.lms`

Example: [`examples/recipe_inventory_instances.lms`](examples/recipe_inventory_instances.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_log_groups

![Inspect bounded log groups metadata](docs/images/recipe_inventory_log_groups.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_log_groups.lms`

Example: [`examples/recipe_inventory_log_groups.lms`](examples/recipe_inventory_log_groups.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_parameters

![Inspect bounded parameters metadata](docs/images/recipe_inventory_parameters.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_parameters.lms`

Example: [`examples/recipe_inventory_parameters.lms`](examples/recipe_inventory_parameters.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_queues

![Inspect bounded queues metadata](docs/images/recipe_inventory_queues.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_queues.lms`

Example: [`examples/recipe_inventory_queues.lms`](examples/recipe_inventory_queues.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_secrets

![Inspect bounded secrets metadata](docs/images/recipe_inventory_secrets.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_secrets.lms`

Example: [`examples/recipe_inventory_secrets.lms`](examples/recipe_inventory_secrets.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_tables

![Inspect bounded tables metadata](docs/images/recipe_inventory_tables.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_tables.lms`

Example: [`examples/recipe_inventory_tables.lms`](examples/recipe_inventory_tables.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_topics

![Inspect bounded topics metadata](docs/images/recipe_inventory_topics.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_topics.lms`

Example: [`examples/recipe_inventory_topics.lms`](examples/recipe_inventory_topics.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_vpcs

![Inspect bounded vpcs metadata](docs/images/recipe_inventory_vpcs.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_vpcs.lms`

Example: [`examples/recipe_inventory_vpcs.lms`](examples/recipe_inventory_vpcs.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### inventory_zones

![Inspect bounded zones metadata](docs/images/recipe_inventory_zones.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_zones.lms`

Example: [`examples/recipe_inventory_zones.lms`](examples/recipe_inventory_zones.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

#### bandwidth

![Break down billed transfer categories and network counters](docs/images/recipe_bandwidth.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_bandwidth.lms`

Example: [`examples/recipe_bandwidth.lms`](examples/recipe_bandwidth.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

#### dynamodb_spend

![Review DynamoDB usage and spend signals](docs/images/recipe_dynamodb_spend.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_dynamodb_spend.lms`

Example: [`examples/recipe_dynamodb_spend.lms`](examples/recipe_dynamodb_spend.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

#### ebs_audit

![Review EBS attachments and snapshot retention signals](docs/images/recipe_ebs_audit.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_ebs_audit.lms`

Example: [`examples/recipe_ebs_audit.lms`](examples/recipe_ebs_audit.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

#### ec2_spend

![Break down EC2 compute spend and current resource signals](docs/images/recipe_ec2_spend.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_ec2_spend.lms`

Example: [`examples/recipe_ec2_spend.lms`](examples/recipe_ec2_spend.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

#### eip_audit

![Review idle public IPv4 allocations and estimated run-rate](docs/images/recipe_eip_audit.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_eip_audit.lms`

Example: [`examples/recipe_eip_audit.lms`](examples/recipe_eip_audit.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

#### lambda_spend

![Review Lambda usage and spend signals](docs/images/recipe_lambda_spend.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_lambda_spend.lms`

Example: [`examples/recipe_lambda_spend.lms`](examples/recipe_lambda_spend.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

#### savings_plans

![Review Savings Plans and Reserved Instance utilization and coverage](docs/images/recipe_savings_plans.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_savings_plans.lms`

Example: [`examples/recipe_savings_plans.lms`](examples/recipe_savings_plans.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

#### spend_detail

![Review account spend detail and optimization signals](docs/images/recipe_spend_detail.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_spend_detail.lms`

Example: [`examples/recipe_spend_detail.lms`](examples/recipe_spend_detail.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

#### idle_instances

![Flag stopped-instance state for further review; never delete](docs/images/recipe_idle_instances.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_idle_instances.lms`

Example: [`examples/recipe_idle_instances.lms`](examples/recipe_idle_instances.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/audits.lms`; function `recipe_idle`.

#### naming_compliance

![Check case-sensitive lmaws_ and lmaws- naming among prefix candidates](docs/images/recipe_naming_compliance.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_naming_compliance.lms`

Example: [`examples/recipe_naming_compliance.lms`](examples/recipe_naming_compliance.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/audits.lms`; function `recipe_naming`.

#### tag_compliance

![Report missing and unknown tag presence without assuming compliance](docs/images/recipe_tag_compliance.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_tag_compliance.lms`

Example: [`examples/recipe_tag_compliance.lms`](examples/recipe_tag_compliance.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/audits.lms`; function `recipe_compliance`.

#### leftover_report

![Inspect aged active/pending records in the local run ledgers](docs/images/recipe_leftover_report.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_leftover_report.lms`

Example: [`examples/recipe_leftover_report.lms`](examples/recipe_leftover_report.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/prefix.lms`; function `recipe_leftovers`.

#### prefix_search

![Find lmaws_ and lmaws- names across supported account inventories](docs/images/recipe_prefix_search.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_prefix_search.lms`

Example: [`examples/recipe_prefix_search.lms`](examples/recipe_prefix_search.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/prefix.lms`; function `recipe_prefix_search`.

#### sweeper

![Dry-run leftover review; discovery never authorizes deletion](docs/images/recipe_sweeper.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sweeper.lms`

Example: [`examples/recipe_sweeper.lms`](examples/recipe_sweeper.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/prefix.lms`; function `recipe_sweeper`.

#### lifecycle

![Select a disposable queue/topic/table/bucket/parameter/log-group lifecycle](docs/images/recipe_lifecycle.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_lifecycle.lms`

Example: [`examples/recipe_lifecycle.lms`](examples/recipe_lifecycle.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

#### sandbox_bucket

![Create and tear down one owned bucket with its run ledger](docs/images/recipe_sandbox_bucket.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_bucket.lms`

Example: [`examples/recipe_sandbox_bucket.lms`](examples/recipe_sandbox_bucket.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

#### sandbox_log_group

![Create and tear down one owned log group with its run ledger](docs/images/recipe_sandbox_log_group.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_log_group.lms`

Example: [`examples/recipe_sandbox_log_group.lms`](examples/recipe_sandbox_log_group.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

#### sandbox_parameter

![Create and tear down one owned parameter with its run ledger](docs/images/recipe_sandbox_parameter.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_parameter.lms`

Example: [`examples/recipe_sandbox_parameter.lms`](examples/recipe_sandbox_parameter.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

#### sandbox_queue

![Create and tear down one owned queue with its run ledger](docs/images/recipe_sandbox_queue.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_queue.lms`

Example: [`examples/recipe_sandbox_queue.lms`](examples/recipe_sandbox_queue.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

#### sandbox_table

![Create and tear down one owned table with its run ledger](docs/images/recipe_sandbox_table.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_table.lms`

Example: [`examples/recipe_sandbox_table.lms`](examples/recipe_sandbox_table.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

#### sandbox_topic

![Create and tear down one owned topic with its run ledger](docs/images/recipe_sandbox_topic.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_topic.lms`

Example: [`examples/recipe_sandbox_topic.lms`](examples/recipe_sandbox_topic.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

<!-- RECIPES:END -->

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

v0.1.3 writes are limited to those six resource kinds. Compute, networking, IAM, ECS, Lambda, DNS and Secrets Manager are metadata-only.

## Cost per example

Every example prints a final `estimated cost: $...` line. Read-only examples use `$0.00`; write examples estimate each request and resource from a price table, exact request counts, fractional minutes alive and fractional GB-month storage. The table uses conservative us-east-1 prices as of 2026-10-25, ignores free-tier credits, and does not call Cost Explorer. Prices vary by region and change over time.

Each ledger refuses the next creation above the example cap of $0.05 or the whole-run hard ceiling of $0.25. Evidence is stored as `evidence/live-cost-<example>-<run-id>.json`; successful entries include the price table, requests, resources and leftover count. Nineteen read-only examples retain measured $0.00 evidence. The seven write/lifecycle examples are run once with `AWS_PROFILE=lmaws`; each successful lifecycle has a measured price-table estimate and is independently verified absent with the read-only `default` profile. The four IAM-dependent examples are intentionally skipped and labelled **estimated, not measured live**.

Profiles: `default` is READ-ONLY; **only `AWS_PROFILE=lmaws` may mutate**, in `us-east-1`. The host rejects real create/update/delete calls under any other active profile. No OIDC, IAM edits, credential/profile edits or alternate identity are used. The federated session policy at `~/.aws/session-tools/tasks/iam-snapshots/local-lmaws-session.json` is re-issued by `~/.aws/session-tools/scripts/aws-profile-session.py`; its combined plaintext inline/managed policy is limited to 2,048 characters and scopes resources to `lmaws_` / `lmaws-` names plus `lmaws_test` tags. Do not put account IDs or policy contents in this public repository.

The v0.1.3 native campaign added six successful lifecycle runs and independent
default-profile absence checks: measured estimates total $0.00001272500021 for
the six resource operations plus $0.00000130 for their verification reads. All
resources were deleted with **zero leftovers**. This is price-table accounting
from observed SDK requests and lifetimes, not an AWS invoice measurement.

All 30 examples have [lmcloud/OpenTofu equivalents and results](compare/RESULTS.md).
With released **lmcloud v0.1.10** and AWS provider 5.100.0, all **26 live pairs
completed**: **8 matching comparisons and 18 explicit differences** in supported
outputs or local-state semantics. Four IAM cases are skipped. The SDK
and OpenTofu each created one run-owned bucket and tiny object; all were deleted
and independently verified absent with `default`. There are **zero leftovers**.

The [v0.1.3 comparison campaign](evidence/comparison-campaign-v013.json) records
conservative total accounting of **$0.03503065000042**, below the $0.25 cap,
including the superseded local-build verification runs and two preflight rejects. Provider SDK request counts are
opaque, so its 500-request/$0.0025 per-attempt allowance is reserved before plan;
it is **not a measured AWS charge**. Timings in RESULTS include native rendering
and multiple provider phases with a shared warm plugin cache. A checksum audit
caught a local lmcloud build in the initial comparison pass; all six provider
sides were repeated with the SHA256SUMS-verified release, reusing native evidence.
The total retains both passes and conservative reused-native accounting. See the
[current provider notes](compare/PROVIDER_TEST.md) and [cleanup proof](evidence/comparison-cleanup-v013.json).

Per-run ledgers include preflight/tag/verification requests, retries and storage. Prices vary by region and time. [Local test steps and profile model](docs/USER_TEST.md).

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

- **inventory** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-inventory-r71d606a0xcaf04f53.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/inventory/inventory.lms`
- **buckets** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/buckets.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-buckets-r957ab3d1xc5e247e7.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/buckets/buckets.lms`
- **instances** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/instances.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-instances-ra4a54d9fxb3054905.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/instances/instances.lms`
- **vpcs** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/vpcs.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-vpcs-r62eeb5c9x53334996.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/vpcs/vpcs.lms`
- **security_groups** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/security_groups.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-security_groups-r978c99a4x285a43fa.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/security_groups/security_groups.lms`
- **tables** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tables.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-tables-r0a638e82x6bb64168.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/tables/tables.lms`
- **queues** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queues.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-queues-rad2e44b3x2dcc4dd7.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/queues/queues.lms`
- **topics** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topics.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-topics-r3f3a6389xd6084890.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/topics/topics.lms`
- **functions** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/functions.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-functions-r8b53f0abx71fc40db.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/functions/functions.lms`
- **log_groups** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_groups.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-log_groups-r87934eb2x848e4203.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/log_groups/log_groups.lms`
- **alarms** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/alarms.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-alarms-r2f6f55b6x5be54f83.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/alarms/alarms.lms`
- **zones** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/zones.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-zones-r38602169x68ff4e86.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/zones/zones.lms`
- **secrets** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/secrets.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-secrets-r320f386bx9cea4ec7.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/secrets/secrets.lms`
- **parameters** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/parameters.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-parameters-r61d3586dx74ab4fa6.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/parameters/parameters.lms`
- **clusters** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/clusters.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-clusters-rc6e3bf8bx64b54aaf.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/clusters/clusters.lms`
- **roles** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/roles.lms` — running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/roles/roles.lms`
- **identity** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/identity.lms` — running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/identity/identity.lms`
- **resource_graph** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/resource_graph.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-resource_graph-r2511a45fxb4544623.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/resource_graph/resource_graph.lms`
- **tag_compliance** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tag_compliance.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-tag_compliance-r7cb07155x9d6941ad.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/tag_compliance/tag_compliance.lms`
- **queue_pipeline** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queue_pipeline.lms` — running this example costs about $0.00000360 (measured live; independently verified deletion). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/queue_pipeline/queue_pipeline.lms`
- **sandbox_lifecycle** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sandbox_lifecycle.lms` — running this example costs about $0.00000000 (measured live; independently verified deletion). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/sandbox_lifecycle/sandbox_lifecycle.lms`
- **before_after** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/before_after.lms` — running this example costs about $0.00000400 (measured live; independently verified deletion). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/before_after/before_after.lms`
- **read_only_audit** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/read_only_audit.lms` — running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/read_only_audit/read_only_audit.lms`
- **regional_posture** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/regional_posture.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-regional_posture-r8c324e7dx1c334aa2.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/regional_posture/regional_posture.lms`
- **service_matrix** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/service_matrix.lms` — running this example costs about $0.00 (estimated, not measured live; IAM intentionally skipped for federated profiles). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/service_matrix/service_matrix.lms`

- **bucket_objects** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/bucket_objects.lms` — running this example costs about $0.00001781 ([measured live estimate](evidence/live-cost-bucket_objects-raaa7c272xd3864f73.json); lmaws profile, independently verified deletion). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/bucket_objects/bucket_objects.lms`
- **table_items** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/table_items.lms` — running this example costs about $0.00000063 (measured live; independently verified deletion). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/table_items/table_items.lms`
- **topic_publish** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topic_publish.lms` — running this example costs about $0.00000450 (measured live; independently verified deletion). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/topic_publish/topic_publish.lms`
- **log_retention** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_retention.lms` — running this example costs about $0.00000000 (measured live; independently verified deletion). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/log_retention/log_retention.lms`

The gallery contains 27 lmplot charts and 3 lmdraw diagrams generated from all 30 examples. `scripts/test-gallery.py` checks every URL, image and isolated demo run. The reusable recipe examples always force synthetic mode. Public CI forces `LMAWS_LIVE=0`, uses in-process fakes only, and never receives OIDC or cloud credentials. Live runs use the default AWS profile on this machine, with per-example ledgers, a dry-run sweeper and teardown.


- **sweeper** — `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sweeper.lms` — running this example costs about $0.00 ([live evidence](evidence/live-cost-sweeper-rb06fb78dx83ba4d51.json)). · lmcloud: `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/sweeper/sweeper.lms`

Compiler minimum: lmscript 0.2.420. Host schema bytes omit built-in std; `--dsl-signatures` includes it and `--without-std` selects host declarations.
