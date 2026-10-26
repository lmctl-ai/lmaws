# lmaws recipes

Reusable LMScript recipes for audits, inventory, spend review and safely owned sandboxes.
The access column describes AWS permissions; local reports are written only when a recipe is called.
Each wrapper is runnable directly. Import the paired library from its raw URL when composing recipes; wrappers perform the execution step.
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

Import-only composition example (functions do not execute on import):

```javascript
import "https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms";
let report=recipe_inventory({task:"queues",top:5,output:"data/my-queues",live:false});
println("matched rows:",len(report.rows));
```


## Identity and access posture

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`inventory_identity.lms`](inventory_identity.lms) | Inspect bounded identity metadata (synthetic only; federated IAM cases skipped live) | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_identity [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_roles.lms`](inventory_roles.lms) | Inspect bounded roles metadata (synthetic only; federated IAM cases skipped live) | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_roles [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_security_groups.lms`](inventory_security_groups.lms) | Inspect bounded security groups metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_security_groups [--live] | $0.00 displayed; capped request estimate in ledger |

## Inventory

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`inventory.lms`](inventory.lms) | Review all supported inventories; IAM entries are skipped live | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory [--live] | $0.00 displayed; request cap $0.05 |
| [`inventory_alarms.lms`](inventory_alarms.lms) | Inspect bounded alarms metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_alarms [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_buckets.lms`](inventory_buckets.lms) | Inspect bounded buckets metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_buckets [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_clusters.lms`](inventory_clusters.lms) | Inspect bounded clusters metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_clusters [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_functions.lms`](inventory_functions.lms) | Inspect bounded functions metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_functions [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_instances.lms`](inventory_instances.lms) | Inspect bounded instances metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_instances [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_log_groups.lms`](inventory_log_groups.lms) | Inspect bounded log groups metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_log_groups [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_parameters.lms`](inventory_parameters.lms) | Inspect bounded parameters metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_parameters [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_queues.lms`](inventory_queues.lms) | Inspect bounded queues metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_queues [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_secrets.lms`](inventory_secrets.lms) | Inspect bounded secrets metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_secrets [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_tables.lms`](inventory_tables.lms) | Inspect bounded tables metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_tables [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_topics.lms`](inventory_topics.lms) | Inspect bounded topics metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_topics [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_vpcs.lms`](inventory_vpcs.lms) | Inspect bounded vpcs metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_vpcs [--live] | $0.00 displayed; capped request estimate in ledger |
| [`inventory_zones.lms`](inventory_zones.lms) | Inspect bounded zones metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_zones [--live] | $0.00 displayed; capped request estimate in ledger |

## Idle and waste detection

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`idle_instances.lms`](idle_instances.lms) | Flag stopped-instance state for further review; never delete | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/idle_instances [--live] | $0.00 displayed; request cap $0.05 |

## Tag and naming compliance

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`tag_compliance.lms`](tag_compliance.lms) | Report missing and unknown tag presence without assuming compliance | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/tag_compliance [--live] | $0.00 displayed; request cap $0.05 |

## Leftover search and cleanup by prefix

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`leftover_report.lms`](leftover_report.lms) | Inspect aged active/pending records in the local run ledgers | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/leftover_report [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 0 | $0.00 synthetic; live request cap $0.05 |
| [`prefix_search.lms`](prefix_search.lms) | Find lmaws_ and lmaws- names across supported account inventories | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/prefix_search [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 0 | $0.00 synthetic; live request cap $0.05 |
| [`sweeper.lms`](sweeper.lms) | Dry-run leftover review; discovery never authorizes deletion | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/sweeper [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 0 | $0.00 synthetic; live request cap $0.05 |

## Safe lifecycle sandboxes

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`lifecycle.lms`](lifecycle.lms) | Select a disposable queue/topic/table/bucket/parameter/log-group lifecycle | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/lifecycle [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_bucket.lms`](sandbox_bucket.lms) | Create and tear down one owned bucket with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_bucket [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_log_group.lms`](sandbox_log_group.lms) | Create and tear down one owned log group with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_log_group [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_parameter.lms`](sandbox_parameter.lms) | Create and tear down one owned parameter with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_parameter [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_queue.lms`](sandbox_queue.lms) | Create and tear down one owned queue with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_queue [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_table.lms`](sandbox_table.lms) | Create and tear down one owned table with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_table [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |
| [`sandbox_topic.lms`](sandbox_topic.lms) | Create and tear down one owned topic with its run ledger | Write with the lmaws profile | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile lmaws --output data/sandbox_topic [--live] [--apply] | Synthetic $0.00; live generally below $0.0001; cap $0.05 |

## Picture-first examples

Each recipe points at an offline synthetic example so its output can be previewed safely.

### inventory_identity

![Inspect bounded identity metadata (synthetic only; federated IAM cases skipped live)](../docs/images/recipe_inventory_identity.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_identity.lms`

Example: [`examples/recipe_inventory_identity.lms`](../examples/recipe_inventory_identity.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_roles

![Inspect bounded roles metadata (synthetic only; federated IAM cases skipped live)](../docs/images/recipe_inventory_roles.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_roles.lms`

Example: [`examples/recipe_inventory_roles.lms`](../examples/recipe_inventory_roles.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_security_groups

![Inspect bounded security groups metadata](../docs/images/recipe_inventory_security_groups.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_security_groups.lms`

Example: [`examples/recipe_inventory_security_groups.lms`](../examples/recipe_inventory_security_groups.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory

![Review all supported inventories; IAM entries are skipped live](../docs/images/recipe_inventory.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory.lms`

Example: [`examples/recipe_inventory.lms`](../examples/recipe_inventory.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_alarms

![Inspect bounded alarms metadata](../docs/images/recipe_inventory_alarms.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_alarms.lms`

Example: [`examples/recipe_inventory_alarms.lms`](../examples/recipe_inventory_alarms.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_buckets

![Inspect bounded buckets metadata](../docs/images/recipe_inventory_buckets.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_buckets.lms`

Example: [`examples/recipe_inventory_buckets.lms`](../examples/recipe_inventory_buckets.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_clusters

![Inspect bounded clusters metadata](../docs/images/recipe_inventory_clusters.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_clusters.lms`

Example: [`examples/recipe_inventory_clusters.lms`](../examples/recipe_inventory_clusters.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_functions

![Inspect bounded functions metadata](../docs/images/recipe_inventory_functions.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_functions.lms`

Example: [`examples/recipe_inventory_functions.lms`](../examples/recipe_inventory_functions.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_instances

![Inspect bounded instances metadata](../docs/images/recipe_inventory_instances.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_instances.lms`

Example: [`examples/recipe_inventory_instances.lms`](../examples/recipe_inventory_instances.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_log_groups

![Inspect bounded log groups metadata](../docs/images/recipe_inventory_log_groups.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_log_groups.lms`

Example: [`examples/recipe_inventory_log_groups.lms`](../examples/recipe_inventory_log_groups.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_parameters

![Inspect bounded parameters metadata](../docs/images/recipe_inventory_parameters.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_parameters.lms`

Example: [`examples/recipe_inventory_parameters.lms`](../examples/recipe_inventory_parameters.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_queues

![Inspect bounded queues metadata](../docs/images/recipe_inventory_queues.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_queues.lms`

Example: [`examples/recipe_inventory_queues.lms`](../examples/recipe_inventory_queues.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_secrets

![Inspect bounded secrets metadata](../docs/images/recipe_inventory_secrets.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_secrets.lms`

Example: [`examples/recipe_inventory_secrets.lms`](../examples/recipe_inventory_secrets.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_tables

![Inspect bounded tables metadata](../docs/images/recipe_inventory_tables.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_tables.lms`

Example: [`examples/recipe_inventory_tables.lms`](../examples/recipe_inventory_tables.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_topics

![Inspect bounded topics metadata](../docs/images/recipe_inventory_topics.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_topics.lms`

Example: [`examples/recipe_inventory_topics.lms`](../examples/recipe_inventory_topics.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_vpcs

![Inspect bounded vpcs metadata](../docs/images/recipe_inventory_vpcs.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_vpcs.lms`

Example: [`examples/recipe_inventory_vpcs.lms`](../examples/recipe_inventory_vpcs.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### inventory_zones

![Inspect bounded zones metadata](../docs/images/recipe_inventory_zones.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_inventory_zones.lms`

Example: [`examples/recipe_inventory_zones.lms`](../examples/recipe_inventory_zones.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms`; function `recipe_inventory`.

### idle_instances

![Flag stopped-instance state for further review; never delete](../docs/images/recipe_idle_instances.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_idle_instances.lms`

Example: [`examples/recipe_idle_instances.lms`](../examples/recipe_idle_instances.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/audits.lms`; function `recipe_idle`.

### tag_compliance

![Report missing and unknown tag presence without assuming compliance](../docs/images/recipe_tag_compliance.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_tag_compliance.lms`

Example: [`examples/recipe_tag_compliance.lms`](../examples/recipe_tag_compliance.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/audits.lms`; function `recipe_compliance`.

### leftover_report

![Inspect aged active/pending records in the local run ledgers](../docs/images/recipe_leftover_report.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_leftover_report.lms`

Example: [`examples/recipe_leftover_report.lms`](../examples/recipe_leftover_report.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/prefix.lms`; function `recipe_leftovers`.

### prefix_search

![Find lmaws_ and lmaws- names across supported account inventories](../docs/images/recipe_prefix_search.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_prefix_search.lms`

Example: [`examples/recipe_prefix_search.lms`](../examples/recipe_prefix_search.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/prefix.lms`; function `recipe_prefix_search`.

### sweeper

![Dry-run leftover review; discovery never authorizes deletion](../docs/images/recipe_sweeper.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sweeper.lms`

Example: [`examples/recipe_sweeper.lms`](../examples/recipe_sweeper.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/prefix.lms`; function `recipe_sweeper`.

### lifecycle

![Select a disposable queue/topic/table/bucket/parameter/log-group lifecycle](../docs/images/recipe_lifecycle.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_lifecycle.lms`

Example: [`examples/recipe_lifecycle.lms`](../examples/recipe_lifecycle.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

### sandbox_bucket

![Create and tear down one owned bucket with its run ledger](../docs/images/recipe_sandbox_bucket.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_bucket.lms`

Example: [`examples/recipe_sandbox_bucket.lms`](../examples/recipe_sandbox_bucket.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

### sandbox_log_group

![Create and tear down one owned log group with its run ledger](../docs/images/recipe_sandbox_log_group.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_log_group.lms`

Example: [`examples/recipe_sandbox_log_group.lms`](../examples/recipe_sandbox_log_group.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

### sandbox_parameter

![Create and tear down one owned parameter with its run ledger](../docs/images/recipe_sandbox_parameter.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_parameter.lms`

Example: [`examples/recipe_sandbox_parameter.lms`](../examples/recipe_sandbox_parameter.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

### sandbox_queue

![Create and tear down one owned queue with its run ledger](../docs/images/recipe_sandbox_queue.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_queue.lms`

Example: [`examples/recipe_sandbox_queue.lms`](../examples/recipe_sandbox_queue.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

### sandbox_table

![Create and tear down one owned table with its run ledger](../docs/images/recipe_sandbox_table.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_table.lms`

Example: [`examples/recipe_sandbox_table.lms`](../examples/recipe_sandbox_table.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.

### sandbox_topic

![Create and tear down one owned topic with its run ledger](../docs/images/recipe_sandbox_topic.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_topic.lms`

Example: [`examples/recipe_sandbox_topic.lms`](../examples/recipe_sandbox_topic.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/lifecycle.lms`; function `recipe_lifecycle`.
