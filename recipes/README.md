# lmaws recipes

![Review account spend detail and optimization signals](../docs/images/recipe_spend_detail.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_spend_detail.lms`

![Find every literal lmaws prefix variant through native account APIs](../docs/images/recipe_prefix_search.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_prefix_search.lms`

![Create and tear down one owned queue with its run ledger](../docs/images/recipe_sandbox_queue.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_sandbox_queue.lms`

Reusable LMScript recipes for audits, inventory, spend review and safely owned sandboxes.
The access column describes AWS permissions; local reports are written only when a recipe is called.
Each generated entry is self-contained and runnable directly. Import the paired library from its raw URL when composing recipes; entry scripts perform the execution step.
Use `lmaws`, never the `aws` CLI. Read-only recipes use `default`; writes require
`AWS_PROFILE=lmaws`, the ownership prefix/tag, a ledger and teardown.

All executable recipes default to synthetic fixtures. Use `--preview` for a no-call plan,
or the runner's `lmctl script --dry-run recipes/<name>.lms`. Live inventory needs `--live`;
live sandboxes also require `--apply --profile lmaws`. Prefix discovery is read-only; sweeper deletion
requires --delete, the lmaws profile, matching run tags and original creation-ledger proof.

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


## Identity and access posture

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`grant_session_policy.lms`](grant_session_policy.lms) | Preview statement-level diff or grant the lmaws_session customer-managed IAM policy | Write with the admin profile | --policy lmaws_session --file POLICY.json --profile admin --top 20 --output data/grant_session_policy [--live] [--apply] | $0.00 IAM metadata; live apply requires AWS_PROFILE=admin and LMAWS_ADMIN_GRANT=1 |
| [`inventory_identity.lms`](inventory_identity.lms) | Inspect bounded identity metadata (synthetic only; federated IAM cases skipped live) | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_identity [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_roles.lms`](inventory_roles.lms) | Inspect bounded roles metadata (synthetic only; federated IAM cases skipped live) | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_roles [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_security_groups.lms`](inventory_security_groups.lms) | Inspect bounded security groups metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_security_groups [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`policy_lint.lms`](policy_lint.lms) | Validate and lint an IAM managed policy JSON document offline against lmaws guardrails | Read-only | --file POLICY.json --top 20 --output data/policy_lint | $0.00 offline lint |

## Inventory

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`inventory.lms`](inventory.lms) | Review all supported inventories; IAM entries are skipped live | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory [--live] | $0.00 synthetic; live request cap $0.05 |
| [`inventory_alarms.lms`](inventory_alarms.lms) | Inspect bounded alarms metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_alarms [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_buckets.lms`](inventory_buckets.lms) | Inspect bounded buckets metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_buckets [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_clusters.lms`](inventory_clusters.lms) | Inspect bounded clusters metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_clusters [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_functions.lms`](inventory_functions.lms) | Inspect bounded functions metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_functions [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_instances.lms`](inventory_instances.lms) | Inspect bounded instances metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_instances [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_log_groups.lms`](inventory_log_groups.lms) | Inspect bounded log groups metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_log_groups [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_parameters.lms`](inventory_parameters.lms) | Inspect bounded parameters metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_parameters [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_queues.lms`](inventory_queues.lms) | Inspect bounded queues metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_queues [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_secrets.lms`](inventory_secrets.lms) | Inspect bounded secrets metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_secrets [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_tables.lms`](inventory_tables.lms) | Inspect bounded tables metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_tables [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_topics.lms`](inventory_topics.lms) | Inspect bounded topics metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_topics [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_vpcs.lms`](inventory_vpcs.lms) | Inspect bounded vpcs metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_vpcs [--live] | $0.00 synthetic; live capped request estimate in ledger |
| [`inventory_zones.lms`](inventory_zones.lms) | Inspect bounded zones metadata | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/inventory_zones [--live] | $0.00 synthetic; live capped request estimate in ledger |

## Cost and spend

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`bandwidth.lms`](bandwidth.lms) | Break down billed transfer categories and network counters | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`dynamodb_spend.lms`](dynamodb_spend.lms) | Review DynamoDB usage and spend signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`ebs_audit.lms`](ebs_audit.lms) | Review EBS attachments and snapshot retention signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`ec2_spend.lms`](ec2_spend.lms) | Break down EC2 compute spend and current resource signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`eip_audit.lms`](eip_audit.lms) | Review idle public IPv4 allocations and estimated run-rate | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`lambda_spend.lms`](lambda_spend.lms) | Review Lambda usage and spend signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`savings_plans.lms`](savings_plans.lms) | Review Savings Plans and Reserved Instance utilization and coverage | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |
| [`spend_detail.lms`](spend_detail.lms) | Review account spend detail and optimization signals | Read-only | --period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR] | Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25 |

## Idle and waste detection

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`idle_instances.lms`](idle_instances.lms) | Flag stopped-instance state for further review; never delete | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/idle_instances [--live] | $0.00 synthetic; live request cap $0.05 |

## Tag and naming compliance

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`naming_compliance.lms`](naming_compliance.lms) | Check case-sensitive lmaws_ and lmaws- naming among prefix candidates | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/naming_compliance [--live] | $0.00 synthetic; live request cap $0.05 |
| [`tag_compliance.lms`](tag_compliance.lms) | Report missing and unknown tag presence without assuming compliance | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/tag_compliance [--live] | $0.00 synthetic; live request cap $0.05 |

## Leftover search and cleanup by prefix

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`leftover_report.lms`](leftover_report.lms) | Inspect account resources by age and their creation-ledger proof | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/leftover_report [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 24 [--delete --profile lmaws] | $0.00 synthetic; live request cap $0.05 |
| [`prefix_search.lms`](prefix_search.lms) | Find every literal lmaws prefix variant through native account APIs | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/prefix_search [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 24 [--delete --profile lmaws] | $0.00 synthetic; live request cap $0.05 |
| [`sweeper.lms`](sweeper.lms) | Plan account cleanup; explicit delete checks prefix, tag and run ledger | Read-only | --task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/sweeper [--live] --ledger-dir .lmaws-local/recipes/ledgers --older-hours 24 [--delete --profile lmaws] | $0.00 synthetic; live request cap $0.05 |

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

## Compute and fleet

| File | What it does | Access | Arguments | Typical cost |
|---|---|---|---|---|
| [`ami_lookup.lms`](ami_lookup.lms) | Latest Ubuntu 24.04 and Amazon Linux 2023 AMIs (arm64, x86_64) from public SSM parameters | Read-only with the lmaws-ec2 profile | --region us-east-1 --profile lmaws-ec2 --output data/ami_lookup [--live] | $0.00 (public SSM parameters are free) |
| [`cpu_credits.lms`](cpu_credits.lms) | CPU credit balance, usage, surplus and headroom of burstable instances, without SSH | Read-only | --tag-key Project --tag-value VALUE --instance ID --hours 24 --region us-east-1 --profile default --output data/cpu_credits [--live] | $0.00 synthetic; live CloudWatch statistics about $0.00005 per instance; cap $0.05 |
| [`ebs_roots.lms`](ebs_roots.lms) | EBS volumes, attachments, root DeleteOnTermination and the AZ lock, as a report | Read-only | --region us-east-1 --profile default --output data/ebs_roots [--live] | $0.00 synthetic; live Describe calls are free; cap $0.05 |
| [`eip_map.lms`](eip_map.lms) | Map Elastic IPs to instances, flag idle ones, report pinned addresses (never releases) | Read-only | --tag-key Project --region us-east-1 --profile default --output data/eip_map [--live] | $0.00 synthetic; live Describe calls are free; cap $0.05 |
| [`fleet_status.lms`](fleet_status.lms) | Discover tagged instances: state, type, addresses and root-storage policy | Read-only | --tag-key Project --tag-value VALUE --region us-east-1 --profile default --output data/fleet_status [--live] | $0.00 synthetic; live EC2 Describe calls are free; cap $0.05 |
| [`spot_nano_lifecycle.lms`](spot_nano_lifecycle.lms) | Launch one tagged no-public-IP spot nano, check it, terminate it and prove zero leftovers | Write with the lmaws-ec2 profile | --region us-east-1 --profile lmaws-ec2 --output .lmaws-local/compute/spot_nano_lifecycle [--live --apply] | Synthetic $0.00; live about $0.0005 (spot nano minutes + 8 GiB gp3); cap $0.05 |
| [`spot_prices.lms`](spot_prices.lms) | Spot price history per AZ for nano types, cheapest AZ and saving vs On-Demand | Read-only | --types t4g.nano,t3.nano --hours 3 --region us-east-1 --profile default --output data/spot_prices [--live] | $0.00 synthetic; live Describe calls are free; cap $0.05 |

## Picture-first examples

Each recipe points at an offline synthetic example so its output can be previewed safely.

### grant_session_policy

![Preview statement-level diff or grant the lmaws_session customer-managed IAM policy](../docs/images/recipe_grant_session_policy.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_grant_session_policy.lms`

Example: [`examples/recipe_grant_session_policy.lms`](../examples/recipe_grant_session_policy.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/iam_policy.lms`; function `recipe_grant_session_policy`.

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

### policy_lint

![Validate and lint an IAM managed policy JSON document offline against lmaws guardrails](../docs/images/recipe_policy_lint.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_policy_lint.lms`

Example: [`examples/recipe_policy_lint.lms`](../examples/recipe_policy_lint.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/iam_policy.lms`; function `recipe_policy_lint`.

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

### bandwidth

![Break down billed transfer categories and network counters](../docs/images/recipe_bandwidth.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_bandwidth.lms`

Example: [`examples/recipe_bandwidth.lms`](../examples/recipe_bandwidth.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

### dynamodb_spend

![Review DynamoDB usage and spend signals](../docs/images/recipe_dynamodb_spend.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_dynamodb_spend.lms`

Example: [`examples/recipe_dynamodb_spend.lms`](../examples/recipe_dynamodb_spend.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

### ebs_audit

![Review EBS attachments and snapshot retention signals](../docs/images/recipe_ebs_audit.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_ebs_audit.lms`

Example: [`examples/recipe_ebs_audit.lms`](../examples/recipe_ebs_audit.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

### ec2_spend

![Break down EC2 compute spend and current resource signals](../docs/images/recipe_ec2_spend.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_ec2_spend.lms`

Example: [`examples/recipe_ec2_spend.lms`](../examples/recipe_ec2_spend.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

### eip_audit

![Review idle public IPv4 allocations and estimated run-rate](../docs/images/recipe_eip_audit.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_eip_audit.lms`

Example: [`examples/recipe_eip_audit.lms`](../examples/recipe_eip_audit.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

### lambda_spend

![Review Lambda usage and spend signals](../docs/images/recipe_lambda_spend.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_lambda_spend.lms`

Example: [`examples/recipe_lambda_spend.lms`](../examples/recipe_lambda_spend.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

### savings_plans

![Review Savings Plans and Reserved Instance utilization and coverage](../docs/images/recipe_savings_plans.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_savings_plans.lms`

Example: [`examples/recipe_savings_plans.lms`](../examples/recipe_savings_plans.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

### spend_detail

![Review account spend detail and optimization signals](../docs/images/recipe_spend_detail.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_spend_detail.lms`

Example: [`examples/recipe_spend_detail.lms`](../examples/recipe_spend_detail.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/spend.lms`; function `recipe_spend`.

### idle_instances

![Flag stopped-instance state for further review; never delete](../docs/images/recipe_idle_instances.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_idle_instances.lms`

Example: [`examples/recipe_idle_instances.lms`](../examples/recipe_idle_instances.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/audits.lms`; function `recipe_idle`.

### naming_compliance

![Check case-sensitive lmaws_ and lmaws- naming among prefix candidates](../docs/images/recipe_naming_compliance.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_naming_compliance.lms`

Example: [`examples/recipe_naming_compliance.lms`](../examples/recipe_naming_compliance.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/audits.lms`; function `recipe_naming`.

### tag_compliance

![Report missing and unknown tag presence without assuming compliance](../docs/images/recipe_tag_compliance.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_tag_compliance.lms`

Example: [`examples/recipe_tag_compliance.lms`](../examples/recipe_tag_compliance.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/audits.lms`; function `recipe_compliance`.

### leftover_report

![Inspect account resources by age and their creation-ledger proof](../docs/images/recipe_leftover_report.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_leftover_report.lms`

Example: [`examples/recipe_leftover_report.lms`](../examples/recipe_leftover_report.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/prefix.lms`; function `recipe_leftovers`.

### prefix_search

![Find every literal lmaws prefix variant through native account APIs](../docs/images/recipe_prefix_search.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_prefix_search.lms`

Example: [`examples/recipe_prefix_search.lms`](../examples/recipe_prefix_search.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/prefix.lms`; function `recipe_prefix_search`.

### sweeper

![Plan account cleanup; explicit delete checks prefix, tag and run ledger](../docs/images/recipe_sweeper.png)

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

### ami_lookup

![Latest Ubuntu 24.04 and Amazon Linux 2023 AMIs (arm64, x86_64) from public SSM parameters](../docs/images/recipe_ami_lookup.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_ami_lookup.lms`

Example: [`examples/recipe_ami_lookup.lms`](../examples/recipe_ami_lookup.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/compute.lms`; function `recipe_ami_lookup`.

### cpu_credits

![CPU credit balance, usage, surplus and headroom of burstable instances, without SSH](../docs/images/recipe_cpu_credits.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_cpu_credits.lms`

Example: [`examples/recipe_cpu_credits.lms`](../examples/recipe_cpu_credits.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/compute.lms`; function `recipe_cpu_credits`.

### ebs_roots

![EBS volumes, attachments, root DeleteOnTermination and the AZ lock, as a report](../docs/images/recipe_ebs_roots.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_ebs_roots.lms`

Example: [`examples/recipe_ebs_roots.lms`](../examples/recipe_ebs_roots.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/compute.lms`; function `recipe_ebs_roots`.

### eip_map

![Map Elastic IPs to instances, flag idle ones, report pinned addresses (never releases)](../docs/images/recipe_eip_map.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_eip_map.lms`

Example: [`examples/recipe_eip_map.lms`](../examples/recipe_eip_map.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/compute.lms`; function `recipe_eip_map`.

### fleet_status

![Discover tagged instances: state, type, addresses and root-storage policy](../docs/images/recipe_fleet_status.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_fleet_status.lms`

Example: [`examples/recipe_fleet_status.lms`](../examples/recipe_fleet_status.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/compute.lms`; function `recipe_fleet_status`.

### spot_nano_lifecycle

![Launch one tagged no-public-IP spot nano, check it, terminate it and prove zero leftovers](../docs/images/recipe_spot_nano_lifecycle.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_spot_nano_lifecycle.lms`

Example: [`examples/recipe_spot_nano_lifecycle.lms`](../examples/recipe_spot_nano_lifecycle.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/compute.lms`; function `recipe_spot_nano_lifecycle`.

### spot_prices

![Spot price history per AZ for nano types, cheapest AZ and saving vs On-Demand](../docs/images/recipe_spot_prices.png)

`lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_spot_prices.lms`

Example: [`examples/recipe_spot_prices.lms`](../examples/recipe_spot_prices.lms).
Import library: `https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/compute.lms`; function `recipe_spot_prices`.
