# Local AWS-agent test procedure (v0.1.2)

READY FOR USER TEST. All 19 read-only and the bucket/object native/lmcloud pairs
completed live using lmcloud v0.1.10 and AWS provider 5.100.0: seven comparisons
match, 13 retain explicit output or local-state differences. Six previously denied
write/lifecycle examples remain not comparable; one metadata read per prior failure
confirmed absence without proving create permission. Four IAM examples remain
estimated only and must be skipped. No lmcloud core patch was needed.
See [RESULTS](../compare/RESULTS.md), [campaign costs](../evidence/comparison-campaign-v0110.json)
and [independent cleanup proof](../evidence/comparison-cleanup-v0110.json).

Use lmctl/lmscript >=0.2.420. Native autoruns need no Java. Comparison autoruns also
need Python 3, curl and AWS CLI for ledgers and independent metadata-only checks.
No OIDC or AWS credentials belong in CI. Never use agentcore-poc or admin.

From a new local directory, with the user's existing profiles:

```sh
export AWS_DEFAULT_PROFILE=default AWS_PROFILE=default
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true LMAWS_LIVE=1
export LMAWS_MAX_COST_USD=0.05
export LMAWS_LEDGER_DIR="$PWD/ledgers"
export LMAWS_EVIDENCE_DIR="$PWD/evidence"
export LMSCRIPT_TOOL_CACHE="$PWD/.tools-lmaws-v012"
```

`default` is READ-ONLY and is used for all inventories and independent deletion
checks. Only `lmaws` may create/update/delete; the native host and comparison
runtime reject other profiles for writes. Both configured profiles were verified
to target the same account without printing its ID. The host never edits IAM,
credentials or profiles. The owner's agent may grant the following scoped actions
to the existing lmaws role; no IAM write permissions are needed by these examples.

| Service | Required IAM actions | Resource scope |
| --- | --- | --- |
| S3 | `s3:CreateBucket`, `s3:PutBucketTagging`, `s3:GetBucketTagging`, `s3:ListBucket`, `s3:DeleteBucket`; `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` | `arn:aws:s3:::lmaws-*`; object actions on `arn:aws:s3:::lmaws-*/*` |
| SQS | `sqs:CreateQueue`, `sqs:TagQueue`, `sqs:GetQueueUrl`, `sqs:ListQueueTags`, `sqs:SendMessage`, `sqs:DeleteQueue` | `arn:aws:sqs:us-east-1:<account>:lmaws_*` |
| SSM | `ssm:PutParameter`, `ssm:AddTagsToResource`, `ssm:ListTagsForResource`, `ssm:DeleteParameter` | `arn:aws:ssm:us-east-1:<account>:parameter/lmaws_*` (Standard String only; no value reads needed) |
| DynamoDB | `dynamodb:CreateTable`, `dynamodb:TagResource`, `dynamodb:DescribeTable`, `dynamodb:ListTagsOfResource`, `dynamodb:PutItem`, `dynamodb:DeleteTable` | `arn:aws:dynamodb:us-east-1:<account>:table/lmaws_*` |
| SNS | `sns:CreateTopic`, `sns:TagResource`, `sns:ListTagsForResource`, `sns:GetTopicAttributes`, `sns:Publish`, `sns:DeleteTopic` | `arn:aws:sns:us-east-1:<account>:lmaws_*` |
| CloudWatch Logs | `logs:CreateLogGroup`, `logs:TagResource`, `logs:TagLogGroup`, `logs:ListTagsLogGroup`, `logs:PutRetentionPolicy`, `logs:DeleteLogGroup` | `arn:aws:logs:us-east-1:<account>:log-group:lmaws_*` and its `:*` form where required by the action |

The action table describes native SDK requests. The external AWS provider performs
its own metadata reads; the existing lmaws profile completed the recorded
bucket/object comparison.

Use your account in `<account>`. Where supported, require the creation request tag
`aws:RequestTag/lmaws_test` and restrict tag keys to `lmaws_test`; authorize later
mutations only for the matching `aws:ResourceTag/lmaws_test`. Consult each service's
condition support rather than applying one blanket tag condition: S3 tags are
applied after CreateBucket, so initial create/tag and rollback must work on the
name scope before a tag exists. Host-side ownership checks additionally require
the exact run ID, prefix and ledger. Do not grant writes outside these prefixes.

Inventory/preflight calls that cannot use a resource ARN need `Resource: "*"`:
`s3:ListAllMyBuckets`, `sqs:ListQueues`, `sns:ListTopics`, `dynamodb:ListTables`,
`ssm:DescribeParameters`, `logs:DescribeLogGroups`, `ec2:DescribeInstances`,
`ec2:DescribeVpcs`, `ec2:DescribeSecurityGroups`, `lambda:ListFunctions`,
`cloudwatch:DescribeAlarms`, `route53:ListHostedZones`, `secretsmanager:ListSecrets`,
`ecs:ListClusters`. These are metadata-only; no secret-value
reads, IAM writes, EC2 creates, or Lambda creates are needed by this release.
`sts:GetCallerIdentity` supplies masked identity metadata. Skip `roles`, `identity`, `read_only_audit` and `service_matrix` live: federated profiles cannot call IAM. No IAM grants, profile repair or identity switching are part of this test.

AWS references: [SQS actions and tag conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sqs.html),
[S3 operation permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
(`HeadObject` uses `s3:GetObject`; `HeadBucket` uses `s3:ListBucket`).


## Native autoruns: exact profile for each example

S3 `bucket_objects`: measured estimated cost $0.00001781, independently absent after
cleanup. Read-only examples print $0.00. The six denied lifecycle examples remain
price-table estimates: SQS/DynamoDB/SNS $0.0001 planning allowance; Standard SSM and
empty Logs $0.00. Actual request/lifetime estimates are written in each ledger,
including denied attempts. Default per-example cap $0.05; hard run ceiling $0.25.

Each command below has its own cap. For one aggregate capped batch use the checkout
harness described below, not independent commands. Do not rerun writes merely to
refresh screenshots. IAM commands are listed only as offline demos, without live mode.

```sh
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/alarms.lms
AWS_PROFILE=lmaws timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/before_after.lms
AWS_PROFILE=lmaws timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/bucket_objects.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/buckets.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/clusters.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/functions.lms
LMAWS_LIVE=0 AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/identity.lms # IAM: offline only
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/instances.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_groups.lms
AWS_PROFILE=lmaws timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_retention.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/parameters.lms
AWS_PROFILE=lmaws timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queue_pipeline.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queues.lms
LMAWS_LIVE=0 AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/read_only_audit.lms # IAM: offline only
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/regional_posture.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/resource_graph.lms
LMAWS_LIVE=0 AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/roles.lms # IAM: offline only
AWS_PROFILE=lmaws timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sandbox_lifecycle.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/secrets.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/security_groups.lms
LMAWS_LIVE=0 AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/service_matrix.lms # IAM: offline only
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sweeper.lms
AWS_PROFILE=lmaws timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/table_items.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tables.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tag_compliance.lms
AWS_PROFILE=lmaws timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topic_publish.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topics.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/vpcs.lms
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/zones.lms
```

A repository checkout can enforce the aggregate campaign budget and skip IAM:

```sh
# Install/download the v0.1.2 platform executable into target/lmaws, verify SHA256SUMS.
LMAWS_LIVE=1 AWS_PROFILE=lmaws python3 scripts/test-live-examples.py --host target/lmaws --example bucket_objects
# Reuse the successful native proof to avoid repeating its creation.
# Other six write examples remain skipped until the owner establishes create permission.
export TF_PLUGIN_CACHE_DIR="${TMPDIR:-/tmp}/lmaws-provider-cache"
mkdir -p "$TF_PLUGIN_CACHE_DIR"
# Run exactly one native/lmcloud comparison:
LMAWS_LIVE=1 AWS_PROFILE=lmaws AWS_REGION=us-east-1 timeout 1050 compare/run.sh bucket_objects \
  --native-evidence evidence/live-cost-bucket_objects-<run-id>.json
LMAWS_LIVE=1 AWS_PROFILE=default AWS_REGION=us-east-1 timeout 1050 compare/run.sh inventory
```

All 30 direct comparison URLs are beside their native examples in README. Example:

```sh
LMAWS_LIVE=1 AWS_PROFILE=lmaws timeout 900 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/compare/bucket_objects/bucket_objects.lms
```

Comparison scripts embed their HCL and download this repo's small Python runtime
and fail-closed metadata verifier. Without LMAWS_LIVE=1 they only initialize and
validate; they never apply. With live mode, they check every phase return value,
preflight absence, prefix/tag ownership and cost reservation before apply, retain
private state, always attempt destroy after apply (including failure), and verify
absence using default. OpenTofu's request counts are not exposed by lmcloud; its
cost ledger therefore reserves a conservative 500-request upper allowance ($0.0025),
including tiny storage. This is explicitly an allowance, not measured SDK traffic.
Reserve this upper allowance before plan for both metadata reads and writes.
The successful campaign created one SDK bucket/object and one provider bucket/object;
all were deleted. Total conservative campaign accounting, including retries and
independent checks, was $0.05754170 (native $0.00004000; provider upper bound $0.0575).

## Sweep and evidence

```sh
AWS_PROFILE=default timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sweeper.lms
# With the downloaded host on PATH:
lmaws --sweep "$LMAWS_LEDGER_DIR" --older-than-hours 0
# For a direct comparison autorun directory (downloaded helper), dry-run only:
python3 compare-runtime.py --sweep
# Repository comparison state, dry-run only; no AWS calls or deletion:
python3 compare/sweep.py --older-than-hours 0
```

Require `leftover_count=0`, `sweeper_leftover_count=0`, and `absent:true` in independent
default-profile checks. A denied/unknown/network response is never absence. Preserve
failed comparison state under ignored `compare/runs/`; do not delete it before resolving
cleanup. No automated sweeper deletes resources. The current comparison campaign
created one SDK bucket/object and one provider bucket/object; all were independently
verified absent. Its conservative total was $0.05754170, including retries and
metadata checks. Prices vary by region and time; no Cost Explorer request was made.

Comparison scripts pin lmcloud v0.1.10 for reproducibility. Its provider installer
and single-number version output work; the former v0.1.9 blockers are resolved.
Set a scratch `TF_PLUGIN_CACHE_DIR` before comparisons to reuse the ~676 MiB
provider. Results describe observed resources and selected numeric outputs,
not complete API parity. No cloud credentials or OIDC belong in public CI.
