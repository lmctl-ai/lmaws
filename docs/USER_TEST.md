# Local user AWS-agent test procedure (v0.1.1)

Status: READY FOR USER TEST after fake-only five-platform CI and the v0.1.1 release.
Nineteen read-only examples have measured $0.00 evidence. The remaining examples
are labelled in README as “estimated from price table, not yet measured live” because
the federated session `awsspot-local-default` denied SQS CreateQueue and
`ssm:PutParameter`, while IAM ListRoles returned InvalidClientTokenId. The host
never edits IAM users/keys or changes profiles.

Run locally, never in GitHub Actions or another CI service. No OIDC setup, cloud
credentials in GitHub, trust policy or Cost Explorer request is needed.

```sh
export AWS_PROFILE=default
export AWS_DEFAULT_PROFILE=default
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
export LMAWS_LIVE=1
export LMAWS_MAX_COST_USD=0.05
export LMAWS_LEDGER_DIR="$PWD/ledgers"
export LMAWS_EVIDENCE_DIR="$PWD/evidence"
export LMSCRIPT_TOOL_CACHE="$PWD/.tools-lmaws-v011"
```

Use the configured default profile. It must allow metadata inventories and scoped
create/tag/use/delete operations for the example's `lmaws_` resources (S3 names use
`lmaws-`), with `lmaws_test=<run-id>`. It must allow ownership-tag reads and deletion
so cleanup can finish. Fix the local profile outside this host if authentication
or authorization fails; do not add cloud credentials or OIDC to public CI.

After v0.1.1 is published, use a fresh tool cache and ensure an older `lmaws` is not
on PATH. From an empty directory, run each of the 30 `lmctl autorun` URLs listed in
README. Read-only examples print `estimated cost: $0.00`; README gives the
price-table estimate for each blocked example. Each run writes its PNG, a private
ledger, sanitized `evidence/live-cost-<example>-<run-id>.json`, and its estimate.

```sh
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sweeper.lms
```

The live write examples need least-privilege permissions restricted to the run's
`lmaws_` names (S3 uses `lmaws-`) and `lmaws_test=<run-id>` tag:

| Service | Required IAM actions | Resource scope |
| --- | --- | --- |
| S3 | `s3:CreateBucket`, `s3:PutBucketTagging`, `s3:GetBucketTagging`, `s3:ListBucket`, `s3:DeleteBucket`; `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` | `arn:aws:s3:::lmaws-*`; object actions on `arn:aws:s3:::lmaws-*/*` |
| SQS | `sqs:CreateQueue`, `sqs:TagQueue`, `sqs:GetQueueUrl`, `sqs:ListQueueTags`, `sqs:SendMessage`, `sqs:DeleteQueue` | `arn:aws:sqs:us-east-1:<account>:lmaws_*` |
| SSM | `ssm:PutParameter`, `ssm:AddTagsToResource`, `ssm:ListTagsForResource`, `ssm:DeleteParameter` | `arn:aws:ssm:us-east-1:<account>:parameter/lmaws_*` (Standard String only; no value reads needed) |
| DynamoDB | `dynamodb:CreateTable`, `dynamodb:TagResource`, `dynamodb:DescribeTable`, `dynamodb:ListTagsOfResource`, `dynamodb:PutItem`, `dynamodb:DeleteTable` | `arn:aws:dynamodb:us-east-1:<account>:table/lmaws_*` |
| SNS | `sns:CreateTopic`, `sns:TagResource`, `sns:ListTagsForResource`, `sns:GetTopicAttributes`, `sns:Publish`, `sns:DeleteTopic` | `arn:aws:sns:us-east-1:<account>:lmaws_*` |
| CloudWatch Logs | `logs:CreateLogGroup`, `logs:TagResource`, `logs:TagLogGroup`, `logs:ListTagsLogGroup`, `logs:PutRetentionPolicy`, `logs:DeleteLogGroup` | `arn:aws:logs:us-east-1:<account>:log-group:lmaws_*` and its `:*` form where required by the action |

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
`ecs:ListClusters`, and `iam:ListRoles`. These are metadata-only; no secret-value
reads, IAM writes, EC2 creates, or Lambda creates are needed by this release.
`sts:GetCallerIdentity` supplies masked identity metadata. The four IAM-dependent
examples (`roles`, `identity`, `read_only_audit`, `service_matrix`) need
`iam:ListRoles`; no wildcard `iam:Get*`/`iam:List*` grant is necessary.
`InvalidClientTokenId` is an authentication issue, not a missing IAM allow: the
owner must repair/refresh the existing `awsspot-local-default` federated session
behind profile `default`, without switching identity. lmaws does not do this.

AWS references: [SQS actions and tag conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sqs.html),
[S3 operation permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
(`HeadObject` uses `s3:GetObject`; `HeadBucket` uses `s3:ListBucket`).

The sweeper example scans the directory in `LMAWS_LEDGER_DIR`, asserts zero ledger
leftovers, prints `$0.00`, and never deletes account resources. With the native
binary installed on PATH, its equivalent CLI is:

```sh
lmaws --sweep "$LMAWS_LEDGER_DIR" --older-than-hours 0
```

Default per-example cap: $0.05. Hard whole-run cap: $0.25. The host refuses the next
resource before its projected estimate exceeds the cap, reserves cleanup headroom,
and never blocks teardown because a cap was reached. The local batch harness
shares a $0.25 campaign estimate across evidence files.

Candidate development test (repository checkout, local compiler and built host):

```sh
LMAWS_LIVE=1 python3 scripts/test-live-examples.py --host target/lmaws
# To retry one example after fixing the local default profile:
LMAWS_LIVE=1 python3 scripts/test-live-examples.py --host target/lmaws --example queue_pipeline
```

Check both `leftover_count` and `sweeper_leftover_count` are zero, every provider
verification says `absent:true`, the PNG exists, and the process exits successfully.
An AccessDenied or invalid-token run is failed evidence even if it left no resource.
Never interpret an authorization/network error as proof that a resource is absent.

## All 30 local autoruns

Expected cost: the 19 measured read-only examples print `$0.00`; four IAM-dependent read-only examples are estimated at `$0.00`, not yet measured live. The five S3/DynamoDB/SQS/SNS write examples have a `$0.0001` planning allowance each, and SSM/log retention are estimated at `$0.00`, not yet measured live. Prices and assumptions are in README. No credentials are supplied to CI.

Run from a new directory with `lmctl`/`lmscript` 0.2.420 or newer installed; do not put an old `lmaws` on PATH. The environment above opts into live calls; omit `LMAWS_LIVE=1` for the offline demo. A single live batch should use the aggregate-cap harness below rather than 30 independent runs (each independent autorun has its own $0.05 cap).

```sh
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/alarms.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/before_after.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/bucket_objects.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/buckets.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/clusters.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/functions.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/identity.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/instances.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_groups.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/log_retention.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/parameters.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queue_pipeline.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/queues.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/read_only_audit.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/regional_posture.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/resource_graph.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/roles.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sandbox_lifecycle.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/secrets.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/security_groups.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/service_matrix.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sweeper.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/table_items.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tables.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/tag_compliance.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topic_publish.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/topics.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/vpcs.lms
timeout 300 lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/zones.lms
```

For aggregate $0.25 enforcement across the batch, clone the repo, download the matching v0.1.1 executable from the release to `target/lmaws` (Windows: `target/lmaws.exe`), verify SHA256SUMS, and pass its absolute path to `scripts/test-live-examples.py --host`. The harness runs all 30 with the default profile and deducts existing campaign evidence from the budget. Inspect failures before rerunning.
