# Local user AWS-agent test procedure (candidate v0.1.1)

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

* S3 `CreateBucket`, `PutObject`, `GetObject`, `HeadObject`, `ListBucket`,
  `DeleteObject`, `DeleteBucket`.
* SQS `CreateQueue`, `GetQueueUrl`, `GetQueueAttributes`, `SendMessage`,
  `ReceiveMessage`, `DeleteMessage`, `DeleteQueue`.
* SSM `PutParameter`, `GetParameter`, `DescribeParameters`, `DeleteParameter`
  (Standard String only).
* DynamoDB `CreateTable`, `DescribeTable`, `PutItem`, `Scan`, `DeleteTable`.
* SNS `CreateTopic`, `GetTopicAttributes`, `Publish`, `DeleteTopic`.
* CloudWatch Logs `CreateLogGroup`, `DescribeLogGroups`, `PutRetentionPolicy`,
  `DeleteLogGroup`.

The roles, identity, read_only_audit and service_matrix examples need read-only
IAM inventory calls including `iam:ListRoles` and the `Get*`/`List*` calls shown by
their errors. IAM list operations cannot be resource-scoped; grant no user, key,
trust-policy, or policy-write actions. `InvalidClientTokenId` is a federated-session
authentication problem, so repair `awsspot-local-default` outside lmaws rather than
switching identity.

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
