# Lambda execution role

`grant_lambda_role.lms` manages one pre-built role, `lmaws_lambda_exec`, for the
lmweblab Lambda scenarios. The lmaws session never creates IAM roles and the
policy linter continues to reject role-management actions.

The typed API is:

```text
Cloud.iam_role_get(string name) -> Row
Cloud.iam_role_put(string name, string specification_json, bool apply) -> Row
Cloud.iam_role_delete(string name, bool apply) -> Row
Lambda.wait_active(int timeout_seconds) -> Row
```

The role specification has exactly `trust_policy`, `permissions_boundary`,
`managed_policies` (array of ARNs), and `inline_policies` (name-to-document map).
The public recipe uses `${aws:PrincipalAccount}` in the boundary ARN; the host
resolves it to the caller account before dispatch. Optional customer managed
policies must belong to that account and have root-path names `lmaws_lambda_*`.
Live output is restricted to the ignored `.lmaws-local/iam-role/` directory.

The role is created or updated only through the admin grant path:

```text
AWS_PROFILE=admin LMAWS_LIVE=1 LMAWS_ADMIN_GRANT=1 \
  lmctl recipes/grant_lambda_role.lms --live --profile admin --preview
AWS_PROFILE=admin LMAWS_LIVE=1 LMAWS_ADMIN_GRANT=1 \
  lmctl recipes/grant_lambda_role.lms --live --profile admin --apply
```

Preview is the default and performs a typed validation plus statement-level
diff. The host refuses every trust policy except a single Lambda service
principal, requires the `arn:aws:iam::<account>:policy/lmaws_boundary`
permissions boundary, and accepts only the AWS Lambda basic execution managed
policy plus inline access scoped to `lmaws_` DynamoDB tables, SQS queues and SNS
topics and `lmaws-` S3 buckets. The boundary is mandatory and is not attached as
a managed policy.

The source boundary document is the Lead-owned v1 file at
`~/.aws/session-tools/tasks/iam-snapshots/lmaws-boundary-policy.json`; it is
read for operator verification only and is never edited by this repository.
No account IDs, role ARNs, or live policy documents belong in committed files.

The role remains after a scenario so later Lambda scenarios can reuse it. Role
deletion is a separate explicit admin operation and is not part of normal
Lambda teardown. Live Lambda verification is pending the Lead's PassRole
statement rollout. That statement is intentionally limited to:

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::*:role/lmaws_*",
  "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}
}
```

Only the `lmaws_session` policy context accepts this PassRole exception. IAM
mutations remain forbidden; the explicitly permitted scoped IAM metadata reads
are described by the policy lint API.

## Live verification readiness

The live hello test runs only after the Lead confirms the session-policy rollout
and refreshed `lmaws` credentials. Use `Lambda.wait_active(60)` before invoking;
cleanup is idempotent when both the script and host teardown delete the handle.

[Lambda creates `/aws/lambda/<function-name>` log groups on invocation](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-loggroups.html).
The supplied session-policy snapshot does not cover that namespace for log-group
administration. A zero-leftovers test needs the Lead to approve scoped creation,
tagging and deletion for `/aws/lambda/lmaws_*` as well. Never use admin for the
Lambda test or its cleanup. No extra session-policy grant is applied by this recipe.
