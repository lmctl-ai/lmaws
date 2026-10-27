# Lambda execution role

`grant_lambda_role.lms` manages one pre-built role, `lmaws_lambda_exec`, for the
lmweblab Lambda scenarios. The lmaws session never creates IAM roles and the
policy linter continues to reject role-management actions.

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
