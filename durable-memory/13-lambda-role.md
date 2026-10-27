# Lambda execution role grant

The host exposes guarded `iam_role_get`, `iam_role_put` and `iam_role_delete`
calls for the one reusable `lmaws_lambda_exec` role. Reads and previews are
safe; applying or deleting requires the admin profile, `LMAWS_LIVE=1`,
`LMAWS_ADMIN_GRANT=1` and `--apply`. The ordinary `lmaws` session cannot create
roles.

Role validation is deliberately narrow: Lambda is the only trusted service,
the v1 `lmaws_boundary` permissions boundary is mandatory, the AWS Lambda
basic execution policy is the only AWS managed policy, and the inline policy
is limited to prefixed DynamoDB, SQS, SNS and S3 resources. The boundary source
is the Lead-owned `~/.aws/session-tools/tasks/iam-snapshots/lmaws-boundary-policy.json`;
the repo never edits or commits that file.

`recipes/grant_lambda_role.lms` previews a typed diff and lint report, then can
apply the role. It writes live output only under ignored
`.lmaws-local/iam-role/`. The role is retained for reuse by lmweblab scenarios;
normal Lambda teardown does not delete it.

The exact PassRole exception accepted in `lmaws_session` is:

```json
{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::*:role/lmaws_*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}
```

Missing, widened, extra-condition, wrong-service, wrong-resource, mixed-action,
or any other `iam:` statements fail lint. Live Lambda create/invoke/delete
verification remains pending the Lead's policy rollout; tests use synthetic or
loopback transports only until then.
