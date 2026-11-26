# Adopting existing shared resources for bounded updates

`cloud.sdk_adopt_existing(service, id, poc, statePath, record)` performs only
read-only AWS identity/tag checks. `record=false` previews; `record=true` records
an adopted entry in the private local ledger. It never claims the resource was
created by this run and never changes AWS tags or resources. It requires the
admin profile and LMAWS_ADMIN_GRANT=1. The caller must explicitly authorize the
particular existing resource outside this library.

Supported existing resources are exact same-account us-east-1 ECS service ARNs
and exact EC2 security-group IDs. They must already carry `poc=<poc>` verified
live. Adoption enables only `ecs:UpdateService` or
`ec2:AuthorizeSecurityGroupIngress` respectively, with the normal sdk_call
apply/region/profile/live/tag guards. Adopted entries never authorize deletes,
even when the deletion operation exists for resources created by a run.
Preview writes no ledger. Repeated recording is idempotent. Use the same exact ARN
or group ID in update input; short-name aliases are intentionally not adopted.

This supports a shared Fargate service created before the SDK ledger existed;
never fabricate creation records to bypass ownership checks. Service rollout and
rollback are both UpdateService operations and both can replace running tasks.
Read and preserve the full current service/task state and review a true diff first.

SDK read output redacts ALB HttpHeaderConfig.Values, including arbitrary origin
header names, and environment secret values with case-insensitive Name/Value keys.
A redacted task definition must not be used to recreate existing containers.

Validation: scripts/test-sdk-call.py runs 47 checks against a loopback AWS fake,
including preview/record, wrong account/profile/tag, permitted update preview and
refused deletion for adopted resources. SdkCallRedactionChecks checks headers and
case-insensitive environment redaction without any network access.
