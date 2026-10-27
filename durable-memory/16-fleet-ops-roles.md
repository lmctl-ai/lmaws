# Fleet operational instance roles ("No agent holds admin")

## Core invariant

Agents and EC2 instance metadata roles must never hold or create admin permissions:

- **Instance roles (`awsspot-ops-t4g1`, `awsspot-ops-t4g2`)**: hold only the exact operational permissions needed for `t4g1` (`Role=current`) and `t4g2` (`Role=m7g`) to do their job, capped by a mandatory permissions boundary (`awsspot-ops-boundary`).
- **Federated agent sessions (`default`, `lmaws`, `lmaws-ec2`, `lmaws-web`)**: issued via `sts:GetFederationToken`, which AWS structurally blocks from calling `iam:*` and caps to `ReadOnlyAccess` or `lmaws_session`.
- **Human admin (`AWS_PROFILE=admin`)**: used only from the operator workstation when a human explicitly runs a grant recipe with `LMAWS_ADMIN_GRANT=1`, `--live`, `--apply`, and `--i-am-the-admin-human`.

## Read-only discovery via `AWS_PROFILE=default`

Running `LMAWS_LIVE=1 AWS_PROFILE=default lmctl recipes/fleet_roles.lms --live --profile default` discovers the live fleet posture using only read APIs:

1. **EC2 instance & association discovery (`allowed`)**: `ec2:DescribeInstances` and `ec2:DescribeIamInstanceProfileAssociations` confirm both `t4g1` (`Role=current`) and `t4g2` (`Role=m7g`) currently use instance profile `awsspot-admin` (`association_state=associated`). All concrete IDs (`i-*`, `iip-assoc-*`, 12-digit account ID) are masked by `FleetRoles.maskFleetIds`.
2. **CloudTrail 30-day management-event evidence (`allowed`)**: `cloudtrail:LookupEvents` over 30 days by EC2 role session username (`i-*`) succeeds with `AWS_PROFILE=default` and confirms the real operational call surface:
   - `t4g1`: `ssm:UpdateInstanceInformation` (295), `ssm:ListInstanceAssociations` (126), `ec2:DescribeAddresses` (76), `cognito-idp:ListUsers` (70), `ec2:AssociateAddress` (68 `Client.DryRunOperation` + 26 `OK`), `secretsmanager:GetSecretValue` (43), `kms:Decrypt` (43), `secretsmanager:ListSecrets` (2), `cloudfront:CreateInvalidation` (1).
   - `t4g2`: `ssm:UpdateInstanceInformation` (406), `ssm:ListInstanceAssociations` (175), `secretsmanager:GetSecretValue` (60), `kms:Decrypt` (60), `cognito-idp:ListUsers` (44), `ec2:DescribeAddresses` (3), `ec2:DescribeInstances` (1), `sts:GetCallerIdentity` (1).
3. **IAM role/policy read (`denied for federated principal`)**: `sts:GetFederationToken` sessions cannot call `iam:GetRole` (`InvalidClientTokenId` / access denied), so the recipe pairs live EC2 + CloudTrail discovery with the verified snapshots in `tasks/iam-snapshots/`.

## Operations needs model (`FleetRoles.opsNeedsTable()`)

| Operation | Instances | Exact IAM actions | Resource & condition scoping |
| --- | --- | --- | --- |
| `self_stop_watchdog` | `t4g1`, `t4g2` | `ec2:StopInstances` | `arn:aws:ec2:us-east-1:${aws:PrincipalAccount}:instance/*` conditioned on `aws:ResourceTag/Project=awsspot`, per-instance `Role` (`current` vs `m7g`) & `Name` (`t4g1` vs `t4g2`), and `aws:RequestedRegion=us-east-1` |
| `fleet_status_and_cpu_monitor` | `t4g1`, `t4g2` | `sts:GetCallerIdentity`, `ec2:DescribeInstances`, `ec2:DescribeInstanceStatus`, `ec2:DescribeInstanceAttribute`, `ec2:DescribeInstanceCreditSpecifications`, `ec2:DescribeInstanceTypes`, `ec2:DescribeVolumes`, `ec2:DescribeAddresses`, `ec2:DescribeTags`, `cloudwatch:GetMetricData` | `*` conditioned on `StringEqualsIfExists aws:RequestedRegion=us-east-1` |
| `ssm_public_ami_lookup_and_agent_heartbeat` | `t4g1`, `t4g2` | `ssm:GetParameter`, `ssm:GetParameters`, `ssm:UpdateInstanceInformation`, `ssm:ListInstanceAssociations`, `ssm:ListAssociations` | `arn:aws:ssm:us-east-1::parameter/aws/service/canonical/ubuntu/*` for parameter reads; `*` in `us-east-1` for `snap.amazon-ssm-agent` heartbeat |
| `website_deploy_assume_role` | `t4g1`, `t4g2` | `sts:AssumeRole` | `arn:aws:iam::${aws:PrincipalAccount}:role/lmctl-website-deploy` only |
| `s3_www_egtry_com_sync` | `t4g1`, `t4g2` | `s3:ListBucket`, `s3:GetBucketLocation`, `s3:GetObject*`, `s3:PutObject*`, `s3:DeleteObject*`, `s3:AbortMultipartUpload` | `arn:aws:s3:::www.egtry.com` and `arn:aws:s3:::www.egtry.com/*` |
| `codecommit_repo_sync_no_delete` | `t4g1` | `codecommit:GitPull`, `codecommit:GitPush`, `codecommit:Get*`, `codecommit:List*` | `arn:aws:codecommit:us-east-1:${aws:PrincipalAccount}:*` + explicit `Deny` on `DeleteRepository`, `DeleteBranch` |
| `secrets_manager_read_only` | `t4g1`, `t4g2` | `secretsmanager:ListSecrets`, `secretsmanager:GetSecretValue`, `secretsmanager:DescribeSecret`, `kms:Decrypt` | `arn:aws:secretsmanager:us-east-1:${aws:PrincipalAccount}:secret:*` + `kms:Decrypt` conditioned on `kms:ViaService=secretsmanager.us-east-1.amazonaws.com` |
| `cognito_user_pools_non_destructive` | `t4g1`, `t4g2` | `cognito-idp:ListUserPools`, `DescribeUserPool`, `ListUsers`, `AdminGetUser`, `AdminCreateUser`, `AdminSetUserPassword` | `aws:RequestedRegion=us-east-1`, `aws:ResourceAccount=${aws:PrincipalAccount}` + unconditional `Deny` on `cognito-idp:*Delete*`, `ForgetDevice`, `AdminForgetDevice` |
| `ec2_origin_and_region_guardrails` | `t4g1`, `t4g2` | `Deny NotAction sts:GetCallerIdentity` when `Null ec2:SourceInstanceArn=true`; `Deny NotAction sts:*,s3:*,cloudfront:*` when `aws:RequestedRegion!=us-east-1` | Blocks off-instance credential use and non-`us-east-1` regions |

## Dedicated instance-role lint (`IamPolicies.lintInstanceRole`)

Rather than weakening `IamPolicies.lint` (which enforces `lmaws-*`/`lmaws_*` prefix and `lmaws_test` tag rules for `lmaws_session`), `IamPolicies.lintInstanceRole` (`cloud.iam_policy_lint_instance_role(doc)` / `policy.lint_instance_role()`) validates operational EC2 instance roles and boundaries with dedicated rule IDs:

- `INSTANCE_ROLE_NO_ADMIN_WILDCARD`: rejects `*`, `iam:*`, `ec2:*`, `s3:*`, `sts:*`, `kms:*`, `secretsmanager:*`.
- `INSTANCE_ROLE_FORBIDDEN_ESCALATION`: rejects `iam:*` (including `iam:PassRole`), `organizations:*`, `account:*`, KMS key mutations or unscoped `kms:Decrypt`, `ec2:TerminateInstances`, `ec2:DeleteVolume`, `ec2:ReleaseAddress`, `ec2:AssociateAddress`, `ec2:RunInstances`, `ec2:StartInstances`, `ec2:ReplaceIamInstanceProfileAssociation`, and `cloudtrail:*` / `config:*` audit tampering.
- `INSTANCE_ROLE_SELF_STOP_SCOPED`: requires `ec2:StopInstances` to be tag-scoped to `Project=awsspot`, `Role`/`Name`, and `us-east-1`.
- `INSTANCE_ROLE_WEBSITE_ASSUME_SCOPED`: restricts `sts:AssumeRole` to `role/lmctl-website-deploy`.
- `INSTANCE_ROLE_WWW_S3_SCOPED`: restricts S3 access to `arn:aws:s3:::www.egtry.com` and `arn:aws:s3:::www.egtry.com/*`.
- `INSTANCE_ROLE_CODECOMMIT_NO_DELETE`, `INSTANCE_ROLE_SECRETS_READ_ONLY`, `INSTANCE_ROLE_COGNITO_NO_DELETE`, and `INSTANCE_ROLE_ORIGIN_AND_REGION_GUARD`.

## Sequential 1-by-1 apply, verification, and one-command rollback

```sh
# 1. Dry-run plan (default, offline)
lmctl recipes/fleet_roles.lms

# 2. Live read-only discovery + plan (AWS_PROFILE=default)
LMAWS_LIVE=1 lmctl recipes/fleet_roles.lms --live --profile default

# 3. Human-admin apply (swaps t4g1 first, verifies via read APIs, then swaps t4g2)
LMAWS_ADMIN_GRANT=1 lmctl recipes/fleet_roles.lms --live --apply --profile admin --i-am-the-admin-human

# 4. One-command rollback (restores t4g2 then t4g1 from recorded association snapshot)
LMAWS_ADMIN_GRANT=1 lmctl recipes/fleet_roles.lms --live --apply --profile admin --i-am-the-admin-human --rollback .lmaws-local/fleet-roles/fleet_roles.rollback.json
```
