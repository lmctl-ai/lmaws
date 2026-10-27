# IAM cheat sheet for lmaws

Reference guide mapping every `lmaws` capability to its exact IAM statements in
`lmaws_session` (23 statements, `5,292 / 6,144` compact chars), why each
statement is scoped the way it is, the exact `AccessDenied` message when a
statement or condition is missing, and the minimal `PolicyBuilder` fix.

Run the cheat sheet recipe or its synthetic picture example:

```bash
lmctl recipes/policy_cheat_sheet.lms --domain example.com
lmctl examples/recipe_policy_cheat_sheet.lms
```

## 1. Capability -> statements, scoping rationale and failure diagnostics

| Capability | Statement Sids (bytes) | Scoping mechanism | Why it is scoped this way | Failure message when missing | Minimal builder fix |
| --- | --- | --- | --- | --- | --- |
| `read_inventory` | `Reads` (`428`), `PublicParams` (`115`) | `Resource: "*"` for `STAR_READ_ALLOWLIST`; `arn:aws:ssm:*::parameter/aws/service/*` for `PublicParams` | Read/Describe/List metadata actions cannot mutate state or read secret payloads (`s3:GetObject`, `ssm:GetParameter` on user params, `logs:GetLogEvents`, and `acm:GetCertificate` are excluded from `*`). Public AMI lookups only need `/aws/service/*`. | `User: arn:aws:sts::*:federated-user/lmaws is not authorized to perform: ec2:DescribeInstances on resource: * because no session policy allows the ec2:DescribeInstances action` | `policy.read_only_inventory().allow("PublicParams", "ssm:GetParameter", "arn:aws:ssm:*::parameter/aws/service/*")` |
| `named_sandboxes` | `NamedTestResources` (`581`) | ARN name prefix (`lmaws-*` / `lmaws_*`) + `aws:ResourceAccount == ${aws:PrincipalAccount}` | S3, SQS, SNS, DynamoDB, SSM, and CloudWatch Logs support resource-name ARN scoping at creation time. Prefixing names with `lmaws-` or `lmaws_` isolates test resources from non-`lmaws` resources in the account, while `aws:ResourceAccount` blocks cross-account writes. | `User: arn:aws:sts::*:federated-user/lmaws is not authorized to perform: s3:PutObject on resource: "arn:aws:s3:::lmaws-*/obj" because no session policy allows the s3:PutObject action` | `policy.name_prefix("NamedTestResources", "s3,sqs,sns,dynamodb,ssm,logs", "lmaws", "-,_", true)` |
| `ec2_spot_nano` | `RunTagged` (`184`), `RunRefs` (`212`), `RunTaggedSg` (`144`), `CreateSg` (`163`), `OwnEc2` (`386`), `TagOnCreate` (`207`), `NanoOnly` (`188`), `SmallDisks` (`164`), `SgMustBeTagged` (`178`) | `aws:RequestTag/lmaws_test` on instance/volume/sg creation; `RunRefs` on subnet/image/eni/spot-request; `ec2:ResourceTag/lmaws_test` on `RunTaggedSg` & `OwnEc2`; explicit `Deny` when `ec2:InstanceType != [t4g.nano,t3.nano]` or `ec2:VolumeSize > 8` | EC2 assigns random IDs (`i-*`, `vol-*`, `sg-*`) at creation time so name-prefix ARNs cannot gate EC2 writes. Tag-on-create forces instance, volume, and security-group creation to carry `lmaws_test`; `subnet/*`, `image/*`, `network-interface/*`, and `spot-instances-request/*` are in `RunRefs` because AWS SDK / Terraform only tag the instance and volume on launch; `OwnEc2` restricts mutations/deletes (including `RevokeSecurityGroupEgress`) to tagged resources. | `User: arn:aws:sts::*:federated-user/lmaws is not authorized to perform: ec2:RunInstances on resource: "arn:aws:ec2:*:*:instance/*" with an explicit deny in a session policy` | `policy.spot_nano_sandbox("lmaws_test", "t4g.nano,t3.nano", 8)` |
| `static_web_stack` | `CfCreate` (`206`), `CfOwn` (`313`), `CfOac` (`236`), `Route53Names` (`334`), `AcmRequest` (`181`), `AcmOwn` (`260`) | `aws:RequestTag/lmaws_test` on `CfCreate` (`CreateDistribution`, `CreateDistributionWithTags`, `TagResource`) & `AcmRequest`; `aws:ResourceTag/lmaws_test` on `CfOwn` & `AcmOwn` (including `acm:GetCertificate`); Route53 `lmaws-*.<domain>` record conditions | ACM certificates and CloudFront distributions use AWS-generated IDs, so creation requires `RequestTag/lmaws_test` and subsequent reads/updates/deletes require `ResourceTag/lmaws_test` (`acm:GetCertificate` stays tag-scoped in `AcmOwn` rather than `*`). Route53 changes are locked to `lmaws-*.<domain>` `A`/`AAAA`/`CNAME`. | `User: arn:aws:sts::*:federated-user/lmaws is not authorized to perform: acm:GetCertificate on resource: "arn:aws:acm:*:*:certificate/*" because no session policy allows the acm:GetCertificate action` | `policy.static_site_stack("lmaws", "lmaws_test", "example.com", "us-east-1")` |
| `serverless_lambda` | `Fn` (`109`), `Ev` (`91`), `LambdaPassRole` (`174`) | ARN prefix `function:lmaws_*` & `rule/lmaws_*`; `iam:PassRole` on `arn:aws:iam::*:role/lmaws_*` with `iam:PassedToService == lambda.amazonaws.com` | Lambda functions and EventBridge rules are scoped by `lmaws_*` name prefix. Creating a Lambda function also requires passing an execution role via `iam:PassRole`; scoping `PassRole` to `role/lmaws_*` and `iam:PassedToService == lambda.amazonaws.com` prevents privilege escalation to admin roles or other AWS services. | `User: arn:aws:sts::*:federated-user/lmaws is not authorized to perform: iam:PassRole on resource: "arn:aws:iam::*:role/lmaws_*" because no session policy allows the iam:PassRole action` | `policy.lambda_deployer_by_name("lmaws").pass_role_to_service("LambdaPassRole", "lmaws", "lambda.amazonaws.com")` |
| `region_guardrail` | `OnlyUsEast1` (`220`), `S3OnlyUsEast1` (`157`) | Explicit `Deny` with `NotAction: [sts:GetCallerIdentity, cloudfront:*, route53:*]` when `aws:RequestedRegion != us-east-1`; S3 `s3:LocationConstraint != us-east-1` deny | Prevents stray resources and surprise charges in other AWS regions while exempting global control-plane services (`sts`, `cloudfront`, `route53`) whose endpoints do not use regional `us-east-1` requests, and blocks S3 buckets with a non-`us-east-1` `LocationConstraint`. | `User: arn:aws:sts::*:federated-user/lmaws is not authorized to perform: ec2:DescribeInstances on resource: * with an explicit deny in a session policy` | `policy.region_lock("OnlyUsEast1", "us-east-1", "sts:GetCallerIdentity,cloudfront:*,route53:*")` |

## 2. EC2 `RunInstances` 6-sub-resource probe expansion (`simulate_run_instances`)

A single `ec2:RunInstances` API call is evaluated by AWS IAM against **six**
distinct sub-resource ARNs with different condition keys. Calling
`policy.simulate_run_instances(instance_type, volume_gib, tag_key, tag_value, region[, expected])`
expands the launch into all six sub-resource probes and fails the overall launch
if any sub-resource is denied:

| Probe ID | Sub-resource ARN | Condition keys evaluated | Matched `lmaws_session` statement |
| --- | --- | --- | --- |
| `run_instance` | `arn:aws:ec2:<region>:000000000000:instance/i-0demo` | `aws:RequestedRegion`, `ec2:InstanceType`, `aws:RequestTag/<tagKey>` | `RunTagged` (`Allow`) / `NanoOnly` (`Deny` if not `t4g.nano`/`t3.nano`) |
| `run_volume` | `arn:aws:ec2:<region>:000000000000:volume/vol-0demo` | `aws:RequestedRegion`, `ec2:VolumeSize`, `aws:RequestTag/<tagKey>` | `RunTagged` (`Allow`) / `SmallDisks` (`Deny` if `> 8` GiB) |
| `run_subnet` | `arn:aws:ec2:<region>:000000000000:subnet/subnet-0demo` | `aws:RequestedRegion` | `RunRefs` (`Allow`) |
| `run_image` | `arn:aws:ec2:<region>::image/ami-0demo` | `aws:RequestedRegion` | `RunRefs` (`Allow`) |
| `run_network_interface` | `arn:aws:ec2:<region>:000000000000:network-interface/eni-0demo` | `aws:RequestedRegion` | `RunRefs` (`Allow`; implicit ENI is not tagged on launch) |
| `run_spot_instances_request` | `arn:aws:ec2:<region>:000000000000:spot-instances-request/sir-0demo` | `aws:RequestedRegion` | `RunRefs` (`Allow`; implicit spot request is not tagged on launch) |

## 3. Lint read allow-list table (`IamPolicies.READ_ALLOWLIST_TABLE`)

`IamPolicies` enforces read-scoping rules from a reviewable data table
(`IamPolicies.readAllowlistTable()`) where every lint rejection names the exact
rule and allow-list (`[rule=..., allowlist=...]`):

- `STAR_READ_ALLOWLIST`: metadata-only `Describe*` / `List*` / `Get*` actions
  permitted on `Resource: "*"`.
- `TAG_SCOPED_SENSITIVE_READ`: sensitive read actions that are **never** allowed
  on `Resource: "*"` (`acm:GetCertificate` must stay tag-scoped in `AcmOwn`).
- `SSM_PUBLIC_PARAM_ALLOWLIST`: `ssm:GetParameter`, `ssm:GetParameters`,
  `ssm:GetParametersByPath` allowed on `arn:aws:ssm:*::parameter/aws/service/*`.
- `IAM_SCOPED_ROLE_READ_ALLOWLIST`: `iam:GetRole`, `iam:GetRolePolicy`,
  `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:ListRoleTags`
  allowed on `arn:aws:iam::*:role/lmaws_*`.
- `IAM_SCOPED_POLICY_READ_ALLOWLIST`: `iam:GetPolicy`, `iam:GetPolicyVersion`,
  `iam:ListPolicyVersions`, `iam:ListEntitiesForPolicy` allowed on
  `arn:aws:iam::*:policy/lmaws_*`.
- `PASS_ROLE_LAMBDA_ONLY`: `iam:PassRole` allowed only via
  `policy.pass_role_to_service(sid, "lmaws", "lambda.amazonaws.com")` on
  `arn:aws:iam::*:role/lmaws_*` with `StringEquals.iam:PassedToService == "lambda.amazonaws.com"`
  in `lmaws_session`.

## 4. Automatic `AccessDenied` -> minimal builder patch in run evidence

When any AWS SDK call fails with an IAM authorization error (`AccessDenied`,
`AccessDeniedException`, `UnauthorizedOperation`, HTTP `403`), `AwsBackend` and
`CostLedger` automatically parse the error via `PolicyAnalyzer.explainDenial`,
mask all account IDs and concrete resource IDs into ARN wildcards (`lmaws-*` /
`lmaws_*`), extract any condition keys (`aws:RequestTag/...`,
`ec2:InstanceType`, `iam:PassedToService`, etc.), and record the minimal fluent
builder patch in both the `.jsonl` cost ledger (`event: "access_denied_patch"`)
and the run evidence JSON (`access_denied_count`, `access_denied_patch`,
`access_denied_patches`).

## 5. `lmaws_session` size report and lint-valid compaction (`size_report()`)

`policy.size_report()` (included in `recipes/session_policy.lms` `extra_rows`)
reports the compact byte size of each of the 23 statements in `lmaws_session`
(`5,292 / 6,144` chars, `852` bytes of headroom) and verifies three cumulative
compaction strategies that keep `IamPolicies.lint()` valid:

1. `collapse_reads_wildcards`: collapse `Reads` action families into lint-approved
   wildcards (`ec2:Describe*`, `cloudfront:Get*`, `cloudfront:List*`, `logs:Describe*`)
   $\to$ saves **90 bytes** (`5,202 / 6,144`).
2. `merge_identical_resource_condition`: merge statements that share identical
   `Effect`, `Resource`, and `Condition` $\to$ cumulative savings where applicable.
3. `shorten_sids`: shorten statement `Sid`s to compact 2-character codes (`S0`..`SM`)
   while preserving statement structure $\to$ cumulative **287 bytes** saved
   (`5,005 / 6,144`, `1,139` bytes remaining).
