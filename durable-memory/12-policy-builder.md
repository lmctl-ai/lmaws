# Permission builder and IAM analysis (v0.1.12)

Raw AWS IAM JSON is error-prone and constrained by the 2,048-char STS inline
session limit and 6,144-char managed policy limit. `lmaws` provides a typed
fluent Permission Builder (`PolicyBuilder`, `PolicyCatalog`, `PolicyAnalyzer`,
`PolicySimulator`) exposed as the `Policy` host object (`cloud.policy(name)`)
and 12 `Cloud` helper methods.

## Typed builder and action catalog

- `PolicyCatalog` bundles curated actions across 23 AWS services (`sts`, `s3`,
  `ec2`, `sqs`, `sns`, `dynamodb`, `logs`, `ssm`, `route53`, `cloudfront`,
  `acm`, `lambda`, `events`, `ecs`, `cloudwatch`, `ce`, `savingsplans`,
  `pricing`, `cloudformation`, `secretsmanager`, `kms`, `iam`,
  `resource-groups`, `tag`), classifies each action (`list`, `read`, `write`,
  `tagging`, `permissions_management`), expands wildcards (`ec2:Describe*`),
  rejects unknown service prefixes or action typos with Levenshtein suggestions,
  provides account-less/region-less ARN templates (`policy.arn(service, type, pattern)`),
  and maps SDK ledger operations (`s3.CreateBucket`) to IAM actions.
- Intent helpers compile directly to IAM `2012-10-17` statements and conditions:
  `name_prefix`, `require_tag_on_create`, `only_tagged`, `tag_on_create_actions`,
  `deny_untagged_create`, `deny_delete_unless_tagged`, `region_lock`,
  `instance_types`, `max_volume_gib`, `route53_names`, `cidr_only`,
  `mfa_required`, `time_window`, `source_ip`.
- Composable building blocks: `read_only_inventory`, `s3_bucket_sandbox`,
  `queue_sandbox`, `topic_sandbox`, `table_sandbox`, `parameter_sandbox`,
  `log_group_sandbox`, `spot_nano_sandbox`, `static_site_stack`,
  `billing_viewer`, `lambda_deployer_by_name`, `ci_bucket_deployer`,
  `permission_boundary`, `lmaws_session_policy`, `merge_from`.

## Compaction, analysis and simulation

- `fit_inline()`: compacts a multi-statement policy to fit the 2,048-char STS
  inline limit (drops Sids, merges statements with identical Effect+Action+Condition
  or Effect+Resource+Condition, collapses prefix wildcards) and reports saved
  and remaining bytes.
- `split_managed()`: splits policies into balanced `<= 6,144`-char managed parts
  while retaining global and service-specific `Deny` guardrails on every part
  that needs them.
- `explain()` and `matrix()`: plain-English per-statement explanations, risk
  flags (`wildcard_write`, `missing_region_lock`, `missing_tag_gate`), and
  `service x action_class x scope` matrix rows.
- `explain_denial(error_text)`: parses `AccessDenied` messages, masks account IDs,
  identifies `explicit_deny` vs `implicit_deny` and failing conditions, and
  emits a minimal fluent builder snippet.
- `policy_from_ledger(paths)` and `policy_import_json(raw_json)`: synthesize
  least-privilege policies from observed run ledgers or migrate existing IAM JSON
  into fluent builder code.
- `policy_simulate` and `policy_simulate_principal`: evaluate probe tables
  (`action|resource|k=v|expected`) deterministically offline or live via AWS IAM
  `SimulateCustomPolicy` / `SimulatePrincipalPolicy` (`AWS_PROFILE=admin` required live).

## Dogfood and recipes

`recipes/session_policy.lms` generates the 22-statement `lmaws_session` managed
policy (`5,109` compact chars) byte-for-byte identically (`+0 ~0 -0 =22`,
`byte_identical=true`) to `~/.aws/session-tools/tasks/iam-snapshots/lmaws-managed-policy.json`
and `grant_session_policy.lms --live --profile admin` confirms `0` diff against
the live default policy version. 27 recipes in `recipes/lib/policy_builder.lms`
and matching synthetic picture-first examples (`examples/recipe_*.lms`) cover
all building blocks, compaction, splitting, denial/ledger analysis, diffing,
simulation and migration.
