# Local AWS profile test procedure (latest release)

New here? Start with the one-command [quickstart](../README.md#quickstart), check [which profile you need](PROFILES.md) and the [troubleshooting table](TROUBLESHOOTING.md).

READY FOR USER TEST. All 26 live native/lmcloud pairs completed using lmcloud
v0.1.10 and AWS provider 5.100.0: eight comparisons match and 18 retain explicit
output or local-state differences. Four IAM examples remain estimated only and
must be skipped. No lmcloud core patch was needed.
See [RESULTS](../compare/RESULTS.md), [campaign costs](../evidence/comparison-campaign-v013.json)
and [independent cleanup proof](../evidence/comparison-cleanup-v013.json).

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
export LMSCRIPT_TOOL_CACHE="$PWD/.tools-lmaws-v013"
```

`default` is READ-ONLY and is used for all inventories and independent deletion
checks. Only `lmaws` may create/update/delete; the native host and comparison
runtime reject other profiles for writes. The host never edits IAM, credentials or
profiles. The `lmaws` profile is a federated session issued by the existing local
session tooling. The policy file is `~/.aws/session-tools/tasks/iam-snapshots/local-lmaws-session.json`.
For SQS, SSM, DynamoDB, SNS and CloudWatch Logs it allows run-owned `lmaws_` and
`lmaws-` names; S3 buckets and objects use `lmaws-` because underscores are not
valid in bucket names. The `lmaws_test` ownership tag is required for mutable
resources. IAM examples remain skipped because federated sessions cannot call IAM.

The session policy is assembled by the existing tooling at
`~/.aws/session-tools/scripts/aws-profile-session.py` from that local task policy
and is re-issued there when a session expires. AWS STS limits the combined
plaintext inline and managed session policy to 2,048 characters; keep the
service/action/resource patterns concise and scoped to these prefixes. Do not copy account IDs, tokens or
policy contents into this repository, and never use the admin profile to run an
example. S3 bucket names cannot contain underscores, so S3 always uses `lmaws-`.
See the [STS federation policy limits](https://docs.aws.amazon.com/cli/latest/reference/sts/get-federation-token.html)
for the plaintext policy and packed-size limits.

The external AWS provider performs its own metadata reads; the existing lmaws
profile is used for the write comparison while `default` independently checks
absence after teardown.

The host applies ownership tags and verifies the exact run ID, prefix and ledger;
S3 tagging occurs after bucket creation. The four IAM examples are offline-only:
federated sessions cannot call IAM. No profile repair or identity switching is
part of this test.

AWS references: [SQS actions and tag conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sqs.html),
[S3 operation permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
(`HeadObject` uses `s3:GetObject`; `HeadBucket` uses `s3:ListBucket`).


## Native autoruns: exact profile for each example

S3 `bucket_objects` and the six lifecycle examples report measured price-table
estimates in the evidence files; each is independently absent after cleanup.
The six new measurements are: `before_after` $0.00000400,
`queue_pipeline` $0.00000360, `sandbox_lifecycle` $0.00000000,
`table_items` $0.00000063, `topic_publish` $0.00000450 and `log_retention`
$0.00000000. Read-only examples print $0.00. Default per-example cap $0.05;
hard run ceiling $0.25.

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
# Install/download the latest release executable into target/lmaws, verify SHA256SUMS.
LMAWS_LIVE=1 AWS_PROFILE=lmaws python3 scripts/test-live-examples.py --host target/lmaws --example bucket_objects
# Reuse the successful native proof to avoid repeating its creation.
# The six write examples can be run once with AWS_PROFILE=lmaws after re-issuing the
# federated session; do not repeat writes merely to refresh screenshots.
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
The new campaign created six native lifecycle parents and twelve provider
lifecycle parents across the initial local-build and corrected published-binary
passes: queues, parameters, tables/items, topics and log groups. All were deleted.
Two naming preflight rejects created nothing. Conservative accounting is
$0.03503065000042, below $0.25, including fourteen provider-plan allowances and
reused-native accounting. Provider request counts are not measured.

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
cleanup. No automated sweeper deletes resources. The current six-example campaign's
native and provider lifecycle resources were all independently verified absent;
the earlier bucket/object proof remains retained baseline evidence. Its
conservative total was $0.03503065000042, including both provider verification
passes and metadata checks. Prices vary by region and time; no Cost Explorer request was made.

Comparison scripts pin lmcloud v0.1.10 for reproducibility. Its provider installer
and single-number version output work; the former v0.1.9 blockers are resolved.
Set a scratch `TF_PLUGIN_CACHE_DIR` before comparisons to reuse the ~676 MiB
provider. Results describe observed resources and selected numeric outputs,
not complete API parity. No cloud credentials or OIDC belong in public CI.


## Read-only spend report

The new eight spend examples are synthetic by default. See
[SPEND_REPORT.md](SPEND_REPORT.md) for the separate default-profile live opt-in,
private output directory, CE/metric query cap and pricing assumptions. Never
commit real report contents or pictures; this guide contains no live spend values.

## Compute recipes and the spot nano lifecycle (v0.1.5)

Read-only compute recipes use `default`; the AMI lookup and the lifecycle use the separate
`lmaws-ec2` federated profile (EC2 spot nano only, us-east-1, `lmaws_test` tags at creation; see
[durable-memory/10-compute.md](../durable-memory/10-compute.md)). From a checkout or with the
released host on PATH:

```sh
lmctl recipes/fleet_status.lms --live --profile default --tag-key Project --tag-value YOUR_PROJECT
lmctl recipes/cpu_credits.lms --live --profile default --tag-key Project --tag-value YOUR_PROJECT --hours 24
lmctl recipes/eip_map.lms --live --profile default
lmctl recipes/spot_prices.lms --live --profile default --types t4g.nano,t3.nano --hours 3
lmctl recipes/ebs_roots.lms --live --profile default
lmctl recipes/ami_lookup.lms --live --profile lmaws-ec2
lmctl recipes/spot_nano_lifecycle.lms --preview
lmctl recipes/spot_nano_lifecycle.lms --live --apply --profile lmaws-ec2   # run once
```

Expected lifecycle output: the plan (cheapest eligible AZs, max price at most On-Demand), the
attempts (a capacity refusal falls back to the next candidate), running within seconds, status
checks ok in about two minutes, `stop: UnsupportedOperation` (one-time spot instances cannot be
stopped), terminated, the spot cost (well below $0.05) and `leftovers: 0`. Reports, ledgers and
evidence stay in the git-ignored `.lmaws-local/`. If EC2 leaves the one-time request
active after termination and the session policy does not allow `ec2:CancelSpotInstanceRequests`,
the recipe reports `denied by the session policy` and exits nonzero; rerun teardown later with
`cloud.spot_recover("<run id>")` (needs the local spot ledger). Never use these recipes against
instances that do not carry this run's `lmaws_test` tag; the host refuses them.

## IAM managed-policy workflow (`lmaws_session`, v0.1.6)

Inline STS session policies are capped at 2,048 characters, whereas customer-managed IAM policies
support up to 6,144 compact characters. `lmaws` includes a typed, linted customer-managed policy API
(`iam_policy_lint`, `iam_policy_get`, `iam_policy_versions`, `iam_policy_put`, `iam_policy_delete`)
restricted to policy names matching `^lmaws_[a-z0-9_-]{1,64}$`.

- **Offline lint** of any local policy JSON file (`$0.00`, no AWS calls):
  ```sh
  lmctl recipes/policy_lint.lms --policy-file ~/.aws/session-tools/tasks/iam-snapshots/lmaws-managed-policy.json
  ```
- **Dry-run diff** against the current default version of `lmaws_session` (default mode without `--apply`):
  ```sh
  AWS_PROFILE=admin lmctl recipes/grant_session_policy.lms --live --profile admin --policy-name lmaws_session --policy-file ~/.aws/session-tools/tasks/iam-snapshots/lmaws-managed-policy.json
  ```
- **Apply a managed policy grant** (`admin` is permitted ONLY for `lmaws_` IAM policy writes when `LMAWS_ADMIN_GRANT=1`, `--apply`, and `--live` are all set; `admin` is refused for every other mutating call, and `lmaws`/`lmaws-ec2` are refused for IAM policy writes):
  ```sh
  AWS_PROFILE=admin LMAWS_ADMIN_GRANT=1 lmctl recipes/grant_session_policy.lms --live --apply --profile admin --policy-name lmaws_session --policy-file ~/.aws/session-tools/tasks/iam-snapshots/lmaws-managed-policy.json
  ```
  `lmaws_session` (5,290 compact characters, 23 statements, 0 lint findings) is generated byte-for-byte by `recipes/session_policy.lms`, applied live, and verified with `0` diff against the live default policy version. The additional statement permits `iam:PassRole` only for `lmaws_*` roles when Lambda is the passed service.

## Fluent Permission Builder, compaction, denial analysis and IAM simulator (v0.1.12)

Instead of hand-editing raw IAM JSON, use `recipes/session_policy.lms` and the 27 permission builder recipes in `recipes/lib/policy_builder.lms`:

```sh
# Generate the 22-statement lmaws_session policy and compare against a snapshot file ($0.00 offline):
lmctl recipes/session_policy.lms --domain example.com --file ~/.aws/session-tools/tasks/iam-snapshots/lmaws-managed-policy.json
# Compact a multi-statement policy into the 2,048-char STS inline session limit:
lmctl recipes/policy_fit_inline.lms --prefix lmaws
# Split a large policy into balanced <= 6,144-char managed parts while keeping Deny guardrails:
lmctl recipes/policy_split_managed.lms --domain example.com
# Diagnose an AWS AccessDenied message and emit a minimal builder snippet:
lmctl recipes/policy_explain_denial.lms
# Synthesize least-privilege IAM permissions from observed run ledgers:
lmctl recipes/policy_from_ledger.lms
# Evaluate allow/deny security probes offline or live via IAM SimulateCustomPolicy (admin profile required live):
lmctl recipes/policy_simulate_probes.lms
AWS_PROFILE=admin lmctl recipes/policy_simulate_probes.lms --live --profile admin
```

## Native `credential_process` and `session_doctor`

`lmaws --credential-process <mode>` needs no AWS CLI or Python. It reads only static credentials from the selected source profile (`--source-profile NAME` / `LMAWS_CREDENTIAL_SOURCE_PROFILE`, default `agent-issuer`), ignoring ambient credentials, recursive helpers, roles, SSO and metadata. Names containing `admin` are refused unless a human explicitly sets `LMAWS_ALLOW_ADMIN_SOURCE=1`; agents never use admin. All modes use `awsspot-local-<mode>` and 3,600 seconds. Owner-only caches are scoped to the source credentials and policy contents and expire five minutes early.

- `default`: actual inline policy from `--policy-file PATH`, `LMAWS_DEFAULT_SESSION_POLICY`, or `~/.aws/session-tools/tasks/iam-snapshots/local-default-session.json`, plus `ReadOnlyAccess`. Combined compact policy and ARN length must be <=2,048; unavailable/malformed/oversized policies fail closed.
- `lmaws`, `lmaws-ec2`, `lmaws-web`: `arn:aws:iam::<source-account>:policy/lmaws_session`, resolved using the source's STS identity, without an inline policy.

The helper never changes AWS resources or permissions. See [PROFILES.md](PROFILES.md).

Install the native binary at `~/.local/bin/lmaws` on Linux/macOS and `%USERPROFILE%\.local\bin\lmaws.exe` (`C:\Users\<user>\.local\bin\lmaws.exe`) on Windows, then configure `~/.aws/config`:

```ini
[default]
region = us-east-1
credential_process = lmaws --credential-process default

[profile lmaws]
region = us-east-1
credential_process = lmaws --credential-process lmaws

[profile lmaws-ec2]
region = us-east-1
credential_process = lmaws --credential-process lmaws-ec2

[profile lmaws-web]
region = us-east-1
credential_process = lmaws --credential-process lmaws-web
```

Verify profile session resolution, `0600` cache expiry/TTL, caller identity, and dry-run/read-only effective permission & guardrail probes without creating any resources:

```sh
lmctl recipes/session_doctor.lms --live --profile lmaws
lmctl recipes/session_doctor.lms --live --profile default
```
