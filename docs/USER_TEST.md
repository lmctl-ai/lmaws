# Local user AWS-agent test procedure (candidate v0.1.1)

Status: live validation is blocked by the configured default profile. Do not treat
this candidate as READY FOR USER TEST until every example has successful live cost
evidence with leftover_count=0. The current profile denies SQS creation and
ssm:PutParameter; IAM ListRoles returns InvalidClientTokenId. The host never edits
IAM users/keys or escalates the profile to overcome these errors.

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

After the patch is published, use a fresh tool cache and ensure an older `lmaws`
is not on PATH. For each example, copy its exact `lmctl autorun` command and expected
cost from README. Each writes its PNG, a new private ledger, and a sanitized
`evidence/live-cost-<example>-<run-id>.json`, and ends with its estimated cost.

```sh
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/sweeper.lms
```

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
