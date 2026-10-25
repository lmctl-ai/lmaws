# Per-example local cost policy (v0.1.1 candidate)

The user replaced earlier OIDC/cost wording: no OIDC or AWS credentials in CI;
default public CI uses fakes only. Local live runs use the configured default AWS
profile, one region (us-east-1 for the cached price table), explicit LMAWS_LIVE=1,
LMAWS_MAX_COST_USD default 0.05 and hard ceiling 0.25.

CostLedger writes price units, current SDK transmission attempts (including retries),
resource lifetimes in fractional minutes, payload/storage upper bounds, cleanup
headroom, cap refusals and totals. It uses exact decimal arithmetic. DynamoDB writes
round attribute/key/value bytes up to 1 KiB; SQS/SNS examples are restricted to 64 KiB.
Storage uses cumulative bytes as an upper bound and a 30-day month. AWS free-tier
credits are deliberately ignored. Prices are a us-east-1 snapshot, vary by region,
and change over time. No Cost Explorer API is called.

Each aws.example(name) session chooses live only with LMAWS_LIVE=1, creates a unique
run ledger, shares a whole-program budget across clients, cleans up in finally,
verifies provider absence, folds the local sweeper, and writes sanitized evidence.
Read-only examples print estimated cost: $0.00 as requested; unrounded micro-costs
remain in evidence. Writes print eight decimal places to preserve tiny estimates.

There are 30 examples: the original 25, S3 bucket_objects, DynamoDB table_items,
SNS topic_publish, log_retention, and the local dry-run sweeper. All metadata
assertions accept sparse/empty real accounts; deterministic fixtures are checked
only in demo mode. Public gallery tests force live mode off.

Current local authorization blocker: SQS CreateQueue returns AccessDenied and
ssm:PutParameter returns AccessDeniedException. IAM ListRoles returns
InvalidClientTokenId. The default profile requires owner-side correction; this
host must not modify IAM users/keys or assume an unauthorized alternative identity.
Two denied queue names were independently checked absent; the denied parameter
was atomically rejected. All recorded evidence currently has zero leftovers.
Do not claim READY FOR USER TEST or successful live coverage for denied examples.

The cost/evidence candidate is isolated on cost-evidence-v011 so the public v0.1.0
README examples stay compatible with their released binary until the patch is ready.

Five-platform candidate CI is green:
https://github.com/lmctl-ai/lmaws/actions/runs/40164020948 .
Source commit 98cdc8af818cfb50ab9f40ce02c1b534b7d0e9ca. All 30 offline examples
pass on JVM/native packaging checks with live mode forced off. See cost-ci-v011.json.

Live validation: 19/30 unique examples passed, all read-only and displaying $0.00.
Four IAM-dependent examples failed; seven write examples are failed or not yet
validated. No actual resources were created in this candidate run, and every
evidence file has zero leftovers. Conservative campaign estimate: $0.00004630.
See evidence/validation-status-v011.json for the complete per-example state.

Do not merge into main or tag v0.1.1 until the owner corrects default-profile access
and all 30 live examples pass. The currently published v0.1.0 and its main examples
remain intact. The candidate native artifacts can be downloaded from the green CI
run and tested locally; public CI must never receive AWS credentials or OIDC.

Concurrent workspace change observed at handoff: origin/main advanced separately
to 50ab570 (implicit standard imports), and a worktree-only compiler pin edit
changes lmctl 0.2.369 to 0.2.420 in .github/workflows/ci.yml. This edit was not made
by the cost lane and is intentionally left untouched/uncommitted. The five green
checks certify the dispatched cost candidate 98cdc8a, not that pending compiler
change. Integrate the newer main/SDK work and rerun checks when resuming; do not
overwrite the concurrent edit or claim the cost branch is merged/released.

## Publishing rule superseded on resume

The user explicitly permits publishing before live testing. The earlier live-only
release gate above is historical and superseded. Merge current main's implicit-std
schema and compiler 0.2.420, validate all five fake-only platforms, then release
v0.1.1. Preserve the 19 measured read-only results; label all other examples as
estimated from price table, not yet measured live. The federated session
awsspot-local-default denied SQS CreateQueue and ssm:PutParameter; IAM ListRoles
returned InvalidClientTokenId. No IAM, credentials, profile or identity changes
are authorized or performed. The user's own AWS agent will validate live later.
