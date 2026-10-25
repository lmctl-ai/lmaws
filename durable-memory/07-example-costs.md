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
