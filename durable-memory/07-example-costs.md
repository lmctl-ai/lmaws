# Ownership, profiles, teardown and cost

`Sandbox` accepts only fresh run-owned names: `lmaws_<run-id>_...`, or
`lmaws-<run-id>-...` for S3, with `lmaws_test=<run-id>` ownership tags. It forces
creation intents to a new JSONL ledger before requests; updates/deletes require
a run entry and provider-verified tags. Cleanup runs in reverse order on success,
exceptions and shutdown. Failed cleanup remains recoverable, not falsely deleted.
Sweeping (`lmaws --sweep DIR --older-than-hours 0` or `Cloud.sweep`) is local,
dry-run only; it never authorizes deletion of discovered account resources.

Real mutations require `LMAWS_LIVE=1` and active profile exactly `lmaws`.
Profile resolution is AWS_PROFILE, AWS_DEFAULT_PROFILE, then default; real clients
use that named profile. Default is read-only. Use us-east-1; live cost sessions
reject other regions. Do not use admin/agentcore-poc or alter IAM/credentials/
profiles. IAM examples stay skipped under the federated setup. No OIDC or cloud
credentials belong in CI; demo and loopback fakes bypass real credentials only.
The `lmaws` profile is issued by the existing local session helper at
`~/.aws/session-tools/scripts/aws-profile-session.py` from
`~/.aws/session-tools/tasks/iam-snapshots/local-lmaws-session.json`; its session
policy permits both `lmaws_` and `lmaws-` resource names for SQS, SSM, DynamoDB,
SNS and Logs, and `lmaws-` S3 names, with `lmaws_test` ownership tags. STS caps
the combined plaintext inline and managed policy at 2,048 characters, so keep
additions concise and re-issue the session through the same helper when it
expires. Never copy policy
contents, account IDs or credentials into evidence or documentation.

`CostLedger` embeds its us-east-1 price snapshot in each ledger with decimal unit
prices, resource lifetimes in minutes, SDK transmission attempts/retries, billing
units and storage upper bounds. Prices are estimates, vary by region/time and
ignore free-tier credits; no billing or Cost Explorer calls are made. SQS/SNS
payload accounting uses 64 KiB units; DynamoDB writes round to 1 KiB; storage uses
a 30-day month. Cleanup headroom is reserved before another creation/request;
cleanup remains allowed after cap exhaustion.

`LMAWS_MAX_COST_USD` defaults to $0.05 per program/example, with a hard $0.25
ceiling. Sessions share one cost ledger; separate independent autoruns do not
share a cumulative cap. Use the live/comparison campaign harness for a capped
batch. `aws.example` emits sanitized evidence with leftovers, verification and
prices; read-only output is `estimated cost: $0.00`, writes retain fractional
estimates (including denied attempts). Private raw ledgers retain exact resource
IDs for recovery; public output masks account IDs and never includes credentials,
secret values, payload contents or raw SDK errors. See [live results](03-live.md).
