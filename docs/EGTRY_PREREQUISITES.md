# Bounded shared-service prerequisites

These operations support one explicitly authorized deployment, not general IAM or
bucket-policy administration. All writes retain sdk_call's admin, grant, region,
live/apply and local state guards. Dry-run is the default. No release was made.

* CreateSecret accepts only `poc-go-fargate-egtry-origin` in account 254332045686,
  poc=go-fargate, a SecretString `{{env:NAME}}`, and tags. DescribeSecret must return
  ResourceNotFound before both preview and apply. No replacement, PutSecretValue,
  or deletion is exposed. The value is resolved in memory only; request logging,
  receipts and service exceptions cannot reveal it. Secrets Manager stores it as
  intended; local plans/ledgers never store its value.
* Existing IAM adoption accepts only poc-go-fargate-task and poc-go-fargate-exec.
  GetRole verifies the account/ARN and ListRoleTags verifies poc=go-fargate.
  Adoption snapshots all inline policy documents and refuses truncated lists.
  Only PutRolePolicy for the new name egtry-origin-read is allowed; any existing
  inline-policy drift or overwrite is refused. The task policy is exactly one
  Allow s3:GetObject statement over the two approved bucket object ARNs. The exec
  policy is exactly GetSecretValue on the single secret created in this ledger.
  No other fields/statements, wildcard resources (except the explicitly approved
  bucket object suffixes), attach/detach/delete or trust changes are permitted.
* Generic S3 exposes only GetBucketPolicy and bounded PutBucketPolicy on
  www.egtry.com and egtry-v2-254332045686, requiring ExpectedBucketOwner.
  Put takes an extra local-only LmawsPreviousPolicy string, removed before SDK
  transmission. Existing statements and metadata compare equal as canonical JSON
  (including array order); exactly one statement may be appended. It grants the
  CloudFront service principal GetObject over that bucket's objects with one exact
  SourceArn condition naming a distribution created by this ledger, never www's
  E3HQY8QHHHAZP7. The original policy string is saved in the private ledger before
  put, and re-read immediately before transmission; any text drift refuses.

S3 has no atomic conditional PutBucketPolicy. The immediate re-read narrows but
cannot eliminate an external writer's race after that read. Coordinate policy
writers during the apply window. No automatic rollback/deletion is performed.
IAM rollback snapshots preserve prior policies; new grants are retained on stop
rather than deleting policies. A separate validated restore would be needed.

Tests: scripts/test-egtry-prerequisites.py uses loopback AWS protocol fakes and
checks success, dry-run, secret redaction, existing-name refusal, least privilege,
adopted deletion refusal, canonical preservation, provenance and concurrent drift.

## R57 process-scoped secret consumer

`sdk_egtry_secret_apply(secretArn, service, operation, inputJson, stateFile, apply)`
returns a redacted mutation receipt, never a secret value. It accepts only
`arn:aws:secretsmanager:us-east-1:254332045686:secret:poc-go-fargate-egtry-origin-bn8DfF`,
a matching CreateSecret ledger entry, the exact name and tags app=egtry /
poc=go-fargate, and admin with an explicit grant. Preview verifies metadata but
never calls GetSecretValue. Apply reads AWSCURRENT and supplies only the in-memory
`EGTRY_ORIGIN_SECRET` placeholder environment of that single SDK call. It neither
changes the OS environment nor exposes a value to lmcode/lmscript. The map is
cleared on return; JVM strings cannot promise physical memory erasure.

Consumers are limited to CreateRule at the approved listener/priority157 and
CreateDistributionWithTags for egtry-test.egtry.com with two origin-go.lmctl.ai
headers. Placeholders anywhere else are refused. The generic GetSecretValue and
BatchGetSecretValue denylist is unchanged. Secret-bearing errors lose their
cause/message; receipts, plans and ledger contain no value. Each foreground apply
must reconstruct its request from durable bindings, then exit. No persistent
executor shell or process-only state is required. No release was published.
