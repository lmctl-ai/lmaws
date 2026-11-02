# `lmaws` Go Port Findings (Shared `lmcloud` Schema, Built on `lmcloud/hostkit`)

## 1. Coexistence of Shared `lmcloud` Schema and Legacy `lmaws` Surface

- Following the multi-schema host pattern (`~/lmctl-mono/lmscript/durable-memory/dsl-framework.md` and the `lmoci` Go port pilot), `lmaws` supports subcommand routing:
  - `lmaws cloud --lmcode FILE | --lmcode-schema [--json] | --lmcode-signatures [--without-std]` selects the shared provider-neutral `lmcloud` schema (`github.com/lmctl-ai/lmcloud/schema.Bytes`, verified against `schema/lmcloud.dsl.json` and `lmcloud.lock`).
  - During the Go port (Phases A–C), top-level `lmaws --lmcode ... | --lmcode-schema | --lmcode-signatures` also serves the shared `lmcloud` schema so conformance harnesses invoking `<host> --lmcode $DSLFILE` run unchanged.
  - All 82 Java source files and `pom.xml` remain untouched in place while the legacy 223-method surface is scheduled for a subsequent phase.

## 2. `hostkit` Migration (`hostkit-port`)

- `lmaws` migrated onto `github.com/lmctl-ai/lmcloud/hostkit`, `hostkit/cloudhost`, `hostkit/invoke`, `hostkit/fakeadapter`, and `github.com/lmctl-ai/lmcloud/schema`:
  - Deleted duplicated provider-neutral packages from `lmaws`: `internal/invoke/`, `internal/host/`, `internal/safety/`, and `schema/schema.go`.
  - All provider-neutral responsibilities—argument validation, metadata key regex enforcement, error state and `[CODE] op (target): msg (http=N, provider_code=X)` abort formatting, `last_error()`, endpoint resolution/validation, bounded retry policy (3 attempts on `429, 500, 502, 503, 504`, `Retry-After` up to 2s), `object_list_all` / `queue_list` pagination with stalled-token detection, queue payload wire encoding (`__lmcloud_empty__`, `__lmcloud_b64__`), receipt error precedence, dry-run short-circuiting, and secret redaction—now live exclusively in `hostkit`.
  - `internal/aws` implements `hostkit.ObjectStore` and `hostkit.Queue` with AWS SDK v2 (`github.com/aws/aws-sdk-go-v2/service/s3` and `service/sqs`) with SDK retries disabled (`RetryMaxAttempts: 1`, `aws.NopRetryer{}`) so `hostkit.RetryPolicy` is the single retry layer.

## 3. SIM/FAKE ONLY Enforcement & Endpoint Routing

- `aws.Endpoints()` registers prefix `"LMAWS"` and native environment variables `AWS_ENDPOINT_URL_S3`, `AWS_ENDPOINT_URL_SQS`, and `AWS_ENDPOINT_URL`.
- `hostkit.EndpointResolver` rejects any plain `http://` non-loopback endpoint (`0.0.0.0`, `127.0.0.1.evil.example`, RFC1918 addresses) pre-flight with `ErrorCode.INVALID_ARGUMENT` (`http_status == 0`) before any network traffic.
- `Adapter.route(ctx)` routes:
  - `""` with `LMAWS_LIVE != "1"` -> `hostkit/fakeadapter` (in-process offline fake).
  - Loopback URL (`127.0.0.1`, `::1`, `localhost`) -> `internal/aws` remote adapter (`awssim`).
  - `LMAWS_LIVE == "1"` or any non-loopback `https://` endpoint -> `ErrorCode.UNAUTHENTICATED` (`ProviderCode: "LiveCredentialsNotImplemented"`), never sending simulator credentials (`test`/`test`) off-host.

## 4. AWS-Specific Adapter Semantics & Compatibility Middleware

1. **`LMAWS_COMPAT_STRIP_S3_XID` / `stripS3XIDMiddleware` Compatibility Option & Removal Condition:**
   - `github.com/aws/aws-sdk-go-v2/service/s3` serializes `?x-id=<Operation>` (`PutObject`, `GetObject`, `DeleteObject`, `ListBuckets`, etc.) onto S3 request URLs.
   - Pre-`dc7b063` released `awssim` binaries reject `?x-id=` in `--auth enforce` mode because `x-id` was not in `AuthFilter.S3_QUERY`.
   - `internal/aws/remote.go` isolates `stripS3XIDMiddleware` behind `Options.StripS3XID *bool` and environment variable `LMAWS_COMPAT_STRIP_S3_XID` (defaulting to enabled; set `LMAWS_COMPAT_STRIP_S3_XID=0` or `false` to disable).
   - **Exact removal condition:** Delete `Options.StripS3XID`, `stripS3XIDEnabled()`, and `stripS3XIDMiddleware` in `internal/aws/remote.go` once an `awssim` release containing commit `dc7b063` (branch `fix-sdk-compat`, which adds `"x-id"` and `"fetch-owner"` to `AuthFilter.S3_QUERY` and `ChangeMessageVisibility`/`PurgeQueue`/`SetQueueAttributes` to `SUPPORTED.get("sqs")`) is published and pinned by `lmcloud/scripts/sims.lock`.
   - Verified in `test-go.sh` Step 11: against the JVM build of `awssim` (`dc7b063`) in `--auth enforce` mode with **`LMAWS_COMPAT_STRIP_S3_XID=0`**, all 12 object-storage and 13 queue conformance scenarios pass with **0 skips (`25/25`)**.
2. **S3 `us-east-1` `CreateBucket` Idempotency (H3) & S3 `HEAD` 403 Classification (H2):**
   - Because S3 in `us-east-1` returns `200 OK` when re-creating an already-owned bucket, `CreateBucket` probes `HeadBucket` first and returns `(false, nil)` when `HeadBucket` succeeds (`200 OK`).
   - When `HeadBucket` returns `403` or `404`, `CreateBucket` falls through to `CreateBucket` (`PUT /{bucket}`, body-bearing), classifying `InvalidAccessKeyId`/`SignatureDoesNotMatch` (`UNAUTHENTICATED`) vs `AccessDenied` (`PERMISSION_DENIED`) from the XML error body.
   - On `HeadBucket` and `HeadObject`, if a `403` response lacks an explicit `X-Amzn-Errortype` header (as real S3 `HEAD` responses have no body), the adapter issues a body-bearing fallback probe (`GetBucketLocation` for `HeadBucket`, ranged `GetObject` `bytes=0-0` for `HeadObject`) so `UNAUTHENTICATED` vs `PERMISSION_DENIED` is classified accurately and never mapped to `exists == false`.
3. **S3 `HeadObject` 404 Disambiguation (Missing Key vs Missing Bucket, Scenario 10):**
   - When `HeadObject` returns `404` without `NoSuchBucket`, `HeadObject` probes `HeadBucket` to qualify `NOT_FOUND` with `hostkit.AbsentObject` (when bucket exists, mapped by `cloudhost` to `exists=false, OK`) vs `hostkit.AbsentBucket` (`NoSuchBucket`, mapped by `cloudhost` to `NOT_FOUND`).
4. **SQS Queue URL Normalization, Long-Polling, and `ChangeMessageVisibility`:**
   - `resolveQueueURL` resolves the queue URL via `GetQueueUrl` and normalizes its scheme/host to the active loopback endpoint.
   - `Receive` combines SQS `WaitTimeSeconds` with a client-side deadline poll so early empty responses continue polling until messages arrive or `waitSeconds` elapses.

## 5. `hostkit` v3 Adoption (`09a18e4`) & Provider Notes

- **Dry `ErrorCode` Enum Evaluation (merged upstream in lmcode-go `06cd9ae9`):** `Registry.Enum` is published in `github.com/lmctl-ai/lmcode-go v0.6.39-0.20261102140952-06cd9ae991d9` (see `sdk.lock`), so `cloudhost.Register` declares `ErrorCode` via `Registry.Enum` (`cloudhost.EnumsDeclared() == true`) and `lmscript --dry-run` programs can evaluate `cloud.last_error().code() == ErrorCode.OK`. The former temporary local `replace` of `lmcode-go` (and of `lmcloud`) is gone: the host builds on the published tagged modules `lmcloud v0.1.0` and the pinned `lmcode-go` pseudo-version with no local replaces.
- **Create Ownership Tokens (`QueueCreateTokenReader` for SQS; S3 documented limitation):**
  - **SQS (`CreateQueue` / `QueueCreateToken`):** `CreateQueue` stores `hostkit.CreateToken(ctx)` atomically in the `CreateQueue` request's `Tags` map (`"lmcloud-create-token": tok`). Because SQS `CreateQueue` on an already-existing queue with matching/default attributes returns HTTP `200 OK` while retaining the existing queue's original tags, `CreateQueue` **always** reads back the queue's tags via `ListQueueTags` after `200 OK` and reports `created=true` only when `"lmcloud-create-token"` matches the token generated for this call (otherwise `created=false`). Likewise, if a retry receives `400 QueueAlreadyExists`, `cloudhost.QueueCreate` resolves ownership via `QueueCreateToken` (`ListQueueTags`).
  - **S3 (`CreateBucket`):** S3 `CreateBucket` (`PUT /{bucket}`) has no tag or metadata parameter in the create request itself (bucket tagging requires a separate `PutBucketTagging` request and is therefore not atomic with creation). Consequently, `Adapter` does not implement `hostkit.BucketCreateTokenReader`; after a conflict (`409 BucketAlreadyOwnedByYou`) on an accessible bucket, `bucket_create` returns `false` with `ErrorCode.OK` (`lmcloud` `durable-memory/09-hostkit.md` §4).
- **Per-Route Queue Capabilities (`hostkit.Router` + `QueueCapsFor`):** `Adapter` routes via `hostkit.Router{Pick: hostkit.EndpointRoutes{Offline: fake, Sim: remote, ...}.Pick}` and implements `QueueCapsFor`, so the offline fake route reports `LongPoll: false` (waiting `~1s` in `hostkit.WaitLoop` when `wait=1`) while the loopback `awssim` route reports `LongPoll: true`.
- **`Program.Main`, `ReadBoundedErr`, and `httpguard`:** `cmd/lmaws/main.go` uses `cloudhost.Program.Main` with `Hooks`, `Init`, `Help`, `Notices`, and `Commands["--sweep"]`; `GetObject` uses `hostkit.ReadBoundedErr`; fault-injecting tests in `aws_test.go` use `hostkit/httpguard`.
- **Remaining provider-specific notes:**
  - Live AWS credential chain (`aws-sdk-go-v2/config` default chain, SSO, WebIdentity, IMDS) is intentionally disabled in Phase A–C (`LiveCredentialsNotImplemented`).
  - Cached released `awssim` binary fetched via `lmcloud/scripts` (`sims.lock` pin `v0.2.0`) predates `awssim` commit `dc7b063`, so `LMAWS_COMPAT_STRIP_S3_XID` must remain enabled by default until `awssim` cuts a new release and `lmcloud/scripts/sims.lock` updates its pin.
