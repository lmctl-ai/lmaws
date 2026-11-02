# `lmaws` Go Port Findings (Shared `lmcloud` Schema, SIM/FAKE ONLY)

## 1. Coexistence of Shared `lmcloud` Schema and Legacy `lmaws` Surface

- Following the multi-schema host pattern (`~/lmctl-mono/lmscript/durable-memory/dsl-framework.md` and the `lmoci` Go port pilot), `lmaws` supports subcommand routing:
  - `lmaws cloud --lmcode FILE | --lmcode-schema [--json] | --lmcode-signatures [--without-std]` selects the shared provider-neutral `lmcloud` schema (`schema/lmcloud.dsl.json`).
  - During the Go port (Phases A–C), top-level `lmaws --lmcode ... | --lmcode-schema | --lmcode-signatures` also serves the shared `lmcloud` schema so conformance harnesses invoking `<host> --lmcode $DSLFILE` run unchanged.
  - All 82 Java source files and `pom.xml` remain untouched in place while the legacy 223-method surface is scheduled for a subsequent phase.

## 2. SIM/FAKE ONLY Enforcement

- `lmaws` enforces a strict SIM/FAKE ONLY boundary:
  - `ValidateEndpointURL` rejects any non-loopback endpoint (only `127.0.0.1`, `::1`, and `localhost` are permitted; both `http://127.0.0.1.evil.example:4566` and `https://s3.us-east-1.amazonaws.com` fail pre-flight with `ErrorCode.INVALID_ARGUMENT` and `http_status == 0`).
  - No live AWS credentials, shared config/credentials files, or EC2 IMDS endpoints are ever read or contacted.
  - Simulator credentials default to `test` / `test` (`us-east-1`) and can be overridden per invocation or operation via `LMAWS_SIM_ACCESS_KEY_ID` and `LMAWS_SIM_SECRET_ACCESS_KEY`.

## 3. Official AWS Go SDK v2 (`aws-sdk-go-v2`) & `awssim` Findings

1. **Smithy `x-id` Query Parameter vs `awssim --auth enforce` (`stripS3XIDMiddleware`):**
   - `github.com/aws/aws-sdk-go-v2/service/s3` v1.107.1 serializes `?x-id=PutObject`, `?x-id=GetObject`, `?x-id=DeleteObject`, and `?x-id=ListBuckets` onto S3 request URLs.
   - In `awssim` (`AuthFilter.java` lines 43 and 72), enforced mode (`--auth enforce`) whitelists S3 query parameters (`tagging`, `location`, `list-type`, `prefix`, `delimiter`, `encoding-type`, `continuation-token`, `max-keys`, `start-after`) and rejects requests containing `x-id` with `403 AccessDenied ("Unsupported S3 operation in enforced mode")`.
   - `lmaws` attaches a Smithy Build middleware (`stripS3XIDMiddleware` in `internal/host/host.go`) that strips `x-id=...` from `req.URL.RawQuery` before SigV4 signing, so both `--auth open` and `--auth enforce` work seamlessly.
2. **S3 Default Checksum Calculation (`RequestChecksumCalculationWhenRequired`):**
   - `s3.Options.RequestChecksumCalculation` is set to `aws.RequestChecksumCalculationWhenRequired` (and `ResponseChecksumValidation` to `aws.ResponseChecksumValidationWhenRequired`) so `PutObject` sends standard `X-Amz-Content-Sha256` payload hashes rather than `STREAMING-UNSIGNED-PAYLOAD-TRAILER` chunked bodies.
3. **S3 `us-east-1` `CreateBucket` Idempotency (H3) & S3 `HEAD` 403 Classification (H2):**
   - Because S3 in `us-east-1` returns `200 OK` when re-creating an already-owned bucket, `BucketCreate` probes `HeadBucket` first and returns `(false, nil)` when `HeadBucket` succeeds (`200 OK`).
   - When `HeadBucket` returns `403` (which on S3 `HEAD` has no XML body), `BucketCreate` falls through to `CreateBucket` (`PUT /{bucket}`), which is body-bearing and returns `<Error><Code>InvalidAccessKeyId|SignatureDoesNotMatch|AccessDenied</Code></Error>`, classifying `UNAUTHENTICATED` vs `PERMISSION_DENIED` accurately.
   - Additionally, `classifyAWSError` inspects the `X-Amzn-Errortype` response header emitted by `awssim` even on `HEAD` responses.
4. **S3 `HeadObject` 404 Disambiguation (Missing Key vs Missing Bucket, Scenario 10):**
   - When `HeadObject` returns `404`, `ObjectHead` probes `HeadBucket` to distinguish a missing key in an existing bucket (`Exists: false`, `ErrorCode.OK`) from a missing bucket (`ErrorCode.NOT_FOUND`, `NoSuchBucket`).
5. **SQS Queue URL Normalization & Long-Polling:**
   - `resolveQueueURLLocked` resolves the queue URL via `GetQueueUrl` and normalizes its scheme/host to the configured loopback endpoint.
   - `QueueReceive` combines SQS `WaitTimeSeconds` with a client-side deadline poll so visibility-timeout redelivery (Scenarios 06 & 07) and empty-queue waits (Scenario 08) behave deterministically.
