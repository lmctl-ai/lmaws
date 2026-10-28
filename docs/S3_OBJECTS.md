# Persistent sandbox S3 objects

Released in v0.1.23. The separately authorized lmfiles live100-object/30-round campaign passed all phases and independently proved zero leftovers. Its persistent ledger counted1433 requests with estimated request cost$0.0018854 under$0.05; see [sanitized evidence](https://github.com/lmctl-ai/lmfiles/blob/main/docs/S3_100_RESULTS.json). v0.1.22 lacks these bindings. CI remains fake-only; this manual live result does not authorize arbitrary accounts or resources.

| Signature | Result |
|---|---|
| `Cloud.s3_bucket_create_exact(string name, string run_id)` | JSON string |
| `Cloud.s3_bucket_attach(string name, string run_id)` | JSON string |
| `Cloud.s3_bucket_delete(string name, string run_id)` | JSON string |
| `Cloud.s3_put_file(string bucket, string key, string path, string options_json)` | JSON string |
| `Cloud.s3_head_object(string bucket, string key)` | JSON string |
| `Cloud.s3_list_objects(string bucket, string prefix, int max_keys_total)` | Rows |
| `Cloud.s3_delete_objects(string bucket, string keys_json)` | Rows |
| `Cloud.s3_ledger_summary(string run_id)` | JSON string; callable directly on `aws` without a cloud session |

Create/attach binds the bucket to the run **in this process**. A restarted executor must attach before object methods. This performs an explicit GetBucketTagging; it is not a zero-request operation. Reuse one Cloud/session across a bounded manifest instead of spawning one host per file. New bindings never auto-delete on host close or retry a data-plane request invisibly.

## Guards and recovery

All bucket names are valid lowercase, hyphen-prefixed `lmaws-...` names, at most63 characters, and operations are restricted to us-east-1. Mutations require the actual client and active profile to be `lmaws`, plus live/fake transport mode. Reads permit `lmaws` or `default`; admin is refused. The host rechecks `lmaws_test=<run_id>` before **every mutation**. Missing, unreadable or mismatched tags cannot authorize a write. Run IDs are1..64 lowercase alphanumeric/underscore/hyphen characters, starting with an alphanumeric.

Create uses the exact caller name. Existing matching-tag buckets reattach; existing untagged or foreign-tag buckets are refused without CreateBucket or retagging. A per-name local process lock serializes creation across executors sharing the ledger directory. A per-run operation lock serializes each API operation through its receipt; create preflights the complete minimum tagging/verification request budget before CreateBucket so an already exhausted cap cannot bootstrap an untagged bucket. After a fresh create acknowledgement the host rechecks tags before bootstrap tagging, then verifies its tag before returning. Bootstrap tagging is the necessary creation exception; it never retags a preexisting unowned bucket. Use globally unique run names. A kill between create and initial tagging can leave an untagged bucket; automatic attach refuses it and operator review is required rather than unsafe adoption.

DeleteBucket revalidates ownership and relies on S3's atomic empty-bucket condition. It never empties a bucket implicitly; nonempty/versioned buckets remain untouched and return BucketNotEmpty. NoSuchBucket is an absence observation, while denied reads are not absence. An attach receipt with `exists=false`, `error_code=NoSuchBucket` can independently confirm final bucket absence. Existing process-owned Run/sweeper reports are not absence proof for these persistent resources; the caller owns explicit teardown.

## File PUT and HEAD

PUT options are a JSON object:

- `content_type`, `cache_control`, `metadata` (string map, total user metadata at most2KiB).
- `checksum_algorithm`: only `SHA256`; `checksum_sha256`: optional expected base64 SHA-256; `expected_sha256`: optional expected64-hex digest. Any supplied value must match the local snapshot.
- `if_none_match`: only `"*"`, or `if_match`: the exact ETag; combining both is refused.
- `operation_id`: optional caller correlation value.

The host copies the source into a private temporary snapshot, detects concurrent source changes, hashes the snapshot and streams that stable file through upstream SDK PutObject with ChecksumAlgorithm SHA256 and its value. Files are bounded to16MiB; no multipart upload or composite-checksum claim is made. A caller with a planned fingerprint should provide `expected_sha256` so a changed revision is refused before uploading.

The non-throwing data receipt contains `ok`, `http_status`, `error_code`, `ambiguous`, `etag`, `checksum_sha256`, `version_id`, `request_id`, `bytes`, `started`, `finished`, `sha256` and correlation/stage evidence. `ok=true` requires a successful response and a server checksum matching the full snapshot digest. A missing/mismatched checksum is unconfirmed.412 is an ordinary `ok=false`, non-ambiguous response. Network failures or5xx after dispatch are ambiguous: never mark the object published from them. No SDK automatic retries are made; an executor explicitly decides whether to retry or verify an uncertain write. A failed ownership-read before PUT is not a dispatched PUT. Schema, ownership and cost-cap refusals may abort safely; earlier receipts are already durable.

HEAD requests ChecksumMode ENABLED and returns factual existence, size, ETag, timestamp, Content-Type, Cache-Control, user metadata, checksum and version.404 means absent;403/network error leaves `exists=null`. The returned checksum/type is server metadata, not a fresh object read or fabricated full-content hash; preexisting multipart objects can use composite checksum forms. No object GET is added.

## Lists and deletion

`max_keys_total=0` selects1000; valid explicit bounds are1..1000. Listing follows continuation tokens, respects prefix and returns key, size, ETag, last_modified and storage_class. A truncated list at the bound, repeated token or malformed pagination is refused rather than returned as a complete inventory. Use a narrower prefix if needed. Rows columns follow the host's string-column convention.

`keys_json` is an array of up to1000 unique key strings. DeleteObjects returns an outcome row for each key, including `ok` (`"true"`/`"false"`), status, error_code, ambiguous and request_id. Partial service errors remain individual failures; omitted/unconfirmed outcomes are not called deleted. An empty list performs no SDK request. Version-specific deletion/listing is outside this bounded API; newly created correctness-test buckets are unversioned.

## Durable counts and cost

`LMAWS_LEDGER_DIR/<run>-s3-operations.jsonl` stores headers, request reservations, ownership bindings, intents and result receipts. Use the **same directory and run ID** after restart; prefer an absolute LMAWS_LEDGER_DIR when a job can change working directories. A different directory is a different journal, not recovery. Each SDK transmission is admitted against cumulative cost under an OS file lock and fsynced before dispatch. Reopening cannot raise the persisted cap; lowering it also constrains already-open executors. Default cap$0.05, hard ceiling$0.25. The header includes the existing S3 price table; tag reads/writes, verification, pagination, failures and cleanup are counted. Delete requests use the table's free DELETE rate.

The ledger is conservative: a reservation that was fsynced immediately before a kill can count even if the wire send did not occur. A torn/malformed ledger fails closed rather than losing a potential charge. API receipts are fsynced before return. The ledger estimates request attempts; storage/transfer need separate script estimates. The bounded lmfiles correctness run uses tiny objects and explicit teardown, not a storage-cost or scale qualification.

`aws.s3_ledger_summary(run_id)` is local only, with `attempts`, `by_operation`, estimated request cost, cap, price table and path. A missing ledger reports zero without creating a run. For a no-change phase, skip attach/create/HEAD/list entirely and compare local summaries before/after; neither summary resolves credentials nor sends AWS requests. Counts include actual ownership checks, not just PUTs. Do not call an old process-only counter a whole recovered-run count.

## Verification and examples

The [synthetic recipe](../recipes/s3_objects.lms) and gallery image are schematic stages, not measured request counts; they make zero AWS calls and refuse live execution. Use the guarded API only in an explicitly authorized job.

`S3OperationLedgerChecks` covers fsync persistence, restart, simultaneous processes, cap reduction/increase refusal, malformed/torn journals and pure no-op summaries. `scripts/test-s3-objects.py` uses actual SDK requests against a local fake S3 endpoint: full headers/checksums,412, lost response/5xx, pagination, partial deletion, metadata and ownership guards, executor kill/recovery and cumulative cap refusal. Both run in test.sh. No production bucket or account data occurs in public fixtures.

The supplied local session-policy and managed-policy files grant `s3:*` on `lmaws-*` buckets and objects, including PutObject, GetObject, GetObjectAttributes, DeleteObject, ListBucket, GetBucketTagging, PutBucketTagging, CreateBucket and DeleteBucket. No missing action or admin policy update was found in that file audit; this is not a claim that a live run has succeeded. The Lead released v0.1.23. The separately authorized lmfiles live run subsequently completed without IAM changes or denials; its unique owned bucket was deleted and NoSuchBucket/404 was observed from a new executor. No tag/release or CI credential setup was performed by that test.
