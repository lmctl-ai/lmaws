# Persistent S3 object API

Eight Cloud methods implement exact bucket create/attach/delete, snapshot-based conditional file PUT, checksum HEAD, bounded list, per-key DeleteObjects and local ledger summary. Full signatures, options and limits: [S3_OBJECTS](../docs/S3_OBJECTS.md).

Only lmaws mutates, only us-east-1/lmaws- buckets, and every mutation rechecks the exact lmaws_test run tag. Reads permit default/lmaws. Existing untagged/foreign buckets are never adopted; initial tagging follows fresh creation acknowledgement. Creation is locally serialized by bucket name. Run IDs and ledger directory must persist; each executor attaches explicitly.

PutObject uses a stable temporary snapshot and full SHA-256, at most16MiB. Successful checksum echo is required for ok;412 is a factual failure, lost-response/5xx is ambiguous. No hidden SDK retries or automatic host-close cleanup. Auth/schema/cap failures may abort; prior receipts are fsynced.

S3OperationLedger locks the cumulative price admission and fsyncs before every SDK attempt. Counts survive kills; a torn journal fails closed. Caps cannot rise on reopen and reductions constrain existing handles. Pure s3_ledger_summary makes no SDK/credential calls and a missing run reports zero. Request estimates exclude ongoing storage/transfer. Never attach/list/HEAD during a claimed zero-request phase.

Fake SDK and concurrent-process persistence tests are part of test.sh. The synthetic recipe/image represent eight stages, not live request counts.85 recipes/125 examples at this change. IAM file audit found all required S3 actions under existing s3:* scoped to lmaws-*; no admin update or live resource operation was performed.

Main is ready for the Lead's v0.1.23 release; no tag/release is cut by this task. The lmfiles100-object live run remains Sol2's separately authorized work after that release. No live-success/absence claim is made here.
