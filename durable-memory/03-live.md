# Approved live testing

The Lead relayed explicit user approval for this machine under CLOUD_BRIEF safety
rules. The opt-in runner is `LMAWS_LIVE=1 python3 scripts/test-live.py target/lmaws`.
It uses only the configured default AWS profile and its one configured region;
environment credential overrides and fake endpoints are removed for this test.

The native host reads identity and selected inventories through safe metadata
projections. It then creates one uniquely named SQS queue and one standard SSM
String parameter, tags both with lmaws_test=run-id, sends a nonsecret fixture message
and updates the nonsecret parameter. It deliberately fails a DSL assertion after
both exist to prove finally-based teardown. It never fetches parameter/secret values
or modifies IAM users/keys.

Every creation intent is durably logged before the API request. On failure the
outer verifier may recover only resources matching that run's ledger, exact prefix
and ownership tag. It checks deletion independently using AWS CLI GetQueueUrl and
DescribeParameters (metadata only). Private raw logs/ledgers stay in ignored
live-ledger/. A sanitized result is saved in live-v010.json. Never print credential
files, raw SDK error details or live AWS data into the gallery.

Verified native live run r170f2785352f4d76 in us-east-1 created queue
lmaws_r170f2785352f4d76_queue and standard String parameter
lmaws_r170f2785352f4d76_parameter. Both were deleted by the host after the deliberate
assertion failure, without outer recovery, and independently verified absent.
See live-v010.json. No real resource remains from this run.
