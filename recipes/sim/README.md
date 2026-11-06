# lmaws recipes against awssim

Runnable lmscript recipes that drive the real `lmaws` hosts against the local
[awssim](https://github.com/lmctl-ai/awssim) emulator on `127.0.0.1`. Nothing here
contacts AWS: the native host gets `LMAWS_ENDPOINT`, the Go lmcloud build gets
`LMCLOUD_ENDPOINT`, and both refuse non-loopback origins. Every recipe creates
prefixed, run-owned resources, asserts what the emulator did, writes a JSON report
under `data/sim/<recipe>/` and ends with `PASS <recipe>`.

Two host surfaces are used:

- **native lmaws** (`cli="lmaws"`, the AWS SDK for Java host released as `lmaws`):
  run ledgers, S3 object journal, DynamoDB items, SQS redrive, IAM policy builder
  and grants, Lambda, EventBridge, Spot/EC2 sandboxes, serverless scenario.
- **lmaws cloud** (`cmd/lmaws`, the Go build serving the shared
  [lmcloud](https://github.com/lmctl-ai/lmcloud) schema): portable bucket, object and
  queue operations plus `last_error()` classification used by the permissions recipe.

## Start the emulator

```bash
awssim serve                                              # open mode, :4566
FLOCI_SERVICES_EC2_ENABLED=true awssim serve --port 4567  # EC2 control plane (metadata only, no Docker)
lmscript recipes/sim/auth_enforced_denial.lms --prepare   # writes data/sim/auth_enforced_denial/awssim-auth.json
awssim serve --port 4568 --auth enforce --auth-config data/sim/auth_enforced_denial/awssim-auth.json
```

The EC2 recipes need a VPC whose id looks like `vpc-[0-9a-z]+` with one subnet;
awssim's built-in default VPC id does not, so create one (the runner below does
this through the EC2 `CreateVpc`/`CreateSubnet` actions) or pass `--vpc`/`--subnet`.

## Run

```bash
export PATH="$PWD/bin:$PATH"                 # or wherever the lmaws release binary lives
go build -o build/sim/lmaws-cloud ./cmd/lmaws
lmscript recipes/sim/static_site_bucket.lms --cloud-host build/sim/lmaws-cloud
lmscript recipes/sim/sandbox_stack.lms
lmscript recipes/sim/ec2_web_server.lms --endpoint http://127.0.0.1:4567
```

Common flags: `--endpoint URL` (default `AWSSIM_ENDPOINT` or the port listed per
recipe), `--host PATH` (native host; its schema is read from the `lmaws` on PATH),
`--cloud-host PATH` (Go build, default `LMAWS_CLOUD_BIN` or `lmaws`), `--run ID`,
`--out DIR`, `--help`. Recipes never read AWS profiles: the native host signs with
awssim's dummy `test`/`test` credentials once `LMAWS_ENDPOINT` is a loopback origin.

`python3 scripts/test-sim-recipes.py` starts the three emulator modes on free ports,
seeds the EC2 network, runs every recipe in a temporary directory and tears
everything down. It takes `--awssim`, `--lmaws`, `--cloud-host`, `--lmscript`
(or `AWSSIM_BIN`, `LMAWS_BIN`, `LMAWS_CLOUD_BIN`, `LMSCRIPT_BIN`) and `--only NAME`.

## Catalog

| Recipe | Host | awssim services | What it proves |
| --- | --- | --- | --- |
| `static_site_bucket.lms` | lmaws cloud | S3 | Publish a five-file static site with content types and cache metadata, list by prefix, republish with a new ETag, tear down |
| `queue_worker.lms` | lmaws cloud | SQS | Enqueue site jobs, drain them with ack, nack one for redelivery, end empty, delete the queue |
| `auth_enforced_denial.lms` | lmaws cloud | S3, SQS, SigV4 policy engine (`--auth enforce`) | Author the credential/policy file with `_json_`, allowed operations succeed, `*denied*` names fail `PERMISSION_DENIED`/403, a wrong secret fails `UNAUTHENTICATED`; SKIPs on an open-mode emulator |
| `sandbox_stack.lms` | lmaws | S3, SQS, SNS, DynamoDB, SSM, CloudWatch Logs | Six run-owned backend resources, inventories, ledger cleanup to zero |
| `s3_site_publish.lms` | lmaws | S3 | Exact bucket create/attach, checksummed PUT receipts, HEAD, bounded list, presigned browser upload, selective delete, request ledger |
| `dynamodb_sessions.lms` | lmaws | DynamoDB | Session table with TTL, plain and conditional (`attribute_not_exists`/`attribute_exists`) writes |
| `sqs_dead_letter.lms` | lmaws | SQS | Job queue plus dead-letter queue, redrive policy with maxReceiveCount 3, policy removal |
| `iam_least_privilege.lms` | lmaws (admin grant path) | IAM, STS | Typed policy builder (site buckets, table, queue, Lambda by name, region lock), lint, size report, create/read/version/delete in IAM, boundary-capped Lambda execution role |
| `lambda_api.lms` | lmaws | Lambda, S3, EventBridge | Function from inline source, function URL, S3 ObjectCreated notification, scheduled rule target, delete |
| `serverless_stack.lms` | lmaws | DynamoDB, S3, Lambda, EventBridge, Logs | The lmweblab serverless scenario (table, report bucket, Lambda from a file, rule) with durable state and zero leftovers after `down()` |
| `inventory_snapshot.lms` | lmaws (default profile) | STS, S3, SQS, SNS, DynamoDB, Lambda, Logs, SSM, Secrets Manager, IAM, CloudWatch, Route 53, ECS | Read-only snapshot of every inventory as JSON plus a per-service count CSV |
| `ec2_web_server.lms` | lmaws (lmaws-ec2 profile) | EC2 (`FLOCI_SERVICES_EC2_ENABLED=true`) | Provision a nano web server: owned security group, 80/tcp from one /32, user-data, running, stop/start, terminate, teardown with no leftovers |
| `ec2_fleet_inventory.lms` | lmaws (default profile) | EC2 | VPCs, subnets, security groups with open ports, instances, volumes, addresses, one status probe |
| `leftover_sweep.lms` | lmaws + lmaws cloud | S3, SQS, EC2 tags | Untracked `lmaws-` resources are discovered, the sweep refuses them without run-ledger proof, the owner removes them explicitly |

## Emulator findings

Recorded while verifying against awssim v0.2.29 (floci 2.3.0); each is reflected
in the recipes rather than hidden:

- awssim answers the AWS SDK for Java v2 checksummed `PutObject`
  (`ChecksumAlgorithm=SHA256`) with `BadDigest`, in open and enforce mode. The
  journaled `s3_put_file` returns a non-ambiguous `ok=false` receipt, which
  `s3_site_publish.lms` records instead of asserting a publish. Plain PUTs
  (`Run.put`, the lmcloud `object_put`) work.
- `find_prefix`, `leftovers` and `cleanup_prefix` query EC2 tags, so they need the
  EC2-enabled emulator; on a default awssim they fail with HTTP 400 "Service ec2 is not enabled".
- The host validates SQS queue URLs against `https://sqs.us-east-1.amazonaws.com/...`,
  so `sqs_event_source_mapping` and the serverless `queues`/`worker` steps cannot
  target emulator URLs; the serverless recipe stops at the `event` step.
- awssim's CloudFront keeps no resource tags, so a `web_stack` distribution cannot pass
  the host's ownership check for `cache`, `invalidate` or `down`; CloudFront is left out.
- Lambda invocation needs a Docker-backed emulator; the recipes create, wire and delete
  functions but never invoke them.
- Run-owned resources are removed by the native host when its process exits, even when
  a program forgets `cleanup()`; `leftover_sweep.lms` therefore creates its orphans
  through the lmcloud schema, which keeps no ledger.
