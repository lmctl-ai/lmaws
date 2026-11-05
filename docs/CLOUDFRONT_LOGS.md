# Read-only legacy CloudFront log retrieval

`Cloud.cloudfront_logs(distributionId, fromDate, toDate, outputDir,
maxObjects, maxCompressedBytes)` inventories or downloads existing S3 gzip
logs. Only the default profile is accepted. The CloudFront distribution's
own legacy logging configuration supplies the bucket/prefix; the caller
cannot substitute an arbitrary bucket. Logging must already be enabled.

Dates are UTC, start inclusive and end exclusive, with a maximum 31-day
range. Keys follow `prefix/ID.YYYY-MM-DD-HH.unique.gz`; a configured prefix
without its trailing directory separator is normalized. The collector
paginates S3 results and limits object count to 12,000 and compressed bytes
to 512 MiB. A byte cap of zero means metadata inventory only, with no GET or
raw output directory. No configuration, restores, puts or deletes occur in AWS.

Raw output must be under `evidence/` or `.lmaws-local/`. Directories are private
(0700) and files private (0600) where POSIX permissions are available. Local
filenames are SHA-256 hashes of object keys. Existing exact-size files are
reused without another GET; streaming reads are bounded by the listed size.
Archive classes are skipped without restoration. Per-object reasons and the
`complete` flag preserve cap/archive incompleteness rather than claiming zero
traffic. No cookie contents or raw log lines are returned through the API.

The metadata includes `cookie_logging_enabled`, object storage classes,
materialized paths/byte totals and warnings. Cookie logging describes the
current distribution setting; historical log contents must also be checked.
Downloaded byte totals include reused local cache files, not just this run's
network transfer. Request-cost estimates do not include internet egress or
storage-tier retrieval fees.

Standard logs can be delayed/incomplete and use response-completion time.
Inventory/download completeness is not a promise that every HTTP request was
logged. Logs can contain IPs and cookies; keep raw files private and share
only the aggregates needed for an investigation. A User-Agent label is not
proof of the sender's identity.

`CloudFrontLogsChecks` injects SDK proxies to verify prefix/date requests,
read-only operations, inventory-only behavior, archive/cap flags, cache reuse,
private modes and basic invalid inputs without AWS access.
