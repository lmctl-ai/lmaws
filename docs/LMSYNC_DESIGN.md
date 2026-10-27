# lmsync: local believed-state manager

Status: **design only, brief v2**. This is the only current sync design. It
consolidates the useful publication examples from root `SYNC_DESIGN.md` at
`d0f033f`, replacing its integrated sync/policy engine with the boundary below.
No implementation, AWS command, workflow dispatch, benchmark or repository creation
is performed here. The future `lmctl-ai/lmsync` repository is not created now.

Contents: [boundary](#definition-and-boundary), [API](#1-core-api-and-neutral-data),
[belief/verification](#2-believed-state-and-verification-scripts),
[optional logs](#3-optional-planresult-log-glue),
[durability](#4-durable-db-and-failure-injection),
[Java stores](#5-java-implementation-and-scale-tier-storage),
[example jobs and host gaps](#6-example-jobs-scripts-own-every-decision),
[multi-host milestone](#7-one-lmscript-two-hosts-first-milestone),
[benchmarks](#8-benchmark-plan-proving-the-local-state-claim),
[implementation](#9-positioning-risks-and-implementation-breakdown).

## Definition and boundary

lmsync stores a **local model of believed remote state**. It provides a Java
lmcode host/library for DB access, local scanning, neutral comparisons, recording
and optional local log helpers. It makes **zero remote calls, ever**: no list,
remote stat, HEAD, credential resolution, cloud client or SSH connection. A query
about an arbitrary subset reads local state; it does not enumerate a target tree.

**One sync job is one user-authored LMScript.** That script calls lmsync for state
and a cloud/SFTP host for actions, then reports the results to lmsync. lmaws keeps
its existing Java/GraalVM host and SDK v2; lmazure and lmgcp keep their own hosts.
There is no C++, JNI, native sidecar or full-host rewrite in this design.

| lmsync owns | The job script owns | The transfer host owns |
|---|---|---|
| DB durability, local file observations, hashes, snapshots, comparisons, set differences, record/forget, import/export, integrity queries | Key mapping; include/exclude choices; what to add/delete; cache/freshness; safety thresholds; budgets; verification sample/rate; when to rebuild; retention; invalidation | Provider/SSH protocol, remote actions explicitly requested by the script, credentials, host-key/ownership checks, service limits, transfer receipts and provider cost ledger |

There is **no config-file-driven rules engine**, automatic upload/delete choice,
record-age warning, quota policy or cloud-specific target validation in lmsync.
A page may be unchanged for years. Operational tuning parameters (batch size,
store cache, hash mode, scan globs) are ordinary API arguments, not rules that
trigger remote work. Script templates may choose defaults; core does not impose
them. A no-op job can avoid invoking its transfer host entirely. If that host is
invoked, count its security/metadata calls as well as transfers; never market
zero decision requests as zero total requests for a script that chose verification.

```mermaid
flowchart LR
  F[Local files / explicit subsets] --> S[lmsync: local DB + scan + query]
  S --> J[One user LMScript: decisions]
  J --> H[lmaws / lmazure / lmgcp / SFTP host]
  H --> R[Remote actions]
  H --> C[Confirmed result data]
  C --> J
  J --> S
```

## 1. Core API and neutral data

All signatures below are proposed, not existing bindings. The canonical enum is
`CompareState { UNKNOWN, SAME_AS_RECORDED, CHANGED, RECORDED_BUT_MISSING_LOCALLY }`. Parameters are typed
lmcode values/handles; enum values are distinct from strings. Streaming cursors
and bounded batches are the main interface; convenience arrays are size-bounded.

```text
sync.open(path: string, namespace: string, options: OpenOptions) -> StateDB
StateDB.close() -> CloseReceipt
StateDB.target(namespace: string) -> Target
StateDB.scan(root: string, options: ScanOptions) -> ScanRun
StateDB.scan_paths(paths: PathSource, options: ScanOptions) -> ScanRun
ScanRun.next_batch(max_rows: int) -> ObservationBatch
ScanRun.finish() -> ScanReceipt
StateDB.hash_paths(paths: PathSource, algorithm: HashAlgorithm) -> ObservationCursor
StateDB.query(target: Target, paths: PathSource) -> StateCursor
StateDB.query_batch(target: Target, paths: PathBatch) -> StateBatch
StateDB.local_not_recorded(target: Target, scope: PathScope) -> StateCursor
StateDB.recorded_not_local(target: Target, scope: PathScope) -> StateCursor
StateDB.records(target: Target, scope: PathScope) -> RecordCursor
StateDB.record(target: Target, path: PathId, result: RecordMetadata) -> RecordReceipt
StateDB.forget(target: Target, path: PathId) -> RecordReceipt
StateDB.mark_suspect(target: Target, paths: PathSource, note: string) -> RecordReceipt
StateDB.set_suspect(target: Target, paths: PathSource, value: bool, note: string) -> RecordReceipt
StateDB.begin() -> WriteBatch
WriteBatch.record / forget / mark_suspect(...) -> WriteBatch
WriteBatch.commit() -> CommitReceipt
WriteBatch.rollback() -> void
StateDB.import_records(source: LocalRecordSource, options: ImportOptions) -> ImportReceipt
StateDB.export_records(target: Target, output: string, options: ExportOptions) -> ExportReceipt
StateDB.snapshot() -> ReadSnapshot
StateDB.doctor(options: DoctorOptions) -> IntegrityReport
```

Cursors expose `has_next`, `next_batch`, streaming JSONL/CSV output and `close`.
Default batches may be 4,096 records, with a caller-provided memory ceiling. Byte budgets can shorten a batch below max_rows; oversized metadata uses bounded
streaming/blob references. No million-row array is required. Explicit path lists, stdin/NUL lists, globs, git
changes, manifests and unrelated directories are adapters producing PathSource;
the core need not run git or understand a build system. The script turns a git
diff or manifest into paths. scan_paths observes only those local paths.

`PathId` is a local root identity plus relative path, or a caller-named logical
path for non-file events. Multiple roots allow unrelated directories and prevent
same-basename confusion. Local filesystem paths and caller-supplied target names
are separate. A Target is an **opaque namespace**, such as `site-production` or
`sftp-staging`, optionally with a caller-stored descriptor. The core does not
parse S3 buckets, enforce `lmaws-*`, perform flatten/strip/add-prefix mapping, or
resolve a hostname. Those choices and their collision checks are script/host work.
One local path can have a separate record for every target in the same DB.

### Comparison semantics

Query compares the latest local observation with the source fingerprint attached
to the recorded result; it performs no remote I/O and no implicit local tree scan.
The script calls scan or scan_paths first when it wants refreshed observations.
Query returns the local and recorded observations, comparison basis (`stat` or
`digest`), hash availability, explicit suspect annotation and record metadata.

| Neutral state | Exact meaning |
|---|---|
| `unknown` | No record, or insufficient local observation to compare; reason distinguishes these cases. It does not assert absence on the remote |
| `same-as-recorded` | The compared local fingerprint agrees with the one the script last recorded, under the disclosed stat/hash basis |
| `changed` | The local comparison differs; if hashing was deferred, this may mean changed stat inputs rather than proven different bytes |
| `recorded-but-missing-locally` | A recorded path has an explicitly observed local absence, from a completed scope scan or scan_paths result |

A scan receipt includes its root, filter/traversal parameters and completed coverage.
Excluded/unvisited paths are not marked absent, and changing include/exclude
parameters is not evidence that previously observed files disappeared.
A path not yet observed is not declared missing. A failed/partial scan exposes its
incomplete scope; set differences cannot describe that unobserved portion as
confirmed absence. The helpers compare local DB sets, not the remote namespace. Old upload-index
policy verdicts such as new/key-conflict/stale are not core states; the script can
distinguish absent-record vs unobserved-local reason data and map them as it wishes.
None of the four states means upload, delete, warn, refuse or rebuild. Even a
`same-as-recorded` file may need a script-chosen action because its desired remote
key or HTTP metadata changed. Conversely `changed` does not require an upload.
A suspect flag is data set by the script, not a fifth policy verdict or a TTL.

### Scan and hash cost

ScanOptions supplies include/exclude globs, symlink handling, hash algorithm/mode,
worker/batch limits and local scope. Empty filter choices mean no caller filter;
there is no built-in project/deploy exclusion policy. Hash modes are ON_CHANGE,
ON_DEMAND and ALWAYS; size/mtime checks reuse known hashes where applicable.
Record timestamp precision and optional ctime/file identity. If a stat change
hashes to the same content, disclose both facts. Never equate an opaque provider
ETag with a local content hash.

Use bounded per-directory/shard queues, streaming observations and spill files,
not a whole-tree list in memory. Directory mtimes can help detect name changes;
descendant content edits need not alter a parent directory mtime. Do not skip
children on that evidence alone. An optional local watcher is just an observation
accelerator; JDK WatchService can use Linux inotify without a new native binding.
Overflow, a stopped watcher or an interrupted scan is returned as a local
observation gap. The script chooses whether/how to rescan; no cloud verification
or record-age policy follows automatically.

A same-size edit with preserved timestamps can evade stat-based comparison. The
script can request ALWAYS hashing or an immutable source snapshot when that
matters. Re-stat around hashing and report local mutation rather than publishing
a misleading digest. The core does not certify that a later transfer read the
same bytes: the action host must report the actual transferred fingerprint.

### Record and forget

RecordMetadata carries an immutable **source fingerprint for the bytes reported
transferred**, an action/event ID and an opaque result payload. It can hold an
ETag/version, remote path, content type, Cache-Control, upload ID, SFTP attributes,
phase/status or arbitrary caller data; core does not interpret these business
fields. A logical action/event may have no source-file fingerprint.

`record` must not implicitly attach today's local fingerprint to yesterday's
transfer. Callers pass the plan/source snapshot or actual transferred hash. If a
file changed while/after uploading, a subsequent scan must still compare against
the bytes actually reported uploaded. `forget` removes believed state via a local
transaction/tombstone; it never deletes a remote path. The caller is free to
record or forget directly without any plan/log mechanism.

## 2. Believed state and verification scripts

Outside changes are invisible until a script chooses to check. Age alone does
not make a record suspect, and opening/querying never calls the remote. A DB can
faithfully preserve a mistaken user report; it cannot independently certify a
remote effect. Document these limits instead of implying a local remote oracle.

A verification script chooses N recorded paths, calls lmaws HEAD (or another
host's equivalent), compares returned data using its own policy, then explicitly
marks suspect, records revised metadata, forgets or does nothing. Sampling rate,
selection seed, cost cap, checksums and behavior on mismatch all belong to that
script. A failed sample cannot certify unsampled paths. Multipart/composite ETags,
metadata changes and encrypted objects need explicit interpretation by the host/
script, not a content-equivalence rule hidden in lmsync.

A rebuild script can fetch a listing, S3 Inventory or other records with its cloud
host, then call import_records on a **local** stream. lmsync never fetches a URL or
creates Inventory. The script chooses prefix fan-out/concurrency, coverage,
pricing/admission, validation and whether to replace or merge a target snapshot.
ImportOptions provides mechanical append/upsert/replace and transaction choices;
a replace is local state replacement, not remote deletion. Preserve import
provenance in caller metadata. A listing does not necessarily recover source paths
through a non-invertible flatten/custom mapping, and Inventory may not contain
custom metadata or checksum values. Unknown information stays unknown.

No watcher detects outside remote edits. Multiple machines can hold different
beliefs; any remote coordination/leases or conditional-write policy belongs in
the job and action host. Local single-writer locking only protects this DB.

## 3. Optional plan/result log glue

This is a **thin file codec/helper library**, not a mandatory workflow, scheduler
or executor. A script may use direct record() calls instead. A plan is data the
script wrote; lmsync never synthesizes upload/delete instructions from a state.

Proposed helpers: `plan_writer`, `result_writer`, `read_instructions`,
`read_results`, `unconfirmed(plan, results)`, and `apply_records(db, results)`.
The last helper applies only explicit record/forget projections supplied by the
script. It does not infer a projection from a verb such as `delete` or `invalidate`.
All readers/writers stream in bounded batches and return data/receipts.

### Wire grammar

Versioned UTF-8 JSON Lines; one compact object per line, LF terminator. Strings
use JSON escaping, so spaces, quotes, tabs, backslashes and embedded newlines in
path names are unambiguous. Never use whitespace-separated shell instructions or
shell interpolation. Metadata is bounded per line; large payloads refer to a
local blob plus digest. Store nanosecond timestamps, byte counters/IDs that may
exceed JavaScript's exact integer range as decimal strings. Timestamps are UTC
RFC3339 data, not expiration instructions.

Each managed line has `v`, `kind`, `job`, `op`, `payload` and a checksum. Result
lines additionally have an immutable `result_id` and explicit
`completes_instruction` boolean; separate accepted/completed/progress projections
can share an instruction op but use different result IDs. The helper
uses its versioned canonical JSON encoding of payload for CRC32C and instruction
SHA-256; all hosts share the codec conformance fixtures. Logs from external tools
may be imported explicitly, but are not silently treated as managed crash receipts.
The examples below omit computed checksums for readability; actual helper output
includes them and each result binds the full instruction digest.

```json
{"v":1,"kind":"instruction","job":"example","op":"add-a","payload":{"verb":"add","target":"site","path":"assets/a b \"quoted\".css","source_fingerprint":{"size":"3","mtime_ns":"<decimal-int64>","hash":"<digest>"},"args":{"remote_path":"assets/a.css"},"record_projection":"record"}}
{"v":1,"kind":"instruction","job":"example","op":"delete-b","payload":{"verb":"delete","target":"site","path":"old.css","args":{"remote_path":"old.css"},"record_projection":"forget"}}
{"v":1,"kind":"instruction","job":"example","op":"event-c","payload":{"verb":"cloudfront.invalidate","target":"events","path":"invalidation/event-c","args":{"paths":["/*"]},"record_projection":"record"}}
{"v":1,"kind":"result","job":"example","op":"add-a","result_id":"add-a-complete","completes_instruction":true,"payload":{"instruction_digest":"<sha256>","confirmed":true,"timestamp":"2026-01-01T00:00:00Z","projection":{"kind":"record","target":"site","path":"assets/a b \"quoted\".css","source_fingerprint":{"hash":"<actually-transferred-digest>"},"metadata":{"remote_path":"assets/a.css","phase":"uploaded","etag":"<opaque>"}}}}
```

`verb` is an arbitrary caller string; `args` and result metadata are caller data.
The only projection primitives are local `record`, `forget` or `none`. Metadata
can describe an accepted/pending remote action if that is what the script reports;
it must not thereby be presented as completed publication. Job/op identifiers and
instruction digest detect conflicting reuse. Replaying the same confirmed `(job,result_id)` is idempotent; a different
payload for that same result ID is an integrity conflict. Only the caller's
explicit completes_instruction marker removes an instruction from the unconfirmed
set. Progress/event data need not imply a fully uploaded file. A transaction commits its result-log replay offset and record changes
together, so a crash cannot skip a result or double-apply it.

A writer fsyncs a complete confirmed result before declaring that receipt durable.
A torn final line is retained/ignored as unconfirmed and can be truncated only to
the last verified line boundary. Corruption in a middle line is an error, not an
excuse to skip later results. Plan files commit atomically; appending to a journal
is single-writer. The helper never executes any verb or invokes a provider.

### Resume and the confirmation gap

Resume means the script re-plans the unconfirmed remainder. Completed results
replay into the DB even if the process died before its DB update. A transfer that
completed remotely but crashed **before** producing a durable confirmation remains
unconfirmed: lmsync cannot infer success without a report. Its instruction is not
lost, and the script can safely retry with provider idempotency/conditional writes
or explicitly reconcile the known path. It may repeat transfer work or cost.

Scripts should store multipart/progress events without a completed-file source
fingerprint until they actually report that full-file success. The core does not
interpret phase strings.

The invariant is no lost **durably reported** success and no false unchanged
inferred from intent, a start record, file existence or a partial line. Exactly-once
remote effects across a process/network/filesystem crash are not promised. A
script that reports an incorrect result can corrupt its own belief; the library
must not manufacture confirmation. Changed local sources are re-planned rather
than marked uploaded with a newly observed fingerprint. Optional log glue is not
required for small direct-call jobs, but those jobs accept a larger confirmation
window unless the action host emits its own durable result receipt.

## 4. Durable DB and failure injection

Logical records: local paths/observations; target namespaces; `(target,path)`
recorded source fingerprint and opaque metadata; explicit suspect notes; local
forget tombstones; import provenance; generations/transaction IDs; optional replay
IDs and offsets. Keep local observations separate from recorded state so scanning
never overwrites believed transfer success. Provider-specific key/hash indexes,
quota counters and release catalogs are user data or script-side structures, not
core business tables.

Use transactional/WAL storage, checksummed pages/records, monotonic committed
sequence numbers and versioned codecs. On open, validate the manifest, recover
committed WAL transactions, discard only incomplete tail records and report
structural corruption. Do not silently open an empty DB or forget records when a
file is corrupt. Compaction writes/fsyncs a new generation, atomically commits its
manifest and only then releases old unpinned files. Compaction drops superseded
records/tombstones only when snapshots no longer need them; it never expires a
path because of age. Export/backup produces a consistent checksummed snapshot;
import validates it into a staging generation before an explicit local commit.

Single writer uses an OS file lock plus diagnostic PID/process-start/instance data.
The OS releases the lock after a crash. Stale text in a lock file can be replaced
only after acquiring the real lock; do not unlink/recreate an actively locked file
or use a timeout to steal a live writer's lock. Refuse filesystems without the
required locking/atomic-rename/fsync guarantees. Concurrent readers see stable
snapshots, not partial writes. Same-process MVCC readers are the first milestone;
other processes use immutable exported/pinned generations or an explicitly
qualified snapshot protocol. Do not promise concurrent live MVStore opens across
processes without testing it. Reader crash releases OS pins/handles; compaction
never deletes a generation still pinned by a live reader.

Doctor reports local checksum/manifest/sequence/index consistency, dangling
references, transaction/replay integrity and storage statistics. It performs no
HEAD, rebuild or provider verification, and returns data for the script to handle.
Opening old-format data requires a versioned migration, not automatic semantic
policy changes. Memory, disk space, file offsets and malformed-input limits are
implementation/resource constraints, not upload/delete policy.

A deterministic kill-point harness will exercise these boundaries:

| Kill/fault point | Required observation after reopen |
|---|---|
| After plan commit, before any transfer | DB unchanged; all instructions unconfirmed |
| Mid-transfer/part | No completed record; script can use stored opaque provider resume data or retry |
| After remote transfer, before result append | Unconfirmed intent retained; no fabricated same-as-recorded |
| After fsynced result, before DB record | Replay restores exactly that reported source snapshot/result |
| During DB transaction/replay-offset commit | Both record and offset commit, or neither |
| Mid-compaction/manifest swap | Last complete committed generation remains readable |
| Disk full / failed fsync | No success acknowledgment for an undurable transaction |
| Truncated last log line | Previous verified receipts replay; last operation stays unconfirmed |
| Corrupt middle log/page/index record | Doctor/open reports corruption; no silent row loss |
| Stale lock metadata / crashed writer | OS lock can be reacquired safely; live locks cannot be stolen |
| Reader crash / active snapshot during compaction | No use-after-delete; obsolete files reclaimed only after pin release |

Compare recovered state to an independent model oracle at every kill point.
Test large offsets, empty DB, duplicate/conflicting operation IDs, arbitrary path
quoting, many targets and millions of streamed rows in JVM and native-image runs.

## 5. Java implementation and scale-tier storage

Implement lmsync as a Java lmcode host with JDK local I/O/hash primitives. GraalVM
native-image remains the deployment route; no AWS SDK, SSH client or cloud ledger
belongs in its dependency graph. TransferManager is an **lmaws** concern. No C++
or external native component is selected, and there is no JNI fallback at runtime.

| Store | Primary-source evidence / uncertainty | Recommendation |
|---|---|---|
| Direct H2 MVStore | Java file-backed log-structured maps, MVCC and configurable cache; our native-image/large-file/crash workload still needs qualification | Small-tier candidate using explicit byte codecs, no SQL/server or object serialization |
| Custom sorted runs + sparse fences + Bloom filters | Implementable with Java NIO; immutable generations, WAL and compaction are our engineering responsibility | Recommended 100M/1B path; small-tier fallback/common export format |
| iq80 Java LevelDB / embedded LSM | Java port with batches/snapshots/cache controls; reviewed README describes limited testing, and no representative native-image qualification was found | Prototype/benchmark alternative, not an assumed production dependency |
| MapDB | JVM file-backed collections; exact dependency/reachability/durability behavior needs testing | Optional candidate; no unmeasured native-image claim |
| Xerial SQLite JDBC | Native-image support exists, but SQLite is loaded from platform native libraries through JNI | Not compatible with this brief's Java-only/no-JNI requirement |
| RocksDB JNI | Adds native libraries and per-platform JNI packaging/testing | Not needed by the proposed Java design; only reconsider with explicit new user direction if every viable Java approach fails |

Sources: [MVStore](https://h2database.github.io/html/mvstore.html),
[iq80](https://github.com/dain/leveldb), [MapDB](https://mapdb.org/doc/),
[SQLite JDBC](https://github.com/xerial/sqlite-jdbc). These provide feature evidence,
not measured lmsync results. Check pinned-version reachability and file locking
in the actual GraalVM binary; a working JVM test is not native-image certification.
No dependency is added by this design.

Sizing model: average path 96 UTF-8 bytes, one local observation plus one target
record, SHA-256 when known, roughly 128 bytes of opaque result metadata and
amortized lookup/filter overhead. Estimate **400–700 bytes per path-target pair**;
long metadata, many targets, snapshots and logs increase it. This is a planning
model, not measured codec output. Shared local observations amortize across targets.

| Tier | Proposed store | Estimated live disk at limit | Index working memory target | Proposed pre-observed 1M-query latency on recorded NVMe hardware |
|---|---|---:|---:|---|
| <=1M paths | Qualified MVStore, sorted-run fallback | 0.4–0.7 GB | 64–192 MiB | <=20 s warm / <=60 s cold |
| <=100M | Sharded sorted runs/WAL/manifest | 40–70 GB | <=512 MiB | <=20 s warm / <=120 s cold |
| <=1B | Same, bounded open shards and on-disk index/filter partitions | 400–700 GB | <=1,024 MiB | Target <=30 s warm / <=180 s cold; projection until tested |

All latency figures are **acceptance goals, not measurements**. Budget at least
2x live disk for compaction, plus configured WAL/snapshot/export headroom. At 1B
this is roughly 0.8–1.4 TB before extra retained data. Report heap, direct buffers,
RSS and OS page cache separately; no all-RAM object map or hidden unlimited mmap.
A 10-bit/key Bloom set uses about 1.25 GB at 1B, so filters/fences must be partitioned
on disk and cached, not all loaded. False positives always check full keys.

Cap memtable, block/filter caches, open shards/files and compaction workers through
plain resource options. Use checksummed blocks, explicit encodings, bounded merge
buffers, 64-bit offsets and versioned manifests. These limits bound local resources;
they never decide which remote action a script should take. Migration is a
streaming local operation retaining the prior generation until commit. Qualify
Linux x64 dynamic-glibc native images first, then macOS and Windows; retain the
existing Java cloud hosts. If Java options fail, present actual evidence and
native/JNI package-size, platform and maintenance costs before any new decision.
Do not assert RocksDB is necessary while a viable Java sorted-store design exists.

## 6. Example jobs: scripts own every decision

The following are **design sketches of seven standalone `.lms` jobs**, not new
runnable examples in this change. Each future file contains editable CONFIG values,
its policy code and calls to state and transfer hosts. Import-only helpers may
avoid boilerplate; there is no central rules/config engine or second job file.
All examples get picture-first READMEs, a synthetic architecture picture and an
assertion/request-count chart made with lmdraw/lmplot, a short `lmctl <raw-url>.lms`
caption, cost assumptions and fake-mode assertions. The real pictures/scripts
are implementation deliverables, not fabricated evidence in this design.

### (a) `publish_ttl.lms`: static site with lmaws

Illustrative policy in one user script:

```text
CONFIG: root, DB path, target name, owned lmaws bucket receipt,
        entry globs, entry TTL=30, asset TTL=300, transfer concurrency, run cap.

lmsync block:
  open DB; scan root with the script's explicit scan options;
  query the site's paths against its recorded target;
  for each neutral row:
    script decides whether bytes or desired key/HTTP metadata warrant a PUT;
    if selected, append an add instruction with the source snapshot and headers;
  close DB / finish the optional plan file.

lmaws block, only if there are selected instructions:
  open the script's owned bucket target; admit costs using lmaws;
  stream binary PUTs with the script-selected headers and supported conditions;
  append/fsync confirmed results containing actually transferred fingerprints.

lmsync block:
  replay those explicit record projections, or call record per confirmed result;
  report query counts and recorded outcomes; close DB.
```

The essential policy appears in the future `publish_ttl.lms` itself, for example
(the factory/row/codec APIs are proposed; this is not a runnable current program):

```text
let ROOT = "./public";
let DB = ".lmsync-local/site.db";
let ENTRY_TTL = 30;
let ASSET_TTL = 300;
let CAP_USD = "0.05";

state = _lmcode_ cli="lmsync";
let db = sync.open(${DB}, "site", sync.open_options());
let scope = db.scan(${ROOT}, sync.scan_options().hash_on_change()).finish();
let target = db.target("site");
let rows = db.query(target, sync.paths_from_scan(scope));
let plan = logs.plan_writer(".lmsync-local/plan.jsonl");
while (rows.has_next()) {
  let batch = rows.next_batch(4096);
  let i = 0;
  while (i < batch.len()) {
    let row = batch.at(i);
    let key = row.path().relative();             # USER key mapping
    let ttl = ${ASSET_TTL};
    if (str_ends_with(key, ".html")) { ttl = ${ENTRY_TTL}; }
    let cache = "public,max-age=" + str(ttl);    # USER cache policy
    if (row.state() != CompareState.SAME_AS_RECORDED ||
        row.recorded().get("cache_control") != cache ||
        row.recorded().get("remote_path") != key) {
      plan.append("add", target, row.path(), row.source_snapshot(),
                  data.fields().set("key", key).set("cache_control", cache));
    }
    i = i + 1;
  }
  batch.close();
}
plan.close(); rows.close(); db.close();
end _lmcode_
# save/run state with the standard runner; stop if it failed

transfer = _lmcode_ cli="lmaws";
let cloud = aws.region("us-east-1");
let bucket = cloud.s3_target("lmaws-example-site", "<private owner receipt>");
let instructions = logs.read_instructions(".lmsync-local/plan.jsonl");
let results = logs.result_writer(".lmsync-local/results.jsonl");
while (instructions.has_next()) {
  let instruction = instructions.next();
  if (instruction.verb() == "add") {            # USER action choice
    let reply = bucket.put_file(instruction.get("key"), instruction.local_path(),
        cloud.put_options().cache_control(instruction.get("cache_control")));
    results.confirm_record(instruction, reply.source_fingerprint(), reply.metadata());
  }
}
results.close(); instructions.close();
end _lmcode_
# run only when the plan is nonempty, with CAP_USD admitted by lmaws;
# collect its exit code instead of skipping replay on partial transfer failure

recorded = _lmcode_ cli="lmsync";
let db = sync.open(${DB}, "site", sync.open_options());
logs.apply_records(db, ".lmsync-local/results.jsonl");
db.close();
end _lmcode_
# run replay even after a partial provider failure, then report that failure
```

Production implementation must include the script's preconditions and unknown-key
handling, expected source checksums, content-type mapping, error/result branches
and source-stability checks; the abbreviated example shows the ownership boundary.
No `sync.upload`, `sync.delete_remote` or `sync.execute_plan` function exists.

The script—not lmsync—chooses `changed`/`unknown` rows, maps source to keys, gives
HTML short max-age, skips other rows and refuses unsafe collisions. It does not
implicitly delete omitted objects. Core can return a same-as-recorded row while
the script detects changed desired headers in its stored metadata. A no-op script
skips lmaws; core and job decision work make zero remote queries. Live lmaws may
perform its mandatory security checks when the script requests a transfer; count
them separately. The picture shows scan/query -> chosen PUTs -> recorded receipts.

### (b) `publish_hashed.lms`: content-hashed assets

This script hashes and transforms a supported reference graph, prepares immutable
asset paths and rewritten entries, then feeds those exact derived files/paths
through the same state API. The transformation/helper belongs to script code,
not the DB. Cache immutable assets for a year and entries briefly; the script
sets those headers in lmaws calls. Unsupported dynamic references, cycles and SRI
changes are handled explicitly by the script. It may fail or expand a previewed
dependency closure; lmsync never silently adds files outside the queried subset.
Record final-byte digests separately from source/build fingerprints. The synthetic
picture shows old/new asset URLs and entry-cache delay; assertions cover reference
rewriting and unchanged assets skipped by the script.

Policy sketch inside this single `publish_hashed.lms` (not a core option):

```text
let source = observe_build_inputs();             # local script/helper calls
let derived = rewrite_and_hash_supported_graph(source);
for (asset in derived.assets) {
  let key = "assets/" + asset.final_hash + asset.extension;
  # query its state; USER chooses a PUT/copy when needed
  put_with_lmaws_and_record(asset, key, "public,max-age=31536000,immutable");
}
for (entry in derived.entries) {
  put_with_lmaws_and_record(entry, entry.name, "public,max-age=30");
}
```

Here `rewrite_and_hash_supported_graph` and `put_with_lmaws_and_record` are explicitly
user-owned `.lms` helpers implementing that job's policy/host calls, not lmsync
functions. They stream/batch rather than build an unbounded in-memory graph.

### (c) `publish_release.lms`: prefix activation and rollback

The script stages a complete manifest under a release prefix, records each action,
then asks lmaws to conditionally switch an owned CloudFront origin path or an
explicitly implemented routing pointer. A pointer is not automatically interpreted
by CloudFront. Journal activation as another user-chosen event. Retain previous
complete releases and perform rollback by a new switch, not by re-uploading their
bytes. The switch is a single control-plane commit, not a transaction spanning
all objects/edge locations; entry TTL and distribution propagation remain.

The script chooses keep-last-N, grace time, pins, safety thresholds and exactly
which indexed release paths to delete. It must handle incomplete staging, switch/
record crash gaps and conditional conflicts. No release catalog, GC rule or
rollback action is built into lmsync. A new physical prefix can require PUT/COPY
of unchanged bytes: measure that amplification rather than promising 1% writes
in a mode that deliberately changes every destination key. The picture shows
stage/activate/previous/rollback and a simulated interrupted activation.

Its user-script control flow is explicit:

```text
let release = USER_SELECTED_RELEASE;
let complete = stage_release_with_lmaws_and_record(release);
assert(complete);
let before = read_user_recorded_activation();
let switched = lmaws_switch_origin_path_with_etag(release, before.config_etag);
record_user_activation_event(release, before.release, switched);
# An explicit rollback branch switches to before.release and records that action.
# A separate USER decision computes retained releases and chosen exact GC paths.
```

These helpers are policy-bearing script code. lmsync only stores/retrieves the
reported per-file and activation-event metadata; it does not understand release IDs.

### Freshness policies retained from the earlier design

These are selectable **script templates/options**, not core enums/rules. A script
may expose flags or variables named `ttl`, `hashed`, `release`, `invalidate`, or
combinations. It implements their meaning and passes only plain scan parameters,
state operations and explicit cloud actions to the hosts. Small-site template
recommendation: TTL. Large-site template recommendation retained from the prior
design: release + hashed assets + short-TTL entries, with its staging/retention
tradeoff shown. Hashed + TTL remains a lower-write-amplification alternative.
Neither recommendation is automatically selected by lmsync based on size.

| Script policy | Cost/request implications | Freshness delay | Rollback | Failure modes |
|---|---|---|---|---|
| `ttl` | Changed PUT/metadata operations; ordinary cache misses; no invalidation fee | Entry/asset TTL selected by script | Re-publish retained prior bytes | Mixed caches and non-atomic multi-file publication |
| `hashed,ttl` | Hash/transform CPU, new asset objects and rewritten entry PUTs; keep old referenced assets | New asset URLs avoid stale bytes; entries still wait TTL | Re-publish retained entries pointing at retained assets | Unsupported references, cycles/SRI, premature old-asset deletion |
| `release,ttl` | Stage/copy release objects, one switch plus polls, retention and chosen GC | Switch propagation plus unversioned-entry TTL | Immediate rollback request to retained prefix; not instant global viewer freshness | Incomplete release, switch/record gap, conflicting update, stale entry caches |
| `release,hashed,ttl` | Above plus transformation; exact reuse/copy scheme is script policy | Same switch/entry delay, coherent immutable references | Same switch | Combined graph/activation issues and additional physical keys |
| Explicit `invalidate` combined with any policy | Submitted paths and potential cache-refill cost, plus status calls | Asynchronous completion; browser caches may remain | Whatever the base script implements; invalidating rollback is another explicit action | IAM denial, cap refusal, uncertain completion or broader cold-cache load |

The invalidation example can choose cap 100, prefer one safe wildcard when cheaper,
print a cost estimate first, use the lmaws ledger and allow a separate explicit
cap override. Those choices are visible script policy; no lmsync method enforces
or defaults them. Preserve optional scoped IAM grant via the existing lmaws grant
recipe; remove the current default policy-builder CreateInvalidation grant during
that host's implementation work if adopting this example policy. No policy is
changed by this design. Existing explicit host APIs remain compatible through a
properly guarded/costed implementation; no default job invalidates implicitly.

### (d) `publish_git_diff.lms`: arbitrary cherry-pick

The script obtains a NUL-delimited git diff against its chosen deployed revision,
or accepts an explicit list/manifest/stdin paths, observes only those local paths,
queries them and selects transfers. It can combine unrelated root aliases and
map them to a bucket/prefix chosen in the script. It checks flatten/key collisions
itself before execution. Renames/deleted source entries do not automatically
become remote deletes; the script decides. Its synthetic picture compares the
small chosen subset with a large recorded namespace and shows zero remote
queries by lmsync. The recipe can also demonstrate build-manifest and one-off
file lists without adding corresponding core policy concepts.

For example, the job—not the state library—chooses the candidate list:

```text
let diff = system(["git", "diff", "--name-status", "-z", DEPLOYED_REV, "HEAD"], 30000);
assert(diff.code == 0);
write_file(".lmsync-local/git-paths.nul", diff.stdout);
let candidates = parse_git_diff_as_paths(".lmsync-local/git-paths.nul");
# lmsync scan_paths/query -> USER selection -> lmaws PUT -> lmsync record.
# USER may instead supply a build manifest or a cherry-pick list from several roots.
```

NUL parsing preserves whitespace/quotes; the job handles rename/deletion statuses.
The git invocation is illustrative and was not executed for this design.

### (e) `publish_sftp.lms`: transfer-host sketch

Keep SSH/SFTP in a transfer host, outside lmsync. Proposed calls:
`connect(host, port, auth_ref, known_hosts_or_pin)`, `put_file(local, temp_remote)`,
`fsync_if_supported(temp_remote)`, `rename(temp_remote, final_remote, options)`,
`remove(path)`, optional explicit `stat(path)` and `close`. The script chooses
remote paths, temporary names, overwrite policy and any verification. Transfer
to a sibling temp name and rename only after success; record final-path success
only after rename acknowledgment. Cross-filesystem/non-atomic rename or missing
server extensions must be reported, not presented as atomic. Interrupted temp
files stay unconfirmed; the script chooses cleanup/retry. A successful SFTP
rename is not proof of storage fsync unless the server supports and acknowledges it.

Evaluate [SSHJ](https://github.com/hierynomus/sshj) and maintained
[JSch fork](https://github.com/mwiede/jsch) first; also consider
[Apache MINA SSHD](https://github.com/apache/mina-sshd). These Java libraries provide
SSH/SFTP capabilities, but the selected algorithms, crypto providers, key formats,
resources and exact GraalVM native-image configuration require a prototype. Do not
assert blanket native-image compatibility from JVM use. Choose a pinned patched
version with JDK/pure-Java providers; do not introduce JNI for SSH agents/crypto.

Host-key verification is mandatory via known_hosts or an explicit trusted pin;
no accept-all verifier or automatic trust-on-first-use. Credentials come from
private references/approved agents, never literals or logs. Key mismatch fails
before transfer. No credentials, real server names or real fingerprints enter
committed evidence. Test with a local fake/test SFTP server, key mismatch and
rename failure. The picture shows temp -> confirmed rename -> local record.

Single-job sketch, with the same state/transfer host phases:

```text
let selected = user_selects_from_state_and_local_files();
for (item in selected) {
  let temporary = user_temp_name_next_to(item.remote_path);
  # SFTP HOST: verified connection, PUT temporary, fsync if supported, RENAME final.
  let result = sftp_put_then_rename(item.local_path, temporary, item.remote_path);
  # LMSYNC: record only the source fingerprint and final-path result reported confirmed.
  record_result(item.path, result);
}
```

No remote stat is needed by lmsync; a script that requests one does so through the
SFTP host. This sketch is not a runnable SFTP implementation or library choice.

### (f) `verify_sample.lms`: user-chosen verification

The script selects N random recorded objects with a visible seed and sampling
policy, calls lmaws HEAD with its own ledger allowance, compares metadata/checksum
semantics, and explicitly marks selected records suspect or updates their data.
N, the rate, what constitutes mismatch and any follow-up rebuild are script code.
No core warning appears because a record is old. HEAD cannot always establish
full byte equality; unknown/missing checksum evidence is handled by that script.
Its picture labels sampled vs untested records and shows the actual HEAD count.

The verification choice is visible in the `.lms` source:

```text
let selected = user_reservoir_sample(recorded_paths, N, SEED);
for (path in selected) {
  let actual = lmaws_head(path.recorded_remote_path);  # explicit paid remote action
  if (user_metadata_comparison_says_mismatch(path, actual)) {
    lmsync_mark_suspect(path, "sample mismatch");
  }
}
```

The sample helper, N, seed and comparison are user script code. lmsync provides
record iteration and mark_suspect, not a sampling schedule or verification policy.

### (g) `track_invalidations.lms`: user actions and monthly quota

This job obtains paths from its own logic, chooses exact vs wildcard, counts
submitted paths (a wildcard counts as one), prints cost, admits it through lmaws,
then calls CreateInvalidation with a stable caller reference. It records accepted
and later completed phases in an opaque event namespace using record(), just as
for any other reported action. lmsync has no CloudFront verb handler or monthly
quota counter. The script groups its recorded event metadata by UTC month and
sums accepted path quantities, deduplicating the provider/caller identity.

The account-wide allowance is shared across distributions and outside callers.
Local event history can report **known recorded usage**, not guarantee remaining
free quota. Missing history, other writers and a crash before recording can make
that count incomplete. The script can reconcile/retry a known caller reference
or import reviewed receipts; it cannot assume zero outside usage. Conservative
cost estimation prices paths without assuming remaining allowance. Failed-before-
acceptance attempts are not silently recorded as successful quota use; uncertain
outcomes remain explicit until the script reconciles them. The picture shows
known monthly paths, uncertainty and estimated charge; no real billing evidence.
[AWS invalidation billing](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/PayingForInvalidation.html).

For example, the user's job can express its monthly accounting as:

```text
let known_used = user_sum_recorded_accepted_paths(UTC_MONTH);
let paths = user_selects_and_deduplicates_paths();
let charge = user_estimate_with_uncertain_free_allowance(known_used, paths);
print_estimate_before_call(charge, paths);
let reply = lmaws_create_invalidation(paths, STABLE_CALLER_REFERENCE);
lmsync_record_event("invalidation/" + STABLE_CALLER_REFERENCE,
                   reply.phase, reply.timestamp, paths.count(), reply.metadata);
```

The host ledger still admits the request. The user may expose cap/override flags
in this script; none of those helpers or constants becomes lmsync business logic.

### Exact lmaws actions needed and current gaps

This audit uses the checked `schema/lmaws.dsl.json`, CloudHost registry and
WebStackAws implementation. Names in the proposed column are design names,
not claims that they exist today.

| Script need | Current lmaws surface | Proposed additive transfer-host work |
|---|---|---|
| Persistent owned bucket access | Run.bucket and Run.put(Row,string,string) exist for sandbox/string writes; Web.step uploads a fixed set of site assets | `s3_target(bucket, owner_receipt)` persistent handle with existing prefix/tag/profile guards; explicit lifetime, no implicit deletion on successful close |
| Arbitrary binary PUT with caller headers | Private WebStackAws file upload exists; no general typed file PUT API | `S3Target.put_file(key, local_path, PutOptions) -> TransferReceipt`, content type/Cache-Control/storage class/checksum/conditions chosen by script |
| Streaming multi-file transfer | Current backend uses synchronous URLConnection; no general TransferManager API | SDK v2 S3TransferManager with explicit Java multipart async client and bounded transfer/request/byte options; no CRT |
| DELETE exact objects | Sandbox cleanup/Web.down exist; no general typed per-key receipt-oriented DELETE | `delete_object(key, DeleteOptions) -> ActionReceipt`; expose version/condition outcomes, do not invent a deletion policy |
| Server-side COPY | No general typed COPY binding | `copy_object(source, destination, CopyOptions) -> TransferReceipt`; expose checksum/version/source and destination conditions and full SDK result |
| HEAD for verification | No general typed per-object HEAD binding | `head_object(key, HeadOptions) -> ObjectMetadata`, with absence/denial distinguished and checksums interpreted explicitly |
| Multipart resume | No general typed multipart/resumable receipt surface | Expose opaque resumable state or start/part/complete/abort actions; the script stores upload ID, part receipts, source snapshot and phase in record metadata/logs |
| Release switch/rollback | Web.step builds distributions/cache settings; no general owned origin-path/pointer CAS operation | `distribution_config` + conditional `set_origin_path` or explicit pointer PUT, with opaque config/version receipts and bounded status wait |
| Chosen invalidation paths/status | Web.step("invalidate",...) reaches a private wildcard-only helper | Typed `create_invalidation(paths, caller_reference)` and `get_invalidation`; expose counts/cost/receipt, route through host ledger and optional IAM grant |

The scripts need S3 PutObject/DeleteObject/GetObject (HEAD/copy source), relevant
multipart actions (including abort; ListParts only if that script explicitly
reconciles a known upload), and object version permissions only when selected.
The host validates the exact action/resource request and records its service cost;
lmsync stores only the supplied data. COPY must inspect the complete result, not
assume every HTTP 200 means success, and expose supported preconditions; if the
pinned SDK cannot express a required condition, the script must choose a safe
alternative instead of an unguarded write. [CopyObject API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html).

For examples (a)–(g), preserve `lmaws-*` bucket names and `lmaws_test` ownership in
lmaws, AWS_PROFILE=lmaws for live actions and the existing cost ledger. No such
prefix/profile/cap rule lives in lmsync. TransferManager, its Java async transport,
resumable-state tests and the generic file APIs are missing integration work,
not a reason to replace the Java host. [Java multipart client](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/s3-async-client-multipart.html),
[TransferManager](https://docs.aws.amazon.com/java/api/latest/software/amazon/awssdk/transfer/s3/S3TransferManager.html).

## 7. One LMScript, two hosts; first milestone

**Available today:** a `.lms` file can contain multiple `_lmcode_` / `_dsl_` blocks,
each compiled against its own `cli="host"` schema. `savedsl` writes bytecode;
`dsl_cli(program)` returns the matching executable argv; `system(argv, timeout)`
runs it. `${...}` interpolation supplies scalar strings/numbers/bools, so a file
path can bridge blocks. Schema-bound handles belong to their host process: do not
pass a StateDB/S3 handle to another host, merge schemas blindly or assume that
printing/serializing a compiled block transfers its live objects.

The existing lmweblab report scripts already demonstrate lmdraw and lmplot in one
LMScript. The source contract is in
`lmscript/durable-memory/lmscript_language_reference.md` (DSL blocks) and
`lmscript/lmscript.ts` in the existing monorepo; only local source inspection was
used, with no workflow dispatch. General orchestration is therefore available;
a new universal multi-host VM or cross-language JNI bridge is not required.

Illustrative orchestration shape, using existing runner mechanics but future
lmsync/provider APIs inside the marked bodies:

```text
# === CONFIG ===
let DB_PATH = ".lmsync-local/site.db";
let PLAN_PATH = ".lmsync-local/plan.jsonl";
let RESULT_PATH = ".lmsync-local/results.jsonl";
# === END CONFIG ===
state_program = _lmcode_ cli="lmsync";
  # future local scan/query API; user-written if/loop chooses instructions
end _lmcode_
savedsl(state_program, ".lmsync-local/state.dslb");
let a = system(concat(dsl_cli(state_program), ["--dsl", ".lmsync-local/state.dslb"]), 120000);
assert(a.code == 0);

transfer_program = _lmcode_ cli="lmaws";
  # future file/receipt API; user-written policy consumes PLAN_PATH and writes RESULT_PATH
end _lmcode_
# save and run the transfer host only if this script selected actions

record_program = _lmcode_ cli="lmsync";
  # future local record/log-replay API consumes confirmed RESULT_PATH projections
end _lmcode_
# save and run, check every exit code, close resources, report this job's result
```

This is a mechanism sketch, not a currently executable lmsync script. Markers/
`cli` are supported aliases, but lmsync does not yet exist and has no installed
schema. Current `read_lines` returns an array: do not load a million-line plan
through it. Add thin streaming/bounded file-reader/writer helpers and shared
codec fixtures to participating hosts, or partition local files into bounded
batches. Process one batch or a streaming file in a host, not one process per
file. Keep policy in the `.lms` block's explicit code; helpers do not dispatch
verbs by themselves. Generic local codec APIs are the only common host glue.

lmazure and lmgcp use exactly the same local state/query/record data contract.
Replace the transfer block with their typed blob/object API and receipts; native
.NET/Go/Java implementations can read the versioned files without sharing live
objects or linking the DB. Provider names and Azure/GCP safety/cost rules remain
in those hosts/scripts. No lmsync provider plugin or cloud credential is needed.
SFTP is another explicit transfer block with the same reported-result contract.

### Smallest useful milestone

1. Java lmcode skeleton and a qualified small crash-safe store: open/close, local
   scan/scan_paths, hash-on-change/on-demand, neutral query, set differences,
   record/forget, bounded iteration and transactions.
2. Thin optional plan/result codec with direct-call alternative, idempotent
   confirmed replay, local import/export, doctor and the kill-point tests.
3. One complete `publish_ttl.lms` containing its own choices and two-host glue,
   plus a **local fake S3-like executor** returning deterministic receipts. Test
   first publish, no-op, one changed file, local deletion without automatic remote
   deletion, uncertain transfer, result-before-record crash and changed-source race.
4. Add the smallest lmaws persistent-target/binary-PUT/receipt APIs needed for
   the same script. Test real SDK serialization against loopback transports.
5. **Only after later explicit live authorization**, run that one job against one
   owned test bucket named `lmaws-*`, tagged `lmaws_test`, within lmaws ledger caps.
   The script explicitly cleans its known test objects/bucket in success and
   failure paths and records/report outcomes. The real test is a future milestone,
   not executed or authorized by this design task.

No need to finish every cache policy, SFTP provider, large-store tier or inventory
importer before this local state primitive is useful. The repo is created later;
this document does not create `lmctl-ai/lmsync` or dispatch any build/release job.

## 8. Benchmark plan proving the local-state claim

No measurements are fabricated here. Use deterministic synthetic fixtures and a
local protocol-recording fake endpoint first. A network-denying harness must prove
that all lmsync operations, including doctor/import/recovery, make **zero network
calls**. Benchmark transfer scripts separately, counting every host request,
security check, retry and byte. Emulator timing is not AWS timing.

### Query and request counts

Measure 1M queried paths as index-only lookups with existing local observations,
then separately end-to-end local scan/stat/hash + query. Include random and
localized sets, hits/misses, multiple targets, dirty stat records, unrelated roots
and streaming output. Compare HEAD-per-file and explicit list-and-compare via the
fake action host, not new network methods in lmsync. An arbitrary subset of M paths
need not correspond to a remote directory; enumerating N remote keys still leaves
the application to compare that subset. An existing local DB answers directly.

Expected decision counts below are **hypotheses for measurement**, excluding
separately reported transfer-host security checks. Assume full 1,000-object pages;
directory shape, short pages, retries and baseline options can add requests.

| No-change decision method | 10k files | 200k files | 1M queried paths with a 1B-object target |
|---|---|---|---|
| lmsync local query | 0 remote calls | 0 remote calls | 0 remote calls; 1M local comparisons |
| HEAD/stat per file baseline | 10k HEAD/stat | 200k HEAD/stat | 1M HEAD/stat |
| Flat list-and-compare | About 10 LIST | About 200 LIST | At least 1M LIST pages if enumerating the whole target |
| AWS CLI `s3 sync` tree workflow | Expect about 10 LIST plus measured extras | Expect about 200 LIST plus extras | Destination enumeration scales with the compared namespace |
| rclone ordinary sync | Page lower bound plus per-directory/metadata calls | Same caveat | Measure directory traversal, not only the flat lower bound |
| rclone fast-list sync | About 10 LIST plus measured checks | About 200 LIST plus checks | Enumeration and memory scale with destination |
| rclone no-traverse subset copy | Direct candidate checks measured; no full-tree listing expected | Same | A fair optimized subset competitor; usually trades traversal for direct checks |

Do not claim every tool always lists. Fix/document the exact baseline flags and
versions, including rclone modtime/HEAD-after-upload and fast-list memory choices.
Keep metadata, integrity checks, concurrency, part settings, byte sizes, latency,
region/endpoint and retry policy comparable; report tuned as well as default
baselines. [AWS CLI sync](https://docs.aws.amazon.com/cli/latest/reference/s3/sync.html),
[rclone S3 behavior](https://rclone.org/s3/), [rclone flags](https://rclone.org/flags/).
No baseline commands are executed here. A future non-lmaws AWS baseline requires
its own explicit authorization; loopback/fake comparisons need no real account.

ListObjectsV2 returns at most 1,000 keys/page. A billion keys implies at least a
million LIST requests, roughly $5 under an illustrative $0.005/1,000 request rate,
before other costs. At illustrative $0.0004/1,000 read requests, 1M HEADs cost $0.40;
lmsync's local query costs $0 in remote requests. These are arithmetic examples,
not invoices, performance measurements or hardcoded lmsync prices. Pricing belongs
to the script/action host. [ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html),
[AWS pricing example](https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/cost.html).

### 10k / 200k publication jobs

Create real local synthetic trees of 10k and 200k files with recorded distributions,
seed and digests. Measure first publication, no-change re-run, and 1% changes
(100 / 2,000 files), plus separate metadata-only, preserved-mtime and multipart
variants. Run the same user policy with state enabled and a Java transfer baseline
without remembered state to isolate DB benefits from SDK transfer throughput.

Collect scan/query/decision/transfer/record wall time, CPU/hash bytes, peak heap/RSS,
OS page cache, disk I/O, open-file peak, per-operation request counts, uploaded/copied
bytes and action-host estimated cost. Use at least three trials with hardware,
filesystem, dependency versions and JVM/native-image labels. A cold process is not
a cold filesystem cache; report the distinction. Any picture from fake trials is
clearly synthetic.

With a script that chooses only changed stable-key single-part uploads, expected
PUTs are N initially, 0 on no-op, and 0.01N for a 1% content change, plus host checks
and any verification the script deliberately selected. Release prefixes, hash
rewrites and script-selected verification can amplify these counts; show them as
separate policies, not hidden costs of the state primitive. A 200k first publish
can exceed the existing lmaws $0.25 per-run hard ceiling. Use the fake executor for
that experiment; any later live campaign needs explicit bounded batches, aggregate
cost disclosure and authorization, not a silent cap raise.

### 100M-entry local index test

Generate **100M local index path records**, realistic target records/opaque metadata
and required lookup families on disk, not 100M real local files or S3 objects.
Check free disk/headroom first (the sizing model calls for at least 200 GB for this
test plus extra retention as configured). Measure actual bytes per family, WAL,
filters/fences, compaction amplification, bulk ingest, open/recovery time and
1M-query warm/cold latency under fixed memory limits. Include 90/10 hit/miss mix,
localized/uniform random queries, multiple targets, 1% updates, forget tombstones,
concurrent snapshot readers and forced-kill recovery. Use 64-bit offsets and files
larger than 4 GiB. Compare JVM and shipped GraalVM binaries.

Publish measured size/lookup/RSS results before selecting the 100M tier as stable.
The 1B estimates remain projections until a separately qualified larger test;
do not create a billion remote objects. An all-in-memory microbenchmark is not
evidence for this disk tier. Store failures trigger a better Java codec/store
choice, not automatic JNI adoption or a full C++ rewrite.

## 9. Positioning, risks and implementation breakdown

lmsync is a reusable remembered-state primitive, not another all-in-one cloud sync
product. aws s3 sync/rclone combine comparison and transfer workflows; rsync can
exchange remote file metadata and exploit transfer deltas. Those are useful
capabilities that lmsync does not replace. Its distinct contract is arbitrary
subset questions against a local believed model with zero remote calls, while
user scripts own policy and choose cloud/SFTP actions. Optimized no-traverse
baselines matter; do not pretend they cannot avoid directory enumeration.

| Risk/failure | Boundary and mitigation |
|---|---|
| Outside writer or years-old belief | No age heuristic or hidden query; script chooses explicit verification/reconciliation |
| Same-size preserved-mtime edit | Disclosed stat basis; caller can request hashing/immutable inputs |
| Script records wrong success/current instead of transferred fingerprint | Library must never auto-attach current fingerprint; retain reported source snapshot and test races; user reports remain the trust boundary |
| Remote completion before local confirmation | Intent remains unconfirmed; user retries/reconciles; no exactly-once remote promise |
| Partial scan mistaken for missing files | Incomplete scope is data; unobserved paths are not confirmed missing |
| Metadata/key mapping/freshness changes | Script compares its desired metadata and chooses actions; core same-as-recorded is not an upload decision |
| Multi-target/shared-key collisions | Script maps/checks physical destinations; core keeps separate namespace/path records |
| Disk full, checksum corruption, stale lock | Crash-safe commit, doctor, OS locking and validated backup/import; no silent empty-store fallback |
| Huge output or cached filter growth | Bounded cursors/spills/caches; no unbounded arrays or all-in-memory 1B map |
| Native-image/store/SSH compatibility | Qualify exact pinned binaries/providers; no implicit JNI/native transport fallback |
| Incorrect free-quota assumptions | Script tracks known events, discloses incomplete history and uses host pricing/admission |
| Policy creeping into core | Review rejects auto-upload/delete/age/rebuild/cache/provider/ledger decisions in lmsync |

Implementation steps for coders:

1. Freeze the neutral value types, comparison basis, target/path identity, local
   record metadata and result confirmation semantics. Publish codec fixtures.
2. Qualify Java small-store candidates under native-image; implement crash-safe
   open/transactions/record/forget, writer locking, snapshot readers and doctor.
3. Implement bounded scan/scan_paths/hash/query/set-difference cursors and local
   import/export. Test empty/missing/unobserved states and arbitrary subsets.
4. Add optional generic plan/result codecs and replay offsets. Run the complete
   kill-point/model-oracle harness; no provider dependency is permitted.
5. Build example (a) as **one LMScript** with a fake executor and pictures. Add the
   minimal lmaws file/receipt APIs, then later the explicitly authorized test-bucket
   milestone. Do not create the lmsync repo or execute that milestone in this task.
6. Add example jobs (b)–(g) and provider/SFTP capabilities separately, keeping their
   choices in script source and costs/security in their hosts. Preserve all
   existing examples and host APIs. No config-driven policy engine is introduced.
7. Implement/qualify sorted-run large tiers, local 100M benchmark and format
   migration. Record measurements and limits; enable advertised tiers only after
   durability/memory/lookup evidence, not optimistic extrapolation.
8. Integrate schema/help/signatures, native-image packaging and repeatable fake
   tests across platforms. Review core purity and existing recipe conventions.
   Live cloud trials and release/workflow actions remain separately authorized.

Acceptance: core tests prove zero network attempts; every query returns neutral
state plus provenance; every reported confirmation survives a crash; uncertain
work never becomes unchanged; scripts can implement different policies without
changing lmsync. No default freshness, retention, invalidation, age or delete rule
is added to the core. This document is the consolidated design; root
`SYNC_DESIGN.md` is only a pointer.
