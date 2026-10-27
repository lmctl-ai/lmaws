# Independent Design Review: `docs/LMSYNC_DESIGN.md` (`lmfiles`)

Reviewed document: [`docs/LMSYNC_DESIGN.md`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md) (1,329 lines on `main` of `lmctl-ai/lmaws`).  
Audited against local repositories and binaries:
- [`lmaws`](file:///home/mma/repos/dsl/lmaws) (`0.1.19` worktree, [`Sandbox.java`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/Sandbox.java), [`WebRun.java`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/WebRun.java), [`WebStackAws.java`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/WebStackAws.java), [`CostLedger.java`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/CostLedger.java))
- [`lmcurl`](file:///home/mma/repos/dsl/lmcurl) (`8e65448`, [`cpp/http.cpp`](file:///home/mma/repos/dsl/lmcurl/cpp/http.cpp), [`cpp/core.cpp`](file:///home/mma/repos/dsl/lmcurl/cpp/core.cpp))
- [`lmssh`](file:///home/mma/repos/dsl/lmssh) (`68e6159`, OpenSSH `V_10_6_P1`, [`cpp/host.cpp`](file:///home/mma/repos/dsl/lmssh/cpp/host.cpp))
- [`lmcode-java`](file:///home/mma/repos/dsl/lmcode-java) (`0.1.1`, [`Value.java`](file:///home/mma/repos/dsl/lmcode-java/src/main/java/io/lmctl/lmcode/Value.java), [`Registry.java`](file:///home/mma/repos/dsl/lmcode-java/src/main/java/io/lmctl/lmcode/Registry.java), [`VmString.java`](file:///home/mma/repos/dsl/lmcode-java/src/main/java/io/lmctl/lmcode/VmString.java), [`std/lmcode-std.schema.json`](file:///home/mma/repos/dsl/lmcode-java/std/lmcode-std.schema.json))
- [`lmdb`](file:///home/mma/repos/dsl/lmdb) (`0.1.1`, [`pom.xml`](file:///home/mma/repos/dsl/lmdb/pom.xml), [`lmdb-h2/reflect-config.json`](file:///home/mma/repos/dsl/lmdb/src/main/resources/META-INF/native-image/ai.lmctl/lmdb-h2/reflect-config.json))
- `@lmctl-ai/lmctl` (`0.2.420`, `lmscript` parser/runtime)

---

## Executive Summary

The v2 revision of [`docs/LMSYNC_DESIGN.md`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md) successfully establishes the core architectural boundary required by the user:
- **Zero remote calls in the registry** (lines 36–38, 1156–1158, 1324).
- **Zero business rules in core** — invalidation, freshness, retry/gone-skip, local deletion, sampling, and caps stay in one user-authored `.lms` script per job (lines 40–58, 73–76, 1327–1328).
- **No "index too old" warning**, no config-file rules engine, and no JNI/C++/libssh2/Java-SSH transport inside `lmfiles` (lines 43–45, 51–53, 523–528, 761).

However, cross-checking the design against the **actual implementations** of `lmcode-java`, `lmcurl`, `lmaws`, `lmssh`, `lmdb`, and `lmctl` reveals **four HIGH-severity technical issues** and **five MEDIUM/LOW issues** that must be resolved before implementation starts:

1. **[HIGH — F1]** Section 1's proposed "Typed API" (lines 131–169) and Section 6's relational query syntax (lines 695–702) use 24+ value-struct parameter types (`OpenOptions`, `StageResult`, `Query`, `StageSelector`, etc.) that **do not exist in `lmcode`'s `dsl.schema: 2` type system** ([`Value.java`](file:///home/mma/repos/dsl/lmcode-java/src/main/java/io/lmctl/lmcode/Value.java) supports only `int`, `float`, `string`, `bool`, `void`, and opaque host handles).
2. **[HIGH — F2]** In [`lmcurl/cpp/http.cpp:415-416`](file:///home/mma/repos/dsl/lmcurl/cpp/http.cpp#L415-L416), `Request.send()` **throws a fatal `dslvm::Error` (`exit code 3`) whenever `result.error` is non-empty**. Consequently, `response.error()` in `LMSYNC_DESIGN.md` lines 807 & 811 is dead code on transport errors (`STATUS_PATH` and `ERROR_PATH` are never written), and any multi-URL batch inside one `lmcurl` process (line 1101) aborts on the first failed URL. Conversely, the per-URL `_lmcode_` splicing shown on lines 796–814 spawns one `lmcurl` process per URL, forfeiting HTTP/2 connection reuse across millions of legal URLs.
3. **[HIGH — F3]** Steady-state `stage_difference(fetched.ok, cleaned.ok)` (lines 204–211, 579–581, 664–665) at 100M laws/cases — where 99.995M items are already in both stages and only 5,000 items are newly fetched — requires scanning **200M posting entries (~800 seconds cold at the 250k IDs/s target)** on every incremental run unless the store maintains a compact per-item stage-revision bitmask or materialized pending-frontier index.
4. **[HIGH — F4]** The **3–5 KiB/item storage estimate** (lines 91–100, 548–571; 300–500 GB live + 0.6–1.0 TB compaction headroom at 100M items) is inflated by **~4–5x** because it assumes verbatim repetition of `(stage, namespace)` strings, 128-bit `ItemId`s, and SHA-256 digests across 15 records and secondary postings per item. With dictionary-interned IDs (`u16` stage/namespace), dense internal `u64` item IDs, raw 32-byte digests, and prefix-compressed sorted runs, the same 3-alias / 5-stage / 6-event model fits in **~750–1,050 B/item (~75–105 GB live at 100M items)**.

---

## Ranked Findings (with Exact Line References)

### [F1 — HIGH] Section 1 Typed API & Section 6 Query Snippets Exceed the `lmcode` (`dsl.schema: 2`) Type System
- **Lines**: [`LMSYNC_DESIGN.md:131-169`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L131-L169), [`639-646`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L639-L646), [`695-702`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L695-L702)
- **Evidence**:
  - In [`lmcode-java/src/main/java/io/lmctl/lmcode/Value.java:5-17`](file:///home/mma/repos/dsl/lmcode-java/src/main/java/io/lmctl/lmcode/Value.java#L5-L17) and [`Registry.java`](file:///home/mma/repos/dsl/lmcode-java/src/main/java/io/lmctl/lmcode/Registry.java), `_lmcode_` (`dsl.schema: 2`) supports only four scalar types (`int`, `float`, `string`, `bool`), `void`, standard collection handles (`IntList`, `FloatList`, `StrList`, `StrMap`, `Json`), and host-owned opaque object handles.
  - `_lmcode_` has **no struct/record literals**, **no named/keyword arguments**, and **no inline relational query expressions** (`published.last_success join items where published.source_revision != items.content_revision` on lines 695–696).
  - Section 1's signatures introduce **24 distinct input struct types** (`OpenOptions`, `Identity`, `ItemFields`, `Alias`, `Observation`, `IdentitySource`, `CompareOptions`, `StageResult`, `Query`, `StageSelector`, `JoinOptions`, `ScalarPredicate`, `TimeField`, `TimeRange`, `GroupFields`, `AggregateFields`, `EventCursor`, `EventFilter`, `ScanOptions`, `PathSource`, `LocalRecordSource`, `ImportOptions`, `ExportOptions`, `DoctorOptions`) and **18 return handle types**.
  - Furthermore, `lmcode-java`'s collection/handle arena enforces a per-run object limit (65,536 collection objects in [`StdContainers.java`](file:///home/mma/repos/dsl/lmcode-java/src/main/java/io/lmctl/lmcode/StdContainers.java)). If every item, receipt, query predicate, and stage result is a distinct host handle constructed via builder methods, a single batch of 10,000 items will exhaust the handle arena.
- **Recommendation**:
  - Follow the established `lmaws` ([`CloudHost.java`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/CloudHost.java), [`Rows.java`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/Rows.java)) and `lmdb` ([`HostApi.java`](file:///home/mma/repos/dsl/lmdb/src/main/java/ai/lmctl/lmdb/HostApi.java)) pattern: keep host object types down to **4–5 core handles** (`Registry`, `Snapshot`, `Cursor`, `WriteBatch`, `Row`/`Rows`) and pass structured options/filters/results as canonical JSON `string` or `StrMap` arguments (or a small reusable `Query` builder handle).

---

### [F2 — HIGH] `lmcurl` `Request.send()` Throws Fatal `dslvm::Error` on Transport Failures, Breaking Both Receipt Writing and Batch Execution
- **Lines**: [`LMSYNC_DESIGN.md:649-656`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L649-L656), [`796-814`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L796-L814), [`1025`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L1025), [`1101`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L1101)
- **Evidence**:
  - Lines 806–811 of `LMSYNC_DESIGN.md` write:
    ```text
    let response = request.send();
    if (response.error() == "" && response.status() == 200) {
      response.save(${PART_PATH});
    }
    file_write(${STATUS_PATH}, str(response.status()));
    file_write(${ERROR_PATH}, response.error());
    ```
  - However, in [`lmcurl/cpp/http.cpp:415-416`](file:///home/mma/repos/dsl/lmcurl/cpp/http.cpp#L415-L416), `Session::perform` executes:
    ```cpp
    if (!result.error.empty())
      throw dslvm::Error("HTTP transport failed: " + result.error);
    ```
  - Verified empirically with `lmctl` + `lmcurl`: when a request encounters any transport error (connection refused, DNS failure, TLS error, timeout, or size limit), `request.send()` **throws `dslvm::Error` and terminates the `lmcurl` process with exit code `3`** before lines 807–813 execute. Neither `STATUS_PATH` nor `ERROR_PATH` is written, and `response.error()` is **always `""`** whenever `request.send()` returns normally.
  - This creates a direct contradiction with line 1101 (*"Process one batch or a streaming file in a host, not one process per file"*):
    - If a single `lmcurl` `_lmcode_` block loops over a batch of 100 URLs, **one transient timeout on URL #1 kills the entire `lmcurl` process** and aborts URLs #2–#100.
    - If the outer `lmscript` instead compiles and spawns one `lmcurl` process per URL (as lines 796–814 do), ingesting 10M legal URLs requires **10M `savedsl` writes + 10M child processes**, losing HTTP/2 connection reuse (`curl.session` dies after one request) and adding >10 hours of pure `fork/exec` + TLS handshake overhead.
- **Recommendation**:
  - Add to Section 6's `lmcurl` gap table (line 1025): `Request.allow_error(bool) -> Request` (or make `Request.download_to_file(path, offset) -> Response` return transport errors in `Response.error()` with `Response.status() == 0` instead of throwing `dslvm::Error`), so a single `lmcurl` `Session` can process a multi-URL batch file (`file_lines(batch_path)`) over persistent HTTP/2 connections and write per-URL receipts even when individual URLs fail.

---

### [F3 — HIGH] `stage_difference(A, B)` Anti-Join Degrades to a 200M-Entry Scan at Steady State for the 100M Law/Case Pipeline
- **Lines**: [`LMSYNC_DESIGN.md:195-211`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L195-L211), [`579-581`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L579-L581), [`664-665`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L664-L665), [`677-678`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L677-L678), [`697-698`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L697-L698)
- **Evidence**:
  - Recipes (b), (c), and (d) rely on `stage_difference(fetched.ok, cleaned.ok, require_matching_source_revision=true)` and `stage_difference(cleaned.ok, published.ok, ...)`.
  - In the user's workload ("millions of laws and cases" tracked through `fetched` -> `cleaned` -> `published`), **99.9%+ of items are in all three stages at steady state** (e.g., $|A| = 100,000,000$, $|B| = 99,995,000$, $|A \setminus B| = 5,000$).
  - Line 204–205 specifies: *"Stage A minus B uses ordered posting merge/anti-join with bounded buffers, O(|A|+|B|) sequential reads worst case, or indexed probes from a sparse A."*
  - Because $A$ (`fetched.ok`) has 100M items, $A$ is **not sparse**! An $O(|A| + |B|)$ merge must stream **200,000,000 posting entries** across both stages just to emit 5,000 pending items. At the design's own qualification target of `>=250k examined posting IDs/s cold` and `>=1M/s warm` (lines 579–580), finding 5,000 uncleaned items takes **200 seconds warm / 800 seconds (13.3 minutes) cold** on every single job invocation.
- **Recommendation**:
  - Maintain a compact **per-item stage bitmap + revision match bit** (or a **materialized frontier index** `(namespace, stage_mask, item_id)` / delta queue updated transactionally on `stage_record`).
  - Alternatively, make recipes (b) and (c) consume the `changes(after=cursor)` event stream (like recipe (f)) for steady-state incremental work and reserve full `stage_difference` anti-joins for backfills and reconciliation reports.

---

### [F4 — HIGH] The 3–5 KiB/Item Storage Estimate (300–500 GB at 100M) Is Inflated ~4–5x by Key/ID Repetition
- **Lines**: [`LMSYNC_DESIGN.md:91-100`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L91-L100), [`548-571`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L548-L571), [`1228-1231`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L1228-L1231)
- **Evidence**:
  - Lines 556–557 compute:
    `300 B item + 3×160 B aliases + 140 B observation + 5×280 B stages + 6×220 B events + 700 B indexes = 4,340 B/item (about 4.24 KiB)` -> **300–500 GB live disk** and **0.6–1.0 TB with compaction headroom** at 100M items (lines 566, 570–571, 1231).
  - That arithmetic assumes naive, uninterned record encoding where:
    1. Every alias, stage projection, event, and index entry repeats a 16-byte `ItemId` (and/or 64-byte hex SHA-256) plus full UTF-8 `stage` and `namespace` strings ~20 times per item;
    2. All 5 stage projections are stored as separate key-value rows (`(stage, namespace, item, slot)`) with 280 B each (1,400 B/item);
    3. Prefix compression on sorted alias keys (`https://court.example.gov/cases/2026/...`) and varint delta encoding on posting lists are uncredited.
  - **What a leaner layout looks like (~750–1,050 B/item = 75–105 GB at 100M items)**:
    1. **Dense internal `u64` `item_num` (8 B, or 4–5 B varint/delta in sorted postings)** mapped once from the external 16-byte `ItemId`.
    2. **Dictionary-interned `(stage, namespace, slot)` IDs (`u16` `stage_ns_id`)**: a registry has tens of `(stage, namespace)` pairs, not millions. Replacing `(stage, namespace)` strings with a 2-byte `stage_ns_id` saves ~30–50 B on every stage projection, event, and index entry.
    3. **Raw 32-byte binary SHA-256 digests** (`byte[32]` instead of 64-byte hex ASCII), saving 32 B per digest across item, observation, 5 stages, and 6 events (~400 B/item saved).
    4. **Co-located Item + Stage Projection row**: storing the item core + its 5 stage projections together under `item_num` eliminates 5x key/header/fence overhead and embeds the **stage status/revision bitmask** directly in the item header (solving **[F3]** simultaneously!):
       - Co-located Item + Observation + 5 Stage summaries: `~320–420 B`
       - 3 Aliases (front/prefix-compressed in sorted run): `~180–240 B`
       - 6 Append-only Events (segmented by epoch, binary header + compact metadata): `~200–300 B`
       - Secondary postings (delta-varint `item_num` in stage/status/hash indexes): `~60–90 B`
       - **Total leaner layout**: **~760–1,050 B/item** (**76–105 GB live at 100M items**, ~150–210 GB with 2x compaction headroom — fitting comfortably on a standard developer workstation NVMe drive where 1 TB free is often unavailable).

---

### [F5 — MEDIUM-HIGH] Crash/Resume & Log Grammar Edge Cases: Non-UTF-8 POSIX Paths, Missing `plan` Parameter in `apply_records`, and `lmssh` SFTP Quoting
- **Lines**: [`LMSYNC_DESIGN.md:81-84`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L81-L84), [`334-384`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L334-L384), [`457-475`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L457-L475), [`953-981`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L953-L981)
- **Evidence**:
  1. **Non-UTF-8 POSIX paths vs UTF-8 JSONL grammar (lines 82, 342–344)**:
     - Line 82 states that alias bytes are *"caller supplied, compared exactly"*, and [`lmcode-java`'s `VmString`](file:///home/mma/repos/dsl/lmcode-java/src/main/java/io/lmctl/lmcode/VmString.java) stores raw `byte[]`. However, line 342 mandates *"Versioned UTF-8 JSON Lines"*. On Linux/POSIX, filesystem paths extracted from historical legal archives may contain arbitrary non-NUL `byte[]` sequences that are **not valid UTF-8**. Standard `String(bytes, UTF_8)` replaces invalid bytes with `U+FFFD`, corrupting exact byte identity and causing `FileNotFoundException` on replay.
     - **Fix**: Define an explicit lossless encoding in the wire grammar for non-UTF-8 byte strings (e.g., `{"$b64": "..."}` or `\u00XX`-style byte escaping when `!isValidUtf8(bytes)`).
  2. **`apply_records(db, results)` cannot detect out-of-plan results or verify `instruction_digest` without `plan` (lines 335, 357–358, 373–378)**:
     - Line 358 says *"each result binds the full instruction digest"*, and line 373 says *"Job/op identifiers and instruction digest detect conflicting reuse."*
     - Yet on line 335, the signature is `apply_records(db, results)` (without `plan`), whereas `unconfirmed(plan, results)` takes both! If `apply_records` only reads `results.jsonl`, it cannot check that:
       - `result.op` actually exists in `plan.jsonl` (rejecting out-of-plan log lines),
       - `result.payload.instruction_digest` matches the planned instruction's SHA-256, and
       - two different `result_id` lines for the same `op` with `completes_instruction: true` do not carry conflicting projections.
     - **Fix**: Change the signature on line 335 to `apply_records(db, plan, results)` (or require `plan` digest verification during `apply_records`).
  3. **Embedded newlines and glob characters in `lmssh` paths (lines 343–344, 958, 966–969, 978)**:
     - Lines 343–344 note that embedded newlines in path names are unambiguous in JSONL. However, in [`lmssh/cpp/host.cpp:114-121`](file:///home/mma/repos/dsl/lmssh/cpp/host.cpp#L114-L121), `sftp_quote` (used by `Session.rename`, `Session.rm`, `Session.mkdir`, `Session.ls`, `Session.exists`) only escapes `"` and `\`:
       ```cpp
       for (char c : path) {
         if (c == '"' || c == '\\') q += '\\';
         q += c;
       }
       ```
     - Because `lmssh` feeds commands to `sftp -b -` over stdin delimited by `\n`, any path containing `\n` or `\r` **injects a new SFTP batch command line**, and any path containing `*`, `?`, or `[` undergoes OpenSSH `sftp` glob expansion!
  4. **Record-size cap and `fsync` batching in JSONL journals (lines 345, 380–383)**:
     - Line 345 says *"Metadata is bounded per line"*, and line 381 says *"A torn final line is retained/ignored as unconfirmed"*. The design should state an explicit hard maximum line length (e.g., `64 KiB` per JSONL line) so the reader can distinguish a corrupt/runaway line without buffering unbounded memory before seeing `\n`, and allow batched `fsync` per N results so spinning disks / cloud EBS volumes aren't bottlenecked at 100–500 IOPS by per-line `fsync`.

---

### [F6 — MEDIUM] GraalVM Native-Image Store Claims & the 4 GiB Virtual Address Space Ceiling
- **Lines**: [`LMSYNC_DESIGN.md:530-544`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L530-L544), [`565-567`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L565-L567), [`588-596`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L588-L596)
- **Local Verification Results**:
  1. **Direct H2 MVStore (`com.h2database:h2:2.3.232`, line 532) — VERIFIED LOCALLY in [`lmdb`](file:///home/mma/repos/dsl/lmdb/pom.xml)**:
     - Sibling repo [`lmdb`](file:///home/mma/repos/dsl/lmdb) already compiles H2 `2.3.232` (including `org.h2.mvstore.*`) into standalone GraalVM native binaries across all 5 release targets (`linux-x64`, `linux-arm64`, `macos-arm64`, `macos-x64`, `windows-x64`).
     - **Important caveat found in [`lmdb/pom.xml:59-60`](file:///home/mma/repos/dsl/lmdb/pom.xml#L59-L60) and [`lmdb-h2/reflect-config.json`](file:///home/mma/repos/dsl/lmdb/src/main/resources/META-INF/native-image/ai.lmctl/lmdb-h2/reflect-config.json)**:
       - If the full `com.h2database:h2` artifact is used, its embedded `META-INF/native-image/reflect-config.json` **must be excluded** (`--exclude-config .*h2-.*[.]jar META-INF/native-image/reflect-config[.]json`), otherwise H2's upstream metadata pulls in `java.awt.Toolkit` and breaks headless Linux native binaries. (Better yet: depend on the standalone **`com.h2database:h2-mvstore`** artifact, which omits SQL, server, and AWT console classes entirely.)
       - Even when using only `MVMap<byte[], byte[]>`, `MVStore` still uses reflection in `FilePath.registerDefaultProviders()` and `org.h2.mvstore.type.MetaType` (`ByteArrayDataType.INSTANCE`, `StringDataType.INSTANCE`, `LongDataType.INSTANCE`) when opening store headers; the 17 entries in [`lmdb-h2/reflect-config.json`](file:///home/mma/repos/dsl/lmdb/src/main/resources/META-INF/native-image/ai.lmctl/lmdb-h2/reflect-config.json) are required.
  2. **Custom Java NIO Sorted Runs + WAL (line 533) — VERIFIED LOCALLY**:
     - Pure `java.nio.channels.FileChannel`, `FileLock`, `ByteBuffer`, and `MessageDigest` (`SHA-256`) / `CRC32C` are already used in [`lmaws/src/main/java/ai/lmctl/lmaws/Sandbox.java`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/Sandbox.java) and [`WebRun.java`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/WebRun.java) in GraalVM native-image with zero reflection or JNI.
  3. **Xerial SQLite JDBC (`org.xerial:sqlite-jdbc:3.50.3.0`, line 536) — VERIFIED LOCALLY in [`lmdb`](file:///home/mma/repos/dsl/lmdb)**:
     - Confirmed incompatible with the user's **Java-only / no-C++ / no-JNI / no-external-native** requirement: in [`lmdb/durable-memory/01-architecture.md`](file:///home/mma/repos/dsl/lmdb/durable-memory/01-architecture.md) and [`03-native-size.md`](file:///home/mma/repos/dsl/lmdb/durable-memory/03-native-size.md), SQLite-JDBC requires custom static C/JNI archives + `JdbcSubstitutions` on Linux and extracts native `.dylib`/`.dll` binaries at runtime on macOS/Windows.
  4. **iq80 LevelDB (line 534) & MapDB (line 535) — UNVERIFIED LOCALLY (Not present in workspace)**:
     - Neither is present in local Maven repos; additionally, `iq80/leveldb` uses `sun.misc.Unsafe` / `MappedByteBuffer` unmap reflection tricks that are brittle on Java 21+ / GraalVM 25 native-image, and MapDB 3.x pulls in Kotlin stdlib + Eclipse Collections + Guava + `Unsafe` serialization.
  5. **Critical Native-Image Virtual Address Space Constraint (`-R:ReservedAddressSpaceSize=4g`)**:
     - Both [`lmaws/scripts/build-native.sh:8`](file:///home/mma/repos/dsl/lmaws/scripts/build-native.sh#L8) and [`lmdb/pom.xml:64-65`](file:///home/mma/repos/dsl/lmdb/pom.xml#L64-L65) build native images with `-R:ReservedAddressSpaceSize=4g -R:MaxHeapSize=3072m` so binaries pass `test.sh` under a **6 GiB virtual address space limit (`ulimit -v`)**.
     - Consequently, **the storage engine must NEVER use `FileChannel.map` (`mmap`)** for data/index files (`FilePathNioMapped` in H2 or `mmap` in sorted runs), because mapping even a 4 GiB shard will immediately fail with `OutOfMemoryError: Map failed` under the 6 GiB virtual address limit. All disk reads/writes must use explicit `FileChannel.read(ByteBuffer, position)` / `write(ByteBuffer, position)`.

---

### [F7 — MEDIUM] Missing and Inaccurate Entries in the Section 6 Gap Tables (`lmcurl`, `lmaws`, `lmssh`)
- **Lines**: [`LMSYNC_DESIGN.md:857-924`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L857-L924), [`950-1034`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L950-L1034)
- **What is wrong or missing in the Section 6 gap table (lines 1023–1029)**:
  1. **`lmcurl` non-throwing transport error handling / batch execution**:
     - Missing from the table at line 1025: `Request.send()` currently throws `dslvm::Error` on any transport failure ([`lmcurl/cpp/http.cpp:415-416`](file:///home/mma/repos/dsl/lmcurl/cpp/http.cpp#L415-L416)). `Request.download_to_file(path, offset) -> Response` (or a `Request.allow_error(bool)` setter) must capture transport errors in `Response.error()` without throwing, so a single `lmcurl` process can run a batch of downloads and emit failure receipts.
  2. **`lmaws` `Web.step("invalidate", "{}")` behavior vs `track_invalidations.lms` (lines 916–924)**:
     - Lines 916–920 state that `web.step("invalidate", "{}")` requests the owned distribution's wildcard invalidation and advises checking `seconds_invalidate`.
     - However, in [`lmaws/src/main/java/ai/lmctl/lmaws/WebRun.java:68, 151`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/WebRun.java#L68):
       - `"invalidate"` is **not** in the repeatable step set (`Set.of("record_http","reserve_http","dns_weighted","cache")`), so calling `web.step("invalidate", "{}")` a second time on the same `WebRun` state file is a **silent no-op** that returns `summary()` without calling CloudFront!
       - In [`WebStackAws.java:129`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/WebStackAws.java#L129), `invalidate(id)` ignores the JSON argument and hardcodes `"/*"`.
       - In [`WebRun.java:74`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/WebRun.java#L74), if `web.step(...)` throws a `RuntimeException`, `WebRun.step` **automatically invokes `down()` and tears down the entire web stack**!
     - Therefore, `Cloud.cloudfront_invalidate(distribution_id, paths_json, caller_ref, run_id) -> Row` (returning `invalidation_id`, `status`, and `caller_reference` without tearing down the stack on error) should be listed in the gap table on lines 1023–1029.
  3. **`lmaws` `Cloud.s3_put_file` integrity & batch/delete gaps (line 1026)**:
     - `Cloud.s3_put_file(bucket, key, local_path, content_type, cache_control, run_id) -> Row` (line 1026) omits an `expected_sha256` parameter. Passing `sha256` allows S3 `PutObject` to verify `ChecksumSHA256` end-to-end on upload and return the confirmed `sha256`/`etag`/`version_id` in the receipt `Row`.
     - If a single `lmaws` `_lmcode_` block uploads a batch of files, `Cloud.s3_put_file` should either return error fields in `Row` (rather than throwing an uncaught exception that aborts the batch) or be paired with `Cloud.s3_put_batch(plan_path, results_path)`.
     - Also note `lmaws`'s [`CostLedger.java:16, 170`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/CostLedger.java#L16): `CostLedger` currently `fsync`s (`c.force(true)`) on every single AWS SDK request and caps each run at `$0.25` (<=50,000 S3 PUTs).
  4. **`lmssh` `sftp_quote` newline/glob gap and non-OpenSSH SFTP overwrite (lines 958, 968–980, 1034)**:
     - Line 1034 states *"There is no lmssh transport blocker for the shown jobs."*
     - While normal paths work today, [`lmssh/cpp/host.cpp:114-121`](file:///home/mma/repos/dsl/lmssh/cpp/host.cpp#L114-L121) (`sftp_quote`) must reject `\n`/`\r` and escape glob characters (`*`, `?`, `[`) so paths with glob metacharacters do not fail in `Session.rename`/`rm`/`mkdir`, and `Session.put`/`get`/`rename` throw on the first failed file if batched inside one `_lmcode_` block.

---

### [F8 — LOW-MEDIUM] Multi-Process Filesystem Mailbox IPC Will Bottleneck on Per-Request `fsync` + `rename` Under High Worker Concurrency
- **Lines**: [`LMSYNC_DESIGN.md:429-455`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L429-L455)
- **Evidence**:
  - Lines 432–439 propose a multi-process mode where workers communicate with the DB owner via an OS-local filesystem mailbox: writing a temp request file, `fsync`ing, atomically renaming into the request directory, polling for a temp->renamed+`fsync`ed reply file, and durably deduplicating request IDs before unlinking reply files.
  - Each RPC requires **>=2 file creations, >=2 `fsync`s, >=2 atomic directory renames, and directory polling**. At 1,000 small items/s across 8 worker processes, that is >=4,000 `fsync`s/s and >=4,000 directory mutations/s on a single lock directory.
- **Recommendation**:
  - For the single-script `.lms` architecture in Section 7 (`state_program` -> `transfer_program` -> `record_program`), each `lmfiles` invocation runs as a **single owner process** over a batch (zero mailbox IPC needed!). Keep single-process batched execution as the primary path in Milestone 1, and if the filesystem mailbox is implemented later for multi-process workers, require **coarse batching** (e.g., >=32–256 claims/completions per mailbox file) rather than single-item RPCs.

---

### [F9 — LOW] Milestone Scope Can Be Trimmed Further & DSL Context Name `files` Collides Conceptually with `file_*` Builtins
- **Lines**: [`LMSYNC_DESIGN.md:1`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L1), [`22-25`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L22-L25), [`132`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L132), [`1123-1149`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md#L1123-L1149)
- **Evidence & Recommendations**:
  - See Sections (6) and (7) below for the concrete milestone split and naming analysis.

---

## Detailed Review by Prompt Dimension

### (1) Contradictions with User Requirements
- **Overall alignment**: Strong. The current [`LMSYNC_DESIGN.md`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md) explicitly enforces:
  - Local registry of paths/URLs deciding actions without remote queries (lines 27–38).
  - `lmcode` API with zero business rules in core; policy in one `.lms` script per job (lines 40–58, 73–76).
  - Download manager (`lmcurl`), upload manager (`lmaws`), and rsync alternative (`lmssh`) using the existing products (lines 40–45, 758–761).
  - Millions of laws/cases tracked across `downloaded`/`fetched`, `cleaned`, `published` (lines 27–29, 620–690).
  - Java-only (`no C++, JNI, external native component`, lines 43–44, 523–528, 536–537).
  - No "index too old" warning (lines 51–53, 225, 275–276, 301–302, 1327).
- **Direct fixes applied wiki-style to [`LMSYNC_DESIGN.md`](file:///home/mma/repos/dsl/lmaws/docs/LMSYNC_DESIGN.md)**:
  - **Line 146**: Changed `digest: bytes` to `digest: string` (`lmcode` `dsl.schema: 2` has no `bytes` primitive type).
  - **Line 541–543**: Added local reference to sibling repo [`lmdb`](file:///home/mma/repos/dsl/lmdb)'s GraalVM native-image H2 (`--exclude-config` on AWT reflection metadata and `MetaType`/`FilePath` reflection entries).
  - **Line 861**: Removed the inaccurate claim that `Cloud.s3_presigned_put(...)` is part of `lmaws`'s checked public DSL surface (`lmaws --dsl-signatures` has no such method).
  - **Lines 796, 868, 880, 953, 974, 1078, 1085, 1090**: Added `let ` to outer `lmscript` `_lmcode_` variable bindings for consistency with `let` declarations in `lmscript` functions and strict blocks.

### (2) Crash/Resume Invariants & Log/Claim Correctness
- **No lost uploads / No false "unchanged" or "published" / Confirmation gap (lines 386–406)**:
  - Sound. Recording `intent` in `plan.jsonl` never mutates believed remote state; a crash after remote transfer but before `results.jsonl` `fsync` leaves the item unconfirmed so resume re-plans it (at-least-once transfer, zero fabricated `same-as-recorded`).
  - Attaching the **planned/transferred source fingerprint and revision** (rather than whatever bytes currently sit on disk at completion time, lines 108–115, 286–295) prevents a concurrent local file edit during upload from falsely marking the new local revision as published.
- **Lease/fenced claims (lines 457–475)**:
  - Using a monotonic clock while the owner process is alive + `(owner_epoch, monotonic_fencing_token, expected_source_revision)` on `complete(...)` prevents a slow worker whose lease expired from overwriting a newer revision's stage projection.
  - **Edge case to tighten**: On line 473–474 (*"A late worker can explicitly append its factual historical receipt with the old revision, without replacing a newer successful projection"*), specify that an expired/fenced token's `complete(token, ...)` call **must return a distinct `fenced-or-expired` status** and only append an audit event if the caller explicitly opted into historical-audit recording, never updating `last_success` if `last_success.source_revision > receipt.source_revision`.
- **Log grammar & quoting edge cases (lines 340–384)**:
  - **Spaces, quotes, tabs, embedded newlines**: Safe inside JSONL strings, **except** when passed to `lmssh`'s `sftp -b -` batch channel (`[F5.3]`).
  - **Non-UTF-8 paths**: Must define a lossless byte-encoding fallback (`$b64` or hex escape) because strict UTF-8 JSON cannot round-trip arbitrary POSIX path bytes (`[F5.1]`).
  - **Long lines & torn writes**: Enforce a hard per-line byte ceiling (e.g. `64 KiB`), verify CRC32C + trailing `\n` before accepting a line, and truncate only a torn final line on recovery (`[F5.4]`).
  - **Duplicate & out-of-plan log lines**: `apply_records` must accept `plan` (`apply_records(db, plan, results)`) so it can reject any `result.op` not present in `plan`, verify `instruction_digest`, and treat duplicate `(job, result_id)` with identical payload as idempotent while flagging a differing payload or conflicting second `completes_instruction: true` for the same `op` as an integrity error (`[F5.2]`).

### (3) Query Efficiency at 100M, Storage Math & GraalVM Native-Image Compatibility
- **"Items in stage A but not stage B" at 100M (`[F3]`)**:
  - **Not efficient at steady state with the proposed posting-only layout**: when $|A| \approx 100\text{M}$ (`fetched.ok`) and $|B| \approx 99.995\text{M}$ (`cleaned.ok`), an $O(|A| + |B|)$ posting merge scans 200M entries (~800 s cold) to return 5,000 items. Co-locating a compact per-item stage-status/revision bitmask or maintaining a pending-frontier index reduces steady-state selection to $O(|A \setminus B|)$.
- **Storage estimate of 3–5 KiB/item (`[F4]`)**:
  - **Inflated ~4–5x** for a well-engineered binary store (though believable if implemented as naive JSON/string keys across 15 separate key-value rows per item). A leaner layout using dense `u64` internal item IDs, interned `u16` `(stage, namespace)` IDs, raw 32-byte SHA-256 digests, co-located item+stage projections, and prefix/delta-compressed sorted runs requires **~750–1,050 B/item (~75–105 GB live at 100M items)** instead of 300–500 GB.
- **GraalVM native-image compatibility (`[F6]`)**:
  - **H2 MVStore**: **Verified locally** via [`lmdb`](file:///home/mma/repos/dsl/lmdb/pom.xml) (`com.h2database:h2:2.3.232`), which builds and passes native-image CI on all 5 platforms when H2's AWT reflection config is excluded and [`lmdb-h2/reflect-config.json`](file:///home/mma/repos/dsl/lmdb/src/main/resources/META-INF/native-image/ai.lmctl/lmdb-h2/reflect-config.json) (`MetaType` + `FilePath` providers) is included.
  - **Custom Java NIO sorted runs + WAL**: **Verified locally** (uses only JDK `FileChannel`/`ByteBuffer`/`FileLock`/`MessageDigest`/`CRC32C` already proven in `lmaws` and `lmdb`).
  - **Xerial SQLite JDBC & RocksDB JNI**: **Verified incompatible** with the Java-only / no-JNI / no-external-native requirement (`lmdb` requires custom C/JNI static archives on Linux and runtime-extracted `.dylib`/`.dll` on macOS/Windows).
  - **iq80 LevelDB & MapDB**: **Unverified locally** (not in workspace; both carry `sun.misc.Unsafe` / `MappedByteBuffer` / transitive dependency risks on GraalVM 25).
  - **Virtual address space rule**: Because `lmaws` and `lmdb` set `-R:ReservedAddressSpaceSize=4g` and test under a 6 GiB `ulimit -v`, `lmfiles` must use `FileChannel` `pread`/`pwrite`, **never `mmap`**.

### (4) Example Scripts & Multi-Host Mechanism Verification
- **Multi-host mechanism (Section 7, lines 1054–1094)**:
  - **Verified working today** in `@lmctl-ai/lmctl 0.2.420`: a single `.lms` script can compile multiple `_lmcode_ cli="..."` (or `_dsl_ cli="..."`) blocks against different host binaries (`lmcurl`, `lmaws`, `lmssh`, `lmplot`, `lmdraw`), write bytecode via `savedsl(prog, path)`, resolve the binary argv via `dsl_cli(prog)`, and execute via `system(concat(dsl_cli(prog), ["--dsl", path]), timeout_ms)` while passing data through local files and `${...}` scalar splices.
  - **Verified `parallel` limitation (lines 479–484)**: Confirmed in `lmctl`'s parser (`cli/lmscript.js`) that `parallel([ call1(), call2() ])` is an AST keyword construct (`ParallelExpr`) requiring a literal bracketed list of direct function calls; passing a variable (`parallel(tasks)`) fails at parse time with `Expected '[' starting array of function calls in 'parallel([ ... ])'`.
- **Example scripts vs real current APIs of `lmcurl`, `lmaws`, `lmssh`**:
  - All five `_lmcode_` blocks in Section 6 (lines 796–814, 868–874, 880–886, 953–960, 974–981) compile cleanly against the current schemas of `lmcurl`, `lmaws`, and `lmssh`.
  - **Behavioral mismatches uncovered by source audit**:
    1. `lmcurl`: `request.send()` throws `dslvm::Error` on any transport failure (`[F2]`), so lines 807–811 never write `STATUS_PATH`/`ERROR_PATH` on transport errors, and per-URL `_lmcode_` compilation/spawning does not scale to millions of URLs.
    2. `lmaws`: `web.step("invalidate", "{}")` (lines 916–920) is non-repeatable within a `WebRun` and tears down the entire web stack on any exception (`[F7.2]`).
    3. `lmssh`: `Session.put`/`get`/`rename` throw on error and `sftp_quote` does not escape `*`/`?`/`[` or reject `\n` (`[F5.3]`, `[F7.4]`).
  - **Policy boundary**: None of the examples hide policy in `lmfiles` core.

### (5) Gap Tables Audit (Section 6, lines 1016–1034)
- The four items already in the table on lines 1023–1029 (`Request.download_to_file`, `Cloud.s3_put_file`, `Web.step("origin_path", ...)`, `Cloud.s3_head_object`) are real gaps.
- **Missing from the gap table (`[F7]`)**:
  1. **`lmcurl`**: Non-throwing error capture (`Request.allow_error(bool)` or non-throwing `download_to_file`) + batch execution inside a single `Session` so one failed URL does not abort a batch run.
  2. **`lmaws`**:
     - `expected_sha256` parameter on `Cloud.s3_put_file` (for S3 `ChecksumSHA256` verification and receipt reporting),
     - `Cloud.cloudfront_invalidate(distribution_id, paths_json, caller_ref, run_id) -> Row` (because `Web.step("invalidate", "{}")` is a one-shot `"/*"` step that silently no-ops on repeat calls and calls `down()` on failure),
     - `Cloud.s3_delete_objects(bucket, keys_json, run_id) -> Row` (if a user script explicitly chooses remote retention cleanup in `B3`/`B4`),
     - Buffered/batched `CostLedger` `fsync` (current [`CostLedger.java:170`](file:///home/mma/repos/dsl/lmaws/src/main/java/ai/lmctl/lmaws/CostLedger.java#L170) `fsync`s on every SDK call).
  3. **`lmssh`**: `sftp_quote` validation/escaping for `\n`, `\r`, and SFTP glob metacharacters (`*`, `?`, `[`) in [`lmssh/cpp/host.cpp:114-121`](file:///home/mma/repos/dsl/lmssh/cpp/host.cpp#L114-L121).

### (6) Milestone Review (Section 7, lines 1123–1149)
- **Is it the smallest useful slice?**
  - Almost, but items 1–4 in Section 7 (lines 1125–1138) still pack too many subsystems into a single first milestone (item/alias/observation/stage/event/claim store + `scan`/`scan_paths`/`hash_paths` + optional plan/result JSONL codec + `import_records`/`export_records` + `doctor` + `publish_ttl.lms` + fake S3 executor + `lmaws` `Run.bucket/put/cleanup` smoke).
  - **Recommended tighter split**:
    - **Milestone 1A (Core Registry + Crash Harness)**: Single-process Java `lmcode` host with `open`/`close`, `item_upsert`, `alias_add`, `observe`, `stage_record`/`stage_forget`, `query_subset`, `stage_difference`, `claim`/`complete`, `doctor`, and the deterministic kill-point harness (Section 4) passing on both JVM and GraalVM native-image under `-R:ReservedAddressSpaceSize=4g`.
    - **Milestone 1B (Two-Host End-to-End Job)**: Plan/result JSONL helpers + `publish_ttl.lms` running end-to-end against both the local fake executor and `lmaws --dry-run` (`Run.bucket/put/cleanup`), before building filesystem tree scanners (`scan`), archive rotation, or multi-process mailbox IPC.
- **Testable Acceptance List for Milestone 1**:
  1. `lmfiles --version`, `--help`, `--notices`, `--dsl-schema [--json]`, `--dsl-signatures`, and `--self-test` pass in both JVM and standalone GraalVM native-image (with Linux ELF audit confirming dynamic `glibc <= 2.35` only and zero JNI/external `.so` dependencies).
  2. Network-denying sandbox test (`unshare -n` on Linux / socket-blocking security test) proves `0` socket syscalls across all `lmfiles` operations (`open`, `query_subset`, `stage_difference`, `claim`, `complete`, `apply_records`, `doctor`).
  3. All 17 kill-point fault-injection scenarios in Section 4's table (lines 497–515) match the reference model oracle on reopen with zero false `same-as-recorded` or lost confirmed receipts.
  4. `publish_ttl.lms` executes 5 consecutive runs in an empty temp directory: (a) initial publish of $N$ files -> $N$ transfers, (b) immediate re-run -> $0$ transfers and $0$ action-host invocations, (c) 1 modified file -> $1$ transfer, (d) simulated crash after receipt `fsync` before DB commit -> replay records the 1 transfer without re-uploading, (e) simulated crash before receipt `fsync` -> resume re-plans the 1 unconfirmed file.

### (7) Naming Review: `lmfiles` (lines 1, 22–25)
- **Collision check**:
  - **Existing `lmctl-ai` repos**: Checked all 70 directories in `/home/mma/repos/dsl`. Neither `lmfiles`, `lmtrack`, nor `lmregistry` exists (`lmdb` is taken by the JDBC client; `lmsync` is an empty leftover directory).
  - **Common OS/CLI tools**: Checked PATH and Debian/Ubuntu `apt-cache` — `lmfiles`, `lmtrack`, and `lmregistry` have **zero collisions** with standard Unix, macOS, or Windows tools.
- **Assessment of `lmfiles` vs `lmtrack` / `lmregistry`**:
  - **Strengths of `lmfiles`**: Short, memorable, matches the `lm<noun>` family naming convention (`lmaws`, `lmcurl`, `lmssh`, `lmdb`, `lmhtml`, `lmpdf`), and immediately communicates the domain (file/artifact workflows) better than abstract `lmregistry`.
  - **Weaknesses of `lmfiles`**:
    1. Items often start as **URLs before any file exists** (lines 27, 629–630), and the tool **never transfers, copies, moves, or deletes files** (lines 31, 675, 720). Users seeing `lmfiles` may assume it is a file-manipulation or file-transfer tool.
    2. Inside `_lmcode_` blocks, using `context files: Files` (`files.open(...)` on line 132) sits alongside `lmcode_std_v3`'s `file_read`, `file_write`, `file_append`, `file_exists`, `file_lines`, blurring local file I/O with registry DB queries.
  - **Verdict**: Keeping the product/binary name **`lmfiles`** (with **`lmtrack`** as the strongest alternative if URL/stage lifecycle tracking should be emphasized over files) is fine, **provided** the `_lmcode_` context object on line 132 is named `registry` or `track` (or `files.open_db(...)`) so scripts clearly distinguish registry state calls from `file_write`/`move_file`.

---

## Top 5 Riskiest Assumptions in the Design

1. **[Assumption 1 — CRITICAL] Single-URL-per-process `_lmcode_` execution (or throwing batch calls) can scale to millions of ingested laws/cases (lines 642–644, 796–814, 1101).**
   - *Why it is risky*: Splicing per-item variables (`${URL_PATH}`, `${PART_PATH}`) into an `_lmcode_` block and running `savedsl` + `system(lmcurl --dsl ...)` spawns one process per item (destroying HTTP/2 connection pooling and spending hours in `fork/exec`), while putting a loop inside `_lmcode_` currently aborts the entire batch on the first transport error because `lmcurl`'s `Request.send()`, `lmssh`'s `Session.put`/`get`/`rename`, and `lmaws`'s SDK calls throw uncaught host exceptions on error.
   - *Mitigation*: Require non-throwing batch/receipt modes in `lmcurl` (`download_to_file` / `allow_error`) and `lmaws` (`s3_put_file` returning status/error in `Row`) so one host process handles a bounded batch of 100–1,000 items over pooled connections.

2. **[Assumption 2 — HIGH] $O(|A| + |B|)$ posting-merge anti-joins for `stage_difference(A, B)` are fast enough for frequent incremental pipeline runs at 100M items (lines 204–211, 579–581, 664–678).**
   - *Why it is risky*: In a mature 100M-item corpus where 99.995M items are already fetched, cleaned, and published, scanning 200M postings on every run to find 5,000 newly fetched items takes minutes of disk I/O per stage transition.
   - *Mitigation*: Embed a compact stage-status/revision bitmask in the item record and maintain a sparse pending-frontier index (or drive incremental runs from `changes(after=cursor)`).

3. **[Assumption 3 — HIGH] `lmcode`'s schema and handle arena can directly express Section 1's 24 struct parameter types and object-per-row returns (lines 131–169).**
   - *Why it is risky*: `lmcode-java` (`dsl.schema: 2`) only supports primitive scalars (`int`, `float`, `string`, `bool`) and opaque host handles (capped at 65,536 collection handles per run). Designing the API around dozens of fine-grained struct types will force an late, painful rewrite of the entire DSL surface when `schema/lmfiles.dsl.json` is authored.
   - *Mitigation*: Rewrite Section 1's signature block to use `Registry`, `Cursor`, `WriteBatch`, and `Row`/`Rows` with JSON `string` / `StrMap` options and batch file streams before implementation begins.

4. **[Assumption 4 — HIGH] 100M items require 300–500 GB live disk and 0.6–1.0 TB compaction headroom (lines 548–571, 1228–1231), and GraalVM native-image can address multi-hundred-GB stores without hitting virtual memory limits.**
   - *Why it is risky*: Requiring ~1 TB of free local disk makes the 100M benchmark unrunnable on standard developer/CI machines, while any accidental use of `mmap` (`FileChannel.map`) in H2 MVStore or custom sorted runs will immediately crash under the `lmctl-ai` GraalVM native-image `-R:ReservedAddressSpaceSize=4g` / 6 GiB `ulimit -v` ceiling.
   - *Mitigation*: Use dictionary-interned `u16` stage/namespace IDs, dense `u64` internal item IDs, raw 32-byte digests, and prefix-compressed sorted runs to cut live footprint to ~75–105 GB at 100M items, and forbid `mmap` in favor of `FileChannel` `pread`/`pwrite`.

5. **[Assumption 5 — MEDIUM] Multi-process coordination via a per-request filesystem mailbox (`temp file` + `fsync` + `rename` + polling) can sustain parallel worker throughput without lock/inode thrashing (lines 429–455).**
   - *Why it is risky*: Per-claim or per-completion file creation + `fsync` + `rename` in a shared directory serializes all workers on directory inode locks and disk flush latency.
   - *Mitigation*: Keep the single-process batch architecture (`state_program` -> `transfer_program` -> `record_program`, Section 7) as the default execution model, and require coarse batching (>=32–256 items per request file) whenever the filesystem mailbox is used.
