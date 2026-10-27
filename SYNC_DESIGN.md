# Site sync design: selectable freshness strategies

Status: **design only; correction 3**. This document specifies future typed APIs,
recipe flags and examples. No sync implementation, live test, IAM change or AWS
command is part of this change. The strategies are user choices, not an automatic
invalidation step. Preview is the default; applying a plan is a separate action.

## Selection and defaults

`freshness` is a set of typed enum values: `TTL | HASHED | RELEASE | INVALIDATE`.
The recipe exposes the lowercase spellings through repeatable `--freshness`
flags or a comma-separated value. Order is irrelevant and duplicates are removed.
Unknown names and invalid option values fail before any dispatch.

| Input | Normalized plan |
|---|---|
| omitted or `ttl` | Plain paths, short-TTL entries, no reference rewriting or invalidation |
| `hashed` or `hashed,ttl` | Hash immutable assets; rewrite supported references; short-TTL entries |
| `release` or `release,ttl` | Immutable release prefix, short-TTL entries, atomic activation and retained rollback |
| `release,hashed,ttl` | Release isolation plus hashed assets and short-TTL entries |
| `invalidate` or `ttl,invalidate` | Plain TTL deployment plus explicitly requested invalidation |
| `hashed,ttl,invalidate` | Hash assets and invalidate only the selected mutable entry paths |

`TTL` composes as the entry-file policy when HASHED or RELEASE is selected. It
does not turn immutable assets back into mutable paths. HASHED and RELEASE imply
TTL for entries even when the user omits that enum value; preview prints the
normalized set. INVALIDATE is never implied by another strategy, a changed file,
a deployment failure or a rollback. There is no default invalidation permission.

Proposed defaults: entry max-age 30 seconds; plain mutable asset max-age 300
seconds; immutable asset max-age 31,536,000 seconds; keep at least the last 3
complete releases; invalidation path cap 100. Entry patterns include HTML and
explicitly configured mutable manifests/service-worker entry files. API paths
remain uncached. Browser and CDN TTL settings must agree; CDN minimum TTL is zero.
No stale-while-revalidate extension is silently added.

**Small site default:** `ttl`, with backward-compatible assets and the 30-second
entry/300-second asset policy. Size is a recommendation, not an automatic mode
switch; a large site may still explicitly choose plain TTL.

**Large site default:** `release,hashed,ttl`, retaining 3 complete releases plus
the retention grace. It avoids routine invalidation and gives fast rollback
without uploading the previous release again. HASHED alone remains a selectable
middle ground for sites that do not need release activation or retained rollback.

## Typed API and recipe contract

Proposed host representation (not implemented signatures):

```java
enum Freshness { TTL, HASHED, RELEASE, INVALIDATE }
// SyncOptions stores a copied EnumSet<Freshness>; enum factories are immutable values.
SyncOptions freshness(Freshness strategy); // additive, deduplicated
SyncOptions entryTtlSeconds(int seconds);
SyncOptions mutableAssetTtlSeconds(int seconds);
SyncOptions keepReleases(int count);
SyncOptions releaseGraceSeconds(int seconds);
SyncOptions invalidationPathCap(int count);
SyncOptions allowInvalidationPathCapOverride(boolean explicitOverride);
SyncOptions invalidationScope(InvalidationScope scope); // AUTO, EXACT, SITE_WILDCARD
SyncPlan syncPlan(String localDirectory, SiteHandle ownedSite, SyncOptions options);
```

The DSL uses factories returning type `Freshness`, rather than unvalidated string
arguments or integer bit flags. For example, the proposed equivalent of
`--freshness hashed,ttl` is:

```text
let cloud = aws.demo();
let options = cloud.sync_options()
    .freshness(cloud.freshness_hashed())
    .freshness(cloud.freshness_ttl())
    .entry_ttl_seconds(30);
let plan = cloud.sync_plan("./site", owned_site, options);
// Preview the plan; applying also requires the existing live/apply/profile guards.
```

These are API design examples, not runnable current bindings. The recipe parses
only the four enum spellings and builds the same typed options. A saved plan
contains the normalized choices, content/index digests, owner receipt, price-table
revision, TTLs, selected invalidation paths and their scope/cap/override decisions.
Applying refuses stale local content, stale remote index or distribution ETag,
changed ownership, or changed billable parameters; it requires a new preview.

Proposed recipe/example deliverables for the implementation phase:

| Reusable recipe / synthetic example | Required demonstration |
|---|---|
| `recipes/sync_site.lms` / `examples/sync_ttl.lms` | Default TTL; stable names and unchanged bytes/references |
| same recipe / `examples/sync_hashed.lms` | Changed asset hash, rewritten entry, immutable asset header and short entry TTL |
| same recipe / `examples/sync_release.lms` | Upload, activate, rollback without re-upload, then index-driven GC |
| same recipe / `examples/sync_invalidate.lms` | Explicit opt-in; path/cost preview, cap refusal and ledger reservation |

Illustrative future commands; **do not execute them for this design task**:

```sh
lmctl recipes/sync_site.lms --source ./site --site lmaws_demo --freshness ttl --preview
lmctl recipes/sync_site.lms --source ./site --site lmaws_demo --freshness hashed,ttl --preview
lmctl recipes/sync_site.lms --source ./site --site lmaws_demo --freshness release,hashed,ttl --keep-releases 3 --preview
lmctl recipes/sync_site.lms --source ./site --site lmaws_demo --freshness hashed,ttl,invalidate --invalidation-path-cap 100 --preview
# Explicit cap override is separate from selecting invalidation or changing the cap:
lmctl recipes/sync_site.lms --source ./site --site lmaws_demo --freshness invalidate --invalidation-scope exact --invalidation-path-cap 100 --allow-invalidation-path-cap-override --preview
```

Synthetic examples must print normalized options, operation counts, cost and
asserted outcomes. Their future README captions use `lmctl <raw-url>.lms`, show
synthetic pictures and disclose cost assumptions. Actual recipe/API/schema work
is a later implementation task; this change adds no runnable sync files.

## Strategy behavior

### TTL: plain names, no rewriting

Compare local content digests with the authoritative sync index; upload changed
assets first and publish entries last. An unchanged byte digest with changed
headers still needs a metadata update. Keep original names and reference bytes.
Use short entry Cache-Control and the configured mutable-asset TTL. Multi-object
publication is not atomic: assets must be backward-compatible during mixed-cache
windows. Plain TTL rollback re-uploads the previous snapshot; it does not recover
old content if the caller has not retained it. Deletion waits through the declared
retention grace and only targets owned keys recorded in the index.

### Hashed: content-addressed assets and short-lived entries

Build a local reference graph, transform supported references, and compute each
asset's full SHA-256 from its final bytes before assigning its immutable name.
Rewrite HTML links/src/srcset, CSS url/import and supported static JS/module
references using structured parsers or a validated build manifest, not blanket
text replacement. Leave external/data URLs alone. Dynamic runtime references,
unresolved imports and cyclic rewrite graphs require an explicit prepared build
contract or a refused plan; do not silently publish broken references or claim a
hash of pre-rewrite bytes identifies different final bytes.

Upload assets before entries. Entries retain stable URLs and short TTLs. New
asset URLs avoid old cached bytes; old asset URLs remain available through index
retention for cached entries and supported open sessions. Validate SRI and source
map/reference changes or refuse unsupported cases. Re-applying identical content
is a no-op. HASHED alone does not promise an atomic multi-page release or a
one-operation rollback: entries must be retained/re-published for rollback.

### Release: stage, activate, rollback, collect

Write a complete manifest under `releases/<release-id>/`, using a unique immutable
ID tied to the plan digest. Commit a completed-release marker only after upload
verification. Incomplete releases cannot be activated or counted as rollback
candidates. The index tracks pending, complete, active, previous, pinned and GC
states, plus exact keys, sizes and digests. Never infer deletion candidates from
an unbounded bucket scan or from a caller-supplied prefix alone.

The initial switch implementation changes the owned CloudFront default origin's
OriginPath with the observed distribution ETag (`If-Match`). A stable
`/releases/*` behavior uses a root-path origin; assets referenced by release HTML
have release-qualified URLs, so an older entry continues to fetch its own assets
while edge configurations differ. Reject distribution behavior conflicts. Changing
OriginPath does not itself evict an already cached unversioned entry response.

The switch is one conditional configuration update, not a cross-service atomic
transaction or a globally simultaneous viewer change. Journal intent before the
switch and finalize the release index afterward. On a crash, reconcile the index
against the actual origin configuration before retrying or collecting anything.
Conflicting index/distribution ETags stop the operation instead of overwriting
another deployer. All waits and retries are bounded.

Rollback immediately requests a switch to a retained complete release: no
re-upload or rebuild, one switch operation plus index bookkeeping and bounded
status reads. **Instant rollback means immediate control-plane selection**, not
instant CDN or browser freshness. Existing entry TTLs and CloudFront propagation
still apply. An optional pointer backend needs an explicit request router that
resolves the pointer and incorporates release identity in cache keys; CloudFront
does not automatically interpret an S3 pointer JSON file. No extra edge component
or its permissions/cost is silently deployed.

GC uses a conditional index update and exact indexed keys. Keep at least last N
complete releases (default 3), current/previous rollback targets, pins, in-flight
switch targets and everything within the retention grace. A suggested initial
grace is 24 hours, configurable to the supported client/session lifetime; open
tabs and lazy-loaded old chunks can outlive HTML TTL. N is a minimum, not authority
to delete referenced content. Unknown/drifted keys and uncertain activation states
are preserved and reported. Only successfully deleted keys are removed from the
index; interrupted GC resumes from receipts. A separately owned site/run receipt
must match provider `lmaws_test` tags; a new deploy operation ID does not authorize
adopting or retagging a foreign bucket/distribution.

### Invalidate: explicit, counted and cost-admitted

This option is off unless INVALIDATE is selected. Hashing, release switches,
rollback and cache TTL expiry never trigger it automatically.

1. Canonicalize, validate and deduplicate URL paths against the owned site's
   scope, including entry aliases/query-string policy. Print both changed-file
   candidate count and final submitted path count; API batches do not reduce the
   number of billable paths.
2. AUTO compares exact paths with a single safe site wildcard. Prefer that
   wildcard when it reduces the estimated invalidation charge; also show the
   cache-refill/request/transfer tradeoff. For a shared distribution, a cheaper
   `/*` cannot widen the site's ownership scope. Require a dedicated owned
   distribution or an approved owned prefix for such a wildcard. EXACT remains
   selectable. A wildcard counts as one submitted path, not the number of keys
   it matches; preview also reports the indexed objects it can affect.
3. Refuse when final submitted paths exceed `--invalidation-path-cap` (positive
   integer, default 100), unless the user explicitly passes
   `--allow-invalidation-path-cap-override`. Selecting INVALIDATE, splitting into
   batches or changing strategies is not an override. Even with the override,
   service quotas, bounded memory, run dollar cap and ledger hard ceiling remain.
4. Before CreateInvalidation, print `estimated invalidation cost: $X.XXXX`, the
   submitted path count, price-table assumption and the whole-run estimate.
   Reserve that cost in the existing ledger **before** network dispatch. A
   refused admission makes zero invalidation calls.
5. Journal a stable CallerReference and exact batch digest. Retry uncertain
   outcomes with that same identity, reconcile by invalidation ID and use bounded
   GetInvalidation polling. Do not create a second billable batch after a timeout.
   Definite pre-dispatch failures release unused reservation; uncertain dispatched
   work remains reserved until reconciled. Record requested/submitted paths,
   wildcard decision, override, batch ID (private), estimate and final status.
6. If upload/activation succeeded but invalidation failed, report deployment
   committed / freshness pending. Resume just the recorded invalidation; do not
   report complete freshness or automatically roll back/upload again.

Price-table planning uses $0.005 per submitted path conservatively, without
assuming unused monthly allowance. AWS documents an account-wide monthly allowance
of 1,000 paths, and a wildcard counts as one. If a validated allowance/billing-plan
receipt is provided, show the lower estimate separately; concurrent account usage
can consume it. One wildcard therefore has a conservative $0.005 path estimate;
100 exact paths have $0.50 and can exceed the existing run budget even though the
path cap allows them. The path override never raises that budget. Include origin
refill/storage/transfer assumptions in the total; a local estimate is not an AWS
billing ceiling against arbitrary traffic. Prices and plan eligibility must be
rechecked when implementing, and the ledger stores the price-table revision.

## Comparison and request accounting

Let U be uploaded objects after metadata/content comparison, E changed entries,
L paginated index/list reads, V verification reads, W bounded control-plane polls,
D indexed deletion requests, P submitted invalidation paths and B invalidation
batches. These are logical counts; preview itemizes multipart/copy/tag/ownership
calls and SDK retries separately. One invalidation API request with 100 paths
means B=1, P=100, not one charged path. S3 request/byte prices come from the existing
regional ledger table; no mode is described as free merely because it avoids
invalidation. Unchanged syncs skip data writes and invalidation.

| Option | Incremental cost | Requests above common ownership/index checks | Freshness delay | Rollback ability | Failure modes |
|---|---|---|---|---|---|
| `ttl` | Changed object/metadata requests, storage and normal cache misses; no invalidation fee | U writes + index CAS + L/V reads; D when collecting | Entries up to entry TTL; stable-name assets up to mutable TTL, plus configured caches | Re-publish retained prior snapshot; requires its bytes | Mixed versions across files, stale browser assets, partial publication |
| `hashed,ttl` | Changed hashed bytes, rewritten entries and retained old assets; no invalidation fee | Asset/entry writes within U + index CAS + L/V; D after grace | New asset URL fresh on first fetch; entry discovery still waits its TTL | Re-publish retained entries pointing at retained hashes | Unsupported/dynamic references, cycles, SRI drift, premature asset GC |
| `release,ttl` | Complete release staging/retention (deduplicated copy only where safe), switch and normal serving; no invalidation fee | U staging writes + completion/index CAS writes + 1 conditional switch + W; GC D | OriginPath propagation and unversioned-entry TTL; old and new viewers can coexist | Immediate switch request to retained prefix, no data upload; propagation/TTL still apply | Activation/index crash gap, ETag conflict, incomplete manifest, stale entry cache, unsafe GC |
| `release,hashed,ttl` | Release cost plus hash/rewriter CPU; immutable URL reuse where index proves identical bytes | Release counts, including rewritten entries and any verified reuse | Same entry/switch delay; release-qualified immutable assets stay coherent | Same release switch; retain old asset references | Combined rewrite/activation issues; unsupported graph must fail in preview |
| `ttl,invalidate` or `hashed,ttl,invalidate` | Above base cost + conservatively P × $0.005 + possible cold-cache refill | Base counts + B CreateInvalidation + bounded status reads; charge by P | Asynchronous invalidation completion; browser caches/service workers may still retain responses | Base mode's rollback, with a new explicit invalidation if desired | Missing optional IAM grant, cap/budget refusal, timeout/pending batch, broad wildcard refill; invalidation cannot clear browser caches |

## Optional IAM grant and implementation gaps

Required design posture: `cloudfront:CreateInvalidation` is **not in the default
lmaws_session policy**. TTL, HASHED and RELEASE do not request it. INVALIDATE needs
an optional, reviewed statement scoped to the owned distribution ARN and run tag;
include `cloudfront:GetInvalidation` for bounded completion checks if not already
covered by read permissions. Never use admin inside sync or auto-grant on denial.

The user enables that capability through the existing
`recipes/grant_session_policy.lms` flow: prepare a COPY of the policy with only the
optional scoped statement, lint/preview the diff, then separately authorize admin
apply with `AWS_PROFILE=admin`, `LMAWS_ADMIN_GRANT=1` and `--apply`. Actual sync runs
use `AWS_PROFILE=lmaws`. No private `~/.aws` file is edited by sync. The recipe
example here is a future workflow description, not an executed grant.

Current-code differences to address during implementation: the existing
`PolicyBuilder` named-resource helper still includes CreateInvalidation in its
CloudFront mutation action list, and `WebStackAws.invalidate` emits a wildcard
without the proposed sync path/cost admission. Remove invalidation from default
policy generation/fixtures, preserve an explicit optional grant builder, and route
sync invalidation through the guarded ledger path. Regenerate dependent recipes,
schema/signatures and tests as required then; this design-only change does not
modify those behaviors or a live policy. Existing general cache guards also need
a separate immutable-asset behavior permitting one-year TTLs only for proven
immutable paths; do not extend API/entry caching to achieve that.

## Required offline acceptance tests for implementation

- Default/explicit TTL preserve path/reference bytes and make no invalidation call.
- Recipe flags and typed enums normalize identically; all combinations above,
  duplicate/unknown enum handling, TTL/range errors and plan drift are tested.
- Hash names match final bytes; references, unchanged sync, SRI/cycles, metadata
  updates and retained old-client assets have deterministic fixtures.
- Release staging failures cannot activate; CAS conflicts, crash-after-switch,
  retained rollback without re-upload and interrupted index-only GC are covered.
- Invalidation is absent by default; exact/wildcard choices, both path counts,
  cap 100/101, explicit override and an unchanged plan are tested with zero AWS.
- Cost prints before dispatch; ledger refusal dispatches nothing; batching cannot
  discount P; shared free allowance is not assumed; uncertain retries do not
  double-charge or duplicate batches. Denied and timed-out invalidations report
  committed content / pending freshness accurately.
- Optional grant is absent from default generated policy and present only in the
  reviewed opt-in path; all writes retain profile, ownership and prefix guards.
- At least TTL, HASHED and RELEASE have synthetic recipe examples and pictures.
  Live tests and release publication remain separately authorized future work.

Sources checked for the design: [invalidation path billing](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/PayingForInvalidation.html),
[current AWS cost example](https://aws.amazon.com/blogs/media/automate-streaming-content-refresh-with-amazon-cloudfront-cache-tags/),
[origin settings and cached responses](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DownloadDistValuesOrigin.html),
[distribution propagation](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/HowToUpdateDistribution.html),
and [browser/CDN expiration](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Expiration.html).
