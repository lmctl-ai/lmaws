# Architecture and scope

lmaws is a new MIT Java 21 scripting host over AWS SDK for Java v2 2.57.3
(Apache-2.0). It is independent of the older TypeScript lmawscli wrapper.
The released lmcode-java v0.1.1 sources are fetched by immutable commit and
archive SHA-256 in sdk.lock. All runtime Maven JARs are content-pinned in deps.lock.
No third-party implementation sources are committed.

CloudHost registers the typed API and generates schema bytes from exactly that
registry, including the 72 canonical standard functions. The aws context opens
an offline demo session or a single-region live session. Inventories are projected
metadata Rows/Row objects with CSV and JSON exports. Secret-value, password and
IAM user/key operations are absent. Output masks twelve-digit account IDs.
URLConnection is the only HTTP transport; no Apache HTTP, Netty or AWS CRT native
library is bundled. The standard credential chain includes environment, profile,
SSO, container and instance credentials. Profiles and region are resolved at run
time. Public CI uses no AWS account credentials.

Writes are deliberately limited to run-owned S3 buckets/objects, SQS queues/messages,
SNS topics/messages, standard SSM String parameters, DynamoDB on-demand pk/value
tables and CloudWatch log groups/retention. Compute, networking, identity, Lambda,
DNS and Secrets Manager are metadata-only in v0.1.0. This keeps the initial write
surface small and auditable; no Lambda deployment or IAM mutation is implied.

Sandbox creates a new forced-to-disk JSONL ledger before any AWS write. Names carry
the run prefix; resources carry lmaws_test=run-id. Updates/deletes require both an
in-memory ledger entry and verified provider tags. Cleanup runs in reverse order
on success and exceptions; a shutdown hook also attempts teardown. Failed cleanup
remains visible rather than being marked deleted. The sweeper is strictly dry-run
and folds old ledgers; it never authorizes deletion of discovered account resources.

GraalVM native runtime GPLv2 with Classpath Exception, dynamic system glibc LGPL,
static GCC runtime exception and static zlib notices are embedded along with the
SDK/transitive licenses. There are no GPL application dependencies. Java's native
runtime licensing follows the explicit JAVA_BRIEF exception/pattern.

The private ledger retains exact resource identifiers for recovery (account IDs are
identifiers, not credentials). Public JSON/CSV/sweeper output masks account IDs.
Ledger records never contain request payloads, parameter values or SDK error text.

S3 bucket regions come from the provider response, never from the selected client
region (ListBuckets can return resources in other regions). EC2 instance/VPC tag
compliance exposes tag presence without publishing arbitrary tag values.
