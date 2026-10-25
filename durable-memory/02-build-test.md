# Build and test

Java 21+, Maven, Python 3 and the pinned lmctl/lmscript compiler are needed.
`bash test.sh` fetches/verifies the SDK, runs Maven, checks all resolved runtime
artifact digests, CLI/schema/notices/error paths, regression groups, memory limits
and actual SDK HTTP calls to an in-process loopback fake.

`bash scripts/build-native.sh` uses GraalVM CE 25 and emits target/lmaws (or .exe).
`LMAWS_NATIVE=1 bash test.sh` repeats verification against that exact executable,
including offline examples and their visual hosts. The fake endpoint override is
restricted to literal loopback HTTP and uses dummy credentials instead of the real
credential chain. Production endpoints use TLS and the standard AWS chain.

Linux builds use ubuntu-22.04 / ubuntu-22.04-arm and dynamic glibc only, with static
GCC/C++ runtime. The dependency allowlist and glibc symbol ceiling are checked.
macOS uses system libraries. Windows uses GraalVM/MSVC and the documented VC++
runtime prerequisite. No Java installation or adjacent data files are needed.

LMAWS_MAX_MEMORY_MB defaults to 4096 positive whole MiB. The VM tracks cumulative
allocations, retained inventory rows are charged, inputs and inventory cardinality
are bounded, and a child-process restart sets a heap cap at 75% of the budget so
SDK allocations are also bounded. Runtime budgets below 16 MiB fail with a run
error rather than trying to start an unusable JVM. Runaway-allocation tests use
64 MiB everywhere and the default budget inside a 6 GiB address-space ceiling for
Linux native binaries. The host does not set OS rlimits itself.

Native builds use optimization level 1 and two compiler threads to keep the broad
SDK service surface practical on hosted runners; HTTP service latency dominates
this host rather than numeric kernel throughput. The input shaded JAR is copied
to an immutable build snapshot before invoking native-image.

Release CI pins GraalVM CE 25.0.2. Local verification also uses CE 25.4.4.1.1;
the release proof records which binaries were verified. Public corresponding-source
links are included in the embedded notices.

Local JVM and native verification pass all 16 service inventories and six tagged
write/update/delete lifecycles over real SDK HTTP transports. The fake verifies
creation tags from actual requests, pagination, finally cleanup, and a provider
error containing a secret sentinel that never reaches output. All fake resources
are deleted. All 25 examples pass and regenerate companion PNGs. Native Linux
x64 prototype size is 55,511,304 bytes, with only libc.so.6 dynamically needed.

macOS Intel pins GraalVM CE 25.0.1, the final upstream Intel build; 25.0.2
has no macOS x64 asset. Other release lanes pin 25.0.2. Windows Python tests
explicitly decode UTF-8 so embedded upstream license typography is byte-correct.

The host explicitly uses UTF-8 stdout/stderr. Windows JDK console defaults may
otherwise encode help typography in a legacy code page even though notices are
raw UTF-8 bytes; both protocol and diagnostics must use a single encoding.

The Linux address-space test identifies the executable by its ELF header. It must
not run against the JVM shell wrapper in the native stage: GraalVM HotSpot may
reserve a separate libjvmci isolate before the host can enforce its own budget.
