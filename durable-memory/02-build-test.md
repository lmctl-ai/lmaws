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
