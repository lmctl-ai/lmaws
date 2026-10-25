# Release verification

The workflow builds JVM and GraalVM native versions on Linux x64/arm64, macOS
x64/arm64 and Windows x64. Every native executable runs the fake transport suite
and the offline gallery. Tag publication depends on all five platform jobs.
Five executables and SHA256SUMS form the release. Native binaries embed schema
registration and notices; no kernels, JVM or SDK jars are needed at run time.

Main CI is green on all five platforms (see main-ci-v010.json). Tagged publication
and installed-asset verification are the remaining release gates.

## Current release gate (2026-10-25)

Engine candidate 9fed240c4d20cbd0507a2d8c457d0b82c748f8f7 is pushed to main.
Current full matrix: https://github.com/lmctl-ai/lmaws/actions/runs/40157706937 .
All five platform jobs completed successfully on the final engine candidate.
The complete JVM/native SDK, memory, fake transport and 25-example checks passed.

JVM validation passes 16 inventories, six tagged lifecycles, paging, real AWS error
redaction, finally teardown, namespace isolation and UTF-8 output. All 25 examples
and images pass. Source is frozen apart from actual CI failures and release proof.
The approved live native test is done: the only two created resources, listed in
live-v010.json, were deleted and independently verified absent. Additional real
writes are unnecessary. A CE 25.0.2 CI binary also passed default-profile TLS reads.

After the matrix is green: commit proof, push an annotated v0.1.0 tag, wait for all
five tag jobs and publication, verify all five SHA256SUMS and the released Linux
binary, then autorun all 25 raw URLs from isolated empty working directories with
an initially empty shared tool cache. Record exact installed version/hash and PNG
outputs. Update only the lmaws ROADMAP row.
