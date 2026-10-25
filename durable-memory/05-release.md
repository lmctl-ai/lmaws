# Release verification

The workflow builds JVM and GraalVM native versions on Linux x64/arm64, macOS
x64/arm64 and Windows x64. Every native executable runs the fake transport suite
and the offline gallery. Tag publication depends on all five platform jobs.
Five executables and SHA256SUMS form the release. Native binaries embed schema
registration and notices; no kernels, JVM or SDK jars are needed at run time.

Initial release verification is in progress. Do not treat an uploaded work-in-progress
commit or a pending workflow as a completed release. Record final CI/asset/live and
autorun evidence here when all gates pass.
