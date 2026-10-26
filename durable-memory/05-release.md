# Releases and remaining work

Published versions: v0.1.0, v0.1.1 and v0.1.2. v0.1.3 is the pending patch release
for the completed six-example live campaign; update this record only after its tag,
five assets and SHA256SUMS are published. [Release proof](release-v012.json)
records five native executables plus SHA256SUMS and verified asset digests.
[Autorun proof](autorun-v012.json) records all 30 examples from empty working
directories and a fresh shared cache using that exact released binary.

The `v*` workflow builds/tests JVM and native hosts on Linux x64/ARM64, macOS
x64/ARM64 and Windows x64, then publishes the five binaries and SHA256SUMS.
GraalVM CE is pinned to 25.0.2 except macOS Intel at 25.0.1 (the available Intel
release). Linux requires glibc >=2.35; Windows requires the VC++ runtime.
Licenses and corresponding-source links are embedded in THIRD_PARTY_NOTICES.
Local verification is the user-required gate; CI and live AWS access are not
publication gates. The workflow itself still makes its release job depend on its
five platform jobs; that automation dependency has not been removed.

Genuinely open items:

- Four IAM examples remain skipped/estimated because federated sessions cannot
  call IAM. The six scoped lifecycle writes now have live evidence and zero
  leftovers; future sessions must be re-issued through the existing helper.
- Incomplete AWS-provider list/message/category parity and opaque provider
  request accounting; see [comparisons](06-comparisons.md). Provider init/version
  blockers are resolved in lmcloud v0.1.10.
- Replace/remove `scripts/test-live.py`, whose legacy default-profile write smoke
  conflicts with the current lmaws-only mutation policy. Use USER_TEST instead.
- Any service expansion must preserve name/tag/ledger ownership, explicit profile
  guards, capped estimates, redaction and credential-free fake CI. Current API
  intentionally omits IAM, compute and networking writes; they are not shipped.
