# Releases and remaining work

Current verified release: **v0.1.18**, source commit
`2aaba04653733e898469b0faa55b8534ff6bd481`.
[Release proof](release-v0118.json) records all five native assets, verified
SHA256SUMS, Linux linkage, released-native self-tests and exact role API signatures.
[Packaging run 40433490733](https://github.com/lmctl-ai/lmaws/actions/runs/40433490733)
passed all five platform jobs. The release includes guarded Lambda execution-role
grants and the narrow Lambda-only PassRole lint exception, preserving the IAM
builder and persistent serverless work.

The managed/native local gate passed 116 gallery programs, 76 recipe contracts,
ten recipe execution regressions, 38 role controls and SDK role transport cases.
The snapshot has 178 callable bindings, 179 host signature lines including its
context and 251 including std. [Fresh-cache proof](autorun-v0118.json) runs the
public synthetic Lambda grant example from an empty directory/cache, verifies
v0.1.18, validation success, no apply and the PNG. Public proof uses no AWS access.

Live Lambda execution is separately gated on the Lead's explicit PassRole/session
readiness signal and the documented log-cleanup permission. The role grant recipe
is the only administrative path; tests use the lmaws profile. Live account evidence
stays ignored and is not part of the public proof.

Earlier [v0.1.15 release](release-v0115.json) and [v0.1.15 autorun](autorun-v0115.json)
proofs retain the spend-release baseline.

Earlier [v0.1.3 release](release-v013.json), [v0.1.3 autorun](autorun-v013.json),
[v0.1.2 release](release-v012.json) and [v0.1.2 autorun](autorun-v012.json) proofs
remain historical baselines and do not describe the current release.

The manual `ci` workflow must be dispatched with a `v*` tag ref. It builds/tests JVM and native hosts on Linux x64/ARM64, macOS
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
  guards, capped estimates, redaction and credential-free fake CI. Current code
  includes guarded compute and customer-managed IAM policy operations; these
  require their documented explicit approval and ownership checks.

Current source has weighted-DNS and typed/persistent serverless scenario APIs beyond v0.1.16. Their native release artifacts have not been published. The local JVM and loopback gates pass; Lambda scenarios remain fake-only pending explicit role/PassRole authorization and live validation, including actual EventBridge scheduling. The scenario driver rejects real serverless endpoints. Do not infer new-platform native proof from the existing v0.1.16 release.
