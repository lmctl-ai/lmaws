# Releases and remaining work

Current verified release: **v0.1.15**, source commit
`549ee9fd40aa8b4b92b1b1a59d2a70c265d32c72`.
[Release proof](release-v0115.json) records all five binaries, their verified
SHA256SUMS, Linux linkage and released-native offline checks. Packaging run
[40417639588](https://github.com/lmctl-ai/lmaws/actions/runs/40417639588) passed
on all five platforms. The snapshot includes the spend reports and the current
IAM permission builder, credential-process and guarded web-stack API.

The local managed/native gate passed all 115 gallery programs, 75 recipe
contracts, nine recipe execution regressions, 188 spend controls, 33 native SDK
loopback controls and 12 spend API cases. The release has 152 callable bindings,
153 host signature lines including its implicit context, and 225 including std.
[Fresh-cache proof](autorun-v0115.json) records eight public spend URLs from
empty working directories, installing v0.1.15 and producing 12 synthetic images;
no AWS credentials or account data were used. All public proof is synthetic.

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
