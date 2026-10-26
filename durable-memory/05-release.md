# Releases and remaining work

Published versions: v0.1.0, v0.1.1, v0.1.2, v0.1.3, v0.1.4, v0.1.5 and **v0.1.6**.
v0.1.5 added EC2 compute recipes and the `lmaws-ec2` spot nano lifecycle; v0.1.6
adds customer-managed `lmaws_` IAM policy management (`iam_policy_lint`,
`iam_policy_get`, `iam_policy_versions`, `iam_policy_put`, `iam_policy_delete`)
and the `policy_lint` and `grant_session_policy` recipes, and live-applied the
`lmaws_session` managed policy (`v2`, 4,839 compact characters, 0 lint findings).
[Release proof](release-v013.json) records the v0.1.3 five native asset digests and
verified SHA256SUMS. [Fresh-cache proof](autorun-v013.json) records all six scoped
lifecycle examples run offline from empty directories with the released v0.1.3
binary; no native live writes were repeated. The earlier
[30-example proof](autorun-v012.json) remains the v0.1.2 baseline.
Local JVM/native test.sh and all 30 gallery programs passed; the five-platform
packaging run `40377920161` also completed successfully. Final provider-checksum
verification evidence and current notes landed after the source tag without
changing the released runtime.

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
