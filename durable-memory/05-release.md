# Releases and remaining work

Published releases verified through v0.1.3. Tags v0.1.4 through v0.1.7 failed
packaging checks and must not be described as published binaries. v0.1.9 is the
pending patch, preserving concurrent compute, IAM policy (`lmaws_session` `v2`
live-applied), native `lmaws --credential-process <mode>` + `session_doctor`,
account recovery, web-stack and spend-report work.
[Release proof](release-v013.json) records the v0.1.3 five native asset digests and
verified SHA256SUMS. [Fresh-cache proof](autorun-v013.json) records all six scoped
lifecycle examples run offline from empty directories with the released v0.1.3
binary; no native live writes were repeated. The earlier
[30-example proof](autorun-v012.json) remains the v0.1.2 baseline.
Local JVM/native test.sh and all 30 gallery programs passed; the five-platform
packaging run `40377920161` also completed successfully. Final provider-checksum
verification evidence and current notes landed after the source tag without
changing the released runtime.

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
