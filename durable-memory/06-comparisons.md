# lmcloud / OpenTofu comparisons

All 30 examples have `compare/<name>/main.tf` and a generated remote `.lms`
equivalent using `tofu.init`, `validate`, `plan`, `apply`, `show_state` and
`destroy`. [compare/README](../compare/README.md) describes the harness;
[RESULTS](../compare/RESULTS.md) is the per-example summary and
[PROVIDER_TEST](../compare/PROVIDER_TEST.md) records observed upstream findings.
No lmcloud source is vendored or edited. AWS provider 5.100.0 is an external
OpenTofu plugin, not linked/bundled in the native host.

`compare/run.sh <example>` compares resource types/names/tags after run-ID
normalization, outputs, elapsed time, estimated cost and zero-leftover cleanup.
Use default for reads, lmaws for writes; IAM is skipped. `--native-evidence`
reuses a finished live run. The runtime validates a fresh owned plan, writes a
private ledger/state, reserves cost, checks phase booleans and always attempts
destroy after apply, then independently checks absence with default. Local
`compare/sweep.py --older-than-hours 0` is dry-run. State/logs stay ignored.

Observed results: all 26 non-IAM comparisons stopped at init in lmcloud 0.1.9:
AWS provider 5.100.0 could not resolve (“no available releases match”). No plan,
apply or provider resource creation occurred; provider estimated charge was zero.
Four IAM comparisons were skipped. This is not successful live equivalence.
Fresh-cache/bootstrap and all-init records are retained as
[compare-autorun](compare-autorun-v012.json) and
[compare-init](compare-init-results-v012.json).

A separate `@latest` installer failure sees two versions in lmcloud's version
line; scripts pin `github:lmctl-ai/lmcloud@v0.1.9` to avoid it, with checksum
verification intact. The pin does not fix provider initialization. Test a future
fixed binary with the checkout harness's `--lmcloud /absolute/path` option.

Provider list/message APIs are not all equivalent: unsupported inventories and
imperative sends/updates remain explicit gaps in `compare/manifest.json`.
Mocked tests prove compilation, ownership/cap checks and failure teardown, not
live parity. Provider cost uses a conservative 500-request/$0.0025 write allowance,
not observed SDK traffic; shared campaign accounting includes native/verification
cost and refuses further creation past its cap. Regenerate scripts after HCL
changes using `python3 compare/generate.py` and run `scripts/test-compare.py`.
