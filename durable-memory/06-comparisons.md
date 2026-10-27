# Current lmcloud / OpenTofu comparisons

The original 30 examples have `compare/<name>/main.tf` and generated self-contained `.lms`
phases for init, validate, plan, apply, inspect and destroy. Scripts pin released
lmcloud **v0.1.10**, verified against release SHA256SUMS, and AWS provider
**5.100.0**. Real provider installation and single-number version handling work;
the former blockers are resolved. No further lmcloud core defect was found and
no lmcloud source was modified. The provider is external, not bundled in lmaws.

The first six provider successes
used a local build reporting v0.1.10; a checksum audit caught this before final
verification. All six provider sides were repeated with the published Linux x64
asset, SHA256 `5f284718f1c3a3c05cc076712f806e02e6e3ccb821dd6ba0196eefc77ae4549b`.
Native writes stayed at six: their evidence was reused. Both sets of provider
attempts and the two earlier preflight rejects remain in the campaign accounting.

[Campaign evidence](../evidence/comparison-campaign-v013.json) and
[RESULTS](../compare/RESULTS.md) describe **26 completed live pairs**: 19
read-only under default, bucket/object under lmaws, and six additional lifecycle
pairs under the scoped session. Eight match and 18 differ in supported output
fields or local-state semantics. Four IAM pairs remain skipped/estimated only
because federated sessions cannot call IAM. All recorded leftovers are zero.

The retained bucket/object baseline and six new lifecycles are independently
verified absent with default. Both native and provider sweepers returned zero.
[Current cleanup proof](../evidence/comparison-cleanup-v013.json) records the
six lifecycle checks; the earlier bucket proof remains in
[the baseline record](../evidence/comparison-cleanup-v0110.json). Public records
contain only owned test names and counts, not arbitrary account inventory.

The v0.1.3 campaign reserves conservative total accounting of
**$0.03503065000042**, below $0.25, including the superseded local-build verification runs and two preflight
rejects. Provider records reserve a per-attempt allowance; they do not measure
provider SDK request counts. A 500-request/$0.0025 allowance is
reserved before each plan because data sources can incur metadata charges.
Per-example cap is $0.05. End-to-end times include native rendering and repeated
provider phases with a warm ~676 MiB shared scratch `TF_PLUGIN_CACHE_DIR`.

The harness compares post-apply state, including confirmed SDK child writes
reconstructed from its ledger, against required run ownership tags and numeric
example outputs. Latest evidence is selected by recording time, not random ID.
Missing final records mean unknown cleanup. One parent and one bounded inline
child are permitted; file uploads, force-destroy and known foreign parents are
rejected. Destroy runs after apply even on failure; default verifies absence.

Use `compare/run.sh <example>`; successful native evidence can be reused from
`compare/runs/<example>/<run>/native/native-result.json` to avoid another write.
Run campaigns sequentially against the shared budget. Sweep with
`python3 compare/sweep.py --older-than-hours 0` (dry-run only). Raw state/logs stay
ignored. See [USER_TEST](../docs/USER_TEST.md) for exact profiles and permissions.

Genuine limits: AWS provider list/message gaps and unrepresented category splits
remain in `compare/manifest.json`; equal numeric outputs do not establish complete
API parity. Intermittent existing-profile credential-process failures succeeded
on retry and are distinguished from provider download failures. No IAM/profile/
credential changes or alternate identity were used. Regenerate after HCL edits
with `python3 compare/generate.py`; local fake tests compile all 30 scripts and
exercise ownership, content, budget, output and failure-cleanup regressions.
