# Current lmcloud / OpenTofu comparisons

All 30 examples have `compare/<name>/main.tf` and generated self-contained `.lms`
phases for init, validate, plan, apply, inspect and destroy. Scripts pin released
lmcloud **v0.1.10**, verified against release SHA256SUMS, and AWS provider
**5.100.0**. Real provider installation and single-number version handling work;
the former blockers are resolved. No further lmcloud core defect was found and
no lmcloud source was modified. The provider is external, not bundled in lmaws.

[Campaign evidence](../evidence/comparison-campaign-v0110.json) and
[RESULTS](../compare/RESULTS.md) describe **20 completed live pairs**: 19 read-only
under default and one bucket/object lifecycle under lmaws. Seven comparisons
match; 13 explicitly differ in supported output fields or local-state semantics.
Six previously denied writes were not retried; one default-profile metadata read
per case confirmed absence without establishing create permission. Four IAM
pairs remain skipped/estimated only. All recorded leftovers are zero.

Each engine created one owned bucket and tiny object; both were destroyed and
independently checked absent with default. SDK ledgers (25 attempt directories)
and provider state sweepers returned zero; the final bucket inventory also found
neither test bucket. [Cleanup proof](../evidence/comparison-cleanup-v0110.json)
contains only owned test names and counts, not arbitrary account inventory.

Native attempts estimated $0.00004000 from SDK requests/lifetimes. Provider
records reserve a **$0.0575 upper bound across all attempts**, including retries;
they do not measure provider SDK request counts. The combined conservative
campaign total is $0.05754170, below $0.25. A 500-request/$0.0025 allowance is
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
