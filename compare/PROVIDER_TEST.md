# Current AWS provider verification

Released lmcloud **v0.1.10** resolves and installs real external providers. The
comparison campaign downloaded the official release executable, verified it
against release SHA256SUMS, and used AWS provider `hashicorp/aws` **5.100.0**.
Its single-number version output also works with the installer. The former
provider-source/version-format blockers are fixed; no additional lmcloud core
bug was found and no lmcloud source change or patch release was needed.

The shared scratch `TF_PLUGIN_CACHE_DIR` reused the approximately 676 MiB
installed provider across independent working directories. Scripts pin v0.1.10
for reproducibility. The provider stays external; it is not bundled in lmaws.

[Campaign evidence](../evidence/comparison-campaign-v013.json) and
[RESULTS](RESULTS.md) record the earlier 20 live pairs plus the six newly
authorized lifecycle pairs in the v0.1.3 campaign: 26 completed pairs total,
eight matching comparisons and 18 explicit output/local-state differences.
All six writes passed with the lmaws_ ownership prefix/tag, were destroyed,
and were independently absent under the default read-only profile. Four IAM
pairs remain skipped because federated sessions cannot call IAM. All observed
leftovers are zero.

The two lifecycle fixtures that previously used leading-slash names now use
the same lmaws_ prefix as the native examples. `scripts/test-compare.py`
derives their rendered names from the checked-in HCL and rejects a leading slash.

Real runs exposed defects in the lmaws equivalents, now fixed: ECS
`cluster_arns`, the service-matrix Secrets Manager/Route53 references, explicit
all-state EC2 selection, and security-group rule data sources instead of a
nonexistent group `ingress` attribute. Provider schema sources are pinned to
[v5.100.0](https://github.com/hashicorp/terraform-provider-aws/tree/v5.100.0).

Intermittent credential-process refresh failures occurred with the configured
profiles and succeeded on retry. They are categorized as credential failures,
not provider-download failures. No IAM, credential/profile edits or alternate
identity were used. Raw logs/state remain private under ignored `compare/runs/`.

Scope: comparisons check observed resource types/names and required ownership
tags, example numeric outputs, end-to-end time, price-table estimates and cleanup.
They do not establish complete AWS API parity. Missing provider list/message
operations and native category splits remain explicit in `manifest.json`.

A [fresh-directory autorun](../evidence/comparison-bootstrap-v0110.json)
installed the exact checksum-verified release, downloaded both helpers and
initialized/validated the real provider with live mode disabled and no AWS calls.

The v0.1.3 checksum audit found the initial six successful provider runs used a
local build reporting v0.1.10. Those records are retained but superseded for
release verification. All six provider sides were rerun with the published
v0.1.10 Linux x64 asset (SHA256 `5f284718f1c3a3c05cc076712f806e02e6e3ccb821dd6ba0196eefc77ae4549b`),
reusing native evidence, with zero leftovers. The campaign includes all fourteen
attempts: six local-build successes, two preflight rejects, six published-binary
successes. Its conservative total is $0.03503065000042; reused native observations
are conservatively charged again by the harness, not repeated native writes.
