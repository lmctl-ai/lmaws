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

[Campaign evidence](../evidence/comparison-campaign-v0110.json) and
[RESULTS](RESULTS.md) record 20 completed live pairs (19 read-only plus one
bucket/object lifecycle), seven matching comparisons and 13 explicit output/
local-state differences. Six prior denied writes were not repeated after one
metadata-only absence recheck each; those reads do not establish create rights.
Four IAM pairs were skipped. All observed leftovers are zero.

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
