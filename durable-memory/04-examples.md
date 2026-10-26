# Examples and cost labels

There are 115 runnable `.lms` examples: eight spend reports, 75 synthetic-only recipe demonstrations
(including seven EC2 compute recipes, three IAM/session recipes, and 27 permission builder/analysis recipes), two account prefix/leftover discovery examples,
plus the original 30 stories: 19 read-only stories, seven
write/lifecycle stories and four IAM-dependent stories. See [README](../README.md)
for the complete image gallery and cost captions; [USER_TEST](../docs/USER_TEST.md)
describes the federated `lmaws` session policy and profile rules.

The original stories use `aws.example(name)`: demo fixtures by default, live only with
`LMAWS_LIVE=1`. It asserts fixture values only in demo mode, accepts sparse real
inventories, executes saved bytecode, exports CSV and draws its own PNG with
lmplot/lmdraw. Offline examples need no AWS credentials. `sweeper` is a read-only
local ledger report, not a cloud deletion operation.

```sh
LMAWS_LIVE=0 timeout 300 lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/inventory.lms
```

Autorun installs the released native host through the script's `cli`/`install`
binding and writes `images/<name>.png` relative to the invocation directory.
No Java or repository-relative input is required for native autoruns. Rendering
tests run the actual scripts; `examples/render-all.lms` refreshes the original gallery assets. New recipe
examples call paired import-only libraries, force synthetic mode, and are
covered by the same native gallery execution gate.

All README examples label “running this example costs about $X”. Nineteen live
read-only results display `$0.00`; S3 bucket/object and the six lifecycle stories
have measured price-table estimates after the federated session was re-issued.
Four IAM examples remain estimated only. The price table is not an invoice.
See [safety/cost](07-example-costs.md) for price-table limits.

Eight additional deterministic spend examples bring the current gallery to 76. They
use aws.spend rather than the owned-resource example runner and generate 12
figures. Their paid-query planning estimates are explicit; actual fixture runs
cost no AWS money. See [spend reports](09-spend-reports.md).
