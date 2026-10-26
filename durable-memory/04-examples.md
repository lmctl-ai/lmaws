# Examples and cost labels

There are 30 self-contained `.lms` examples: 19 read-only stories, seven
write/lifecycle stories and four IAM-dependent stories. See [README](../README.md)
for the complete image gallery and cost captions; [USER_TEST](../docs/USER_TEST.md)
describes the federated `lmaws` session policy and profile rules.

Each script uses `aws.example(name)`: demo fixtures by default, live only with
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
tests run the actual scripts; `examples/render-all.lms` refreshes gallery assets.

All README examples label “running this example costs about $X”. Nineteen live
read-only results display `$0.00`; S3 bucket/object and the six lifecycle stories
have measured price-table estimates after the federated session was re-issued.
Four IAM examples remain estimated only. The price table is not an invoice.
See [safety/cost](07-example-costs.md) for price-table limits.
