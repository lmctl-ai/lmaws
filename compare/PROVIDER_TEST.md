# lmcloud AWS provider probe

The lmcloud equivalent path was tested with the published `lmcloud 0.1.9`
binary, OpenTofu, a disposable `us-east-1` configuration, and no AWS
credentials or account mutations. The configuration pinned the official AWS
provider source `hashicorp/aws` at `5.100.0`:

<https://registry.terraform.io/providers/hashicorp/aws/5.100.0>

The probe captured the return value from `tofu.init` and the host's error output
before attempting any plan or apply. Initialization returned `false` and the
captured error was:

```text
Failed to resolve provider packages; Could not resolve hashicorp/aws: no available releases match constraints 5.100.0
```

This is recorded in the private probe evidence at
`compare/private/probe-v019/phase-init.ok` and
`compare/private/probe-v019/phase-init.error`. No `.terraform` provider install,
plan, apply, or destroy was attempted after the failed initialization, and no
AWS resource was created. This is an lmcloud/provider-resolution finding; the
lmaws repository does not modify the lmcloud repository.

Source inspection explains the path: lmcloud delegates `tofu.init` to
OpenTofu's `command.InitCommand` (`internal/lmhost/host.go:183-199`). OpenTofu's
implicit provider source (`cmd/tofu/provider_source.go:101-218`) first searches
local plugin mirrors and then queries the upstream registry; lmcloud does not
embed an AWS provider. The failure therefore occurs during provider package
resolution, before AWS credentials or API calls are relevant. A direct registry
version listing contains 5.100.0, so the exact registry-resolution mismatch
remains an lmcloud/OpenTofu provider-installation finding rather than an AWS
permission failure.

## Fresh-cache latest-install finding

An empty-directory autorun with an empty LMSCRIPT_TOOL_CACHE and lmctl/lmscript
0.2.420 downloaded the published v0.1.9 asset, then rejected its version line:

```text
lmcloud --version printed "lmcloud 0.1.9 (opentofu 1.13.2)", which has no single version number
```

The installer requires one MAJOR.MINOR.PATCH version for @latest. This is distinct
from the provider-resolution failure and occurs before any script effect or AWS
call. Comparison scripts therefore pin `github:lmctl-ai/lmcloud@v0.1.9`, whose
release checksum is still verified. They do not alter or wrap lmcloud's version
output. To reproduce the @latest failure, autorun the comparison at commit
9bacb7dbf8a75894db0004d88d8f02a42a6f7c6f with a fresh cache; that snapshot used
@latest. Private bootstrap log: `/tmp/lmaws-compare-autorun-v012-07ej9fu1/private-run.log`.
No lmcloud source was edited for either finding.
