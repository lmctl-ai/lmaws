# File lifecycle registry

Canonical design and implementation qualification:
[docs/LMSYNC_DESIGN.md](docs/LMSYNC_DESIGN.md).

The confirmed product is [lmfiles](https://github.com/lmctl-ai/lmfiles), with
milestones 1A/1B implemented. The registry has no remote actions or business-rule
engine; one user LMScript orchestrates each job with existing action hosts.
