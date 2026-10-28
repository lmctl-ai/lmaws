# Which AWS profile do I need?

lmaws never uses the aws CLI and never picks credentials from the environment for writes: the
profile name decides what a run may do. Every recipe defaults to synthetic data, so the first row
needs no AWS account at all.

| You want to | Profile | Flags | Notes |
|---|---|---|---|
| See pictures, try recipes, read examples | none | (none) | Synthetic fixtures; no AWS calls, no credentials |
| Read-only inventory, audits, spend reports | `default` | `--live` | Describe/List/Get only; spend reports require `default` |
| Create and tear down service sandboxes (queue, topic, table, bucket, parameter, log group), cleanup by prefix | `lmaws` | `--live --apply` | Names `lmaws_<run>_...` / `lmaws-<run>-...`, tag `lmaws_test=<run>`, us-east-1 |
| Web and serverless scenarios (lmweblab) | `lmaws` | `--live --apply` | Run-owned resources only, us-east-1 |
| EC2 spot nano sandbox, latest AMI lookup | `lmaws-ec2` | `--live` (`--apply` for the sandbox) | t4g.nano/t3.nano, 8 GiB gp3, no public IPv4, us-east-1 |
| Create or change `lmaws_` IAM policies and Lambda roles | `admin` | `--live --apply` and `LMAWS_ADMIN_GRANT=1` | Only the grant recipes accept it; every other write refuses `admin` |

Rules enforced by the host (not only by IAM):

- Writes need `LMAWS_LIVE=1` (recipes set it from `--live`) and one of the profiles above; any
  other profile name is read-only. `admin` is refused for every non-IAM mutation.
- `--credential-process <mode>` (modes `default`, `lmaws`, `lmaws-ec2`, `lmaws-web`) issues a
  scoped federated session from the explicitly selected static source profile. The source is
  `agent-issuer` by default and can be set with `--source-profile NAME` or
  `LMAWS_CREDENTIAL_SOURCE_PROFILE`; a name containing `admin` is refused unless the human-only
  `LMAWS_ALLOW_ADMIN_SOURCE=1` override is present. The helper reads only static credentials from
  the selected shared credentials/config files and never falls back to environment, SSO, web
  identity, container, instance metadata, or another ambient source.
- `default` reads the inline session policy from `--policy-file`,
  `LMAWS_DEFAULT_SESSION_POLICY`, or (by default)
  `~/.aws/session-tools/tasks/iam-snapshots/local-default-session.json`, compacts it, and sends
  it with the `ReadOnlyAccess` policy ARN. The compact policy plus ARN must fit STS's 2,048-character
  limit. The three `lmaws*` modes resolve the source account with STS and use its
  `lmaws_session` managed policy ARN. All modes use `awsspot-local-<mode>` and 3,600 seconds.
  Tokens are cached in owner-only files until five minutes before expiry; the cache scope includes
  the source profile and policy inputs.
- CI never gets live credentials: live AWS is refused when `CI=true`; tests use loopback fakes.

Check your setup without changing anything: `lmctl recipes/session_doctor.lms --live` (synthetic
without `--live`). See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the common error messages.


Account-specific permission verification and fleet role scripts live in the private `lmctlhq/admin` repository. Generic conditional-upload APIs retain explicit per-client profile routing and owned cleanup; ordinary default mutators remain blocked. Agents require explicit user approval for each specific admin action, including dry runs.

Private fleet-role wrappers pass `LMAWS_FLEET_ROLES_SPEC` explicitly to the child host. The private runbook owns the mapping and grant rationale; public tests use synthetic fixtures.
