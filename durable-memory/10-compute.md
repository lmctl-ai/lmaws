# EC2 compute recipes and the spot nano lifecycle (v0.1.5)

`Ec2Compute` (EC2/CloudWatch/SSM through the shared clients of `AwsBackend`) adds read-only
reports on `Cloud` and one run-owned lifecycle object `Spot`. Recipes live in
`recipes/lib/compute.lms` (seven entries, category "Compute and fleet"); examples force
synthetic fixtures (`Ec2Compute.Demo`, fixture ids such as `i-0fixture...`, documentation
addresses 198.51.100.x). Live reports go to the git-ignored `.lmaws-local/compute/`.

| Recipe | Host calls | Profile |
|---|---|---|
| fleet_status | `ec2_instances(tag_key, tag_value)` (empty value = tag-key filter), `addresses()` | default |
| cpu_credits | `cpu_credits(ids_csv, hours)`: hourly GetMetricStatistics of CPUCreditBalance/Usage, surplus balance/charged, CPUUtilization | default |
| eip_map | `addresses()`, `ec2_instances("", "")`; idle flag, "pinned: never release" report, never releases | default |
| ami_lookup | `public_parameter(name)`: only `/aws/service/...` (default profile denies ssm:GetParameter) | lmaws-ec2 |
| spot_prices | `spot_prices(types_csv, hours)`: latest Linux/UNIX price per (type, AZ) | default |
| ebs_roots | `volumes()`, `ec2_instances`; DeleteOnTermination, AZ lock, monthly gp3 cost | default |
| spot_nano_lifecycle | `subnets()`, `spot_prices`, `public_parameter`, `spot_run()` ... | lmaws-ec2 + `--live --apply` |

## Tag and safety contract (host side, independent of IAM)

- Writes need `LMAWS_LIVE=1`, `AWS_PROFILE=lmaws` or `lmaws-ec2` (`AwsBackend.MUTATING_PROFILES`;
  every other profile is read-only) and us-east-1. Loopback fakes and demo sessions bypass the gate.
- `Spot.launch`: t4g.nano or t3.nano only; one live instance per run; max price > 0 and <= the
  On-Demand price (0.0042 / 0.0052 USD/h); worst case (max price x 10 min + 8 GiB gp3) must fit
  `LMAWS_MAX_COST_USD`; the security group must be this run's; subnets used by `Project=awsspot`
  instances are refused. RunInstances: one-time spot, interruption terminate, 8 GiB gp3 root
  DeleteOnTermination, `AssociatePublicIpAddress=false` (no public IPv4 charge), IMDSv2, harmless
  user data, `lmaws_test=<run id>` and `Name=lmaws_<run id>` on instance, volume, network-interface
  and spot-instances-request **at creation** (the session policy requires all four).
- Known launch failures return a Row (`status` = InsufficientInstanceCapacity, SpotMaxPriceTooLow,
  MaxSpotInstanceCountExceeded, InvalidParameterValue, UnauthorizedOperation,
  AuthFailure.ServiceLinkedRoleCreationNotPermitted ...) so a script can fall back; the AWS
  message goes to the private spot ledger only.
- `terminate/stop/start/wait_*`: the id must be created by this run, carry `lmaws_test=<run id>`
  and must not carry `Project=awsspot`. Waits are bounded (<= 600 s since the first launch).
- A one-time spot instance cannot be stopped (only persistent requests stop/resume): `stop`
  returns `UnsupportedOperation` and the recipe terminates. Terminating normally closes the
  request, but EC2 can leave it active/fulfilled for minutes: teardown waits 120 s, then calls
  CancelSpotInstanceRequests for this run's request and records a denial in `denied_action()`.
- `teardown()` (also run by host close on every failure path and by the shutdown hook):
  terminate, wait terminated (240 s), delete the security group (retries DependencyViolation for
  180 s), close spot requests. `verify()` checks instances, volumes, ENIs, groups and requests by
  the run tag; `leftovers()` searches the account by the `lmaws_test` tag key and `lmaws*` names.
- `Cloud.spot_recover(run_id)` retries teardown for an earlier run only when its local spot
  ledger `lmaws-spot-<run id>.jsonl` exists, and only for resources tagged with that run id.
- Cost: observed spot price (price history in the launch AZ) x seconds alive + 8 GiB x
  $0.08/GB-month; the recipe asserts it stays below the cap.

## lmaws-ec2 profile (generic description; the policy lives outside this repository)

A federated session (same local session tooling as `lmaws`) whose policy allows: `ec2:Describe*`,
`sts:GetCallerIdentity`, `ssm:GetParameter` on `parameter/aws/service/*`; `ec2:RunInstances` on
instance/volume/network-interface/spot-instances-request only with request tag `lmaws_test`,
on subnets and images, and on security groups that already carry `lmaws_test`;
`ec2:CreateSecurityGroup` (denied without the request tag); `CreateTags` only during
RunInstances/CreateSecurityGroup; Terminate/Stop/Start/DeleteSecurityGroup only on resources
tagged `lmaws_test`; denies instance types other than t4g.nano/t3.nano, volumes above 8 GiB and
every region except us-east-1. It does **not** allow `ec2:CancelSpotInstanceRequests` or
`iam:CreateServiceLinkedRole` (the spot service-linked role must already exist).

## Live proof (2026-10-26, details in the local ledger only)

- Read-only recipes ran live with `default` (ami_lookup with `lmaws-ec2`); EC2 Describe calls are
  free, cpu_credits cost about $0.00015 in CloudWatch requests.
- spot_nano_lifecycle: the cheapest t4g.nano AZ returned InsufficientInstanceCapacity, the second
  AZ launched; running after ~5 s, both status checks ok after ~2 min, stop refused
  (UnsupportedOperation), terminated after ~50 s; volume, ENI and security group gone; estimated
  cost about $0.0002. The one-time spot request stayed active/fulfilled after termination and
  CancelSpotInstanceRequests is denied by the session policy, so the request is the one reported
  leftover (no instance, no charge) until EC2 closes it or the policy allows the cancel.
- lmscript 0.2.426 does not pass `set_env` values to `system()` children (it spawns with its
  start-up environment); `recipe_run` therefore passes settings through `env(1)` on Linux/macOS.
  Before this, `--live` recipes silently ran synthetic. On Windows a live recipe stops with a
  message unless the parent environment already has the settings.
- `Rows.json()` masks any 12+ digit run as an account id, which corrupted long float strings;
  compute metrics are emitted with 4 decimals.
