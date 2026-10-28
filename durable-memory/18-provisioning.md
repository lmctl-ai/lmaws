# On-demand provisioning

Eight Cloud JSON-string methods: ec2_provision_run(config), describe(id), stop(id),
start(id), terminate(id), console(id), dry_run(id, operation), verify(id), with the
same ec2_provision_ prefix. Separate from existing sandbox/spot/fleet APIs.

Default/lmaws/lmaws-ec2/lmaws-web only, including fakes; admin refused. Actual writes
need live/apply opt-in. The script's deferred live plan uses default only. No live
campaign was run; the Lead owns GO and release.

Defaults: on-demand t4g.nano, us-east-1, Canonical Ubuntu 24.04 arm64 public SSM AMI,
10 GiB gp3 (1–20 plus snapshot minimum), default VPC/SG, IMDSv2, no public IPv4,
IAM profile, key pair, spot or EIP. Instance/volume/ENI get provisioner=lmprov,
lmprov_id, Name/owner/purpose at creation. Mutations verify returned ownership and
child tags. Changed roots, foreign tags, duplicate IDs and awsspot are refused.

ProvisionJournal holds per-ID process/file locks and fsyncs checksummed requests,
config/AMI/network/token, state, costs and receipts. Restart re-describes tags and
reuses the exact token/parameters; corruption fails closed. Demo/AWS roots differ.
The job uses private per-ID lmfiles registries and aliases, confirmed lifecycle
stages, failed attempts and pending operations. Continuation reads registry records,
not the JSON inspection copies. See [record/runbook](../docs/PROVISIONING.md).

Costs include instance minimums, gp3 while stopped, optional IPv4 and ongoing
reminders; hard cap $0.25. This is not an AWS billing limit/background cleanup.
Stop/terminate remain available at an exhausted budget. The generated cloud-init
boothook appends every boot; the offline shell test runs it twice.

recipes/provision.lms accepts CONFIG/overrides and lifecycle operations. The
standalone example is generated from the library and source template, runs real
demo bindings plus released lmfiles, and plots actual confirmed stage counts.
Local test.sh is the gate. Linux x64 JVM/native fake gates and the full 126-example
gallery pass with compiler 0.2.420. Live proof still waits for the Lead grant/GO;
other platforms are qualified by their release lanes.

The gallery requires data/provision_job.count from lmfiles, independently of the
script's plot input data/provision-stages.dat. The example snapshots the authoritative
registry and writes its one-row count inside the lmfiles block. Missing artifact
diagnostics name the exact path and producer; native --run checks this contract.
The JVM job regression also requires this count, so PNG-only success cannot hide
a missing data artifact until the native gallery stage.
