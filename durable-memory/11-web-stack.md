# Guarded web-stack integration

`Cloud.web_stack(run_id, domain, private_state_path)` opens a persistent `Web` handle. `step(operation, JSON)`, `status()`, `leftovers()`, and `down()` support the lmscript integration in lmweblab. Raw provider IDs stay in private state. Live mutations require `AWS_PROFILE=lmaws`, `LMAWS_LIVE=1`, us-east-1, the run namespace and exact ownership tags. State lives under `.lmweblab-local/`, uses a process lock and atomic writes, and must not be published.

Steps cover private S3/BPA/uploads, CloudFront OAC and tagged distributions, ACM DNS validation, scoped Route 53 alias/A/CNAME changes and bounded waits, and a public spot nano with caller `/32` HTTP ingress. The instance, disk, ENI and spot request are tagged; the server schedules shutdown with instance-initiated termination. Cleanup checks live ownership and performs a fresh inventory before declaring zero.

AWS requires a certificate covering every custom CloudFront alias, even for HTTP. Obtain and validate ACM before testing the alias with `allow-all`; the HTTPS phase changes the viewer policy to redirect. Distribution creation without an alias can precede ACM.

Local safety gates: `WebStackChecks`, `WebTransportChecks` and `scripts/test-web-http.py`. HTTP assertions in lmweblab use lmcurl; committed pictures contain synthetic fixtures. No live completion is claimed by these fake checks.

The local native gate also runs `scripts/test-web-native.py --host target/lmaws`: real native SDK calls go only to localhost fixtures, including foreign-tag and zero-cap refusal. The Linux linkage check permits only system glibc; the measured local native binary is approximately 94 MiB. JVM proxy request tests remain outside the native built-in self-test.

Certificate preparation may precede distribution creation; the distribution then receives the issued certificate and HTTP alias at creation, avoiding a second deployment wait. Spot creation retries only explicit capacity errors (at most twelve attempts/180 seconds) across public subnets in the same VPC and the two permitted nano architectures. Standard CPU-credit mode prevents surplus-credit charges. OAC deletion additionally requires the private creation nonce recorded in state, because OAC does not support run tags. DNS creation proofs are persisted before INSYNC polling.

`Cloud.web_find(run_id, domain)` reads provider state without the lifecycle file lock, so status works during deployment. HTTP suites reserve a bounded request/transfer estimate before dispatch, then record response counts and payload bounds; interrupted suites retain the admitted upper bound. Each cost ledger includes a `cost_web_snapshot` with the whole-run estimate and web price table.
