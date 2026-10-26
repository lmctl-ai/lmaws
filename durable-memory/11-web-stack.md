# Guarded web-stack integration

`Cloud.web_stack(run_id, domain, private_state_path)` opens a persistent `Web` handle. `step(operation, JSON)`, `status()`, and `down()` support the lmscript integration in lmweblab. Raw provider IDs stay in private state. Live mutations require `AWS_PROFILE=lmaws`, `LMAWS_LIVE=1`, us-east-1, the run namespace and exact ownership tags. State lives under `.lmweblab-local/`, uses a process lock and atomic writes, and must not be published.

Steps cover private S3/BPA/uploads, CloudFront OAC and tagged distributions, ACM DNS validation, scoped Route 53 alias/A/CNAME changes and bounded waits, and a public spot nano with caller `/32` HTTP ingress. The instance, disk, ENI and spot request are tagged; the server schedules shutdown with instance-initiated termination. Cleanup checks live ownership and performs a fresh inventory before declaring zero.

AWS requires a certificate covering every custom CloudFront alias, even for HTTP. Obtain and validate ACM before testing the alias with `allow-all`; the HTTPS phase changes the viewer policy to redirect. Distribution creation without an alias can precede ACM.

Local safety gates: `WebStackChecks`, `WebTransportChecks` and `scripts/test-web-http.py`. HTTP assertions in lmweblab use lmcurl; committed pictures contain synthetic fixtures. No live completion is claimed by these fake checks.
