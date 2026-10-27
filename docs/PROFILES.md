# Which AWS profile do I need?

lmaws never uses the aws CLI and never picks credentials from the environment for writes: the
profile name decides what a run may do. Every recipe defaults to synthetic data, so the first row
needs no AWS account at all.

| You want to | Profile | Flags | Notes |
|---|---|---|---|
| See pictures, try recipes, read examples | none | (none) | Synthetic fixtures; no AWS calls, no credentials |
| Read-only inventory, audits, spend reports | `default` | `--live` | Describe/List/Get only; spend reports require `default` |
| Verify one conditional S3 upload | `default` for HEAD/PUT; `lmaws` controller for sandbox create/delete | `check_s3_upload.lms --policy-file FILE --live` | Own-account only, unique key, If-None-Match; existing bucket requires --allow-leave-object and leaves the object |
| Create and tear down service sandboxes (queue, topic, table, bucket, parameter, log group), cleanup by prefix | `lmaws` | `--live --apply` | Names `lmaws_<run>_...` / `lmaws-<run>-...`, tag `lmaws_test=<run>`, us-east-1 |
| Web and serverless scenarios (lmweblab) | `lmaws` | `--live --apply` | Run-owned resources only, us-east-1 |
| EC2 spot nano sandbox, latest AMI lookup | `lmaws-ec2` | `--live` (`--apply` for the sandbox) | t4g.nano/t3.nano, 8 GiB gp3, no public IPv4, us-east-1 |
| Create or change `lmaws_` IAM policies and Lambda roles | `admin` | `--live --apply` and `LMAWS_ADMIN_GRANT=1` | Only the grant recipes accept it; every other write refuses `admin` |

Rules enforced by the host (not only by IAM):

- Writes need `LMAWS_LIVE=1` (recipes set it from `--live`) and one of the profiles above; any
  other profile name is read-only. `admin` is refused for every non-IAM mutation.
- `--credential-process <mode>` (modes `default`, `lmaws`, `lmaws-ec2`, `lmaws-web`) issues a
  scoped federated session from the explicit static `admin` profile only; ambient credentials
  (environment variables, SSO, instance metadata) are ignored. Tokens are cached `0600` until
  five minutes before expiry.
- CI never gets live credentials: live AWS is refused when `CI=true`; tests use loopback fakes.

Check your setup without changing anything: `lmctl recipes/session_doctor.lms --live` (synthetic
without `--live`). See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the common error messages.

The t3wsl default federated session has an additional own-account S3 upload allowance: PutObject, AbortMultipartUpload and ListMultipartUploadParts, conditioned on s3:ResourceAccount. It explicitly denies Delete*, CreateBucket, PutBucket* and PutObjectAcl. It cannot clean up its uploads. This is not general default-profile write support: other mutators retain their lmaws/lmaws-ec2 guards. The upload-check backend uses separate, explicit profile clients and keeps default out of deletion paths. [Procedure, private journal and policy recommendation](S3_UPLOAD_CHECK.md).
