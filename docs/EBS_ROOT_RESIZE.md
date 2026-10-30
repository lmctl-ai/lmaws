# Guarded online EBS root growth

`Cloud.ebs_root_resize(spec_json, apply, human)` plans or requests growth of one
explicitly identified root gp3 volume. It does not stop/reboot an instance,
detach/replace a volume, alter performance/encryption, grow a guest filesystem,
or create IAM permissions. AWS calls use the Java SDK, never an AWS CLI subprocess.

The JSON spec accepts exactly `account`, `region`, `instance_id`, `volume_id`,
`from_gib`, and `to_gib`. Account and IDs must be literal values; region is currently
restricted to `us-east-1`. Sizes are whole GiB, target must exceed source and must
not exceed 16384 GiB. Both sizes describe the expected transition; this API cannot
shrink a disk. Keep account-specific specs in private administration repositories.

Live inspection requires `LMAWS_LIVE=1` with profile `default`, or a human-authorized
`admin` profile. Admin reads and writes require `AWS_PROFILE=admin`,
`LMAWS_ADMIN_GRANT=1`, the `human=true` argument, and a non-CI environment. Apply
additionally requires `LMAWS_APPLY=1` (or the host's `--apply` flag).
Normal EC2 provisioning and IAM mutation guards are unchanged.

Before a write, the host validates the STS account, backend region, running
instance, exact root mapping with `DeleteOnTermination=false`, gp3 volume,
single attached root-device mapping, in-use state, and expected current size.
The only mutating request is `ModifyVolume(VolumeId, Size)`. Target-size disks
skip that request. An existing modification toward the same target is reported
rather than reissued; conflicting or failed modifications are rejected.

The returned Row includes `instance_id`, `volume_id`, `current_gib` (`old_gib`
alias), `target_gib`, `changed`, `applied`, `modification_state` (`state` alias),
`ready`, and `region`. Values follow the SDK's normal string-valued Row contract.
`ready=true` means actual size equals the target and the modification is
optimizing/completed (or no modification is pending). Poll with `apply=false`
before growing the guest partition/filesystem. Request acceptance alone is not
proof that the new size is usable. The synthetic demo reports simulated sizes;
it never verifies a real disk. No request-cost cap limits persistent storage
charges: account for the extra GiB-month cost separately.

Test offline with `python3 scripts/test-ebs-root-resize.py` after building the
JAR. The test uses an empty credential configuration and a loopback HTTP server
for STS/EC2 protocol responses, including root/attachment/account/size checks,
pending-state retries, idempotence, and the exact size-only mutation request.
