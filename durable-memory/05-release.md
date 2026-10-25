# v0.1.0 release verification

[v0.1.0](https://github.com/lmctl-ai/lmaws/releases/tag/v0.1.0) is public and latest.
Tag commit: 530923e1e174c57e940bfca3f4080aedac8c74f6.
Engine commit: 9fed240c4d20cbd0507a2d8c457d0b82c748f8f7; subsequent changes are documentation/proof.

Both [main CI](https://github.com/lmctl-ai/lmaws/actions/runs/40157706937) and
[tag CI](https://github.com/lmctl-ai/lmaws/actions/runs/40158943726) are green across
Linux x64/arm64, macOS x64/arm64 and Windows x64. The tag publication job is green.
Every platform checks JVM and native CLI/schema/notices, eight SDK regression groups,
six offline sandbox lifecycle checks, 16 inventories and six tagged write lifecycles
through real SDK transports to fake endpoints, paging, failure teardown, AWS error
redaction and 25 illustrated examples. Linux verifies dynamic glibc only, symbol
versions at most 2.35, and memory failure at 64 MiB and the default budget inside a
6 GiB address-space ceiling. Public CI uses no AWS credentials.

Release assets are five native executables plus SHA256SUMS. All downloaded hashes
match the checksum file and GitHub digests. Linux x64 is 76,089,608 bytes; its
embedded schema/notices match the source and its independent fake SDK suite passes.
Both Linux ELF dependency/symbol checks pass. See release-v010.json for all sizes
and hashes and main-ci-v010.json for the platform check links.

All 25 README raw URLs were autorun from separate empty working directories, with
no lmaws on PATH and an initially empty shared tool cache. The first run installed
the published v0.1.0 executable; every case verified that exact version and SHA256
and generated its own 900x560 PNG. No repository-relative input files were needed.
See autorun-v010.json. Gallery images are from the examples, not substitute renders.

The approved default-profile native live smoke in us-east-1 created only one SQS
queue and one Standard-tier SSM String parameter. Deliberate script failure invoked
teardown; both resources were independently verified absent. No recovery deletes
were needed and no real test resource remains. See live-v010.json. A CI-built CE
25.0.2 binary additionally passed real default-profile identity/S3 TLS reads while
creating no resources (ci-linux-readonly-v010.json).

## Distribution boundaries

- Linux requires system glibc >= 2.35; all other linked components are static.
- Windows requires the Microsoft Visual C++ runtime.
- macOS Intel uses GraalVM CE 25.0.1, the final upstream Intel build; other release
  lanes use CE 25.0.2. Toolchain source/notice links are embedded.
- v0.1.0 intentionally exposes six run-owned write kinds. Compute/network/IAM/ECS,
  Lambda, DNS and secret-value operations remain metadata-only or unavailable.
- The sweeper is always dry-run and lists old ledger candidates. Failed/partial
  operations retain records for inspection; it never deletes arbitrary resources.
- No known release-blocking issue remains. Future API expansion must retain
  ownership, redaction and default fake-CI guarantees.
