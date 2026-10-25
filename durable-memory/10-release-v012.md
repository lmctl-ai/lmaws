# v0.1.2 released and verified

Release: https://github.com/lmctl-ai/lmaws/releases/tag/v0.1.2
Source: df5fea07de756b3e13114573792a99e086ebc838.
Main CI 40202485432 and tag CI 40203293427 both passed all five platforms;
the tag publication job succeeded. Every platform ran JVM/native CLI, schema,
cost/profile/memory checks, sixteen fake inventories, six fake lifecycles,
thirty gallery examples and the new fake-only comparison safety tests.

All five downloaded executables and SHA256SUMS match their published SHA-256
digests. Both Linux assets pass the dynamic glibc >=2.35 linkage allowlist.
All thirty native raw URLs ran from separate empty directories with an initially
empty shared tool cache and no lmaws on PATH. Every case used the exact released
v0.1.2 executable/hash, printed its cost and generated its PNG. See autorun-v012.json
and release-v012.json. Local native CLI, fake transport and gallery also passed.

The pinned comparison autorun was independently verified from an empty directory
and empty cache, including actual downloads of its Python runtime/verifier. It
reached lmcloud 0.1.9 initialization and recorded provider_download_failed with zero
leftovers. This is a known upstream failure, not a passing OpenTofu comparison.
See compare-autorun-v012.json, compare-init-results-v012.json and PROVIDER_TEST.md.
The @latest version-format failure is recorded separately; pinning v0.1.9 avoids
that bootstrap failure without changing lmcloud. The nullable optional-env bootstrap
and Windows fake-schema launcher regressions were fixed and tested before tagging.

READY FOR USER TEST, with known limitations explicit:
- 19 read-only native examples and S3 bucket/object passed live.
- Six other write/lifecycle creations were denied under lmaws: SQS twice, SSM,
  DynamoDB, SNS and Logs. Their attempted-request costs are retained; complete
  lifecycle costs remain price-table estimates. All seven were attempted once.
- Four IAM examples were skipped; no IAM, credential or profile changes were made,
  and no other identity was used.
- All 26 non-IAM OpenTofu attempts failed provider resolution before apply; four IAM
  comparisons skipped. Unsupported provider list/message operations are explicit gaps.

Current campaign price-table estimate: $0.00004640 including independent read-only
verification passes. One S3 bucket and its tiny object created, both deleted.
Native ledger sweeper [] and comparison state sweeper zero. All independent absence
checks use default; authorization errors never imply absence. No Cost Explorer call.
Native mutation guard allows only active profile lmaws; default is read-only. Public
CI remains fake-only without cloud credentials or OIDC. The unit tests mock provider
phases, including failure teardown, ownership/child checks and combined cost caps.

Exact local steps, profile selection, all URLs, scoped permission requirements and
sweepers are in docs/USER_TEST.md. To test a future fixed lmcloud build, the checkout
harness accepts --lmcloud /absolute/path/to/lmcloud; it never modifies that repo.
