# Default-profile S3 upload check

`recipes/check_s3_upload.lms` and import-only `recipes/lib/s3_upload.lms` separate offline document simulation from explicit live verification. The synthetic example is `examples/recipe_check_s3_upload.lms`; its image is synthetic and uses the existing plot style.

On t3wsl the default session permits PutObject/AbortMultipartUpload/ListMultipartUploadParts only for its own account, and explicitly denies S3 deletion, bucket creation/configuration and ACL writes. It can overwrite other own-account objects using other clients. `docs/PROFILES.md` records the narrow exception to generic write-profile rules.

Offline probes use PolicySimulator directly and print matching Sids; no IAM simulation API or upload is called. Accept a caller-supplied policy file, or an explicitly readable managed-policy ARN with private own-account context. No admin fallback. Document simulation does not include all effective policy layers.

The live controller uses lmaws for the exact tagged lmaws-s3check-<run> sandbox and cleanup; a separate explicit default client HEADs, conditionally PUTs one byte and verifies size/ETag. SDK guards keep ordinary default mutators blocked. Existing buckets require --allow-leave-object and leave the object; no outside bucket is created/deleted. The live key is always lmaws-s3check/<run>.txt. A denied default PUT never retries through lmaws.

Private atomic creation/ETag journals live under .lmaws-local/s3-upload-check; duplicates are refused. Cleanup checks the run/prefix/tag/ETag and uses conditional deletion; unknown cleanup is not zero. s3_upload_cleanup resumes only an acknowledged sandbox journal, never an explicit-existing-bucket journal. Live region is us-east-1; caps/price tables are shared with recipes.

Verified: all eight supplied-document probes; default upload and lmaws cleanup, size/ETag, final independent zero-leftover prefix audit. See evidence/s3-upload-check.json and docs/S3_UPLOAD_CHECK.md for measured timings and estimated costs. No admin, IAM/profile-file edits or live existing-bucket branch.

Recommendation: narrow resources to approved buckets/prefixes and require s3:if-none-match for object creation. AWS documents Null-based header enforcement and s3:ObjectCreationOperation multipart exceptions. Keep abort/list-parts permissions separate; do not apply proposed policy changes automatically.
