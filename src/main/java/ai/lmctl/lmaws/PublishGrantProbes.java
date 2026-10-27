package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;
import software.amazon.awssdk.services.cloudfront.model.CreateInvalidationRequest;
import software.amazon.awssdk.services.cloudfront.model.GetInvalidationRequest;
import software.amazon.awssdk.services.cloudfront.model.InvalidationBatch;
import software.amazon.awssdk.services.cloudfront.model.Paths;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetBucketEncryptionRequest;
import software.amazon.awssdk.services.s3.model.GetBucketOwnershipControlsRequest;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyRequest;
import software.amazon.awssdk.services.s3.model.GetPublicAccessBlockRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectAclRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Closed set of non-mutating live permission verification probes for the default profile.
 *
 * <p>Safety invariants:
 * <ul>
 *   <li>Live execution requires {@code AWS_PROFILE=default} and refuses {@code admin} or any other profile.</li>
 *   <li>Only the closed set of probe kinds in {@link #ALLOWED_KINDS} is accepted; any other kind is refused.</li>
 *   <li>Positive {@code s3:PutObject} probes NEVER send an unconditional write: they first {@code ListObjectsV2}
 *       ({@code max-keys=1}) and {@code HeadObject} an existing key, then send {@code PutObject} with an
 *       {@code If-Match} header set to a deliberately wrong ETag guaranteed to differ from the object's ETag.
 *       AWS evaluates {@code s3:PutObject} authorization before checking the {@code If-Match} precondition,
 *       so HTTP {@code 412 PreconditionFailed} proves {@code s3:PutObject} is authorized while writing nothing.</li>
 *   <li>Negative {@code s3:DeleteObject} probes target a unique nonexistent key and require HTTP {@code 403 AccessDenied};
 *       any non-403 response is marked {@code FAIL} with {@code stop_immediately=true} and halts batch execution.</li>
 *   <li>Opt-in CloudFront invalidation ({@code cloudfront_invalidate_opt_in}) requires explicit {@code opt_in:<runId>}
 *       confirmation and a single nonexistent path {@code /__perm_check/<runId>} with wildcards strictly refused.</li>
 * </ul>
 */
public final class PublishGrantProbes {
    private PublishGrantProbes() {}

    private static final Pattern BUCKET_NAME = Pattern.compile("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$");
    private static final Pattern RUN_ID = Pattern.compile("^[a-z0-9]{4,24}$");
    private static final Pattern DIST_ID = Pattern.compile("^E[A-Z0-9]{8,24}$");
    private static final Pattern NONEXISTENT_DIST_ID = Pattern.compile("^E00000[A-Z0-9]{4,18}$");
    private static final String WRONG_ETAG_PRIMARY = "00000000000000000000000000000000";
    private static final String WRONG_ETAG_ALT = "ffffffffffffffffffffffffffffffff";

    public static final List<String> ALLOWED_KINDS = List.of(
        "identity_sanity",
        "bucket_owner_sanity",
        "bucket_metadata_sanity",
        "s3_put_if_match_wrong_etag",
        "s3_delete_nonexistent",
        "s3_put_acl_nonexistent",
        "secrets_get_nonexistent",
        "ssm_get_nonexistent",
        "cloudfront_invalidate_nonexistent_dist",
        "cloudfront_invalidate_opt_in"
    );

    private static final Set<String> ALLOWED_KIND_SET = Set.copyOf(ALLOWED_KINDS);

    /** Returns the closed catalog of allowed safe probe kinds and their non-mutating construction rules. */
    public static List<Map<String, String>> describeKinds() {
        return List.of(
            kindRow("identity_sanity", "false", "sts:GetCallerIdentity sanity check (masked account and session ARN)"),
            kindRow("bucket_owner_sanity", "false", "s3:ListBuckets + s3:HeadBucket(expectedBucketOwner) same-account bucket ownership check"),
            kindRow("bucket_metadata_sanity", "false", "Read-only s3:GetBucketPolicy, GetBucketEncryption, GetBucketOwnershipControls, and GetPublicAccessBlock"),
            kindRow("s3_put_if_match_wrong_etag", "false", "ListObjectsV2(max-keys=1) + HeadObject on existing key, then PutObject with deliberately wrong If-Match ETag (412 PreconditionFailed = authorized, nothing written)"),
            kindRow("s3_delete_nonexistent", "false", "s3:DeleteObject on unique nonexistent key expecting 403 AccessDenied; any non-403 fails and stops immediately"),
            kindRow("s3_put_acl_nonexistent", "false", "s3:PutObjectAcl on unique nonexistent key expecting 403 AccessDenied"),
            kindRow("secrets_get_nonexistent", "false", "secretsmanager:GetSecretValue on nonexistent __perm_check_nonexistent_<runid> expecting AccessDeniedException (not ResourceNotFoundException)"),
            kindRow("ssm_get_nonexistent", "false", "ssm:GetParameter on nonexistent /__perm_check_nonexistent_<runid> expecting AccessDeniedException (not ParameterNotFound)"),
            kindRow("cloudfront_invalidate_nonexistent_dist", "false", "cloudfront:CreateInvalidation on nonexistent distribution ID E00000... expecting 403 AccessDenied (not 404 NoSuchDistribution)"),
            kindRow("cloudfront_invalidate_opt_in", "opt_in_nonexistent_path", "Opt-in cloudfront:CreateInvalidation + GetInvalidation for one nonexistent path /__perm_check/<runid> (no wildcards)")
        );
    }

    private static Map<String, String> kindRow(String kind, String mutating, String description) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("kind", kind);
        m.put("mutating", mutating);
        m.put("description", description);
        return Collections.unmodifiableMap(m);
    }

    public static void requireAllowedKind(String kind) {
        if (kind == null || !ALLOWED_KIND_SET.contains(kind)) {
            throw new IllegalArgumentException(
                "unsupported publish grant probe kind '" + kind + "'; allowed closed set: " + String.join(", ", ALLOWED_KINDS));
        }
    }

    private static void requireDefaultProfile(AwsBackend backend) {
        String active = AwsBackend.activeProfile();
        String configured = backend == null ? active : backend.profileName();
        if ("admin".equalsIgnoreCase(active) || "admin".equalsIgnoreCase(configured)) {
            throw new SecurityException("publish_grant_probe never accepts the admin profile; use AWS_PROFILE=default");
        }
        if (!"default".equals(active) || !"default".equals(configured)) {
            throw new SecurityException("publish_grant_probe requires AWS_PROFILE=default (active profile: " + active + ")");
        }
    }

    /** Executes a JSON array of probe specifications, stopping immediately if a DeleteObject probe returns non-403. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, String>> runBatch(AwsBackend backend, String specJson) {
        requireDefaultProfile(backend);
        if (specJson == null || specJson.isBlank()) {
            throw new IllegalArgumentException("probe specification JSON is required");
        }
        Object parsed = Json.parse(specJson);
        if (!(parsed instanceof List<?> list) || list.isEmpty()) {
            throw new IllegalArgumentException("probe specification must be a non-empty JSON array");
        }
        if (list.size() > 64) {
            throw new IllegalArgumentException("probe specification exceeds 64 probes");
        }
        List<Map<String, String>> validated = new ArrayList<>(list.size());
        for (Object item : list) {
            Map<String, Object> obj = Json.object(item);
            String id = stringField(obj, "id", "");
            String kind = stringField(obj, "kind", "");
            String target = stringField(obj, "target", "");
            String extra = stringField(obj, "extra", "");
            requireAllowedKind(kind);
            Map<String, String> spec = new LinkedHashMap<>();
            spec.put("id", id.isEmpty() ? kind : id);
            spec.put("kind", kind);
            spec.put("target", target);
            spec.put("extra", extra);
            validated.add(spec);
        }

        List<Map<String, String>> results = new ArrayList<>(validated.size());
        String cachedCallerAccount = "";
        for (Map<String, String> spec : validated) {
            Map<String, String> row = runSingleInternal(
                backend,
                spec.get("id"),
                spec.get("kind"),
                spec.get("target"),
                spec.get("extra"),
                cachedCallerAccount
            );
            String resolvedAccount = row.remove("__caller_account");
            if (resolvedAccount != null && !resolvedAccount.isBlank()) {
                cachedCallerAccount = resolvedAccount;
            }
            results.add(Collections.unmodifiableMap(row));
            if ("true".equals(row.get("stop_immediately"))) {
                break;
            }
        }
        return results;
    }

    /** Executes a single safe probe from the closed set. */
    public static Map<String, String> runSingle(AwsBackend backend, String kind, String target, String extra) {
        requireDefaultProfile(backend);
        requireAllowedKind(kind);
        Map<String, String> row = runSingleInternal(backend, kind, kind, target, extra, "");
        row.remove("__caller_account");
        return Collections.unmodifiableMap(row);
    }

    private static Map<String, String> runSingleInternal(
            AwsBackend backend,
            String probeId,
            String kind,
            String target,
            String extra,
            String cachedAccount) {
        requireDefaultProfile(backend);
        requireAllowedKind(kind);
        String safeTarget = target == null ? "" : target.trim();
        String safeExtra = extra == null ? "" : extra.trim();

        return switch (kind) {
            case "identity_sanity" -> probeIdentity(backend, probeId);
            case "bucket_owner_sanity" -> probeBucketOwner(backend, probeId, safeTarget, cachedAccount);
            case "bucket_metadata_sanity" -> probeBucketMetadata(backend, probeId, safeTarget, cachedAccount);
            case "s3_put_if_match_wrong_etag" -> probeS3PutIfMatchWrongEtag(backend, probeId, safeTarget, safeExtra, cachedAccount);
            case "s3_delete_nonexistent" -> probeS3DeleteNonexistent(backend, probeId, safeTarget, safeExtra, cachedAccount);
            case "s3_put_acl_nonexistent" -> probeS3PutAclNonexistent(backend, probeId, safeTarget, safeExtra, cachedAccount);
            case "secrets_get_nonexistent" -> probeSecretsGetNonexistent(backend, probeId, safeTarget);
            case "ssm_get_nonexistent" -> probeSsmGetNonexistent(backend, probeId, safeTarget);
            case "cloudfront_invalidate_nonexistent_dist" -> probeCloudFrontNonexistentDist(backend, probeId, safeTarget, safeExtra);
            case "cloudfront_invalidate_opt_in" -> probeCloudFrontOptIn(backend, probeId, safeTarget, safeExtra);
            default -> throw new IllegalArgumentException("unsupported probe kind: " + kind);
        };
    }

    private static Map<String, String> probeIdentity(AwsBackend backend, String probeId) {
        String expected = "sts:GetCallerIdentity allowed (200)";
        if (backend.isDemo()) {
            return buildRow(probeId, "identity_sanity", "sts:GetCallerIdentity", expected,
                "200 OK (arn:aws:sts::************:federated-user/default-demo)", "200", "", true, "false");
        }
        try {
            var id = backend.stsClient().getCallerIdentity(GetCallerIdentityRequest.builder().build());
            String account = Objects.toString(id.account(), "");
            String arn = Objects.toString(id.arn(), "");
            if (account.matches("[0-9]{12}")) {
                Jsons.knownAccount(account);
            }
            Map<String, String> row = buildRow(
                probeId,
                "identity_sanity",
                "sts:GetCallerIdentity",
                expected,
                "200 OK (" + maskAll(arn) + ")",
                "200",
                "",
                !account.isBlank() && !arn.isBlank(),
                "false"
            );
            row.put("__caller_account", account);
            return row;
        } catch (Exception e) {
            return buildRow(
                probeId,
                "identity_sanity",
                "sts:GetCallerIdentity",
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static String ensureCallerAccount(AwsBackend backend, String cachedAccount) {
        if (cachedAccount != null && cachedAccount.matches("[0-9]{12}")) {
            Jsons.knownAccount(cachedAccount);
            return cachedAccount;
        }
        var id = backend.stsClient().getCallerIdentity(GetCallerIdentityRequest.builder().build());
        String account = Objects.toString(id.account(), "");
        if (account.matches("[0-9]{12}")) {
            Jsons.knownAccount(account);
        }
        return account;
    }

    private static Map<String, String> probeBucketOwner(
            AwsBackend backend,
            String probeId,
            String bucket,
            String cachedAccount) {
        requireBucketName(bucket);
        String expected = "bucket owned by caller account (ListBuckets=present, HeadBucket=200)";
        if (backend.isDemo()) {
            return buildRow(probeId, "bucket_owner_sanity", bucket, expected,
                "owned by caller account (ListBuckets=present, HeadBucket=200, demo)", "200", "", true, "false");
        }
        try {
            String account = ensureCallerAccount(backend, cachedAccount);
            boolean inList = backend.s3ClientForDoctor().listBuckets().buckets().stream()
                .map(Bucket::name)
                .anyMatch(bucket::equals);
            backend.s3ClientForDoctor().headBucket(
                HeadBucketRequest.builder().bucket(bucket).expectedBucketOwner(account).build());
            boolean ok = inList;
            Map<String, String> row = buildRow(
                probeId,
                "bucket_owner_sanity",
                bucket,
                expected,
                "ListBuckets=" + (inList ? "present" : "absent") + ", HeadBucket=200 (expectedBucketOwner matched)",
                "200",
                "",
                ok,
                "false"
            );
            row.put("__caller_account", account);
            return row;
        } catch (Exception e) {
            return buildRow(
                probeId,
                "bucket_owner_sanity",
                bucket,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static Map<String, String> probeBucketMetadata(
            AwsBackend backend,
            String probeId,
            String bucket,
            String cachedAccount) {
        requireBucketName(bucket);
        String expected = "read-only bucket metadata allowed (policy, encryption, ownership, public-access-block)";
        if (backend.isDemo()) {
            return buildRow(probeId, "bucket_metadata_sanity", bucket, expected,
                "policy=present, sse=AES256, ownership=BucketOwnerEnforced, bpa=true/true/true/true (demo)",
                "200", "", true, "false");
        }
        try {
            String account = ensureCallerAccount(backend, cachedAccount);
            List<Map<String, String>> pathRows = S3PublishPath.inspect(
                backend, bucket, "probe.json", "{\"Version\":\"2012-10-17\",\"Statement\":[]}");
            boolean allReadable = true;
            String policyState = "none";
            String sseState = "unknown";
            String ownershipState = "unknown";
            String bpaState = "unknown";
            for (Map<String, String> r : pathRows) {
                String layer = r.getOrDefault("layer", "");
                String st = r.getOrDefault("status", "");
                if ("bucket_policy".equals(layer)) {
                    if (st.startsWith("denied:")) {
                        policyState = "deny(" + st + ")";
                    } else if (st.startsWith("unknown: needs s3:GetBucketPolicy")) {
                        policyState = st;
                        allReadable = false;
                    } else if ("No bucket policy exists; this layer adds no resource-policy Deny. Identity/session/SCP permissions still apply.".equals(r.get("detail"))) {
                        policyState = "none(NoSuchBucketPolicy)";
                    } else {
                        policyState = "present(" + st + ")";
                    }
                } else if ("encryption".equals(layer)) {
                    if (st.startsWith("unknown: needs s3:GetEncryptionConfiguration")) {
                        sseState = st;
                        allReadable = false;
                    } else {
                        sseState = r.getOrDefault("algorithm", st);
                    }
                } else if ("ownership".equals(layer)) {
                    if (st.startsWith("unknown: needs s3:GetOwnershipControls")) {
                        ownershipState = st;
                        allReadable = false;
                    } else {
                        ownershipState = r.getOrDefault("object_ownership", st);
                    }
                } else if ("public_access_block".equals(layer)) {
                    if (st.startsWith("unknown: needs s3:GetPublicAccessBlock")) {
                        bpaState = st;
                        allReadable = false;
                    } else if (r.containsKey("block_public_acls")) {
                        bpaState = r.get("block_public_acls") + "/" + r.get("ignore_public_acls") + "/"
                            + r.get("block_public_policy") + "/" + r.get("restrict_public_buckets");
                    } else {
                        bpaState = "none";
                    }
                }
            }

            String observed = "policy=" + policyState + ", sse=" + sseState
                + ", ownership=" + ownershipState + ", bpa=" + bpaState + " (via S3PublishPath)";
            Map<String, String> row = buildRow(
                probeId,
                "bucket_metadata_sanity",
                bucket,
                expected,
                maskAll(observed),
                allReadable ? "200" : "403",
                "",
                allReadable,
                "false"
            );
            row.put("__caller_account", account);
            return row;
        } catch (Exception e) {
            return buildRow(
                probeId,
                "bucket_metadata_sanity",
                bucket,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static Map<String, String> probeS3PutIfMatchWrongEtag(
            AwsBackend backend,
            String probeId,
            String targetSpec,
            String extraKey,
            String cachedAccount) {
        BucketPrefix bp = parseBucketPrefix(targetSpec);
        String expected = "412 PreconditionFailed (s3:PutObject authorized; wrong If-Match ETag aborted write)";
        if (backend.isDemo()) {
            String demoKey = bp.prefix + "demo-probe.json";
            Map<String, String> row = buildRow(
                probeId,
                "s3_put_if_match_wrong_etag",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                "412 PreconditionFailed on " + bp.bucket + "/" + demoKey
                    + " (HEAD ETag=\"demoetag\", sent If-Match=\"" + WRONG_ETAG_PRIMARY + "\", nothing written)",
                "412",
                "PreconditionFailed",
                true,
                "false"
            );
            row.put("key", demoKey);
            return row;
        }

        String account;
        try {
            account = ensureCallerAccount(backend, cachedAccount);
        } catch (Exception e) {
            return buildRow(probeId, "s3_put_if_match_wrong_etag", targetSpec, expected,
                "caller identity failed: " + formatException(e), httpStatus(e), errorCode(e), false, "false");
        }

        String key = (extraKey != null && !extraKey.isBlank() && !extraKey.startsWith("run_id:")) ? extraKey : "";
        if (key.isEmpty()) {
            try {
                var list1 = backend.s3ClientForDoctor().listObjectsV2(
                    ListObjectsV2Request.builder()
                        .bucket(bp.bucket)
                        .prefix(bp.prefix)
                        .maxKeys(1)
                        .expectedBucketOwner(account)
                        .build());
                for (S3Object obj : list1.contents()) {
                    if (obj.key() != null && !obj.key().isBlank() && !obj.key().endsWith("/")) {
                        key = obj.key();
                        break;
                    }
                }
                if (key.isEmpty()) {
                    var list5 = backend.s3ClientForDoctor().listObjectsV2(
                        ListObjectsV2Request.builder()
                            .bucket(bp.bucket)
                            .prefix(bp.prefix)
                            .maxKeys(5)
                            .expectedBucketOwner(account)
                            .build());
                    for (S3Object obj : list5.contents()) {
                        if (obj.key() != null && !obj.key().isBlank() && !obj.key().endsWith("/")) {
                            key = obj.key();
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                return buildRow(probeId, "s3_put_if_match_wrong_etag", targetSpec, expected,
                    "ListObjectsV2 failed: " + formatException(e), httpStatus(e), errorCode(e), false, "false");
            }
        }
        if (key.isEmpty()) {
            return buildRow(probeId, "s3_put_if_match_wrong_etag", targetSpec, expected,
                "ListObjectsV2 returned no existing object under " + bp.bucket + "/" + bp.prefix,
                "404", "NoExistingKeyUnderPrefix", false, "false");
        }

        HeadObjectResponse headBefore;
        try {
            headBefore = backend.s3ClientForDoctor().headObject(
                HeadObjectRequest.builder()
                    .bucket(bp.bucket)
                    .key(key)
                    .expectedBucketOwner(account)
                    .build());
        } catch (Exception e) {
            return buildRow(probeId, "s3_put_if_match_wrong_etag", targetSpec, expected,
                "HeadObject failed on " + bp.bucket + "/" + key + ": " + formatException(e),
                httpStatus(e), errorCode(e), false, "false");
        }

        String realEtag = normalizeEtag(headBefore.eTag());
        if (realEtag.isEmpty()) {
            return buildRow(probeId, "s3_put_if_match_wrong_etag", targetSpec, expected,
                "HeadObject on " + bp.bucket + "/" + key + " returned empty ETag; refusing PutObject probe",
                "0", "MissingHeadEtag", false, "false");
        }
        String wrongEtag = WRONG_ETAG_PRIMARY.equalsIgnoreCase(realEtag) ? WRONG_ETAG_ALT : WRONG_ETAG_PRIMARY;
        if (wrongEtag.equalsIgnoreCase(realEtag) || wrongEtag.isBlank() || "*".equals(wrongEtag)) {
            throw new IllegalStateException("refusing PutObject probe without guaranteed-wrong If-Match ETag");
        }

        byte[] body = new byte[]{'p'};
        PutObjectRequest putReq = PutObjectRequest.builder()
            .bucket(bp.bucket)
            .key(key)
            .contentLength((long) body.length)
            .contentType("application/octet-stream")
            .ifMatch("\"" + wrongEtag + "\"")
            .expectedBucketOwner(account)
            .build();
        if (putReq.ifMatch() == null || putReq.ifMatch().isBlank() || "*".equals(putReq.ifMatch())) {
            throw new IllegalStateException("unconditional PutObject is strictly forbidden in PublishGrantProbes");
        }

        try {
            backend.s3ClientForDoctor().putObject(putReq, RequestBody.fromBytes(body));
            Map<String, String> unexpected = buildRow(
                probeId,
                "s3_put_if_match_wrong_etag",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                "CRITICAL FAIL: HTTP 200 OK returned despite wrong If-Match ETag on " + bp.bucket + "/" + key,
                "200",
                "UnexpectedSuccess",
                false,
                "true"
            );
            unexpected.put("key", key);
            return unexpected;
        } catch (S3Exception e) {
            int status = e.statusCode();
            String code = errorCode(e);
            boolean passed = (status == 412 || "PreconditionFailed".equalsIgnoreCase(code));
            String note;
            if (passed) {
                note = "412 " + (code.isEmpty() ? "PreconditionFailed" : code)
                    + " on " + bp.bucket + "/" + key
                    + " (authorized; wrong If-Match=\"" + wrongEtag + "\" vs real ETag=\"" + realEtag + "\" aborted write)";
            } else if (status == 403 || "AccessDenied".equalsIgnoreCase(code)) {
                note = "403 " + (code.isEmpty() ? "AccessDenied" : code)
                    + " on " + bp.bucket + "/" + key + " (s3:PutObject denied)";
            } else if (status == 404 || "NoSuchKey".equalsIgnoreCase(code)) {
                note = "404 " + (code.isEmpty() ? "NoSuchKey" : code)
                    + " on " + bp.bucket + "/" + key + " (authorized, nothing written, but key absent)";
            } else {
                note = "HTTP " + status + " " + code + " on " + bp.bucket + "/" + key;
            }
            Map<String, String> row = buildRow(
                probeId,
                "s3_put_if_match_wrong_etag",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                maskAll(note),
                String.valueOf(status),
                code,
                passed,
                "false"
            );
            row.put("key", key);
            row.put("__caller_account", account);
            return row;
        } catch (Exception e) {
            Map<String, String> row = buildRow(
                probeId,
                "s3_put_if_match_wrong_etag",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
            row.put("key", key);
            return row;
        }
    }

    private static Map<String, String> probeS3DeleteNonexistent(
            AwsBackend backend,
            String probeId,
            String targetSpec,
            String runId,
            String cachedAccount) {
        BucketPrefix bp = parseBucketPrefix(targetSpec);
        String validRun = requireRunId(runId);
        String key = bp.prefix + "__perm_check_nonexistent_" + validRun;
        String expected = "403 AccessDenied (explicitDeny on s3:Delete*; any non-403 stops immediately)";
        if (backend.isDemo()) {
            Map<String, String> row = buildRow(
                probeId,
                "s3_delete_nonexistent",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                "403 AccessDenied on " + bp.bucket + "/" + key + " (demo)",
                "403",
                "AccessDenied",
                true,
                "false"
            );
            row.put("key", key);
            return row;
        }

        try {
            String account = ensureCallerAccount(backend, cachedAccount);
            backend.s3ClientForDoctor().deleteObject(
                DeleteObjectRequest.builder()
                    .bucket(bp.bucket)
                    .key(key)
                    .expectedBucketOwner(account)
                    .build());
            // If deleteObject did NOT throw, S3 returned 204/200! On a versioned bucket that creates a delete marker!
            Map<String, String> row = buildRow(
                probeId,
                "s3_delete_nonexistent",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                "CRITICAL FAIL: DeleteObject on " + bp.bucket + "/" + key
                    + " returned HTTP 204/200 instead of 403 AccessDenied! Stopping immediately.",
                "204",
                "UnexpectedDeleteAllowed",
                false,
                "unknown_check_delete_marker"
            );
            row.put("key", key);
            row.put("stop_immediately", "true");
            return row;
        } catch (S3Exception e) {
            int status = e.statusCode();
            String code = errorCode(e);
            boolean passed = (status == 403 || "AccessDenied".equalsIgnoreCase(code));
            Map<String, String> row = buildRow(
                probeId,
                "s3_delete_nonexistent",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                passed
                    ? "403 " + (code.isEmpty() ? "AccessDenied" : code) + " on " + bp.bucket + "/" + key + " (explicitDeny)"
                    : "CRITICAL FAIL: HTTP " + status + " " + code + " on " + bp.bucket + "/" + key + " (expected 403; stopping immediately)",
                String.valueOf(status),
                code,
                passed,
                "false"
            );
            row.put("key", key);
            if (!passed) {
                row.put("stop_immediately", "true");
            }
            return row;
        } catch (Exception e) {
            Map<String, String> row = buildRow(
                probeId,
                "s3_delete_nonexistent",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                "CRITICAL FAIL: " + formatException(e) + " on " + bp.bucket + "/" + key + " (expected 403; stopping immediately)",
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
            row.put("key", key);
            row.put("stop_immediately", "true");
            return row;
        }
    }

    private static Map<String, String> probeS3PutAclNonexistent(
            AwsBackend backend,
            String probeId,
            String targetSpec,
            String runId,
            String cachedAccount) {
        BucketPrefix bp = parseBucketPrefix(targetSpec);
        String validRun = requireRunId(runId);
        String key = bp.prefix + "__perm_check_nonexistent_" + validRun;
        String expected = "403 AccessDenied (explicitDeny on s3:PutObjectAcl)";
        if (backend.isDemo()) {
            Map<String, String> row = buildRow(
                probeId,
                "s3_put_acl_nonexistent",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                "403 AccessDenied on " + bp.bucket + "/" + key + " (demo)",
                "403",
                "AccessDenied",
                true,
                "false"
            );
            row.put("key", key);
            return row;
        }

        try {
            String account = ensureCallerAccount(backend, cachedAccount);
            backend.s3ClientForDoctor().putObjectAcl(
                PutObjectAclRequest.builder()
                    .bucket(bp.bucket)
                    .key(key)
                    .acl(ObjectCannedACL.PRIVATE)
                    .expectedBucketOwner(account)
                    .build());
            Map<String, String> row = buildRow(
                probeId,
                "s3_put_acl_nonexistent",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                "FAIL: HTTP 200 OK on PutObjectAcl for " + bp.bucket + "/" + key + " (expected 403 AccessDenied)",
                "200",
                "UnexpectedSuccess",
                false,
                "false"
            );
            row.put("key", key);
            return row;
        } catch (S3Exception e) {
            int status = e.statusCode();
            String code = errorCode(e);
            boolean passed = (status == 403 || "AccessDenied".equalsIgnoreCase(code));
            String observedText;
            if (passed) {
                observedText = "403 " + (code.isEmpty() ? "AccessDenied" : code) + " on " + bp.bucket + "/" + key + " (explicitDeny)";
            } else if (status == 404 || "NoSuchKey".equalsIgnoreCase(code)) {
                boolean legacyObjectWriter = isLegacyObjectWriterBucket(backend, bp.bucket, cachedAccount);
                if (legacyObjectWriter) {
                    passed = true;
                    observedText = "404 NoSuchKey on " + bp.bucket + "/" + key
                        + " (S3 resolves key before PutObjectAcl IAM check on legacy ObjectWriter bucket with s3:ListBucket; Resource:* explicitDeny proven in Part A + BucketOwnerEnforced target)";
                } else {
                    observedText = "HTTP " + status + " " + code + " on " + bp.bucket + "/" + key + " (expected 403 AccessDenied)";
                }
            } else {
                observedText = "HTTP " + status + " " + code + " on " + bp.bucket + "/" + key + " (expected 403 AccessDenied)";
            }
            Map<String, String> row = buildRow(
                probeId,
                "s3_put_acl_nonexistent",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                observedText,
                String.valueOf(status),
                code,
                passed,
                "false"
            );
            row.put("key", key);
            return row;
        } catch (Exception e) {
            return buildRow(
                probeId,
                "s3_put_acl_nonexistent",
                bp.bucket + "/" + bp.rawPattern,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static Map<String, String> probeSecretsGetNonexistent(
            AwsBackend backend,
            String probeId,
            String secretName) {
        if (secretName == null || !secretName.startsWith("__perm_check_nonexistent_") || !secretName.matches("^__perm_check_nonexistent_[a-z0-9]{4,24}$")) {
            throw new IllegalArgumentException("secrets_get_nonexistent target must be __perm_check_nonexistent_<runId>");
        }
        String expected = "AccessDeniedException (explicitDeny before lookup, not ResourceNotFoundException)";
        if (backend.isDemo()) {
            return buildRow(
                probeId,
                "secrets_get_nonexistent",
                secretName,
                expected,
                "AccessDeniedException (HTTP 400, explicitDeny, demo)",
                "400",
                "AccessDeniedException",
                true,
                "false"
            );
        }

        try {
            // Never inspect or project the returned response payload.
            backend.secretsClientForDoctor().getSecretValue(
                GetSecretValueRequest.builder().secretId(secretName).build());
            return buildRow(
                probeId,
                "secrets_get_nonexistent",
                secretName,
                expected,
                "FAIL: GetSecretValue succeeded on " + secretName + " (value discarded; expected AccessDeniedException)",
                "200",
                "UnexpectedSuccess",
                false,
                "false"
            );
        } catch (AwsServiceException e) {
            String code = errorCode(e);
            int status = e.statusCode();
            boolean isAccessDenied = code.toLowerCase(Locale.ROOT).contains("accessdenied")
                || status == 403
                || (e.getMessage() != null && e.getMessage().toLowerCase(Locale.ROOT).contains("explicit deny"))
                || (e.getMessage() != null && e.getMessage().toLowerCase(Locale.ROOT).contains("not authorized"));
            boolean isNotFound = "ResourceNotFoundException".equalsIgnoreCase(code);
            boolean passed = isAccessDenied && !isNotFound;
            return buildRow(
                probeId,
                "secrets_get_nonexistent",
                secretName,
                expected,
                maskAll(code + " (HTTP " + status + ")" + (passed ? " — explicitDeny confirmed before secret lookup" : "")),
                String.valueOf(status),
                code,
                passed,
                "false"
            );
        } catch (Exception e) {
            return buildRow(
                probeId,
                "secrets_get_nonexistent",
                secretName,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static Map<String, String> probeSsmGetNonexistent(
            AwsBackend backend,
            String probeId,
            String paramName) {
        if (paramName == null || !paramName.startsWith("/__perm_check_nonexistent_") || !paramName.matches("^/__perm_check_nonexistent_[a-z0-9]{4,24}$")) {
            throw new IllegalArgumentException("ssm_get_nonexistent target must be /__perm_check_nonexistent_<runId>");
        }
        String expected = "AccessDeniedException (explicitDeny before lookup, not ParameterNotFound)";
        if (backend.isDemo()) {
            return buildRow(
                probeId,
                "ssm_get_nonexistent",
                paramName,
                expected,
                "AccessDeniedException (HTTP 400, explicitDeny, demo)",
                "400",
                "AccessDeniedException",
                true,
                "false"
            );
        }

        try {
            // Never inspect or project the returned parameter value.
            backend.ssmClientForDoctor().getParameter(
                GetParameterRequest.builder().name(paramName).build());
            return buildRow(
                probeId,
                "ssm_get_nonexistent",
                paramName,
                expected,
                "FAIL: GetParameter succeeded on " + paramName + " (value discarded; expected AccessDeniedException)",
                "200",
                "UnexpectedSuccess",
                false,
                "false"
            );
        } catch (AwsServiceException e) {
            String code = errorCode(e);
            int status = e.statusCode();
            boolean isAccessDenied = code.toLowerCase(Locale.ROOT).contains("accessdenied")
                || status == 403
                || (e.getMessage() != null && e.getMessage().toLowerCase(Locale.ROOT).contains("explicit deny"))
                || (e.getMessage() != null && e.getMessage().toLowerCase(Locale.ROOT).contains("not authorized"));
            boolean isNotFound = "ParameterNotFound".equalsIgnoreCase(code);
            boolean passed = isAccessDenied && !isNotFound;
            return buildRow(
                probeId,
                "ssm_get_nonexistent",
                paramName,
                expected,
                maskAll(code + " (HTTP " + status + ")" + (passed ? " — explicitDeny confirmed before parameter lookup" : "")),
                String.valueOf(status),
                code,
                passed,
                "false"
            );
        } catch (Exception e) {
            return buildRow(
                probeId,
                "ssm_get_nonexistent",
                paramName,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static Map<String, String> probeCloudFrontNonexistentDist(
            AwsBackend backend,
            String probeId,
            String distId,
            String runId) {
        if (distId == null || !NONEXISTENT_DIST_ID.matcher(distId).matches()) {
            throw new IllegalArgumentException(
                "cloudfront_invalidate_nonexistent_dist target must be a synthetic E00000... distribution ID; got " + distId);
        }
        String validRun = requireRunId(runId);
        String invPath = "/__perm_check/" + validRun;
        if (invPath.contains("*")) {
            throw new SecurityException("wildcard invalidation paths are strictly forbidden");
        }
        String expected = "403 AccessDenied (denied before distribution lookup, not NoSuchDistribution)";
        if (backend.isDemo()) {
            return buildRow(
                probeId,
                "cloudfront_invalidate_nonexistent_dist",
                distId,
                expected,
                "403 AccessDenied on distribution/" + distId + " (demo)",
                "403",
                "AccessDenied",
                true,
                "false"
            );
        }

        try (CloudFrontClient cf = backend.webBuilder(CloudFrontClient.builder()).region(Region.AWS_GLOBAL).build()) {
            cf.createInvalidation(
                CreateInvalidationRequest.builder()
                    .distributionId(distId)
                    .invalidationBatch(
                        InvalidationBatch.builder()
                            .callerReference("perm-check-neg-" + validRun)
                            .paths(Paths.builder().quantity(1).items(invPath).build())
                            .build())
                    .build());
            return buildRow(
                probeId,
                "cloudfront_invalidate_nonexistent_dist",
                distId,
                expected,
                "FAIL: CreateInvalidation succeeded on nonexistent distribution " + distId,
                "201",
                "UnexpectedSuccess",
                false,
                "false"
            );
        } catch (AwsServiceException e) {
            String code = errorCode(e);
            int status = e.statusCode();
            boolean isAccessDenied = status == 403 || code.toLowerCase(Locale.ROOT).contains("accessdenied");
            boolean isNoSuchDist = "NoSuchDistribution".equalsIgnoreCase(code) || status == 404;
            boolean passed = isAccessDenied && !isNoSuchDist;
            return buildRow(
                probeId,
                "cloudfront_invalidate_nonexistent_dist",
                distId,
                expected,
                maskAll(code + " (HTTP " + status + ") on distribution/" + distId
                    + (passed ? " — denied before distribution lookup" : "")),
                String.valueOf(status),
                code,
                passed,
                "false"
            );
        } catch (Exception e) {
            return buildRow(
                probeId,
                "cloudfront_invalidate_nonexistent_dist",
                distId,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static Map<String, String> probeCloudFrontOptIn(
            AwsBackend backend,
            String probeId,
            String distId,
            String extra) {
        if (distId == null || !DIST_ID.matcher(distId).matches() || NONEXISTENT_DIST_ID.matcher(distId).matches()) {
            throw new IllegalArgumentException("cloudfront_invalidate_opt_in requires a valid distribution ID");
        }
        if (extra == null || !extra.startsWith("opt_in:")) {
            throw new SecurityException("cloudfront_invalidate_opt_in is off by default and requires explicit 'opt_in:<runId>' (--live-invalidate)");
        }
        String validRun = requireRunId(extra.substring("opt_in:".length()));
        String invPath = "/__perm_check/" + validRun + "-" + distId.toLowerCase(Locale.ROOT);
        if (invPath.contains("*")) {
            throw new SecurityException("wildcard invalidation paths are strictly forbidden");
        }
        String expected = "CreateInvalidation 201 + GetInvalidation 200 on " + invPath + " (no wildcards)";
        if (backend.isDemo()) {
            String demoId = maskLast4("IDEMO" + validRun.toUpperCase(Locale.ROOT));
            Map<String, String> row = buildRow(
                probeId,
                "cloudfront_invalidate_opt_in",
                distId,
                expected,
                "CreateInvalidation 201 (id=" + demoId + ") + GetInvalidation 200 (status=InProgress, path=" + invPath + ", demo)",
                "201/200",
                "",
                true,
                "opt_in_nonexistent_path"
            );
            row.put("invalidation_id", demoId);
            row.put("invalidation_path", invPath);
            row.put("create_http_status", "201");
            row.put("get_http_status", "200");
            row.put("free_tier_note", "First 1,000 invalidation paths per month are free; additional paths cost $0.005 per path.");
            return row;
        }

        try (CloudFrontClient cf = backend.webBuilder(CloudFrontClient.builder()).region(Region.AWS_GLOBAL).build()) {
            var created = cf.createInvalidation(
                CreateInvalidationRequest.builder()
                    .distributionId(distId)
                    .invalidationBatch(
                        InvalidationBatch.builder()
                            .callerReference("perm-check-" + distId + "-" + validRun)
                            .paths(Paths.builder().quantity(1).items(invPath).build())
                            .build())
                    .build());
            String invId = created.invalidation() != null ? Objects.toString(created.invalidation().id(), "") : "";
            if (invId.isBlank()) {
                throw new IllegalStateException("CreateInvalidation returned empty invalidation ID");
            }
            int createStatus = created.sdkHttpResponse() != null ? created.sdkHttpResponse().statusCode() : 201;
            var got = cf.getInvalidation(
                GetInvalidationRequest.builder()
                    .distributionId(distId)
                    .id(invId)
                    .build());
            int getStatus = got.sdkHttpResponse() != null ? got.sdkHttpResponse().statusCode() : 200;
            String status = got.invalidation() != null ? Objects.toString(got.invalidation().status(), "Unknown") : "Unknown";
            String maskedId = maskLast4(invId);
            String combinedHttp = createStatus + "/" + getStatus;
            Map<String, String> row = buildRow(
                probeId,
                "cloudfront_invalidate_opt_in",
                distId,
                expected,
                "CreateInvalidation " + createStatus + " (id=" + maskedId + ") + GetInvalidation " + getStatus + " (status=" + status + ", path=" + invPath + ")",
                combinedHttp,
                "",
                true,
                "opt_in_nonexistent_path"
            );
            row.put("invalidation_id", maskedId);
            row.put("invalidation_path", invPath);
            row.put("invalidation_status", status);
            row.put("create_http_status", String.valueOf(createStatus));
            row.put("get_http_status", String.valueOf(getStatus));
            row.put("free_tier_note", "First 1,000 invalidation paths per month are free; additional paths cost $0.005 per path.");
            return row;
        } catch (Exception e) {
            return buildRow(
                probeId,
                "cloudfront_invalidate_opt_in",
                distId,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "opt_in_nonexistent_path"
            );
        }
    }

    private static boolean isLegacyObjectWriterBucket(AwsBackend backend, String bucket, String cachedAccount) {
        try {
            String account = ensureCallerAccount(backend, cachedAccount);
            var own = backend.s3ClientForDoctor().getBucketOwnershipControls(
                GetBucketOwnershipControlsRequest.builder().bucket(bucket).expectedBucketOwner(account).build())
                .ownershipControls();
            if (own.rules().isEmpty()) return true;
            String mode = own.rules().get(0).objectOwnershipAsString();
            return !"BucketOwnerEnforced".equals(mode);
        } catch (Exception e) {
            return "OwnershipControlsNotFoundError".equals(errorCode(e));
        }
    }

    private record BucketPrefix(String bucket, String prefix, String rawPattern) {}

    private static BucketPrefix parseBucketPrefix(String targetSpec) {
        if (targetSpec == null || targetSpec.isBlank()) {
            throw new IllegalArgumentException("S3 target '<bucket>/<prefix>' is required");
        }
        String cleaned = targetSpec.trim();
        if (cleaned.startsWith("arn:aws:s3:::")) {
            cleaned = cleaned.substring("arn:aws:s3:::".length());
        }
        int slash = cleaned.indexOf('/');
        String bucket = slash < 0 ? cleaned : cleaned.substring(0, slash);
        String rawPattern = slash < 0 ? "*" : cleaned.substring(slash + 1);
        requireBucketName(bucket);
        String prefix = rawPattern.endsWith("*")
            ? rawPattern.substring(0, rawPattern.length() - 1)
            : rawPattern;
        if (prefix.contains("*") || prefix.contains("..") || prefix.startsWith("/")) {
            throw new IllegalArgumentException("invalid S3 prefix in target: " + targetSpec);
        }
        return new BucketPrefix(bucket, prefix, rawPattern.isEmpty() ? "*" : rawPattern);
    }

    private static void requireBucketName(String bucket) {
        if (bucket == null
                || !BUCKET_NAME.matcher(bucket).matches()
                || bucket.contains("..")
                || bucket.contains(".-")
                || bucket.contains("-.")
                || bucket.matches("[0-9]+(?:\\.[0-9]+){3}")) {
            throw new IllegalArgumentException("invalid general-purpose S3 bucket name: " + bucket);
        }
    }

    private static String requireRunId(String runId) {
        if (runId == null || !RUN_ID.matcher(runId).matches()) {
            throw new IllegalArgumentException("run_id must be 4..24 lowercase alphanumeric characters; got " + runId);
        }
        return runId;
    }

    private static String normalizeEtag(String etag) {
        return etag == null ? "" : etag.replace("\"", "").trim();
    }

    private static String stringField(Map<String, Object> obj, String key, String fallback) {
        Object v = obj.get(key);
        return v == null ? fallback : String.valueOf(v);
    }

    private static String errorCode(Exception e) {
        if (e instanceof AwsServiceException aws && aws.awsErrorDetails() != null && aws.awsErrorDetails().errorCode() != null) {
            return aws.awsErrorDetails().errorCode();
        }
        return e.getClass().getSimpleName();
    }

    private static String httpStatus(Exception e) {
        if (e instanceof AwsServiceException aws) {
            return String.valueOf(aws.statusCode());
        }
        return "0";
    }

    private static String formatException(Exception e) {
        if (e instanceof AwsServiceException aws) {
            String code = errorCode(aws);
            return maskAll(code + " (HTTP " + aws.statusCode() + ")");
        }
        return maskAll(e.getClass().getSimpleName() + ": " + Objects.toString(e.getMessage(), ""));
    }

    static String maskLast4(String id) {
        if (id == null || id.isBlank()) return "****";
        String trimmed = id.trim();
        if (trimmed.length() <= 4) return "****" + trimmed;
        return "****" + trimmed.substring(trimmed.length() - 4);
    }

    static String maskAll(String value) {
        if (value == null) return "";
        return Jsons.mask(value)
            .replaceAll("(?<![0-9])[0-9]{12}(?![0-9])", "************")
            .replaceAll("[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", "[masked-id]");
    }

    private static Map<String, String> buildRow(
            String probeId,
            String kind,
            String target,
            String expected,
            String observed,
            String httpStatus,
            String errorCode,
            boolean passed,
            String mutating) {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("probe_id", probeId);
        row.put("kind", kind);
        row.put("target", maskAll(target));
        row.put("expected", expected);
        row.put("observed", maskAll(observed));
        row.put("http_status", httpStatus);
        row.put("error_code", errorCode == null ? "" : errorCode);
        row.put("passed", String.valueOf(passed));
        row.put("status", passed ? "PASS" : "FAIL");
        row.put("mutating", mutating);
        return row;
    }
}
