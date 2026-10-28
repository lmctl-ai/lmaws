package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.interceptor.SdkExecutionAttribute;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;
import software.amazon.awssdk.services.cloudfront.model.CreateInvalidationRequest;
import software.amazon.awssdk.services.cloudfront.model.GetInvalidationRequest;
import software.amazon.awssdk.services.cloudfront.model.InvalidationBatch;
import software.amazon.awssdk.services.cloudfront.model.Paths;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.BlockDeviceMapping;
import software.amazon.awssdk.services.ec2.model.CreateTagsRequest;
import software.amazon.awssdk.services.ec2.model.DeleteTagsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeImagesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeSubnetsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeVpcsRequest;
import software.amazon.awssdk.services.ec2.model.EbsBlockDevice;
import software.amazon.awssdk.services.ec2.model.Filter;
import software.amazon.awssdk.services.ec2.model.Image;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.InstanceMarketOptionsRequest;
import software.amazon.awssdk.services.ec2.model.MarketType;
import software.amazon.awssdk.services.ec2.model.RebootInstancesRequest;
import software.amazon.awssdk.services.ec2.model.ResourceType;
import software.amazon.awssdk.services.ec2.model.RunInstancesRequest;
import software.amazon.awssdk.services.ec2.model.SecurityGroup;
import software.amazon.awssdk.services.ec2.model.StartInstancesRequest;
import software.amazon.awssdk.services.ec2.model.StopInstancesRequest;
import software.amazon.awssdk.services.ec2.model.Subnet;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ec2.model.TagSpecification;
import software.amazon.awssdk.services.ec2.model.TerminateInstancesRequest;
import software.amazon.awssdk.services.ec2.model.VolumeType;
import software.amazon.awssdk.services.ec2.model.Vpc;
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

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
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
        "cloudfront_invalidate_opt_in",
        "ec2_default_vpc_sg_sanity",
        "ec2_canonical_ami_sanity",
        "ec2_run_instances_dryrun",
        "ec2_lifecycle_dryrun",
        "ec2_tags_dryrun"
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
            kindRow("cloudfront_invalidate_opt_in", "opt_in_nonexistent_path", "Opt-in cloudfront:CreateInvalidation + GetInvalidation for one nonexistent path /__perm_check/<runid> (no wildcards)"),
            kindRow("ec2_default_vpc_sg_sanity", "false", "Read-only ec2:DescribeVpcs + DescribeSubnets + DescribeSecurityGroups verifying default VPC and default SG has 0 open inbound rules from 0.0.0.0/0 or ::/0"),
            kindRow("ec2_canonical_ami_sanity", "false", "Read-only ec2:DescribeImages resolving latest Canonical arm64 Ubuntu AMI (owner 099720109477) and checking ssm:GetParameter status"),
            kindRow("ec2_run_instances_dryrun", "false", "Non-mutating ec2:RunInstances with DryRun=true (enforced by DryRunEnforcingInterceptor) expecting DryRunOperation (412) or UnauthorizedOperation (403)"),
            kindRow("ec2_lifecycle_dryrun", "false", "Non-mutating ec2:StartInstances/StopInstances/TerminateInstances/RebootInstances with DryRun=true on i-00000000000000000 or masked untagged fleet instance"),
            kindRow("ec2_tags_dryrun", "false", "Non-mutating ec2:CreateTags/DeleteTags with DryRun=true on i-00000000000000000 expecting UnauthorizedOperation (403)")
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
        String cachedCanonicalAmi = "";
        for (Map<String, String> spec : validated) {
            String extraVal = spec.get("extra");
            if (!cachedCanonicalAmi.isBlank() && "ec2_run_instances_dryrun".equals(spec.get("kind")) && extraVal.contains("\"auto\"")) {
                extraVal = extraVal.replace("\"auto\"", "\"" + cachedCanonicalAmi + "\"");
            }
            Map<String, String> row = runSingleInternal(
                backend,
                spec.get("id"),
                spec.get("kind"),
                spec.get("target"),
                extraVal,
                cachedCallerAccount
            );
            String resolvedAccount = row.remove("__caller_account");
            if (resolvedAccount != null && !resolvedAccount.isBlank()) {
                cachedCallerAccount = resolvedAccount;
            }
            String resolvedAmi = row.remove("__canonical_ami_id");
            if (resolvedAmi != null && !resolvedAmi.isBlank()) {
                cachedCanonicalAmi = resolvedAmi;
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
        row.remove("__canonical_ami_id");
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
            case "ec2_default_vpc_sg_sanity" -> probeEc2DefaultVpcSgSanity(backend, probeId, safeTarget);
            case "ec2_canonical_ami_sanity" -> probeEc2CanonicalAmiSanity(backend, probeId, safeTarget);
            case "ec2_run_instances_dryrun" -> probeEc2RunInstancesDryRun(backend, probeId, safeTarget, safeExtra);
            case "ec2_lifecycle_dryrun" -> probeEc2LifecycleDryRun(backend, probeId, safeTarget, safeExtra);
            case "ec2_tags_dryrun" -> probeEc2TagsDryRun(backend, probeId, safeTarget, safeExtra);
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

    private static final String CANONICAL_OWNER_ID = "099720109477";
    private static final String DEFAULT_CANONICAL_AMI_FILTER = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*";
    private static final String DEFAULT_CANONICAL_SSM_PARAM =
        "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id";
    private static final String NONEXISTENT_INSTANCE_ID = "i-0123456789abcdef0";

    /**
     * Execution interceptor that refuses any non-Describe* EC2 HTTP request unless DryRun=true is present in the form body.
     */
    static final class DryRunEnforcingInterceptor implements ExecutionInterceptor {
        @Override
        public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes attributes) {
            String op = attributes.getOptionalAttribute(SdkExecutionAttribute.OPERATION_NAME).orElse("");
            if (op.startsWith("Describe")) {
                return;
            }
            boolean modelDryRun = Boolean.TRUE.equals(
                context.request().getValueForField("DryRun", Boolean.class).orElse(false));
            if (modelDryRun) {
                return;
            }
            String body = "";
            var reqBody = context.requestBody();
            if (reqBody.isPresent()) {
                try (InputStream in = reqBody.get().contentStreamProvider().newStream()) {
                    body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    throw new SecurityException("failed to inspect EC2 request body for DryRun=true enforcement: " + e.getMessage(), e);
                }
            }
            if (body.contains("Action=Describe") || body.startsWith("Action=Describe")) {
                return;
            }
            if (body.contains("DryRun=true") || body.contains("DryRun=True")) {
                return;
            }
            throw new SecurityException(
                "PublishGrantProbes DryRunEnforcingInterceptor blocked non-DryRun EC2 operation '" + op + "'");
        }
    }

    private static Ec2Client buildDryRunEc2Client(AwsBackend backend, String regionName) {
        String targetRegion = (regionName == null || regionName.isBlank()) ? "us-east-1" : regionName.trim();
        var builder = backend.webBuilder(Ec2Client.builder());
        var baseCfg = builder.overrideConfiguration();
        var cfgBuilder = baseCfg != null
            ? baseCfg.toBuilder()
            : software.amazon.awssdk.core.client.config.ClientOverrideConfiguration.builder();
        cfgBuilder.addExecutionInterceptor(new DryRunEnforcingInterceptor());
        cfgBuilder.putHeader("X-Lmaws-Test-Region", targetRegion);
        builder.overrideConfiguration(cfgBuilder.build());
        builder.region(Region.of(targetRegion));
        return builder.build();
    }

    private static Map<String, String> probeEc2DefaultVpcSgSanity(
            AwsBackend backend,
            String probeId,
            String target) {
        String regionName = (target == null || target.isBlank()) ? "us-east-1" : target.trim();
        String expected = "Default VPC present in " + regionName + " and default SG has 0 open inbound rules (0.0.0.0/0 or ::/0)";
        if (backend.isDemo()) {
            Map<String, String> row = buildRow(
                probeId,
                "ec2_default_vpc_sg_sanity",
                "default-vpc/" + regionName,
                expected,
                "Default VPC vpc-**** found (subnets=6, public_ip_on_launch=6), default SG sg-**** open_inbound=false (demo)",
                "200",
                "",
                true,
                "false"
            );
            row.put("default_vpc_found", "true");
            row.put("default_sg_found", "true");
            row.put("default_sg_open_inbound", "false");
            row.put("subnet_count", "6");
            row.put("map_public_ip_subnet_count", "6");
            return row;
        }

        try (Ec2Client ec2 = buildDryRunEc2Client(backend, regionName)) {
            List<Vpc> vpcs = ec2.describeVpcs(DescribeVpcsRequest.builder().build()).vpcs();
            Vpc defaultVpc = vpcs.stream().filter(v -> Boolean.TRUE.equals(v.isDefault())).findFirst()
                .orElse(vpcs.isEmpty() ? null : vpcs.get(0));
            if (defaultVpc == null) {
                return buildRow(probeId, "ec2_default_vpc_sg_sanity", "default-vpc/" + regionName, expected,
                    "No VPC found in " + regionName, "200", "NoVpcFound", false, "false");
            }
            String vpcId = defaultVpc.vpcId();
            List<Subnet> subnets = ec2.describeSubnets(DescribeSubnetsRequest.builder()
                .filters(Filter.builder().name("vpc-id").values(vpcId).build())
                .build()).subnets();
            long publicSubnets = subnets.stream().filter(s -> Boolean.TRUE.equals(s.mapPublicIpOnLaunch())).count();
            long privateSubnets = subnets.size() - publicSubnets;

            List<SecurityGroup> sgs = ec2.describeSecurityGroups(DescribeSecurityGroupsRequest.builder()
                .filters(
                    Filter.builder().name("vpc-id").values(vpcId).build(),
                    Filter.builder().name("group-name").values("default").build()
                ).build()).securityGroups();
            if (sgs.isEmpty()) {
                return buildRow(probeId, "ec2_default_vpc_sg_sanity", "default-vpc/" + regionName, expected,
                    "Default security group not found in default VPC", "200", "NoDefaultSg", false, "false");
            }
            SecurityGroup defaultSg = sgs.get(0);
            boolean openInbound = defaultSg.ipPermissions().stream().anyMatch(p ->
                p.ipRanges().stream().anyMatch(r -> "0.0.0.0/0".equals(r.cidrIp()))
                    || p.ipv6Ranges().stream().anyMatch(r -> "::/0".equals(r.cidrIpv6())));
            int selfRefRules = defaultSg.ipPermissions().stream()
                .mapToInt(p -> p.userIdGroupPairs() == null ? 0 : p.userIdGroupPairs().size())
                .sum();
            boolean ok = !subnets.isEmpty() && !openInbound;
            Map<String, String> row = buildRow(
                probeId,
                "ec2_default_vpc_sg_sanity",
                "default-vpc/" + regionName,
                expected,
                "Default VPC found (subnets=" + subnets.size()
                    + ", map_public_ip_true=" + publicSubnets
                    + ", map_public_ip_false=" + privateSubnets
                    + "), default SG open_inbound=" + openInbound
                    + " (self_group_rules=" + selfRefRules + ")",
                "200",
                openInbound ? "DefaultSgOpenInbound" : "",
                ok,
                "false"
            );
            row.put("default_vpc_found", String.valueOf(Boolean.TRUE.equals(defaultVpc.isDefault())));
            row.put("default_sg_found", "true");
            row.put("default_sg_open_inbound", String.valueOf(openInbound));
            row.put("default_sg_self_rules", String.valueOf(selfRefRules));
            row.put("subnet_count", String.valueOf(subnets.size()));
            row.put("map_public_ip_subnet_count", String.valueOf(publicSubnets));
            row.put("private_subnet_count", String.valueOf(privateSubnets));
            return row;
        } catch (Exception e) {
            return buildRow(probeId, "ec2_default_vpc_sg_sanity", "default-vpc/" + regionName, expected,
                formatException(e), httpStatus(e), errorCode(e), false, "false");
        }
    }

    private static Map<String, String> probeEc2CanonicalAmiSanity(
            AwsBackend backend,
            String probeId,
            String target) {
        String namePattern = (target == null || target.isBlank()) ? DEFAULT_CANONICAL_AMI_FILTER : target.trim();
        String expected = "ec2:DescribeImages resolves available Canonical (099720109477) arm64 Ubuntu AMI";
        if (backend.isDemo()) {
            String demoAmi = "ami-0canonicalarm64demo";
            Map<String, String> row = buildRow(
                probeId,
                "ec2_canonical_ami_sanity",
                namePattern,
                expected,
                "Resolved Canonical arm64 AMI " + demoAmi + " (owner=099720109477, ssm_public_param=AccessDeniedException, demo)",
                "200",
                "",
                true,
                "false"
            );
            row.put("ami_id", demoAmi);
            row.put("ami_owner", CANONICAL_OWNER_ID);
            row.put("ami_architecture", "arm64");
            row.put("ssm_public_param_status", "AccessDeniedException");
            row.put("__canonical_ami_id", demoAmi);
            return row;
        }

        String ssmStatus = "not_checked";
        try {
            backend.ssmClientForDoctor().getParameter(
                GetParameterRequest.builder().name(DEFAULT_CANONICAL_SSM_PARAM).build());
            ssmStatus = "200_Allowed";
        } catch (Exception ssmEx) {
            ssmStatus = errorCode(ssmEx);
        }

        try (Ec2Client ec2 = buildDryRunEc2Client(backend, "us-east-1")) {
            List<Image> images = ec2.describeImages(DescribeImagesRequest.builder()
                .owners(CANONICAL_OWNER_ID)
                .filters(
                    Filter.builder().name("name").values(namePattern).build(),
                    Filter.builder().name("architecture").values("arm64").build(),
                    Filter.builder().name("state").values("available").build(),
                    Filter.builder().name("image-type").values("machine").build(),
                    Filter.builder().name("root-device-type").values("ebs").build()
                ).build()).images();
            Image latest = images.stream()
                .max(Comparator.comparing(img -> Objects.toString(img.creationDate(), "")))
                .orElse(null);
            if (latest == null || latest.imageId() == null || latest.imageId().isBlank()) {
                return buildRow(probeId, "ec2_canonical_ami_sanity", namePattern, expected,
                    "No matching Canonical arm64 AMI found for pattern " + namePattern, "200", "NoCanonicalAmiFound", false, "false");
            }
            String amiId = latest.imageId();
            String amiName = Objects.toString(latest.name(), "");
            Map<String, String> row = buildRow(
                probeId,
                "ec2_canonical_ami_sanity",
                namePattern,
                expected,
                "Resolved " + amiId + " (" + amiName + ", owner=" + CANONICAL_OWNER_ID
                    + ", arch=arm64, ssm_public_param=" + ssmStatus + ")",
                "200",
                "",
                true,
                "false"
            );
            row.put("ami_id", amiId);
            row.put("ami_name", amiName);
            row.put("ami_owner", CANONICAL_OWNER_ID);
            row.put("ami_architecture", "arm64");
            row.put("ssm_public_param_status", ssmStatus);
            row.put("__canonical_ami_id", amiId);
            return row;
        } catch (Exception e) {
            return buildRow(probeId, "ec2_canonical_ami_sanity", namePattern, expected,
                formatException(e), httpStatus(e), errorCode(e), false, "false");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseExtraObject(String extra) {
        if (extra == null || extra.isBlank()) {
            return Map.of();
        }
        String trimmed = extra.trim();
        if (trimmed.startsWith("{")) {
            Object parsed = Json.parse(trimmed);
            if (parsed instanceof Map<?, ?> m) {
                return (Map<String, Object>) m;
            }
        }
        return Map.of();
    }

    private static int intField(Map<String, Object> obj, String key, int fallback) {
        Object v = obj.get(key);
        if (v == null) return fallback;
        if (v instanceof Number n) return n.intValue();
        String s = String.valueOf(v).trim();
        if (s.isEmpty()) return fallback;
        if (s.endsWith(".0")) s = s.substring(0, s.length() - 2);
        return Integer.parseInt(s);
    }

    private static Map<String, String> probeEc2RunInstancesDryRun(
            AwsBackend backend,
            String probeId,
            String target,
            String extra) {
        Map<String, Object> spec = parseExtraObject(extra);
        String regionName = stringField(spec, "region", "us-east-1");
        String instanceType = stringField(spec, "instance_type", "t4g.nano");
        String imageId = stringField(spec, "image_id", "ami-0123456789abcdef0");
        boolean autoRegionalAmi = "auto_regional".equalsIgnoreCase(imageId);
        if ("auto".equalsIgnoreCase(imageId) || imageId.isBlank()) {
            imageId = "ami-0123456789abcdef0";
        }
        int volumeSizeGib = intField(spec, "volume_size_gib", 10);
        String volumeType = stringField(spec, "volume_type", "gp3");
        String provisionerTag = stringField(spec, "provisioner_tag", "lmprov");
        String extraTagKey = stringField(spec, "extra_tag_key", "");
        String extraTagValue = stringField(spec, "extra_tag_value", "");
        String marketType = stringField(spec, "market_type", "on-demand");
        String expectCode = stringField(spec, "expect", "UnauthorizedOperation");

        String summaryTarget = (target == null || target.isBlank() ? "RunInstances(DryRun)" : target)
            + " [type=" + instanceType + ", vol=" + volumeSizeGib + "GiB " + volumeType
            + ", tag=" + (provisionerTag.isEmpty() || "none".equalsIgnoreCase(provisionerTag) ? "none" : "provisioner=" + provisionerTag)
            + ", market=" + marketType + ", region=" + regionName + "]";
        String expected = "EC2 DryRun response matches " + expectCode;

        if (backend.isDemo()) {
            String demoCode = expectCode.contains("|") ? expectCode.split("\\|")[0].trim() : expectCode;
            String demoHttp = "DryRunOperation".equalsIgnoreCase(demoCode) ? "412" : "403";
            Map<String, String> row = buildRow(
                probeId,
                "ec2_run_instances_dryrun",
                summaryTarget,
                expected,
                demoCode + " (HTTP " + demoHttp + ", DryRun=true, demo)",
                demoHttp,
                demoCode,
                true,
                "false"
            );
            row.put("dry_run", "true");
            row.put("instance_type", instanceType);
            row.put("volume_size_gib", String.valueOf(volumeSizeGib));
            row.put("market_type", marketType);
            row.put("region", regionName);
            return row;
        }

        try (Ec2Client ec2 = buildDryRunEc2Client(backend, regionName)) {
            if (autoRegionalAmi) {
                List<Image> imgs = ec2.describeImages(DescribeImagesRequest.builder()
                    .owners(CANONICAL_OWNER_ID)
                    .filters(
                        Filter.builder().name("name").values(DEFAULT_CANONICAL_AMI_FILTER).build(),
                        Filter.builder().name("architecture").values("arm64").build(),
                        Filter.builder().name("state").values("available").build()
                    ).build()).images();
                Image latest = imgs.stream()
                    .max(Comparator.comparing(img -> Objects.toString(img.creationDate(), "")))
                    .orElse(null);
                imageId = (latest != null && latest.imageId() != null && !latest.imageId().isBlank())
                    ? latest.imageId()
                    : "ami-0123456789abcdef0";
            }
            RunInstancesRequest.Builder req = RunInstancesRequest.builder()
                .dryRun(true)
                .imageId(imageId)
                .instanceType(instanceType)
                .minCount(1)
                .maxCount(1)
                .blockDeviceMappings(BlockDeviceMapping.builder()
                    .deviceName("/dev/sda1")
                    .ebs(EbsBlockDevice.builder()
                        .volumeSize(volumeSizeGib)
                        .volumeType(VolumeType.fromValue(volumeType))
                        .deleteOnTermination(true)
                        .build())
                    .build());

            if (!provisionerTag.isBlank() && !"none".equalsIgnoreCase(provisionerTag)) {
                List<Tag> tags = new ArrayList<>();
                tags.add(Tag.builder().key("provisioner").value(provisionerTag).build());
                if (!extraTagKey.isBlank()) {
                    tags.add(Tag.builder().key(extraTagKey).value(extraTagValue).build());
                }
                req.tagSpecifications(
                    TagSpecification.builder().resourceType(ResourceType.INSTANCE).tags(tags).build(),
                    TagSpecification.builder().resourceType(ResourceType.VOLUME).tags(tags).build(),
                    TagSpecification.builder().resourceType(ResourceType.NETWORK_INTERFACE).tags(tags).build()
                );
            }
            if ("spot".equalsIgnoreCase(marketType)) {
                req.instanceMarketOptions(InstanceMarketOptionsRequest.builder()
                    .marketType(MarketType.SPOT)
                    .build());
            }

            ec2.runInstances(req.build());
            return buildRow(
                probeId,
                "ec2_run_instances_dryrun",
                summaryTarget,
                expected,
                "FAIL: RunInstances(DryRun=true) returned without DryRun/Unauthorized exception",
                "200",
                "UnexpectedSuccess",
                false,
                "false"
            );
        } catch (AwsServiceException e) {
            String code = errorCode(e);
            int status = e.statusCode();
            boolean matched = matchesExpectedCode(expectCode, code);
            Map<String, String> row = buildRow(
                probeId,
                "ec2_run_instances_dryrun",
                summaryTarget,
                expected,
                maskAll(code + " (HTTP " + status + ", DryRun=true)"),
                String.valueOf(status),
                code,
                matched,
                "false"
            );
            row.put("dry_run", "true");
            row.put("instance_type", instanceType);
            row.put("volume_size_gib", String.valueOf(volumeSizeGib));
            row.put("market_type", marketType);
            row.put("region", regionName);
            return row;
        } catch (Exception e) {
            return buildRow(
                probeId,
                "ec2_run_instances_dryrun",
                summaryTarget,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static Map<String, String> probeEc2LifecycleDryRun(
            AwsBackend backend,
            String probeId,
            String target,
            String extra) {
        Map<String, Object> spec = parseExtraObject(extra);
        String action = stringField(spec, "action", "terminate").toLowerCase(Locale.ROOT);
        String expectCode = stringField(spec, "expect", "UnauthorizedOperation");
        String regionName = stringField(spec, "region", "us-east-1");
        boolean discoverUntagged = "discovered_untagged_fleet".equalsIgnoreCase(target);
        String expected = "EC2 " + action + " (DryRun=true) response matches " + expectCode;
        String displayTarget = discoverUntagged
            ? action + " on discovered untagged fleet instance (i-****)"
            : action + " on " + NONEXISTENT_INSTANCE_ID;

        if (backend.isDemo()) {
            String demoCode = expectCode.contains("|") ? expectCode.split("\\|")[0].trim() : expectCode;
            String demoHttp = "DryRunOperation".equalsIgnoreCase(demoCode) ? "412" : "403";
            Map<String, String> row = buildRow(
                probeId,
                "ec2_lifecycle_dryrun",
                displayTarget,
                expected,
                demoCode + " (HTTP " + demoHttp + ", DryRun=true, demo)",
                demoHttp,
                demoCode,
                true,
                "false"
            );
            row.put("dry_run", "true");
            row.put("lifecycle_action", action);
            row.put("target_mode", discoverUntagged ? "discovered_untagged_fleet" : "nonexistent");
            return row;
        }

        try (Ec2Client ec2 = buildDryRunEc2Client(backend, regionName)) {
            String instanceId = NONEXISTENT_INSTANCE_ID;
            if (discoverUntagged) {
                String discovered = findFirstNonProvisionerInstanceId(ec2);
                if (discovered == null || discovered.isBlank()) {
                    instanceId = NONEXISTENT_INSTANCE_ID;
                } else {
                    instanceId = discovered;
                }
            }
            switch (action) {
                case "start" -> ec2.startInstances(StartInstancesRequest.builder().dryRun(true).instanceIds(instanceId).build());
                case "stop" -> ec2.stopInstances(StopInstancesRequest.builder().dryRun(true).instanceIds(instanceId).build());
                case "terminate" -> ec2.terminateInstances(TerminateInstancesRequest.builder().dryRun(true).instanceIds(instanceId).build());
                case "reboot" -> ec2.rebootInstances(RebootInstancesRequest.builder().dryRun(true).instanceIds(instanceId).build());
                default -> throw new IllegalArgumentException("unsupported ec2_lifecycle_dryrun action: " + action);
            }
            return buildRow(
                probeId,
                "ec2_lifecycle_dryrun",
                displayTarget,
                expected,
                "FAIL: " + action + "(DryRun=true) returned without exception",
                "200",
                "UnexpectedSuccess",
                false,
                "false"
            );
        } catch (AwsServiceException e) {
            String code = errorCode(e);
            int status = e.statusCode();
            boolean matched = matchesExpectedCode(expectCode, code);
            Map<String, String> row = buildRow(
                probeId,
                "ec2_lifecycle_dryrun",
                displayTarget,
                expected,
                maskAll(code + " (HTTP " + status + ", DryRun=true)"),
                String.valueOf(status),
                code,
                matched,
                "false"
            );
            row.put("dry_run", "true");
            row.put("lifecycle_action", action);
            row.put("target_mode", discoverUntagged ? "discovered_untagged_fleet" : "nonexistent");
            return row;
        } catch (Exception e) {
            return buildRow(
                probeId,
                "ec2_lifecycle_dryrun",
                displayTarget,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static String findFirstNonProvisionerInstanceId(Ec2Client ec2) {
        var resp = ec2.describeInstances(DescribeInstancesRequest.builder().build());
        for (var r : resp.reservations()) {
            for (Instance inst : r.instances()) {
                boolean isProvisioner = inst.tags() != null && inst.tags().stream()
                    .anyMatch(t -> "provisioner".equals(t.key()) && "lmprov".equals(t.value()));
                if (!isProvisioner && inst.instanceId() != null && !inst.instanceId().isBlank()) {
                    return inst.instanceId();
                }
            }
        }
        return null;
    }

    private static Map<String, String> probeEc2TagsDryRun(
            AwsBackend backend,
            String probeId,
            String target,
            String extra) {
        Map<String, Object> spec = parseExtraObject(extra);
        String expectCode = stringField(spec, "expect", "UnauthorizedOperation");
        String opMode = (target == null || target.isBlank()) ? "create_tags_post_launch" : target.trim().toLowerCase(Locale.ROOT);
        String expected = "EC2 " + opMode + " (DryRun=true) response matches " + expectCode;
        String displayTarget = opMode + " on " + NONEXISTENT_INSTANCE_ID;

        if (backend.isDemo()) {
            String demoCode = expectCode.contains("|") ? expectCode.split("\\|")[0].trim() : expectCode;
            Map<String, String> row = buildRow(
                probeId,
                "ec2_tags_dryrun",
                displayTarget,
                expected,
                demoCode + " (HTTP 403, DryRun=true, demo)",
                "403",
                demoCode,
                true,
                "false"
            );
            row.put("dry_run", "true");
            row.put("tag_operation", opMode);
            return row;
        }

        try (Ec2Client ec2 = buildDryRunEc2Client(backend, "us-east-1")) {
            String resourceId = NONEXISTENT_INSTANCE_ID;
            String discovered = findFirstNonProvisionerInstanceId(ec2);
            if (discovered != null && !discovered.isBlank()) {
                resourceId = discovered;
            }
            if ("delete_tags".equals(opMode)) {
                ec2.deleteTags(DeleteTagsRequest.builder()
                    .dryRun(true)
                    .resources(resourceId)
                    .tags(Tag.builder().key("provisioner").value("lmprov").build())
                    .build());
            } else {
                ec2.createTags(CreateTagsRequest.builder()
                    .dryRun(true)
                    .resources(resourceId)
                    .tags(Tag.builder().key("provisioner").value("lmprov").build())
                    .build());
            }
            return buildRow(
                probeId,
                "ec2_tags_dryrun",
                displayTarget,
                expected,
                "FAIL: " + opMode + "(DryRun=true) returned without exception",
                "200",
                "UnexpectedSuccess",
                false,
                "false"
            );
        } catch (AwsServiceException e) {
            String code = errorCode(e);
            int status = e.statusCode();
            boolean matched = matchesExpectedCode(expectCode, code);
            Map<String, String> row = buildRow(
                probeId,
                "ec2_tags_dryrun",
                displayTarget,
                expected,
                maskAll(code + " (HTTP " + status + ", DryRun=true)"),
                String.valueOf(status),
                code,
                matched,
                "false"
            );
            row.put("dry_run", "true");
            row.put("tag_operation", opMode);
            return row;
        } catch (Exception e) {
            return buildRow(
                probeId,
                "ec2_tags_dryrun",
                displayTarget,
                expected,
                formatException(e),
                httpStatus(e),
                errorCode(e),
                false,
                "false"
            );
        }
    }

    private static boolean matchesExpectedCode(String expectSpec, String actualCode) {
        if (expectSpec == null || expectSpec.isBlank()) return true;
        if (actualCode == null) return false;
        for (String token : expectSpec.split("\\|")) {
            if (token.trim().equalsIgnoreCase(actualCode.trim())) {
                return true;
            }
        }
        return false;
    }

    static String maskAll(String value) {
        if (value == null) return "";
        return Jsons.mask(value)
            .replaceAll("(?<![0-9])[0-9]{12}(?![0-9])", "************")
            .replaceAll("[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", "[masked-id]")
            .replaceAll("\\b(i|vpc|subnet|sg|vol|eni|eipalloc)-(?!(?:0{8,17}|0123456789abcdef0)\\b)[0-9a-f]{8,17}\\b", "$1-****");
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
