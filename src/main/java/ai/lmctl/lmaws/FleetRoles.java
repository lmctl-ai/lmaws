package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeIamInstanceProfileAssociationsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeIamInstanceProfileAssociationsResponse;
import software.amazon.awssdk.services.ec2.model.DescribeInstanceStatusRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.Filter;
import software.amazon.awssdk.services.ec2.model.IamInstanceProfileAssociation;
import software.amazon.awssdk.services.ec2.model.IamInstanceProfileSpecification;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.ReplaceIamInstanceProfileAssociationRequest;
import software.amazon.awssdk.services.ec2.model.ReplaceIamInstanceProfileAssociationResponse;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.AddRoleToInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.CreateInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.CreateRoleRequest;
import software.amazon.awssdk.services.iam.model.GetInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.GetInstanceProfileResponse;
import software.amazon.awssdk.services.iam.model.GetRoleRequest;
import software.amazon.awssdk.services.iam.model.GetRoleResponse;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.iam.model.PutRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.Role;
import software.amazon.awssdk.services.iam.model.UpdateAssumeRolePolicyRequest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Generic least-privilege operational EC2 instance-role planner, linter, sequential 1-by-1
 * association swapper, and one-command rollback helper ("No agent holds admin").
 *
 * <p>All defaults in this public class use synthetic example names ({@code ops-node-1},
 * {@code ops-node-2}, {@code example-ops-role-1}, {@code example-ops-role-2},
 * {@code example-ops-boundary}). Private operator scripts may supply custom target names
 * via {@code LMAWS_FLEET_ROLES_SPEC}.
 */
public final class FleetRoles {
    public static final String INSTANCE_1 = "ops-node-1";
    public static final String INSTANCE_2 = "ops-node-2";
    public static final String ROLE_TAG_1 = "primary";
    public static final String ROLE_TAG_2 = "secondary";
    public static final String ROLE_NODE_1 = "example-ops-role-1";
    public static final String ROLE_NODE_2 = "example-ops-role-2";
    public static final String BOUNDARY_NAME = "example-ops-boundary";
    public static final String CURRENT_ADMIN_ROLE = "example-legacy-wide-role";
    public static final String PROJECT_TAG = "example-fleet";
    public static final String DEPLOY_ROLE_NAME = "example-static-deploy";
    public static final String ASSET_BUCKET_NAME = "example-ops-assets";
    public static final String INLINE_POLICY_NAME = "example-ops-permissions";
    public static final String REGION = "us-east-1";

    private FleetRoles() {}

    public record Spec(
        String instance1,
        String instance2,
        String roleTag1,
        String roleTag2,
        String role1,
        String role2,
        String boundaryName,
        String legacyRole,
        String projectTag,
        String deployRoleName,
        String assetBucketName,
        String inlinePolicyName
    ) {
        @SuppressWarnings("unchecked")
        public static Spec active() {
            String raw = System.getenv().getOrDefault("LMAWS_FLEET_ROLES_SPEC", "").trim();
            if (!raw.isEmpty()) {
                if(raw.length()>65536) throw new IllegalArgumentException("fleet spec exceeds 64KiB");
                Object parsed = Json.parse(raw);
                if (parsed instanceof Map<?, ?> m) {
                    Map<String, Object> map = (Map<String, Object>) m;
                    Set<String> expected=Set.of("instance_1","instance_2","role_tag_1","role_tag_2","role_1","role_2","boundary_name","legacy_role","project_tag","deploy_role","asset_bucket","inline_policy_name");
                    if(!map.keySet().equals(expected)) throw new IllegalArgumentException("fleet spec requires exactly the documented target and scope fields");
                    for(var entry:map.entrySet()) {
                        String pattern=entry.getKey().equals("asset_bucket")?"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]":"[A-Za-z0-9][A-Za-z0-9_-]{0,63}";
                        if(!(entry.getValue() instanceof String value) || !value.matches(pattern)) throw new IllegalArgumentException("invalid fleet spec field: "+entry.getKey());
                    }
                    if(map.get("instance_1").equals(map.get("instance_2")) || map.get("role_1").equals(map.get("role_2"))) throw new IllegalArgumentException("fleet targets and roles must differ");
                    return new Spec(
                        str(map, "instance_1", INSTANCE_1),
                        str(map, "instance_2", INSTANCE_2),
                        str(map, "role_tag_1", ROLE_TAG_1),
                        str(map, "role_tag_2", ROLE_TAG_2),
                        str(map, "role_1", ROLE_NODE_1),
                        str(map, "role_2", ROLE_NODE_2),
                        str(map, "boundary_name", BOUNDARY_NAME),
                        str(map, "legacy_role", CURRENT_ADMIN_ROLE),
                        str(map, "project_tag", PROJECT_TAG),
                        str(map, "deploy_role", DEPLOY_ROLE_NAME),
                        str(map, "asset_bucket", ASSET_BUCKET_NAME),
                        str(map, "inline_policy_name", INLINE_POLICY_NAME)
                    );
                }
            }
            if(!raw.isEmpty()) throw new IllegalArgumentException("fleet spec must be a JSON object");
            return new Spec(
                INSTANCE_1, INSTANCE_2, ROLE_TAG_1, ROLE_TAG_2,
                ROLE_NODE_1, ROLE_NODE_2, BOUNDARY_NAME, CURRENT_ADMIN_ROLE,
                PROJECT_TAG, DEPLOY_ROLE_NAME, ASSET_BUCKET_NAME, INLINE_POLICY_NAME
            );
        }

        private static String str(Map<String, Object> m, String key, String fallback) {
            Object v = m.get(key);
            return v == null || String.valueOf(v).isBlank() ? fallback : String.valueOf(v).trim();
        }
    }

    /**
     * Enforces the 5-way human-admin guard for fleet role mutations.
     */
    public static void checkAdminHumanApplyGuard(
            String profile,
            boolean live,
            boolean adminGrantEnv,
            boolean applyFlag,
            boolean humanConfirmed) {
        if (!"admin".equals(profile)) {
            throw new SecurityException(
                "Fleet role apply/rollback requires AWS_PROFILE=admin (active profile: "
                    + (profile == null || profile.isEmpty() ? "<unset>" : profile)
                    + "); agents must never hold or create admin roles.");
        }
        if (!live) {
            throw new SecurityException(
                "Fleet role apply/rollback requires LMAWS_LIVE=1 (--live); default execution is a dry-run plan.");
        }
        if (!adminGrantEnv) {
            throw new SecurityException(
                "Fleet role apply/rollback requires LMAWS_ADMIN_GRANT=1 in the environment.");
        }
        if (!applyFlag) {
            throw new SecurityException(
                "Fleet role apply/rollback requires --apply (LMAWS_APPLY=1).");
        }
        if (!humanConfirmed) {
            throw new SecurityException(
                "Fleet role apply/rollback requires the explicit --i-am-the-admin-human flag "
                    + "(humanConfirmed=true); an agent must never apply instance-role or boundary changes autonomously.");
        }
    }

    /**
     * Masks 12-digit AWS account IDs plus concrete EC2 instance, volume, EIP allocation,
     * EIP association, and IAM instance-profile association IDs.
     */
    public static String maskFleetIds(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        String masked = Jsons.mask(raw);
        masked = masked.replaceAll("\\bi-[0-9a-f]{8,17}\\b", "i-************");
        masked = masked.replaceAll("\\bvol-[0-9a-f]{8,17}\\b", "vol-************");
        masked = masked.replaceAll("\\beipalloc-[0-9a-f]{8,17}\\b", "eipalloc-************");
        masked = masked.replaceAll("\\beipassoc-[0-9a-f]{8,17}\\b", "eipassoc-************");
        masked = masked.replaceAll("\\biip-assoc-[0-9a-f]{8,17}\\b", "iip-assoc-************");
        masked = masked.replaceAll("\\bsir-[0-9a-z]{8,17}\\b", "sir-************");
        masked = masked.replaceAll("\\bsubnet-[0-9a-f]{8,17}\\b", "subnet-************");
        masked = masked.replaceAll("\\bvpc-[0-9a-f]{8,17}\\b", "vpc-************");
        masked = masked.replaceAll("\\beni-[0-9a-f]{8,17}\\b", "eni-************");
        return masked;
    }

    // --- 1. Synthetic Operations Needs Model ---

    public static List<Map<String, String>> opsNeedsTable() {
        Spec s = Spec.active();
        String both = s.instance1 + "," + s.instance2;
        List<Map<String, String>> rows = new ArrayList<>();
        rows.add(row(
            "operation", "self_stop_watchdog",
            "instances", both,
            "service", "ec2",
            "exact_actions", "ec2:StopInstances",
            "resource_scope", "arn:aws:ec2:us-east-1:${aws:PrincipalAccount}:instance/*",
            "condition_scope", "StringEquals aws:ResourceTag/Project=" + s.projectTag + ", aws:ResourceTag/Role=" + s.roleTag1 + "|" + s.roleTag2 + ", aws:ResourceTag/Name=" + s.instance1 + "|" + s.instance2 + ", aws:RequestedRegion=us-east-1",
            "source_script_or_snapshot", "synthetic:idle-watchdog-timer",
            "evidence", "Synthetic fixture: idle timer stops only its own tagged instance when inactive"
        ));
        rows.add(row(
            "operation", "fleet_status_and_cpu_monitor",
            "instances", both,
            "service", "ec2,cloudwatch,sts",
            "exact_actions", "sts:GetCallerIdentity,ec2:DescribeInstances,ec2:DescribeInstanceStatus,ec2:DescribeInstanceAttribute,ec2:DescribeInstanceCreditSpecifications,ec2:DescribeInstanceTypes,ec2:DescribeVolumes,ec2:DescribeAddresses,ec2:DescribeTags,cloudwatch:GetMetricData",
            "resource_scope", "*",
            "condition_scope", "StringEqualsIfExists aws:RequestedRegion=us-east-1",
            "source_script_or_snapshot", "synthetic:fleet-health-check",
            "evidence", "Synthetic fixture: read-only EC2 metadata and CloudWatch CPU metric queries"
        ));
        rows.add(row(
            "operation", "ssm_public_ami_lookup_and_agent_heartbeat",
            "instances", both,
            "service", "ssm",
            "exact_actions", "ssm:GetParameter,ssm:GetParameters,ssm:UpdateInstanceInformation,ssm:ListInstanceAssociations,ssm:ListAssociations",
            "resource_scope", "arn:aws:ssm:us-east-1::parameter/aws/service/canonical/ubuntu/* (GetParameter*), * (agent heartbeat)",
            "condition_scope", "StringEquals aws:RequestedRegion=us-east-1",
            "source_script_or_snapshot", "synthetic:ssm-public-ami-and-agent",
            "evidence", "Synthetic fixture: public Ubuntu AMI parameter lookup and SSM agent heartbeat in us-east-1"
        ));
        rows.add(row(
            "operation", "static_deploy_assume_role",
            "instances", both,
            "service", "sts",
            "exact_actions", "sts:AssumeRole",
            "resource_scope", "arn:aws:iam::${aws:PrincipalAccount}:role/" + s.deployRoleName,
            "condition_scope", "Target role trust policy requires explicit principal ARN",
            "source_script_or_snapshot", "synthetic:static-deploy-role",
            "evidence", "Synthetic fixture: assumes dedicated non-admin deploy role for static asset publishing"
        ));
        rows.add(row(
            "operation", "s3_asset_bucket_sync",
            "instances", both,
            "service", "s3",
            "exact_actions", "s3:ListBucket,s3:GetBucketLocation,s3:GetObject,s3:GetObjectTagging,s3:GetObjectAttributes,s3:PutObject,s3:PutObjectTagging,s3:DeleteObject,s3:DeleteObjectTagging,s3:AbortMultipartUpload",
            "resource_scope", "arn:aws:s3:::" + s.assetBucketName + ", arn:aws:s3:::" + s.assetBucketName + "/*",
            "condition_scope", "Bucket and object ARNs locked to " + s.assetBucketName + "; bucket deletion and policy edits denied",
            "source_script_or_snapshot", "synthetic:s3-asset-sync",
            "evidence", "Synthetic fixture: static asset sync scoped to a single named bucket"
        ));
        rows.add(row(
            "operation", "codecommit_repo_sync_no_delete",
            "instances", s.instance1,
            "service", "codecommit",
            "exact_actions", "codecommit:GitPull,codecommit:GitPush,codecommit:GetRepository,codecommit:GetBranch,codecommit:GetCommit,codecommit:ListRepositories,codecommit:ListBranches",
            "resource_scope", "arn:aws:codecommit:us-east-1:${aws:PrincipalAccount}:*",
            "condition_scope", "StringEquals aws:RequestedRegion=us-east-1 + explicit Deny on codecommit:DeleteRepository,codecommit:DeleteBranch",
            "source_script_or_snapshot", "synthetic:git-sync-policy",
            "evidence", "Synthetic fixture: git pull/push on primary node with explicit repository/branch delete deny"
        ));
        rows.add(row(
            "operation", "secrets_manager_read_only",
            "instances", both,
            "service", "secretsmanager,kms",
            "exact_actions", "secretsmanager:ListSecrets,secretsmanager:GetSecretValue,secretsmanager:DescribeSecret,kms:Decrypt",
            "resource_scope", "* (ListSecrets), arn:aws:secretsmanager:us-east-1:${aws:PrincipalAccount}:secret:* (GetSecretValue,DescribeSecret), arn:aws:kms:us-east-1:${aws:PrincipalAccount}:key/* (kms:Decrypt)",
            "condition_scope", "StringEquals aws:RequestedRegion=us-east-1; kms:Decrypt additionally requires kms:ViaService=secretsmanager.us-east-1.amazonaws.com",
            "source_script_or_snapshot", "synthetic:secrets-read-only",
            "evidence", "Synthetic fixture: read-only secret lookup and KMS decrypt via Secrets Manager in us-east-1"
        ));
        rows.add(row(
            "operation", "cognito_user_pools_non_destructive",
            "instances", both,
            "service", "cognito-idp",
            "exact_actions", "cognito-idp:ListUserPools,cognito-idp:DescribeUserPool,cognito-idp:ListUsers,cognito-idp:AdminGetUser,cognito-idp:AdminCreateUser,cognito-idp:AdminSetUserPassword",
            "resource_scope", "*",
            "condition_scope", "StringEquals aws:RequestedRegion=us-east-1, StringEqualsIfExists aws:ResourceAccount=${aws:PrincipalAccount} + unconditional explicit Deny on cognito-idp:*Delete*,ForgetDevice,AdminForgetDevice",
            "source_script_or_snapshot", "synthetic:cognito-non-destructive",
            "evidence", "Synthetic fixture: operational user-pool queries with unconditional deletion guard"
        ));
        rows.add(row(
            "operation", "ec2_origin_and_region_guardrails",
            "instances", both,
            "service", "all",
            "exact_actions", "Deny NotAction sts:GetCallerIdentity when Null ec2:SourceInstanceArn=true; Deny NotAction sts:*,s3:*,cloudfront:* when aws:RequestedRegion!=us-east-1",
            "resource_scope", "*",
            "condition_scope", "Null ec2:SourceInstanceArn=true; StringNotEquals aws:RequestedRegion=us-east-1",
            "source_script_or_snapshot", "synthetic:origin-and-region-guard",
            "evidence", "Synthetic fixture: prevents exported instance credentials from being used off-instance or outside us-east-1"
        ));
        return rows;
    }

    // --- 2. Policy Document Builders ---

    public static Map<String, Object> buildEc2TrustPolicyMap() {
        Map<String, Object> stmt = new LinkedHashMap<>();
        stmt.put("Sid", "TrustEc2ServiceOnly");
        stmt.put("Effect", "Allow");
        stmt.put("Principal", Map.of("Service", "ec2.amazonaws.com"));
        stmt.put("Action", "sts:AssumeRole");
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("Version", IamPolicies.EXPECTED_VERSION);
        doc.put("Statement", List.of(stmt));
        return doc;
    }

    public static String buildEc2TrustPolicyJson() {
        return IamPolicies.prettyJson(buildEc2TrustPolicyMap());
    }

    public static PolicyBuilder buildNode1Policy() {
        Spec s = Spec.active();
        String selfStopCond = IamPolicies.compactJson(Map.of(
            "StringEquals", row(
                "aws:ResourceTag/Project", s.projectTag,
                "aws:ResourceTag/Role", s.roleTag1,
                "aws:ResourceTag/Name", s.instance1,
                "aws:RequestedRegion", REGION
            )
        ));
        String regionIfExistsCond = IamPolicies.compactJson(Map.of(
            "StringEqualsIfExists", Map.of("aws:RequestedRegion", REGION)
        ));
        String regionEqCond = IamPolicies.compactJson(Map.of(
            "StringEquals", Map.of("aws:RequestedRegion", REGION)
        ));
        String kmsViaSecretsCond = IamPolicies.compactJson(Map.of(
            "StringEquals", row(
                "aws:RequestedRegion", REGION,
                "kms:ViaService", "secretsmanager.us-east-1.amazonaws.com"
            )
        ));
        Map<String, Object> cognitoMap = new LinkedHashMap<>();
        cognitoMap.put("StringEquals", Map.of("aws:RequestedRegion", REGION));
        cognitoMap.put("StringEqualsIfExists", Map.of("aws:ResourceAccount", "${aws:PrincipalAccount}"));
        String cognitoCond = IamPolicies.compactJson(cognitoMap);
        String originNullCond = IamPolicies.compactJson(Map.of(
            "Null", Map.of("ec2:SourceInstanceArn", "true")
        ));
        String nonRegionCond = IamPolicies.compactJson(Map.of(
            "StringNotEquals", Map.of("aws:RequestedRegion", REGION)
        ));

        return new PolicyBuilder(s.role1)
            .allowCond(
                "SelfStopNode1",
                "ec2:StopInstances",
                "arn:aws:ec2:us-east-1:${aws:PrincipalAccount}:instance/*",
                selfStopCond)
            .allowCond(
                "FleetAndCpuRead",
                "sts:GetCallerIdentity,ec2:DescribeInstances,ec2:DescribeInstanceStatus,ec2:DescribeInstanceAttribute,"
                    + "ec2:DescribeInstanceCreditSpecifications,ec2:DescribeInstanceTypes,ec2:DescribeVolumes,"
                    + "ec2:DescribeAddresses,ec2:DescribeTags,cloudwatch:GetMetricData",
                "*",
                regionIfExistsCond)
            .allowCond(
                "SsmPublicUbuntuAmiRead",
                "ssm:GetParameter,ssm:GetParameters",
                "arn:aws:ssm:us-east-1::parameter/aws/service/canonical/ubuntu/*",
                regionEqCond)
            .allowCond(
                "SsmAgentHeartbeat",
                "ssm:UpdateInstanceInformation,ssm:ListInstanceAssociations,ssm:ListAssociations",
                "*",
                regionEqCond)
            .allow(
                "AssumeStaticDeployRole",
                "sts:AssumeRole",
                "arn:aws:iam::${aws:PrincipalAccount}:role/" + s.deployRoleName)
            .allow(
                "AssetBucketRead",
                "s3:ListBucket,s3:GetBucketLocation",
                "arn:aws:s3:::" + s.assetBucketName)
            .allow(
                "AssetObjectSync",
                "s3:GetObject,s3:GetObjectTagging,s3:GetObjectAttributes,s3:PutObject,s3:PutObjectTagging,"
                    + "s3:DeleteObject,s3:DeleteObjectTagging,s3:AbortMultipartUpload",
                "arn:aws:s3:::" + s.assetBucketName + "/*")
            .allowCond(
                "CodeCommitSync",
                "codecommit:GitPull,codecommit:GitPush,codecommit:GetRepository,codecommit:GetBranch,"
                    + "codecommit:GetCommit,codecommit:ListRepositories,codecommit:ListBranches",
                "arn:aws:codecommit:us-east-1:${aws:PrincipalAccount}:*",
                regionEqCond)
            .allowCond(
                "SecretsManagerList",
                "secretsmanager:ListSecrets",
                "*",
                regionEqCond)
            .allowCond(
                "SecretsManagerRead",
                "secretsmanager:GetSecretValue,secretsmanager:DescribeSecret",
                "arn:aws:secretsmanager:us-east-1:${aws:PrincipalAccount}:secret:*",
                regionEqCond)
            .allowCond(
                "SecretsManagerKmsDecrypt",
                "kms:Decrypt",
                "arn:aws:kms:us-east-1:${aws:PrincipalAccount}:key/*",
                kmsViaSecretsCond)
            .allowCond(
                "CognitoUserPoolsOperational",
                "cognito-idp:ListUserPools,cognito-idp:DescribeUserPool,cognito-idp:ListUsers,"
                    + "cognito-idp:AdminGetUser,cognito-idp:AdminCreateUser,cognito-idp:AdminSetUserPassword",
                "*",
                cognitoCond)
            .deny(
                "DenyCodeCommitDelete",
                "codecommit:DeleteRepository,codecommit:DeleteBranch",
                "*")
            .deny(
                "DenyCognitoDestructive",
                "cognito-idp:*Delete*,cognito-idp:ForgetDevice,cognito-idp:AdminForgetDevice",
                "*")
            .denyNotAction(
                "DenyNonEc2InstanceOrigin",
                "sts:GetCallerIdentity",
                "*",
                originNullCond)
            .denyNotAction(
                "DenyNonUsEast1Region",
                "sts:*,s3:*,cloudfront:*",
                "*",
                nonRegionCond);
    }

    public static PolicyBuilder buildNode2Policy() {
        Spec s = Spec.active();
        String selfStopCond = IamPolicies.compactJson(Map.of(
            "StringEquals", row(
                "aws:ResourceTag/Project", s.projectTag,
                "aws:ResourceTag/Role", s.roleTag2,
                "aws:ResourceTag/Name", s.instance2,
                "aws:RequestedRegion", REGION
            )
        ));
        String regionIfExistsCond = IamPolicies.compactJson(Map.of(
            "StringEqualsIfExists", Map.of("aws:RequestedRegion", REGION)
        ));
        String regionEqCond = IamPolicies.compactJson(Map.of(
            "StringEquals", Map.of("aws:RequestedRegion", REGION)
        ));
        String kmsViaSecretsCond = IamPolicies.compactJson(Map.of(
            "StringEquals", row(
                "aws:RequestedRegion", REGION,
                "kms:ViaService", "secretsmanager.us-east-1.amazonaws.com"
            )
        ));
        Map<String, Object> cognitoMap = new LinkedHashMap<>();
        cognitoMap.put("StringEquals", Map.of("aws:RequestedRegion", REGION));
        cognitoMap.put("StringEqualsIfExists", Map.of("aws:ResourceAccount", "${aws:PrincipalAccount}"));
        String cognitoCond = IamPolicies.compactJson(cognitoMap);
        String originNullCond = IamPolicies.compactJson(Map.of(
            "Null", Map.of("ec2:SourceInstanceArn", "true")
        ));
        String nonRegionCond = IamPolicies.compactJson(Map.of(
            "StringNotEquals", Map.of("aws:RequestedRegion", REGION)
        ));

        return new PolicyBuilder(s.role2)
            .allowCond(
                "SelfStopNode2",
                "ec2:StopInstances",
                "arn:aws:ec2:us-east-1:${aws:PrincipalAccount}:instance/*",
                selfStopCond)
            .allowCond(
                "FleetAndCpuRead",
                "sts:GetCallerIdentity,ec2:DescribeInstances,ec2:DescribeInstanceStatus,ec2:DescribeInstanceAttribute,"
                    + "ec2:DescribeInstanceCreditSpecifications,ec2:DescribeInstanceTypes,ec2:DescribeVolumes,"
                    + "ec2:DescribeAddresses,ec2:DescribeTags,cloudwatch:GetMetricData",
                "*",
                regionIfExistsCond)
            .allowCond(
                "SsmPublicUbuntuAmiRead",
                "ssm:GetParameter,ssm:GetParameters",
                "arn:aws:ssm:us-east-1::parameter/aws/service/canonical/ubuntu/*",
                regionEqCond)
            .allowCond(
                "SsmAgentHeartbeat",
                "ssm:UpdateInstanceInformation,ssm:ListInstanceAssociations,ssm:ListAssociations",
                "*",
                regionEqCond)
            .allow(
                "AssumeStaticDeployRole",
                "sts:AssumeRole",
                "arn:aws:iam::${aws:PrincipalAccount}:role/" + s.deployRoleName)
            .allow(
                "AssetBucketRead",
                "s3:ListBucket,s3:GetBucketLocation",
                "arn:aws:s3:::" + s.assetBucketName)
            .allow(
                "AssetObjectSync",
                "s3:GetObject,s3:GetObjectTagging,s3:GetObjectAttributes,s3:PutObject,s3:PutObjectTagging,"
                    + "s3:DeleteObject,s3:DeleteObjectTagging,s3:AbortMultipartUpload",
                "arn:aws:s3:::" + s.assetBucketName + "/*")
            .allowCond(
                "SecretsManagerList",
                "secretsmanager:ListSecrets",
                "*",
                regionEqCond)
            .allowCond(
                "SecretsManagerRead",
                "secretsmanager:GetSecretValue,secretsmanager:DescribeSecret",
                "arn:aws:secretsmanager:us-east-1:${aws:PrincipalAccount}:secret:*",
                regionEqCond)
            .allowCond(
                "SecretsManagerKmsDecrypt",
                "kms:Decrypt",
                "arn:aws:kms:us-east-1:${aws:PrincipalAccount}:key/*",
                kmsViaSecretsCond)
            .allowCond(
                "CognitoUserPoolsOperational",
                "cognito-idp:ListUserPools,cognito-idp:DescribeUserPool,cognito-idp:ListUsers,"
                    + "cognito-idp:AdminGetUser,cognito-idp:AdminCreateUser,cognito-idp:AdminSetUserPassword",
                "*",
                cognitoCond)
            .deny(
                "DenyCognitoDestructive",
                "cognito-idp:*Delete*,cognito-idp:ForgetDevice,cognito-idp:AdminForgetDevice",
                "*")
            .denyNotAction(
                "DenyNonEc2InstanceOrigin",
                "sts:GetCallerIdentity",
                "*",
                originNullCond)
            .denyNotAction(
                "DenyNonUsEast1Region",
                "sts:*,s3:*,cloudfront:*",
                "*",
                nonRegionCond);
    }

    /**
     * Builds the mandatory permissions boundary that caps both operational instance roles.
     */
    public static PolicyBuilder buildBoundaryPolicy() {
        Spec s = Spec.active();
        Map<String, Object> selfStopEq = new LinkedHashMap<>();
        selfStopEq.put("aws:ResourceTag/Project", s.projectTag);
        selfStopEq.put("aws:ResourceTag/Role", List.of(s.roleTag1, s.roleTag2));
        selfStopEq.put("aws:RequestedRegion", REGION);
        String selfStopCond = IamPolicies.compactJson(Map.of("StringEquals", selfStopEq));
        String regionIfExistsCond = IamPolicies.compactJson(Map.of(
            "StringEqualsIfExists", Map.of("aws:RequestedRegion", REGION)
        ));
        String regionEqCond = IamPolicies.compactJson(Map.of(
            "StringEquals", Map.of("aws:RequestedRegion", REGION)
        ));
        String kmsViaSecretsCond = IamPolicies.compactJson(Map.of(
            "StringEquals", row(
                "aws:RequestedRegion", REGION,
                "kms:ViaService", "secretsmanager.us-east-1.amazonaws.com"
            )
        ));
        Map<String, Object> cognitoMap = new LinkedHashMap<>();
        cognitoMap.put("StringEquals", Map.of("aws:RequestedRegion", REGION));
        cognitoMap.put("StringEqualsIfExists", Map.of("aws:ResourceAccount", "${aws:PrincipalAccount}"));
        String cognitoCond = IamPolicies.compactJson(cognitoMap);
        String originNullCond = IamPolicies.compactJson(Map.of(
            "Null", Map.of("ec2:SourceInstanceArn", "true")
        ));
        String nonRegionCond = IamPolicies.compactJson(Map.of(
            "StringNotEquals", Map.of("aws:RequestedRegion", REGION)
        ));

        return new PolicyBuilder(s.boundaryName)
            .allowCond(
                "AllowSelfStopTaggedFleet",
                "ec2:StopInstances",
                "arn:aws:ec2:us-east-1:${aws:PrincipalAccount}:instance/*",
                selfStopCond)
            .allowCond(
                "AllowFleetAndCpuRead",
                "sts:GetCallerIdentity,ec2:DescribeInstances,ec2:DescribeInstanceStatus,ec2:DescribeInstanceAttribute,"
                    + "ec2:DescribeInstanceCreditSpecifications,ec2:DescribeInstanceTypes,ec2:DescribeVolumes,"
                    + "ec2:DescribeAddresses,ec2:DescribeTags,cloudwatch:GetMetricData",
                "*",
                regionIfExistsCond)
            .allowCond(
                "AllowSsmPublicUbuntuAmiRead",
                "ssm:GetParameter,ssm:GetParameters",
                "arn:aws:ssm:us-east-1::parameter/aws/service/canonical/ubuntu/*",
                regionEqCond)
            .allowCond(
                "AllowSsmAgentHeartbeat",
                "ssm:UpdateInstanceInformation,ssm:ListInstanceAssociations,ssm:ListAssociations",
                "*",
                regionEqCond)
            .allow(
                "AllowAssumeStaticDeployRole",
                "sts:AssumeRole",
                "arn:aws:iam::${aws:PrincipalAccount}:role/" + s.deployRoleName)
            .allow(
                "AllowAssetBucketRead",
                "s3:ListBucket,s3:GetBucketLocation",
                "arn:aws:s3:::" + s.assetBucketName)
            .allow(
                "AllowAssetObjectSync",
                "s3:GetObject,s3:GetObjectTagging,s3:GetObjectAttributes,s3:PutObject,s3:PutObjectTagging,"
                    + "s3:DeleteObject,s3:DeleteObjectTagging,s3:AbortMultipartUpload",
                "arn:aws:s3:::" + s.assetBucketName + "/*")
            .allowCond(
                "AllowCodeCommitSync",
                "codecommit:GitPull,codecommit:GitPush,codecommit:GetRepository,codecommit:GetBranch,"
                    + "codecommit:GetCommit,codecommit:ListRepositories,codecommit:ListBranches",
                "arn:aws:codecommit:us-east-1:${aws:PrincipalAccount}:*",
                regionEqCond)
            .allowCond(
                "AllowSecretsManagerList",
                "secretsmanager:ListSecrets",
                "*",
                regionEqCond)
            .allowCond(
                "AllowSecretsManagerRead",
                "secretsmanager:GetSecretValue,secretsmanager:DescribeSecret",
                "arn:aws:secretsmanager:us-east-1:${aws:PrincipalAccount}:secret:*",
                regionEqCond)
            .allowCond(
                "AllowSecretsManagerKmsDecrypt",
                "kms:Decrypt",
                "arn:aws:kms:us-east-1:${aws:PrincipalAccount}:key/*",
                kmsViaSecretsCond)
            .allowCond(
                "AllowCognitoUserPoolsOperational",
                "cognito-idp:ListUserPools,cognito-idp:DescribeUserPool,cognito-idp:ListUsers,"
                    + "cognito-idp:AdminGetUser,cognito-idp:AdminCreateUser,cognito-idp:AdminSetUserPassword",
                "*",
                cognitoCond)
            .deny(
                "DenyPrivilegeEscalationAndIam",
                "iam:*,organizations:*,account:*,kms:CreateKey,kms:ScheduleKeyDeletion,kms:PutKeyPolicy",
                "*")
            .deny(
                "DenyAssumeAdminControllerOrPeerRoles",
                "sts:AssumeRoleWithWebIdentity,sts:AssumeRoleWithSAML,sts:GetFederationToken",
                "*")
            .deny(
                "DenyAssumeProtectedRoles",
                "sts:AssumeRole",
                "arn:aws:iam::*:role/admin*,arn:aws:iam::*:role/lmaws_*")
            .deny(
                "DenyAuditAndLogTampering",
                "cloudtrail:DeleteTrail,cloudtrail:StopLogging,cloudtrail:UpdateTrail,"
                    + "config:DeleteConfigurationRecorder,config:StopConfigurationRecorder,config:DeleteDeliveryChannel",
                "*")
            .deny(
                "DenyDestructiveFleetActions",
                "ec2:TerminateInstances,ec2:DeleteVolume,ec2:ReleaseAddress,ec2:AssociateAddress,ec2:DisassociateAddress,"
                    + "ec2:RunInstances,ec2:StartInstances,ec2:AssociateIamInstanceProfile,"
                    + "ec2:DisassociateIamInstanceProfile,ec2:ReplaceIamInstanceProfileAssociation",
                "*")
            .deny(
                "DenyCodeCommitAndCognitoDeletes",
                "codecommit:DeleteRepository,codecommit:DeleteBranch,"
                    + "cognito-idp:*Delete*,cognito-idp:ForgetDevice,cognito-idp:AdminForgetDevice",
                "*")
            .denyNotAction(
                "DenyNonEc2InstanceOrigin",
                "sts:GetCallerIdentity",
                "*",
                originNullCond)
            .denyNotAction(
                "DenyNonUsEast1Region",
                "sts:*,s3:*,cloudfront:*",
                "*",
                nonRegionCond);
    }

    // --- 3. Read-Only Discovery ---

    private static void requireLiveSpec(AwsBackend backend) {
        if(!backend.isDemo() && !backend.fixtureEndpoint() && System.getenv().getOrDefault("LMAWS_FLEET_ROLES_SPEC","").isBlank()) throw new IllegalStateException("real fleet operations require an explicit private LMAWS_FLEET_ROLES_SPEC");
        Spec.active();
    }

    public static List<Map<String, String>> discover(AwsBackend backend) {
        requireLiveSpec(backend);
        Spec s = Spec.active();
        if (backend.isDemo()) {
            return List.of(
                row(
                    "kind", "fleet_instance_role_discovery",
                    "instance_name", s.instance1,
                    "instance_id", "i-************",
                    "role_tag", s.roleTag1,
                    "state", "running",
                    "instance_type", "t4g.nano",
                    "current_instance_profile", s.legacyRole,
                    "current_instance_profile_arn", "arn:aws:iam::************:instance-profile/" + s.legacyRole,
                    "association_id", "iip-assoc-************",
                    "association_state", "associated",
                    "current_role_name", s.legacyRole,
                    "current_effective_permissions", "Synthetic fixture: legacy wide role prior to least-privilege scoping",
                    "target_role_name", s.role1,
                    "target_instance_profile", s.role1,
                    "target_boundary_name", s.boundaryName,
                    "default_profile_ec2_read", "synthetic_demo (DescribeInstances + DescribeIamInstanceProfileAssociations)",
                    "default_profile_iam_read", "synthetic_demo (federated sts:GetFederationToken sessions cannot call iam:*)",
                    "default_profile_cloudtrail_read", "synthetic_demo (no live CloudTrail call in demo mode)",
                    "cloudtrail_observed_actions", "synthetic:ec2:DescribeInstances,synthetic:cloudwatch:GetMetricData"
                ),
                row(
                    "kind", "fleet_instance_role_discovery",
                    "instance_name", s.instance2,
                    "instance_id", "i-************",
                    "role_tag", s.roleTag2,
                    "state", "running",
                    "instance_type", "t4g.nano",
                    "current_instance_profile", s.legacyRole,
                    "current_instance_profile_arn", "arn:aws:iam::************:instance-profile/" + s.legacyRole,
                    "association_id", "iip-assoc-************",
                    "association_state", "associated",
                    "current_role_name", s.legacyRole,
                    "current_effective_permissions", "Synthetic fixture: legacy wide role prior to least-privilege scoping",
                    "target_role_name", s.role2,
                    "target_instance_profile", s.role2,
                    "target_boundary_name", s.boundaryName,
                    "default_profile_ec2_read", "synthetic_demo (DescribeInstances + DescribeIamInstanceProfileAssociations)",
                    "default_profile_iam_read", "synthetic_demo (federated sts:GetFederationToken sessions cannot call iam:*)",
                    "default_profile_cloudtrail_read", "synthetic_demo (no live CloudTrail call in demo mode)",
                    "cloudtrail_observed_actions", "synthetic:ec2:DescribeInstances,synthetic:secretsmanager:GetSecretValue"
                )
            );
        }

        List<InstanceTarget> targets = discoverLiveInstanceTargets(backend.ec2Client(), false, s);
        String iamProbeStatus = probeIamReadCapability(backend, s);
        CloudTrailProbe ctProbe = probeCloudTrailCapability(backend, targets, s);

        List<Map<String, String>> out = new ArrayList<>();
        for (InstanceTarget t : targets) {
            boolean isSecond = s.instance2.equals(t.instanceName);
            out.add(row(
                "kind", "fleet_instance_role_discovery",
                "instance_name", t.instanceName,
                "instance_id", maskFleetIds(t.instanceId),
                "role_tag", t.roleTag,
                "state", t.state,
                "instance_type", t.instanceType,
                "current_instance_profile", t.currentProfileName,
                "current_instance_profile_arn", maskFleetIds(t.currentProfileArn),
                "association_id", maskFleetIds(t.associationId),
                "association_state", t.associationState,
                "current_role_name", t.currentProfileName.isEmpty() ? s.legacyRole : t.currentProfileName,
                "current_effective_permissions", "Scoped replacement planned",
                "target_role_name", isSecond ? s.role2 : s.role1,
                "target_instance_profile", isSecond ? s.role2 : s.role1,
                "target_boundary_name", s.boundaryName,
                "default_profile_ec2_read", "allowed (DescribeInstances + DescribeIamInstanceProfileAssociations)",
                "default_profile_iam_read", iamProbeStatus,
                "default_profile_cloudtrail_read", ctProbe.status,
                "cloudtrail_observed_actions", ctProbe.observedActions
            ));
        }
        return out;
    }

    private record InstanceTarget(
        String instanceName,
        String instanceId,
        String roleTag,
        String state,
        String instanceType,
        String currentProfileName,
        String currentProfileArn,
        String associationId,
        String associationState
    ) {}

    private static List<InstanceTarget> discoverLiveInstanceTargets(Ec2Client ec2, boolean requireAssociations, Spec s) {
        DescribeInstancesRequest req = DescribeInstancesRequest.builder()
            .filters(
                Filter.builder().name("tag:Project").values(s.projectTag).build(),
                Filter.builder().name("tag:Name").values(s.instance1, s.instance2).build()
            )
            .build();
        Map<String, Instance> byName = new LinkedHashMap<>();
        for (var reservation : ec2.describeInstances(req).reservations()) {
            for (Instance inst : reservation.instances()) {
                if (inst.state() != null && "terminated".equalsIgnoreCase(inst.state().nameAsString())) {
                    continue;
                }
                String name = tagValue(inst.tags(), "Name");
                if (s.instance1.equals(name) || s.instance2.equals(name)) {
                    byName.put(name, inst);
                }
            }
        }

        List<InstanceTarget> targets = new ArrayList<>();
        for (String name : List.of(s.instance1, s.instance2)) {
            boolean isSecond = s.instance2.equals(name);
            Instance inst = byName.get(name);
            if (inst == null) {
                if (requireAssociations) {
                    throw new IllegalStateException("Fleet instance '" + name + "' (tag Project=" + s.projectTag + ", Name=" + name + ") not found");
                }
                targets.add(new InstanceTarget(
                    name, "i-************", isSecond ? s.roleTag2 : s.roleTag1,
                    "unknown", "t4g.nano", s.legacyRole,
                    "arn:aws:iam::************:instance-profile/" + s.legacyRole,
                    "iip-assoc-************", "associated"));
                continue;
            }
            String instId = inst.instanceId();
            String profileArn = inst.iamInstanceProfile() != null && inst.iamInstanceProfile().arn() != null
                ? inst.iamInstanceProfile().arn() : "";
            String assocId = "";
            String assocState = "";
            try {
                DescribeIamInstanceProfileAssociationsResponse assocResp = ec2.describeIamInstanceProfileAssociations(
                    DescribeIamInstanceProfileAssociationsRequest.builder()
                        .filters(Filter.builder().name("instance-id").values(instId).build())
                        .build()
                );
                for (IamInstanceProfileAssociation a : assocResp.iamInstanceProfileAssociations()) {
                    String st = a.stateAsString() == null ? "" : a.stateAsString();
                    if (!"disassociated".equalsIgnoreCase(st)) {
                        assocId = a.associationId() == null ? "" : a.associationId();
                        assocState = st;
                        if (a.iamInstanceProfile() != null && a.iamInstanceProfile().arn() != null && !a.iamInstanceProfile().arn().isBlank()) {
                            profileArn = a.iamInstanceProfile().arn();
                        }
                        break;
                    }
                }
            } catch (AwsServiceException ex) {
                if (requireAssociations) throw ex;
                assocState = "describe_associations_error:" + safeCode(ex);
            }
            if (requireAssociations && assocId.isBlank()) {
                throw new IllegalStateException("No active IAM instance profile association found for " + name);
            }
            String profileName = profileArn.contains("/")
                ? profileArn.substring(profileArn.lastIndexOf('/') + 1)
                : s.legacyRole;
            targets.add(new InstanceTarget(
                name,
                instId,
                tagValue(inst.tags(), "Role"),
                inst.state() == null ? "" : inst.state().nameAsString(),
                inst.instanceTypeAsString() == null ? "" : inst.instanceTypeAsString(),
                profileName,
                profileArn,
                assocId,
                assocState
            ));
        }
        return targets;
    }

    private static String probeIamReadCapability(AwsBackend backend, Spec s) {
        try {
            IamClient iam = backend.iamClient();
            GetRoleResponse role = iam.getRole(GetRoleRequest.builder().roleName(s.legacyRole).build());
            String arn = role.role() != null ? maskFleetIds(role.role().arn()) : s.legacyRole;
            return "allowed (iam:GetRole read " + arn + ")";
        } catch (AwsServiceException ex) {
            return "denied (" + safeCode(ex) + ": sts:GetFederationToken session cannot call iam:*)";
        } catch (RuntimeException ex) {
            return "unavailable (" + maskFleetIds(ex.getMessage()) + ")";
        }
    }

    private record CloudTrailProbe(String status, String observedActions) {}

    @SuppressWarnings("unchecked")
    private static CloudTrailProbe probeCloudTrailCapability(AwsBackend backend, List<InstanceTarget> targets, Spec s) {
        try (var http = UrlConnectionHttpClient.builder().build()) {
            AwsCredentialsProvider creds = backend.credentialsProvider();
            String endpoint = System.getenv().getOrDefault("LMAWS_ENDPOINT", "").trim();
            URI uri = endpoint.isEmpty()
                ? URI.create("https://cloudtrail." + REGION + ".amazonaws.com/")
                : URI.create(endpoint);
            long nowEpoch = Instant.now().getEpochSecond();
            long startEpoch = Instant.now().minus(30, ChronoUnit.DAYS).getEpochSecond();
            List<String> usernames = new ArrayList<>();
            for (InstanceTarget t : targets) {
                if (t.instanceId != null && t.instanceId.startsWith("i-") && !t.instanceId.contains("*")) {
                    usernames.add(t.instanceId);
                }
            }
            if (usernames.isEmpty()) usernames.add(s.legacyRole);

            Set<String> actions = new LinkedHashSet<>();
            int lastCode = 200;
            for (String username : usernames) {
                String body = "{\"LookupAttributes\":[{\"AttributeKey\":\"Username\",\"AttributeValue\":\"" + username + "\"}],"
                    + "\"MaxResults\":25,\"StartTime\":" + startEpoch + ",\"EndTime\":" + nowEpoch + "}";
                byte[] payload = body.getBytes(StandardCharsets.UTF_8);
                SdkHttpFullRequest unsigned = SdkHttpFullRequest.builder()
                    .uri(uri)
                    .method(SdkHttpMethod.POST)
                    .putHeader("Content-Type", "application/x-amz-json-1.1")
                    .putHeader("X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents")
                    .contentStreamProvider(() -> new ByteArrayInputStream(payload))
                    .build();
                SdkHttpFullRequest signed = software.amazon.awssdk.auth.signer.Aws4Signer.create().sign(
                    unsigned,
                    software.amazon.awssdk.auth.signer.params.Aws4SignerParams.builder()
                        .awsCredentials(creds.resolveCredentials())
                        .signingName("cloudtrail")
                        .signingRegion(Region.of(REGION))
                        .build());
                HttpExecuteResponse resp = http.prepareRequest(HttpExecuteRequest.builder()
                    .request(signed)
                    .contentStreamProvider(signed.contentStreamProvider().orElse(null))
                    .build()).call();
                lastCode = resp.httpResponse().statusCode();
                String text = "";
                if (resp.responseBody().isPresent()) {
                    try (InputStream in = resp.responseBody().get()) {
                        text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                    }
                }
                if (lastCode != 200) break;
                Object parsed = Json.parse(text);
                if (parsed instanceof Map<?, ?> map && map.get("Events") instanceof List<?> events) {
                    for (Object evObj : events) {
                        if (evObj instanceof Map<?, ?> ev) {
                            Object rawSrc = ev.get("EventSource");
                            Object rawName = ev.get("EventName");
                            String src = rawSrc == null ? "" : String.valueOf(rawSrc);
                            String name = rawName == null ? "" : String.valueOf(rawName);
                            if (src.endsWith(".amazonaws.com") && !name.isBlank()) {
                                String svc = src.substring(0, src.indexOf('.'));
                                actions.add(svc + ":" + name);
                            }
                        }
                    }
                }
            }
            if (lastCode == 200) {
                String joined = actions.isEmpty() ? "none_in_window" : String.join(",", actions);
                return new CloudTrailProbe("allowed (cloudtrail:LookupEvents HTTP 200)", joined);
            }
            int code = lastCode;
            return new CloudTrailProbe("denied_or_error (HTTP " + code + ")", "unavailable_via_cloudtrail");
        } catch (Exception ex) {
            return new CloudTrailProbe("unavailable (" + maskFleetIds(ex.getClass().getSimpleName()) + ")", "unavailable_via_cloudtrail");
        }
    }

    // --- 4. Plan Output (Diff, Removed Capabilities & Grant-on-Demand) ---

    public static List<Map<String, String>> removedCapabilitiesTable() {
        Spec s = Spec.active();
        return List.of(
            row("service", "iam", "previous_access", "iam:* (CreateRole, CreateUser, CreateAccessKey, AttachRolePolicy, PutRolePolicy, PassRole)", "new_access", "NONE (explicitly denied by " + s.boundaryName + ")", "risk_eliminated", "On-instance agents cannot create admin roles, mint IAM keys, pass roles, or modify policies"),
            row("service", "organizations,account,kms", "previous_access", "organizations:*, account:*, kms:*", "new_access", "NONE (explicitly denied by " + s.boundaryName + ")", "risk_eliminated", "Account-level settings and KMS key policies cannot be modified from an instance"),
            row("service", "sts", "previous_access", "sts:* (AssumeRole on any role, GetFederationToken)", "new_access", "sts:GetCallerIdentity + sts:AssumeRole ONLY on role/" + s.deployRoleName, "risk_eliminated", "Lateral movement to admin, controller, or peer instance roles is blocked"),
            row("service", "ec2_destructive", "previous_access", "ec2:TerminateInstances, ec2:DeleteVolume, ec2:ReleaseAddress, ec2:DeleteSnapshot, ec2:DeleteVpc", "new_access", "NONE (explicitly denied by " + s.boundaryName + ")", "risk_eliminated", "Root volumes, fleet instances, and Elastic IPs cannot be destroyed from inside an instance"),
            row("service", "ec2_fleet_controller", "previous_access", "ec2:RunInstances, ec2:StartInstances, ec2:AssociateAddress, ec2:DisassociateAddress, ec2:ReplaceIamInstanceProfileAssociation", "new_access", "ec2:StopInstances on SELF only (scoped by Project + Role + Name tags)", "risk_eliminated", "An instance cannot launch new instances, start stopped peers, rebind Elastic IPs, or swap its own IAM role"),
            row("service", "s3", "previous_access", "s3:* across every bucket in the account", "new_access", "Read/sync ONLY on arn:aws:s3:::" + s.assetBucketName + " and arn:aws:s3:::" + s.assetBucketName + "/*", "risk_eliminated", "Other S3 buckets and bucket policies cannot be read, modified, or deleted directly from the instance role"),
            row("service", "codecommit", "previous_access", "codecommit:* (including DeleteRepository, DeleteBranch)", "new_access", s.instance1 + " only: GitPull, GitPush, Get*, List* in us-east-1; DeleteRepository/DeleteBranch explicitly denied; " + s.instance2 + ": NONE", "risk_eliminated", "CodeCommit repositories and branches cannot be deleted"),
            row("service", "secretsmanager,kms", "previous_access", "secretsmanager:* (CreateSecret, PutSecretValue, DeleteSecret, GetSecretValue) + kms:*", "new_access", "Read-only ListSecrets, GetSecretValue, DescribeSecret + kms:Decrypt (conditioned on kms:ViaService=secretsmanager.us-east-1.amazonaws.com)", "risk_eliminated", "Secrets and KMS keys cannot be created, overwritten, rotated, or deleted"),
            row("service", "cognito-idp", "previous_access", "cognito-idp:*", "new_access", "Operational user-pool actions in us-east-1 with unconditional explicit Deny on *Delete*/ForgetDevice", "risk_eliminated", "Unconditional Cognito deletion guard enforced in both role and permissions boundary"),
            row("service", "cloudtrail,config", "previous_access", "cloudtrail:*, config:*", "new_access", "NONE (DeleteTrail, StopLogging, UpdateTrail, StopConfigurationRecorder explicitly denied)", "risk_eliminated", "Audit trails and configuration recorders cannot be disabled or tampered with"),
            row("service", "non_us_east_1_regions", "previous_access", "All AWS regions allowed by Action: *", "new_access", "Locked to us-east-1 (except global sts/s3/cloudfront control plane)", "risk_eliminated", "No shadow compute or storage can be accessed in unused regions")
        );
    }

    public static List<Map<String, String>> workflowImpactsTable() {
        Spec s = Spec.active();
        return List.of(
            row(
                "workflow", "Synthetic peer instance start/stop and Elastic IP re-association",
                "where_it_still_works", "Dedicated bastion controller or operator workstation",
                "what_stops_on_instance", "Starting a peer instance or re-associating an Elastic IP from inside a workhorse node is denied",
                "recommended_pattern", "Run fleet start/stop and Elastic IP cutover from the controller or operator workstation",
                "grant_on_demand_statement", IamPolicies.compactJson(Map.of(
                    "Sid", "GrantOnDemandPeerStartAndServiceEip",
                    "Effect", "Allow",
                    "Action", List.of("ec2:StartInstances", "ec2:AssociateAddress"),
                    "Resource", "*",
                    "Condition", Map.of("StringEquals", Map.of("aws:RequestedRegion", REGION))
                ))
            ),
            row(
                "workflow", "Synthetic direct CloudFront cache invalidation",
                "where_it_still_works", "Works when assuming role/" + s.deployRoleName + " via sts:AssumeRole",
                "what_stops_on_instance", "Calling cloudfront:CreateInvalidation directly with the ambient instance role without assuming the deploy role is denied",
                "recommended_pattern", "Assume role/" + s.deployRoleName + " for static asset publishing and CloudFront cache invalidation",
                "grant_on_demand_statement", IamPolicies.compactJson(Map.of(
                    "Sid", "GrantOnDemandCloudFrontInvalidation",
                    "Effect", "Allow",
                    "Action", List.of("cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"),
                    "Resource", "arn:aws:cloudfront::${aws:PrincipalAccount}:distribution/*"
                ))
            ),
            row(
                "workflow", "On-instance IAM role/policy/user edits",
                "where_it_still_works", "Operator workstation only via human-confirmed grant recipes (AWS_PROFILE=admin, LMAWS_ADMIN_GRANT=1, --apply, --i-am-the-admin-human)",
                "what_stops_on_instance", "All iam:* mutations are permanently denied on workhorse instances by both the role policy and " + s.boundaryName,
                "recommended_pattern", "No agent holds admin: human admin reviews the Operations Needs table and runs the grant recipe from the operator workstation",
                "grant_on_demand_statement", "NEVER_GRANTED_TO_INSTANCE_ROLE (use human-only AWS_PROFILE=admin on operator workstation)"
            ),
            row(
                "workflow", "Accessing an additional S3 bucket or SSM parameter path from an instance workload",
                "where_it_still_works", s.assetBucketName + " and /aws/service/canonical/ubuntu/* work out of the box",
                "what_stops_on_instance", "Direct s3:GetObject/PutObject on any other bucket or ssm:GetParameter on private parameters is implicitly denied",
                "recommended_pattern", "Human admin adds a resource-scoped Allow statement, lints with lint_instance_role(), and re-runs with --apply",
                "grant_on_demand_statement", IamPolicies.compactJson(Map.of(
                    "Sid", "GrantOnDemandScopedBucket",
                    "Effect", "Allow",
                    "Action", List.of("s3:GetObject", "s3:PutObject", "s3:ListBucket"),
                    "Resource", List.of("arn:aws:s3:::EXAMPLE-BUCKET", "arn:aws:s3:::EXAMPLE-BUCKET/*")
                ))
            ),
            row(
                "workflow", "Dedicated deploy role trust policy alignment",
                "where_it_still_works", "Both operational roles include AllowAssumeStaticDeployRole in their instance policy and boundary",
                "what_stops_on_instance", "Target deploy role trust policy must list the new operational role ARNs in Principal.AWS",
                "recommended_pattern", "Include arn:aws:iam::<account>:role/" + s.role1 + " and arn:aws:iam::<account>:role/" + s.role2 + " in the deploy role trust policy during cutover",
                "grant_on_demand_statement", IamPolicies.compactJson(Map.of(
                    "Sid", "AllowDeployFromOpsRoles",
                    "Effect", "Allow",
                    "Principal", Map.of("AWS", List.of(
                        "arn:aws:iam::${aws:PrincipalAccount}:role/" + s.role1,
                        "arn:aws:iam::${aws:PrincipalAccount}:role/" + s.role2
                    )),
                    "Action", "sts:AssumeRole"
                ))
            )
        );
    }

    public static Map<String, String> plan(AwsBackend backend) {
        requireLiveSpec(backend);
        Spec s = Spec.active();
        PolicyBuilder node1Builder = buildNode1Policy();
        PolicyBuilder node2Builder = buildNode2Policy();
        PolicyBuilder boundaryBuilder = buildBoundaryPolicy();
        String trustJson = buildEc2TrustPolicyJson();

        String node1Json = node1Builder.json();
        String node2Json = node2Builder.json();
        String boundaryJson = boundaryBuilder.json();

        IamPolicies.LintResult node1InstanceLint = IamPolicies.lintInstanceRole(node1Json);
        IamPolicies.LintResult node2InstanceLint = IamPolicies.lintInstanceRole(node2Json);
        IamPolicies.LintResult boundaryInstanceLint = IamPolicies.lintInstanceRole(boundaryJson);

        node1InstanceLint.requireValid();
        node2InstanceLint.requireValid();
        boundaryInstanceLint.requireValid();

        IamPolicies.LintResult node1SessionLint = IamPolicies.lint(node1Json);
        IamPolicies.LintResult node2SessionLint = IamPolicies.lint(node2Json);

        List<Map<String, String>> discoveryRows = discover(backend);
        List<Map<String, String>> opsRows = opsNeedsTable();
        List<Map<String, String>> removedRows = removedCapabilitiesTable();
        List<Map<String, String>> impactRows = workflowImpactsTable();

        Map<String, Object> rolePlans = new LinkedHashMap<>();
        rolePlans.put(s.instance1, Map.ofEntries(
            Map.entry("instance_name", s.instance1),
            Map.entry("role_tag", s.roleTag1),
            Map.entry("current_role", s.legacyRole),
            Map.entry("current_instance_profile", s.legacyRole),
            Map.entry("new_role", s.role1),
            Map.entry("new_instance_profile", s.role1),
            Map.entry("permissions_boundary", s.boundaryName),
            Map.entry("apply_order", "1 (applied and verified via read APIs before " + s.instance2 + ")"),
            Map.entry("statement_count", String.valueOf(node1InstanceLint.statementCount())),
            Map.entry("compact_length", String.valueOf(node1InstanceLint.compactLength())),
            Map.entry("instance_role_lint_valid", String.valueOf(node1InstanceLint.valid())),
            Map.entry("session_lint_valid", String.valueOf(node1SessionLint.valid())),
            Map.entry("trust_policy_json", trustJson),
            Map.entry("policy_json", node1Json)
        ));
        rolePlans.put(s.instance2, Map.ofEntries(
            Map.entry("instance_name", s.instance2),
            Map.entry("role_tag", s.roleTag2),
            Map.entry("current_role", s.legacyRole),
            Map.entry("current_instance_profile", s.legacyRole),
            Map.entry("new_role", s.role2),
            Map.entry("new_instance_profile", s.role2),
            Map.entry("permissions_boundary", s.boundaryName),
            Map.entry("apply_order", "2 (applied only after " + s.instance1 + " association is verified)"),
            Map.entry("statement_count", String.valueOf(node2InstanceLint.statementCount())),
            Map.entry("compact_length", String.valueOf(node2InstanceLint.compactLength())),
            Map.entry("instance_role_lint_valid", String.valueOf(node2InstanceLint.valid())),
            Map.entry("session_lint_valid", String.valueOf(node2SessionLint.valid())),
            Map.entry("trust_policy_json", trustJson),
            Map.entry("policy_json", node2Json)
        ));

        Map<String, String> out = new LinkedHashMap<>();
        out.put("kind", "fleet_roles_plan");
        out.put("mode", "dry_run_plan");
        out.put("applied", "false");
        out.put("profile", AwsBackend.activeProfile());
        out.put("region", REGION);
        out.put("node1_role", s.role1);
        out.put("node2_role", s.role2);
        out.put("boundary_name", s.boundaryName);
        out.put("node1_lint_valid", String.valueOf(node1InstanceLint.valid()));
        out.put("node2_lint_valid", String.valueOf(node2InstanceLint.valid()));
        out.put("boundary_lint_valid", String.valueOf(boundaryInstanceLint.valid()));
        out.put("node1_compact_length", String.valueOf(node1InstanceLint.compactLength()));
        out.put("node2_compact_length", String.valueOf(node2InstanceLint.compactLength()));
        out.put("boundary_compact_length", String.valueOf(boundaryInstanceLint.compactLength()));
        out.put("node1_statement_count", String.valueOf(node1InstanceLint.statementCount()));
        out.put("node2_statement_count", String.valueOf(node2InstanceLint.statementCount()));
        out.put("boundary_statement_count", String.valueOf(boundaryInstanceLint.statementCount()));
        out.put("trust_policy_json", trustJson);
        out.put("node1_policy_json", node1Json);
        out.put("node2_policy_json", node2Json);
        out.put("boundary_policy_json", boundaryJson);
        out.put("discovery_json", Jsons.encode(discoveryRows));
        out.put("ops_needs_json", Jsons.encode(opsRows));
        out.put("role_plans_json", Jsons.encode(rolePlans));
        out.put("removed_capabilities_json", Jsons.encode(removedRows));
        out.put("workflow_impacts_json", Jsons.encode(impactRows));
        return out;
    }

    // --- 5. Apply & One-Command Rollback (Sequential 1-by-1 Instance Swap) ---

    public static Map<String, String> apply(AwsBackend backend, boolean applyFlag, boolean humanConfirmed) {
        requireLiveSpec(backend);
        if (!applyFlag && !humanConfirmed) {
            return plan(backend);
        }
        checkAdminHumanApplyGuard(
            AwsBackend.activeProfile(),
            !backend.isDemo() && AwsBackend.isLiveEnabled(),
            backend.isAdminGrantEnabledForBackend(),
            applyFlag,
            humanConfirmed
        );
        String ci = System.getenv().getOrDefault("CI", "");
        if (!backend.isDemo() && !backend.fixtureEndpoint() && (ci.equalsIgnoreCase("true") || ci.equals("1"))) {
            throw new IllegalStateException("Live fleet role changes are forbidden in CI");
        }

        Spec s = Spec.active();
        String trustJson = IamPolicies.compactJson(buildEc2TrustPolicyMap());
        String node1Compact = buildNode1Policy().compactJson();
        String node2Compact = buildNode2Policy().compactJson();
        String boundaryCompact = buildBoundaryPolicy().compactJson();

        IamPolicies.lintInstanceRole(node1Compact).requireValid();
        IamPolicies.lintInstanceRole(node2Compact).requireValid();
        IamPolicies.lintInstanceRole(boundaryCompact).requireValid();

        String account = backend.stsClient().getCallerIdentity().account();
        Jsons.knownAccount(account);
        IamClient iam = backend.iamClient();
        Ec2Client ec2 = backend.ec2Client();

        // 1. Create or update the mandatory permissions boundary policy
        String boundaryArn = "arn:aws:iam::" + account + ":policy/" + s.boundaryName;
        ensureManagedBoundaryPolicy(iam, boundaryArn, s.boundaryName, boundaryCompact);

        // 2. Create or update roles + inline policies + instance profiles
        ensureFleetInstanceRoleAndProfile(iam, s.role1, trustJson, boundaryArn, node1Compact, s.instance1, s);
        ensureFleetInstanceRoleAndProfile(iam, s.role2, trustJson, boundaryArn, node2Compact, s.instance2, s);

        // 3. Discover current associations
        List<InstanceTarget> targets = discoverLiveInstanceTargets(ec2, true, s);
        List<Map<String, String>> rollbackEntries = new ArrayList<>();
        List<Map<String, String>> swapSteps = new ArrayList<>();

        // 4. Swap ONE instance at a time: first instance, verify read-only, then second instance
        for (InstanceTarget target : targets) {
            String newProfile = s.instance2.equals(target.instanceName) ? s.role2 : s.role1;
            String newProfileArn = "arn:aws:iam::" + account + ":instance-profile/" + newProfile;

            Map<String, String> rb = new LinkedHashMap<>();
            rb.put("instance_name", target.instanceName);
            rb.put("instance_id", target.instanceId);
            rb.put("association_id", target.associationId);
            rb.put("previous_profile_name", target.currentProfileName);
            rb.put("previous_profile_arn", target.currentProfileArn);
            rb.put("new_profile_name", newProfile);
            rb.put("new_profile_arn", newProfileArn);
            rollbackEntries.add(rb);

            ReplaceIamInstanceProfileAssociationResponse rep = ec2.replaceIamInstanceProfileAssociation(
                ReplaceIamInstanceProfileAssociationRequest.builder()
                    .associationId(target.associationId)
                    .iamInstanceProfile(IamInstanceProfileSpecification.builder()
                        .name(newProfile)
                        .build())
                    .build()
            );
            String updatedAssocId = rep.iamInstanceProfileAssociation() != null
                    && rep.iamInstanceProfileAssociation().associationId() != null
                ? rep.iamInstanceProfileAssociation().associationId()
                : target.associationId;
            rb.put("association_id", updatedAssocId);

            // Read-only verification before proceeding to the next instance
            String verifiedState = verifyAssociationAndStatusReadOnly(ec2, target.instanceId, updatedAssocId, newProfile);
            swapSteps.add(row(
                "instance_name", target.instanceName,
                "instance_id", maskFleetIds(target.instanceId),
                "association_id", maskFleetIds(updatedAssocId),
                "previous_profile", target.currentProfileName,
                "new_profile", newProfile,
                "verified_read_only", verifiedState
            ));
        }

        Map<String, Object> rollbackReceipt = new LinkedHashMap<>();
        rollbackReceipt.put("kind", "fleet_roles_rollback_receipt");
        rollbackReceipt.put("region", REGION);
        rollbackReceipt.put("boundary_name", s.boundaryName);
        rollbackReceipt.put("associations", rollbackEntries);

        Map<String, String> out = new LinkedHashMap<>(plan(backend));
        out.put("mode", "applied");
        out.put("applied", "true");
        out.put("swap_steps_json", Jsons.encode(swapSteps));
        out.put("rollback_receipt_json", Jsons.encode(rollbackReceipt));
        return out;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, String> rollback(
            AwsBackend backend,
            String rollbackReceiptJson,
            boolean applyFlag,
            boolean humanConfirmed) {
        requireLiveSpec(backend);
        if (rollbackReceiptJson == null || rollbackReceiptJson.isBlank()) {
            throw new IllegalArgumentException("Rollback requires a non-empty rollback receipt JSON");
        }
        Object parsed = Json.parse(rollbackReceiptJson);
        if (!(parsed instanceof Map<?, ?> map) || !(map.get("associations") instanceof List<?> rawList) || rawList.isEmpty()) {
            throw new IllegalArgumentException("Rollback receipt JSON must contain a non-empty 'associations' list");
        }

        Spec s = Spec.active();
        List<Map<String, String>> entries = new ArrayList<>();
        for (Object item : rawList) {
            if (!(item instanceof Map<?, ?> m)) continue;
            Map<String, String> entry = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                entry.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
            }
            entries.add(entry);
        }

        // Rollback in reverse order (second instance first, then first instance)
        List<Map<String, String>> reversed = new ArrayList<>(entries);
        java.util.Collections.reverse(reversed);

        if (!applyFlag && !humanConfirmed) {
            List<Map<String, String>> plannedSteps = new ArrayList<>();
            for (Map<String, String> entry : reversed) {
                plannedSteps.add(row(
                    "instance_name", entry.getOrDefault("instance_name", ""),
                    "instance_id", maskFleetIds(entry.getOrDefault("instance_id", "")),
                    "association_id", maskFleetIds(entry.getOrDefault("association_id", "")),
                    "from_profile", entry.getOrDefault("new_profile_name", ""),
                    "restore_profile", entry.getOrDefault("previous_profile_name", s.legacyRole),
                    "status", "dry_run_rollback_plan"
                ));
            }
            return row(
                "kind", "fleet_roles_rollback",
                "mode", "dry_run_rollback_plan",
                "applied", "false",
                "restored_count", String.valueOf(plannedSteps.size()),
                "steps_json", Jsons.encode(plannedSteps)
            );
        }

        checkAdminHumanApplyGuard(
            AwsBackend.activeProfile(),
            !backend.isDemo() && AwsBackend.isLiveEnabled(),
            backend.isAdminGrantEnabledForBackend(),
            applyFlag,
            humanConfirmed
        );
        String ci = System.getenv().getOrDefault("CI", "");
        if (!backend.isDemo() && !backend.fixtureEndpoint() && (ci.equalsIgnoreCase("true") || ci.equals("1"))) {
            throw new IllegalStateException("Live fleet role rollback is forbidden in CI");
        }

        Ec2Client ec2 = backend.ec2Client();
        List<Map<String, String>> restoredSteps = new ArrayList<>();
        for (Map<String, String> entry : reversed) {
            String instName = entry.getOrDefault("instance_name", "");
            String instId = entry.getOrDefault("instance_id", "");
            String assocId = entry.getOrDefault("association_id", "");
            String prevProfile = entry.getOrDefault("previous_profile_name", s.legacyRole);
            if (assocId.isBlank() || prevProfile.isBlank()) {
                throw new IllegalArgumentException("Rollback entry for '" + instName + "' is missing association_id or previous_profile_name");
            }
            ReplaceIamInstanceProfileAssociationResponse rep = ec2.replaceIamInstanceProfileAssociation(
                ReplaceIamInstanceProfileAssociationRequest.builder()
                    .associationId(assocId)
                    .iamInstanceProfile(IamInstanceProfileSpecification.builder()
                        .name(prevProfile)
                        .build())
                    .build()
            );
            String updatedAssocId = rep.iamInstanceProfileAssociation() != null
                    && rep.iamInstanceProfileAssociation().associationId() != null
                ? rep.iamInstanceProfileAssociation().associationId()
                : assocId;
            String verified = verifyAssociationAndStatusReadOnly(ec2, instId, updatedAssocId, prevProfile);
            restoredSteps.add(row(
                "instance_name", instName,
                "instance_id", maskFleetIds(instId),
                "association_id", maskFleetIds(updatedAssocId),
                "restored_profile", prevProfile,
                "verified_read_only", verified
            ));
        }

        return row(
            "kind", "fleet_roles_rollback",
            "mode", "rolled_back",
            "applied", "true",
            "restored_count", String.valueOf(restoredSteps.size()),
            "steps_json", Jsons.encode(restoredSteps)
        );
    }

    private static void ensureManagedBoundaryPolicy(
            IamClient iam,
            String policyArn,
            String policyName,
            String compactDocument) {
        try {
            var existing = iam.getPolicy(r -> r.policyArn(policyArn));
            String verId = existing.policy().defaultVersionId();
            var ver = iam.getPolicyVersion(r -> r.policyArn(policyArn).versionId(verId));
            String currentDoc = IamPolicies.compactJson(Json.parse(IamPolicies.decodeAwsDocument(ver.policyVersion().document())));
            if (!currentDoc.equals(compactDocument)) {
                iam.createPolicyVersion(r -> r.policyArn(policyArn).policyDocument(compactDocument).setAsDefault(true));
            }
        } catch (NoSuchEntityException missing) {
            iam.createPolicy(r -> r
                .policyName(policyName)
                .policyDocument(compactDocument)
                .description("Mandatory permissions boundary for operational EC2 instance roles"));
        } catch (AwsServiceException ex) {
            if (ex.statusCode() == 404 || "NoSuchEntity".equals(safeCode(ex))) {
                iam.createPolicy(r -> r
                    .policyName(policyName)
                    .policyDocument(compactDocument)
                    .description("Mandatory permissions boundary for operational EC2 instance roles"));
            } else {
                throw ex;
            }
        }
    }

    private static void ensureFleetInstanceRoleAndProfile(
            IamClient iam,
            String roleName,
            String trustCompact,
            String boundaryArn,
            String inlineCompact,
            String instanceName,
            Spec s) {
        Role existingRole = null;
        try {
            existingRole = iam.getRole(GetRoleRequest.builder().roleName(roleName).build()).role();
        } catch (NoSuchEntityException ignored) {
        } catch (AwsServiceException ex) {
            if (ex.statusCode() != 404 && !"NoSuchEntity".equals(safeCode(ex))) throw ex;
        }

        if (existingRole == null) {
            iam.createRole(CreateRoleRequest.builder()
                .roleName(roleName)
                .assumeRolePolicyDocument(trustCompact)
                .permissionsBoundary(boundaryArn)
                .description("Least-privilege operational instance role for " + instanceName)
                .tags(
                    software.amazon.awssdk.services.iam.model.Tag.builder().key("Project").value(s.projectTag).build(),
                    software.amazon.awssdk.services.iam.model.Tag.builder().key("Instance").value(instanceName).build()
                )
                .build());
        } else {
            String currentBoundary = existingRole.permissionsBoundary() != null
                ? existingRole.permissionsBoundary().permissionsBoundaryArn() : "";
            if (!boundaryArn.equals(currentBoundary)) {
                iam.putRolePermissionsBoundary(r -> r.roleName(roleName).permissionsBoundary(boundaryArn));
            }
            String currentTrust = IamPolicies.compactJson(Json.parse(IamPolicies.decodeAwsDocument(existingRole.assumeRolePolicyDocument())));
            if (!trustCompact.equals(currentTrust)) {
                iam.updateAssumeRolePolicy(UpdateAssumeRolePolicyRequest.builder()
                    .roleName(roleName)
                    .policyDocument(trustCompact)
                    .build());
            }
        }

        iam.putRolePolicy(PutRolePolicyRequest.builder()
            .roleName(roleName)
            .policyName(s.inlinePolicyName)
            .policyDocument(inlineCompact)
            .build());

        GetInstanceProfileResponse profileResp = null;
        try {
            profileResp = iam.getInstanceProfile(GetInstanceProfileRequest.builder().instanceProfileName(roleName).build());
        } catch (NoSuchEntityException ignored) {
        } catch (AwsServiceException ex) {
            if (ex.statusCode() != 404 && !"NoSuchEntity".equals(safeCode(ex))) throw ex;
        }

        if (profileResp == null) {
            iam.createInstanceProfile(CreateInstanceProfileRequest.builder()
                .instanceProfileName(roleName)
                .build());
            iam.addRoleToInstanceProfile(AddRoleToInstanceProfileRequest.builder()
                .instanceProfileName(roleName)
                .roleName(roleName)
                .build());
        } else {
            boolean hasRole = profileResp.instanceProfile() != null
                && profileResp.instanceProfile().roles() != null
                && profileResp.instanceProfile().roles().stream().anyMatch(r -> roleName.equals(r.roleName()));
            if (!hasRole) {
                iam.addRoleToInstanceProfile(AddRoleToInstanceProfileRequest.builder()
                    .instanceProfileName(roleName)
                    .roleName(roleName)
                    .build());
            }
        }
    }

    private static String verifyAssociationAndStatusReadOnly(
            Ec2Client ec2,
            String instanceId,
            String associationId,
            String expectedProfileName) {
        DescribeIamInstanceProfileAssociationsResponse assocResp = ec2.describeIamInstanceProfileAssociations(
            DescribeIamInstanceProfileAssociationsRequest.builder()
                .associationIds(associationId)
                .build()
        );
        String matchedArn = "";
        String assocState = "";
        for (IamInstanceProfileAssociation a : assocResp.iamInstanceProfileAssociations()) {
            assocState = a.stateAsString() == null ? "" : a.stateAsString();
            if (a.iamInstanceProfile() != null && a.iamInstanceProfile().arn() != null) {
                matchedArn = a.iamInstanceProfile().arn();
            }
        }
        if (!matchedArn.endsWith("/" + expectedProfileName)) {
            throw new IllegalStateException(
                "Read-only verification failed for " + maskFleetIds(instanceId)
                    + ": expected instance profile '" + expectedProfileName + "', got '" + maskFleetIds(matchedArn) + "'");
        }
        var statusResp = ec2.describeInstanceStatus(DescribeInstanceStatusRequest.builder()
            .instanceIds(instanceId)
            .includeAllInstances(true)
            .build());
        String instState = statusResp.instanceStatuses().isEmpty()
                || statusResp.instanceStatuses().get(0).instanceState() == null
            ? "unknown"
            : statusResp.instanceStatuses().get(0).instanceState().nameAsString();
        return "association_state=" + assocState + ",profile=" + expectedProfileName + ",instance_state=" + instState;
    }

    private static String tagValue(List<Tag> tags, String key) {
        if (tags == null) return "";
        for (Tag t : tags) {
            if (key.equals(t.key()) && t.value() != null) return t.value();
        }
        return "";
    }

    private static String safeCode(AwsServiceException ex) {
        return ex.awsErrorDetails() != null && ex.awsErrorDetails().errorCode() != null
            ? ex.awsErrorDetails().errorCode()
            : "AWS_SERVICE_ERROR";
    }

    private static Map<String, String> row(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1] == null ? "" : kv[i + 1]);
        }
        return m;
    }
}
