package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.sync.RequestBody;
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
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Plans and (only with explicit human-admin flags) applies least-privilege operational
 * IAM roles ({@code awsspot-ops-t4g1}, {@code awsspot-ops-t4g2}) and their mandatory
 * permissions boundary ({@code awsspot-ops-boundary}) for the two {@code awsspot} fleet
 * workhorse instances {@code t4g1} and {@code t4g2}.
 *
 * <p>Core invariant: "Eventually we do not want an agent to make an admin role" —
 * agents never hold or create admin; a human admin creates least-privilege operational
 * roles once, capped by a mandatory permissions boundary, and swaps instance profile
 * associations one instance at a time ({@code t4g1} first) with one-command rollback.
 */
public final class FleetRoles {
    public static final String ROLE_T4G1 = "awsspot-ops-t4g1";
    public static final String ROLE_T4G2 = "awsspot-ops-t4g2";
    public static final String BOUNDARY_NAME = "awsspot-ops-boundary";
    public static final String INLINE_POLICY_NAME = "awsspot_ops_permissions";
    public static final String CURRENT_ADMIN_ROLE = "awsspot-admin";
    public static final String REGION = "us-east-1";

    private FleetRoles() {}

    /**
     * Enforces the 5-way human-admin mutation guard required for any live fleet role
     * creation or instance-profile association replacement.
     */
    public static void checkAdminHumanApplyGuard(
            String profile,
            boolean live,
            boolean adminGrant,
            boolean applyFlag,
            boolean humanConfirmed) {
        String cleanProfile = profile == null ? "" : profile.trim();
        if (!applyFlag) {
            throw new IllegalStateException(
                "Fleet role changes require --apply (dry-run plan is the default)");
        }
        if (!humanConfirmed) {
            throw new IllegalStateException(
                "Fleet role changes require explicit human confirmation flag --i-am-the-admin-human (agents must never create or swap instance roles)");
        }
        if (!live) {
            throw new IllegalStateException(
                "Live fleet role changes require LMAWS_LIVE=1 (--live)");
        }
        if (!"admin".equals(cleanProfile)) {
            throw new IllegalStateException(
                "Fleet role changes require AWS_PROFILE=admin; refusing profile '" + cleanProfile + "'");
        }
        if (!adminGrant) {
            throw new IllegalStateException(
                "Fleet role changes with the admin profile require LMAWS_ADMIN_GRANT=1");
        }
    }

    /**
     * Masks concrete AWS account IDs, EC2 instance IDs, volume IDs, EIP allocation IDs,
     * and IAM instance profile association IDs so outputs are safe for committed artifacts.
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

    // --- 1. Operations Needs Model ---

    public static List<Map<String, String>> opsNeedsTable() {
        List<Map<String, String>> rows = new ArrayList<>();
        rows.add(row(
            "operation", "self_stop_watchdog",
            "instances", "t4g1,t4g2",
            "service", "ec2",
            "exact_actions", "ec2:StopInstances",
            "resource_scope", "arn:aws:ec2:us-east-1:${aws:PrincipalAccount}:instance/*",
            "condition_scope", "StringEquals aws:ResourceTag/Project=awsspot, aws:ResourceTag/Role=current|m7g, aws:ResourceTag/Name=t4g1|t4g2, aws:RequestedRegion=us-east-1",
            "source_script_or_snapshot", "scripts/install-idle-watchdog.sh, scripts/m7g-cpu-idle-watchdog.sh, tasks/iam-snapshots/idle-stopper.after.json, tasks/iam-snapshots/m7g-instance.json",
            "evidence", "systemd awsspot-idle-stop.timer (15m SSH/tmux check on t4g1) and m7g-cpu-idle-watchdog (CPU <15% for 6 checks on t4g2) call StopInstances on self"
        ));
        rows.add(row(
            "operation", "fleet_status_and_cpu_monitor",
            "instances", "t4g1,t4g2",
            "service", "ec2,cloudwatch,sts",
            "exact_actions", "sts:GetCallerIdentity,ec2:DescribeInstances,ec2:DescribeInstanceStatus,ec2:DescribeInstanceAttribute,ec2:DescribeInstanceCreditSpecifications,ec2:DescribeInstanceTypes,ec2:DescribeVolumes,ec2:DescribeAddresses,ec2:DescribeTags,cloudwatch:GetMetricData",
            "resource_scope", "*",
            "condition_scope", "StringEqualsIfExists aws:RequestedRegion=us-east-1",
            "source_script_or_snapshot", "scripts/awsspot-fleet.sh (status/cpu), tasks/iam-snapshots/idle-stopper.cpu-monitor.json, tasks/iam-snapshots/m7g-instance.json",
            "evidence", "awsspot-fleet.sh status & cpu and lmaws fleet_status/fleet_cpu_credits read EC2 metadata and CloudWatch CPUUtilization/CPUCreditBalance metrics"
        ));
        rows.add(row(
            "operation", "ssm_public_ami_lookup_and_agent_heartbeat",
            "instances", "t4g1,t4g2",
            "service", "ssm",
            "exact_actions", "ssm:GetParameter,ssm:GetParameters,ssm:UpdateInstanceInformation,ssm:ListInstanceAssociations,ssm:ListAssociations",
            "resource_scope", "arn:aws:ssm:us-east-1::parameter/aws/service/canonical/ubuntu/* (GetParameter*), * (agent heartbeat)",
            "condition_scope", "StringEquals aws:RequestedRegion=us-east-1",
            "source_script_or_snapshot", "tasks/iam-snapshots/idle-stopper.after.json, tasks/iam-snapshots/m7g-instance.json, 30d CloudTrail LookupEvents",
            "evidence", "Public Canonical Ubuntu 24.04 ARM64 AMI parameter lookup plus Ubuntu snap.amazon-ssm-agent heartbeat (30d CloudTrail: t4g1 295 UpdateInstanceInformation + 126 ListInstanceAssociations; t4g2 406 + 175)"
        ));
        rows.add(row(
            "operation", "website_deploy_assume_role",
            "instances", "t4g1,t4g2",
            "service", "sts",
            "exact_actions", "sts:AssumeRole",
            "resource_scope", "arn:aws:iam::${aws:PrincipalAccount}:role/lmctl-website-deploy",
            "condition_scope", "Target role trust policy requires explicit principal ARN",
            "source_script_or_snapshot", "tasks/iam-snapshots/m7g-assume-website-deploy.json, tasks/iam-snapshots/lmctl-website-deploy.trust-with-admin.json",
            "evidence", "Publishing static content to lmnature.com / www.lmnature.com assumes the dedicated lmctl-website-deploy role (S3 + CloudFront CreateInvalidation)"
        ));
        rows.add(row(
            "operation", "s3_www_egtry_com_sync",
            "instances", "t4g1,t4g2",
            "service", "s3",
            "exact_actions", "s3:ListBucket,s3:GetBucketLocation,s3:GetObject,s3:GetObjectTagging,s3:GetObjectAttributes,s3:PutObject,s3:PutObjectTagging,s3:DeleteObject,s3:DeleteObjectTagging,s3:AbortMultipartUpload",
            "resource_scope", "arn:aws:s3:::www.egtry.com, arn:aws:s3:::www.egtry.com/*",
            "condition_scope", "Bucket and object ARNs locked to www.egtry.com; bucket deletion/policy changes denied",
            "source_script_or_snapshot", "tasks/iam-snapshots/idle-stopper.s3-www-egtry-com-write.json, durable-memory/always-on.md",
            "evidence", "Static site sync to www.egtry.com from t4g1 (and hot-standby t4g2 during service EIP failover)"
        ));
        rows.add(row(
            "operation", "codecommit_repo_sync_no_delete",
            "instances", "t4g1",
            "service", "codecommit",
            "exact_actions", "codecommit:GitPull,codecommit:GitPush,codecommit:GetRepository,codecommit:GetBranch,codecommit:GetCommit,codecommit:ListRepositories,codecommit:ListBranches",
            "resource_scope", "arn:aws:codecommit:us-east-1:${aws:PrincipalAccount}:*",
            "condition_scope", "StringEquals aws:RequestedRegion=us-east-1 + explicit Deny on codecommit:DeleteRepository,codecommit:DeleteBranch",
            "source_script_or_snapshot", "tasks/iam-snapshots/idle-stopper.with-codecommit.json",
            "evidence", "Git pull/push for CodeCommit repositories from primary workstation t4g1 without repository or branch deletion rights"
        ));
        rows.add(row(
            "operation", "secrets_manager_read_only",
            "instances", "t4g1,t4g2",
            "service", "secretsmanager,kms",
            "exact_actions", "secretsmanager:ListSecrets,secretsmanager:GetSecretValue,secretsmanager:DescribeSecret,kms:Decrypt",
            "resource_scope", "* (ListSecrets), arn:aws:secretsmanager:us-east-1:${aws:PrincipalAccount}:secret:* (GetSecretValue,DescribeSecret), arn:aws:kms:us-east-1:${aws:PrincipalAccount}:key/* (kms:Decrypt)",
            "condition_scope", "StringEquals aws:RequestedRegion=us-east-1; kms:Decrypt additionally requires kms:ViaService=secretsmanager.us-east-1.amazonaws.com",
            "source_script_or_snapshot", "tasks/iam-snapshots/t4g2-secrets-read.json, 30d CloudTrail LookupEvents",
            "evidence", "Read-only secret retrieval on both workhorses (30d CloudTrail: t4g1 43 GetSecretValue + 43 kms:Decrypt + 2 ListSecrets; t4g2 60 GetSecretValue + 60 kms:Decrypt)"
        ));
        rows.add(row(
            "operation", "cognito_user_pools_non_destructive",
            "instances", "t4g1,t4g2",
            "service", "cognito-idp",
            "exact_actions", "cognito-idp:ListUserPools,cognito-idp:DescribeUserPool,cognito-idp:ListUsers,cognito-idp:AdminGetUser,cognito-idp:AdminCreateUser,cognito-idp:AdminSetUserPassword",
            "resource_scope", "*",
            "condition_scope", "StringEquals aws:RequestedRegion=us-east-1, StringEqualsIfExists aws:ResourceAccount=${aws:PrincipalAccount} + unconditional explicit Deny on cognito-idp:*Delete*,ForgetDevice,AdminForgetDevice",
            "source_script_or_snapshot", "tasks/iam-snapshots/t4g2-cognito-user-pools.json, tasks/iam-snapshots/awsspot-admin.permissions.json, 30d CloudTrail LookupEvents",
            "evidence", "Cognito User Pool operations on both workhorses (30d CloudTrail: t4g1 70 ListUsers; t4g2 44 ListUsers) with unconditional deletion guard"
        ));
        rows.add(row(
            "operation", "ec2_origin_and_region_guardrails",
            "instances", "t4g1,t4g2",
            "service", "all",
            "exact_actions", "Deny NotAction sts:GetCallerIdentity when Null ec2:SourceInstanceArn=true; Deny NotAction sts:*,s3:*,cloudfront:* when aws:RequestedRegion!=us-east-1",
            "resource_scope", "*",
            "condition_scope", "Null ec2:SourceInstanceArn=true; StringNotEquals aws:RequestedRegion=us-east-1",
            "source_script_or_snapshot", "tasks/iam-snapshots/awsspot-admin.permissions.json, tasks/iam-snapshots/idle-stopper.after.json",
            "evidence", "Prevents exported instance role credentials from being used off-instance or outside us-east-1"
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

    public static PolicyBuilder buildT4g1Policy() {
        String selfStopCond = IamPolicies.compactJson(Map.of(
            "StringEquals", row(
                "aws:ResourceTag/Project", "awsspot",
                "aws:ResourceTag/Role", "current",
                "aws:ResourceTag/Name", "t4g1",
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

        return new PolicyBuilder(ROLE_T4G1)
            .allowCond(
                "SelfStopT4g1",
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
                "AssumeWebsiteDeployRole",
                "sts:AssumeRole",
                "arn:aws:iam::${aws:PrincipalAccount}:role/lmctl-website-deploy")
            .allow(
                "WwwEgtryComBucketRead",
                "s3:ListBucket,s3:GetBucketLocation",
                "arn:aws:s3:::www.egtry.com")
            .allow(
                "WwwEgtryComObjectSync",
                "s3:GetObject,s3:GetObjectTagging,s3:GetObjectAttributes,s3:PutObject,s3:PutObjectTagging,"
                    + "s3:DeleteObject,s3:DeleteObjectTagging,s3:AbortMultipartUpload",
                "arn:aws:s3:::www.egtry.com/*")
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

    public static PolicyBuilder buildT4g2Policy() {
        String selfStopCond = IamPolicies.compactJson(Map.of(
            "StringEquals", row(
                "aws:ResourceTag/Project", "awsspot",
                "aws:ResourceTag/Role", "m7g",
                "aws:ResourceTag/Name", "t4g2",
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

        return new PolicyBuilder(ROLE_T4G2)
            .allowCond(
                "SelfStopT4g2",
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
                "AssumeWebsiteDeployRole",
                "sts:AssumeRole",
                "arn:aws:iam::${aws:PrincipalAccount}:role/lmctl-website-deploy")
            .allow(
                "WwwEgtryComBucketRead",
                "s3:ListBucket,s3:GetBucketLocation",
                "arn:aws:s3:::www.egtry.com")
            .allow(
                "WwwEgtryComObjectSync",
                "s3:GetObject,s3:GetObjectTagging,s3:GetObjectAttributes,s3:PutObject,s3:PutObjectTagging,"
                    + "s3:DeleteObject,s3:DeleteObjectTagging,s3:AbortMultipartUpload",
                "arn:aws:s3:::www.egtry.com/*")
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
     * Builds the mandatory permissions boundary ({@code awsspot-ops-boundary}) that caps both
     * {@code awsspot-ops-t4g1} and {@code awsspot-ops-t4g2}. Even if a future policy edit attached
     * broader permissions to an instance role, this boundary explicitly denies:
     * <ul>
     *   <li>{@code iam:*} (including {@code iam:PassRole}, role/policy/user/access-key creation),
     *       {@code organizations:*}, and {@code account:*}</li>
     *   <li>{@code sts:AssumeRole} on any admin, controller, or peer role (only {@code lmctl-website-deploy} is permitted)</li>
     *   <li>{@code cloudtrail:*} and {@code config:*} audit tampering</li>
     *   <li>Destructive fleet mutations ({@code ec2:TerminateInstances}, {@code ec2:DeleteVolume},
     *       {@code ec2:ReleaseAddress}, {@code ec2:ReplaceIamInstanceProfileAssociation}, {@code ec2:RunInstances})</li>
     *   <li>CodeCommit and Cognito deletes</li>
     *   <li>Non-EC2 credential origin and non-{@code us-east-1} regions</li>
     * </ul>
     */
    public static PolicyBuilder buildBoundaryPolicy() {
        Map<String, Object> selfStopEq = new LinkedHashMap<>();
        selfStopEq.put("aws:ResourceTag/Project", "awsspot");
        selfStopEq.put("aws:ResourceTag/Role", List.of("current", "m7g"));
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

        return new PolicyBuilder(BOUNDARY_NAME)
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
                "AllowAssumeWebsiteDeployRole",
                "sts:AssumeRole",
                "arn:aws:iam::${aws:PrincipalAccount}:role/lmctl-website-deploy")
            .allow(
                "AllowWwwEgtryComBucketRead",
                "s3:ListBucket,s3:GetBucketLocation",
                "arn:aws:s3:::www.egtry.com")
            .allow(
                "AllowWwwEgtryComObjectSync",
                "s3:GetObject,s3:GetObjectTagging,s3:GetObjectAttributes,s3:PutObject,s3:PutObjectTagging,"
                    + "s3:DeleteObject,s3:DeleteObjectTagging,s3:AbortMultipartUpload",
                "arn:aws:s3:::www.egtry.com/*")
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
                "arn:aws:iam::*:role/awsspot-*,arn:aws:iam::*:role/admin*,arn:aws:iam::*:role/lmaws_*")
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

    public static List<Map<String, String>> discover(AwsBackend backend) {
        if (backend.isDemo()) {
            return List.of(
                row(
                    "kind", "fleet_instance_role_discovery",
                    "instance_name", "t4g1",
                    "instance_id", "i-************",
                    "role_tag", "current",
                    "state", "running",
                    "instance_type", "t4g.xlarge",
                    "current_instance_profile", CURRENT_ADMIN_ROLE,
                    "current_instance_profile_arn", "arn:aws:iam::************:instance-profile/" + CURRENT_ADMIN_ROLE,
                    "association_id", "iip-assoc-************",
                    "association_state", "associated",
                    "current_role_name", CURRENT_ADMIN_ROLE,
                    "current_effective_permissions", "Action: * on Resource: * (admin wildcard conditioned on ec2:SourceInstanceArn + VPC + private IP)",
                    "target_role_name", ROLE_T4G1,
                    "target_instance_profile", ROLE_T4G1,
                    "target_boundary_name", BOUNDARY_NAME,
                    "default_profile_ec2_read", "allowed (DescribeInstances + DescribeIamInstanceProfileAssociations)",
                    "default_profile_iam_read", "denied_for_federated_principal (sts:GetFederationToken cannot call iam:*; resolved from verified snapshot tasks/iam-snapshots/awsspot-admin.permissions.json)",
                    "default_profile_cloudtrail_read", "synthetic_demo (mirrors 30d CloudTrail LookupEvents by EC2 role session username)",
                    "cloudtrail_observed_actions", "ssm:UpdateInstanceInformation,ssm:ListInstanceAssociations,ec2:DescribeAddresses,cognito-idp:ListUsers,ec2:AssociateAddress,secretsmanager:GetSecretValue,kms:Decrypt,secretsmanager:ListSecrets,cloudfront:CreateInvalidation"
                ),
                row(
                    "kind", "fleet_instance_role_discovery",
                    "instance_name", "t4g2",
                    "instance_id", "i-************",
                    "role_tag", "m7g",
                    "state", "running",
                    "instance_type", "t4g.xlarge",
                    "current_instance_profile", CURRENT_ADMIN_ROLE,
                    "current_instance_profile_arn", "arn:aws:iam::************:instance-profile/" + CURRENT_ADMIN_ROLE,
                    "association_id", "iip-assoc-************",
                    "association_state", "associated",
                    "current_role_name", CURRENT_ADMIN_ROLE,
                    "current_effective_permissions", "Action: * on Resource: * (admin wildcard conditioned on ec2:SourceInstanceArn + VPC + private IP, plus PreserveSecondHostCognitoDeletionGuard)",
                    "target_role_name", ROLE_T4G2,
                    "target_instance_profile", ROLE_T4G2,
                    "target_boundary_name", BOUNDARY_NAME,
                    "default_profile_ec2_read", "allowed (DescribeInstances + DescribeIamInstanceProfileAssociations)",
                    "default_profile_iam_read", "denied_for_federated_principal (sts:GetFederationToken cannot call iam:*; resolved from verified snapshot tasks/iam-snapshots/awsspot-admin.permissions.json)",
                    "default_profile_cloudtrail_read", "synthetic_demo (mirrors 30d CloudTrail LookupEvents by EC2 role session username)",
                    "cloudtrail_observed_actions", "ssm:UpdateInstanceInformation,ssm:ListInstanceAssociations,secretsmanager:GetSecretValue,kms:Decrypt,cognito-idp:ListUsers,ec2:DescribeAddresses,ec2:DescribeInstances,sts:GetCallerIdentity"
                )
            );
        }

        List<InstanceTarget> targets = discoverLiveInstanceTargets(backend.ec2Client(), false);
        String iamProbeStatus = probeIamReadCapability(backend);
        CloudTrailProbe ctProbe = probeCloudTrailCapability(backend, targets);

        List<Map<String, String>> out = new ArrayList<>();
        for (InstanceTarget t : targets) {
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
                "current_role_name", t.currentProfileName.isEmpty() ? CURRENT_ADMIN_ROLE : t.currentProfileName,
                "current_effective_permissions", "t4g2".equals(t.instanceName)
                    ? "Action: * on Resource: * (admin wildcard conditioned on ec2:SourceInstanceArn + VPC + private IP, plus PreserveSecondHostCognitoDeletionGuard)"
                    : "Action: * on Resource: * (admin wildcard conditioned on ec2:SourceInstanceArn + VPC + private IP)",
                "target_role_name", "t4g2".equals(t.instanceName) ? ROLE_T4G2 : ROLE_T4G1,
                "target_instance_profile", "t4g2".equals(t.instanceName) ? ROLE_T4G2 : ROLE_T4G1,
                "target_boundary_name", BOUNDARY_NAME,
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

    private static List<InstanceTarget> discoverLiveInstanceTargets(Ec2Client ec2, boolean requireAssociations) {
        DescribeInstancesRequest req = DescribeInstancesRequest.builder()
            .filters(
                Filter.builder().name("tag:Project").values("awsspot").build(),
                Filter.builder().name("tag:Name").values("t4g1", "t4g2").build()
            )
            .build();
        Map<String, Instance> byName = new LinkedHashMap<>();
        for (var reservation : ec2.describeInstances(req).reservations()) {
            for (Instance inst : reservation.instances()) {
                if (inst.state() != null && "terminated".equalsIgnoreCase(inst.state().nameAsString())) {
                    continue;
                }
                String name = tagValue(inst.tags(), "Name");
                if ("t4g1".equals(name) || "t4g2".equals(name)) {
                    byName.put(name, inst);
                }
            }
        }

        List<InstanceTarget> targets = new ArrayList<>();
        for (String name : List.of("t4g1", "t4g2")) {
            Instance inst = byName.get(name);
            if (inst == null) {
                if (requireAssociations) {
                    throw new IllegalStateException("Fleet instance '" + name + "' (tag Project=awsspot, Name=" + name + ") not found");
                }
                targets.add(new InstanceTarget(
                    name, "i-************", "t4g2".equals(name) ? "m7g" : "current",
                    "unknown", "t4g.xlarge", CURRENT_ADMIN_ROLE,
                    "arn:aws:iam::************:instance-profile/" + CURRENT_ADMIN_ROLE,
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
                : CURRENT_ADMIN_ROLE;
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

    private static String probeIamReadCapability(AwsBackend backend) {
        try {
            IamClient iam = backend.iamClient();
            GetRoleResponse role = iam.getRole(GetRoleRequest.builder().roleName(CURRENT_ADMIN_ROLE).build());
            String arn = role.role() != null ? maskFleetIds(role.role().arn()) : CURRENT_ADMIN_ROLE;
            return "allowed (iam:GetRole read " + arn + ")";
        } catch (AwsServiceException ex) {
            return "denied (" + safeCode(ex) + ": sts:GetFederationToken session cannot call iam:*; using verified repo snapshots in tasks/iam-snapshots/)";
        } catch (RuntimeException ex) {
            return "unavailable (" + maskFleetIds(ex.getMessage()) + ")";
        }
    }

    private record CloudTrailProbe(String status, String observedActions) {}

    @SuppressWarnings("unchecked")
    private static CloudTrailProbe probeCloudTrailCapability(AwsBackend backend, List<InstanceTarget> targets) {
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
            if (usernames.isEmpty()) usernames.add(CURRENT_ADMIN_ROLE);

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
                return new CloudTrailProbe("allowed (cloudtrail:LookupEvents HTTP 200 over 30d by EC2 role session username)", joined);
            }
            int code = lastCode;
            return new CloudTrailProbe(
                "denied_or_error (HTTP " + code + "; operations model derived from awsspot scripts/*.sh and tasks/iam-snapshots/*.json)",
                "unavailable_via_cloudtrail"
            );
        } catch (Exception ex) {
            return new CloudTrailProbe(
                "unavailable (" + maskFleetIds(ex.getClass().getSimpleName()) + "; operations model derived from awsspot scripts/*.sh and tasks/iam-snapshots/*.json)",
                "unavailable_via_cloudtrail"
            );
        }
    }

    // --- 4. Plan Output (Diff, Removed Capabilities, Script Impacts & Grant-on-Demand) ---

    public static List<Map<String, String>> removedCapabilitiesTable() {
        return List.of(
            row("service", "iam", "previous_access", "iam:* (CreateRole, CreateUser, CreateAccessKey, AttachRolePolicy, PutRolePolicy, PassRole)", "new_access", "NONE (explicitly denied by awsspot-ops-boundary)", "risk_eliminated", "On-instance agents cannot create admin roles, mint IAM keys, pass roles, or modify policies"),
            row("service", "organizations,account,kms", "previous_access", "organizations:*, account:*, kms:*", "new_access", "NONE (explicitly denied by awsspot-ops-boundary)", "risk_eliminated", "Account-level settings and KMS key policies cannot be modified from an instance"),
            row("service", "sts", "previous_access", "sts:* (AssumeRole on any role, GetFederationToken)", "new_access", "sts:GetCallerIdentity + sts:AssumeRole ONLY on role/lmctl-website-deploy", "risk_eliminated", "Lateral movement to admin, controller, or peer instance roles is blocked"),
            row("service", "ec2_destructive", "previous_access", "ec2:TerminateInstances, ec2:DeleteVolume, ec2:ReleaseAddress, ec2:DeleteSnapshot, ec2:DeleteVpc", "new_access", "NONE (explicitly denied by awsspot-ops-boundary)", "risk_eliminated", "Protected 150 GiB root volumes, fleet instances, and service/bastion EIPs cannot be destroyed from inside an instance"),
            row("service", "ec2_fleet_controller", "previous_access", "ec2:RunInstances, ec2:StartInstances, ec2:AssociateAddress, ec2:DisassociateAddress, ec2:ReplaceIamInstanceProfileAssociation", "new_access", "ec2:StopInstances on SELF only (scoped by Project=awsspot + Role + Name tags)", "risk_eliminated", "A compromised instance cannot launch new instances, start stopped peers, hijack the service EIP, or swap its own IAM role"),
            row("service", "s3", "previous_access", "s3:* across every bucket in the account", "new_access", "Read/sync ONLY on arn:aws:s3:::www.egtry.com and arn:aws:s3:::www.egtry.com/* (plus website bucket via lmctl-website-deploy)", "risk_eliminated", "Other S3 buckets and bucket policies cannot be read, modified, or deleted directly from the instance role"),
            row("service", "codecommit", "previous_access", "codecommit:* (including DeleteRepository, DeleteBranch)", "new_access", "t4g1 only: GitPull, GitPush, Get*, List* in us-east-1; DeleteRepository/DeleteBranch explicitly denied; t4g2: NONE", "risk_eliminated", "CodeCommit repositories and branches cannot be deleted"),
            row("service", "secretsmanager,kms", "previous_access", "secretsmanager:* (CreateSecret, PutSecretValue, DeleteSecret, GetSecretValue) + kms:*", "new_access", "t4g1 & t4g2: read-only ListSecrets, GetSecretValue, DescribeSecret + kms:Decrypt (conditioned on kms:ViaService=secretsmanager.us-east-1.amazonaws.com)", "risk_eliminated", "Secrets and KMS keys cannot be created, overwritten, rotated, or deleted from either instance"),
            row("service", "cognito-idp", "previous_access", "cognito-idp:* (with delete guard only on t4g2's current instance ID)", "new_access", "t4g1 & t4g2: operational user-pool actions in us-east-1 with unconditional explicit Deny on *Delete*/ForgetDevice", "risk_eliminated", "Cognito deletion guard covers both workhorses, survives instance replacement, and is enforced in both role and permissions boundary"),
            row("service", "cloudtrail,config", "previous_access", "cloudtrail:*, config:*", "new_access", "NONE (DeleteTrail, StopLogging, UpdateTrail, StopConfigurationRecorder explicitly denied)", "risk_eliminated", "Audit trails and configuration recorders cannot be disabled or tampered with"),
            row("service", "non_us_east_1_regions", "previous_access", "All AWS regions allowed by Action: *", "new_access", "Locked to us-east-1 (except global sts/s3/cloudfront control plane)", "risk_eliminated", "No shadow compute or storage can be accessed in unused regions")
        );
    }

    public static List<Map<String, String>> workflowImpactsTable() {
        return List.of(
            row(
                "workflow", "scripts/awsspot-fleet.sh up|down|use & scripts/eip.sh (observed in 30d CloudTrail on t4g1: 26 AssociateAddress OK + 68 DryRunOperation)",
                "where_it_still_works", "Works unchanged from bastion t3 (awsspot-t3-controller) and from the operator laptop (AWS_PROFILE=lmaws-ec2 / admin)",
                "what_stops_on_instance", "Running 'awsspot-fleet.sh up t4g2', 'awsspot-fleet.sh use t4g1|t4g2', or 'eip.sh' FROM INSIDE t4g1 or t4g2 is denied (ec2:StartInstances, ec2:StopInstances on peer, ec2:AssociateAddress)",
                "recommended_pattern", "Run fleet start/stop and service EIP cutover from bastion t3 or operator laptop rather than from inside a workhorse instance",
                "grant_on_demand_statement", IamPolicies.compactJson(Map.of(
                    "Sid", "GrantOnDemandPeerStartAndServiceEip",
                    "Effect", "Allow",
                    "Action", List.of("ec2:StartInstances", "ec2:AssociateAddress"),
                    "Resource", "*",
                    "Condition", Map.of("StringEquals", Map.of("aws:RequestedRegion", REGION))
                ))
            ),
            row(
                "workflow", "Direct CloudFront invalidation without assuming lmctl-website-deploy (observed in 30d CloudTrail on t4g1: 1 cloudfront:CreateInvalidation OK)",
                "where_it_still_works", "Works out of the box when scripts/s3-www.sh assumes arn:aws:iam::<account>:role/lmctl-website-deploy via sts:AssumeRole",
                "what_stops_on_instance", "Calling cloudfront:CreateInvalidation directly with the ambient instance role credentials without first assuming lmctl-website-deploy is denied",
                "recommended_pattern", "Always assume role/lmctl-website-deploy for website S3 sync and CloudFront cache invalidation",
                "grant_on_demand_statement", IamPolicies.compactJson(Map.of(
                    "Sid", "GrantOnDemandCloudFrontInvalidation",
                    "Effect", "Allow",
                    "Action", List.of("cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"),
                    "Resource", "arn:aws:cloudfront::${aws:PrincipalAccount}:distribution/*"
                ))
            ),
            row(
                "workflow", "On-instance IAM role/policy/user edits (aws iam create-role / put-role-policy / attach-role-policy)",
                "where_it_still_works", "Operator laptop only via lmaws grant recipes (AWS_PROFILE=admin, LMAWS_ADMIN_GRANT=1, --apply, --i-am-the-admin-human)",
                "what_stops_on_instance", "All iam:* mutations are permanently denied on t4g1 and t4g2 by both the role policy and awsspot-ops-boundary",
                "recommended_pattern", "No agent holds admin: human admin reviews the Operations Needs table and runs lmaws recipes/fleet_roles.lms from the operator workstation",
                "grant_on_demand_statement", "NEVER_GRANTED_TO_INSTANCE_ROLE (use human-only AWS_PROFILE=admin on operator workstation)"
            ),
            row(
                "workflow", "Accessing a new S3 bucket or SSM parameter path from an instance workload",
                "where_it_still_works", "www.egtry.com and /aws/service/canonical/ubuntu/* work out of the box; lmnature.com works via sts:AssumeRole -> lmctl-website-deploy",
                "what_stops_on_instance", "Direct s3:GetObject/PutObject on any other bucket or ssm:GetParameter on private parameters is implicitly denied",
                "recommended_pattern", "Human admin adds a resource-scoped Allow statement to buildT4g1Policy/buildT4g2Policy and buildBoundaryPolicy, lints with lint_instance_role(), and re-runs fleet_roles.lms --apply",
                "grant_on_demand_statement", IamPolicies.compactJson(Map.of(
                    "Sid", "GrantOnDemandScopedBucket",
                    "Effect", "Allow",
                    "Action", List.of("s3:GetObject", "s3:PutObject", "s3:ListBucket"),
                    "Resource", List.of("arn:aws:s3:::EXAMPLE-BUCKET", "arn:aws:s3:::EXAMPLE-BUCKET/*")
                ))
            ),
            row(
                "workflow", "lmctl-website-deploy role assumption & t3 PassRole companion policies",
                "where_it_still_works", "Both t4g1 and t4g2 have AllowAssumeWebsiteDeployRole in their instance policy and boundary",
                "what_stops_on_instance", "lmctl-website-deploy's trust policy (lmctl-website-deploy.trust-with-admin.json) currently lists role/awsspot-admin and role/awsspot-m7g in Principal.AWS; it must also list role/awsspot-ops-t4g1 and role/awsspot-ops-t4g2",
                "recommended_pattern", "Update lmctl-website-deploy trust policy to include arn:aws:iam::<account>:role/awsspot-ops-t4g1 and arn:aws:iam::<account>:role/awsspot-ops-t4g2 during cutover",
                "grant_on_demand_statement", IamPolicies.compactJson(Map.of(
                    "Sid", "AllowWebsiteDeployFromOpsRoles",
                    "Effect", "Allow",
                    "Principal", Map.of("AWS", List.of(
                        "arn:aws:iam::${aws:PrincipalAccount}:role/" + ROLE_T4G1,
                        "arn:aws:iam::${aws:PrincipalAccount}:role/" + ROLE_T4G2
                    )),
                    "Action", "sts:AssumeRole"
                ))
            )
        );
    }

    public static Map<String, String> plan(AwsBackend backend) {
        PolicyBuilder t4g1Builder = buildT4g1Policy();
        PolicyBuilder t4g2Builder = buildT4g2Policy();
        PolicyBuilder boundaryBuilder = buildBoundaryPolicy();
        String trustJson = buildEc2TrustPolicyJson();

        String t4g1Json = t4g1Builder.json();
        String t4g2Json = t4g2Builder.json();
        String boundaryJson = boundaryBuilder.json();

        IamPolicies.LintResult t4g1InstanceLint = IamPolicies.lintInstanceRole(t4g1Json);
        IamPolicies.LintResult t4g2InstanceLint = IamPolicies.lintInstanceRole(t4g2Json);
        IamPolicies.LintResult boundaryInstanceLint = IamPolicies.lintInstanceRole(boundaryJson);

        t4g1InstanceLint.requireValid();
        t4g2InstanceLint.requireValid();
        boundaryInstanceLint.requireValid();

        // Also run standard session lint to show the exact architectural distinction
        IamPolicies.LintResult t4g1SessionLint = IamPolicies.lint(t4g1Json);
        IamPolicies.LintResult t4g2SessionLint = IamPolicies.lint(t4g2Json);

        List<Map<String, String>> discoveryRows = discover(backend);
        List<Map<String, String>> opsRows = opsNeedsTable();
        List<Map<String, String>> removedRows = removedCapabilitiesTable();
        List<Map<String, String>> impactRows = workflowImpactsTable();

        Map<String, Object> rolePlans = new LinkedHashMap<>();
        rolePlans.put("t4g1", Map.ofEntries(
            Map.entry("instance_name", "t4g1"),
            Map.entry("role_tag", "current"),
            Map.entry("current_role", CURRENT_ADMIN_ROLE),
            Map.entry("current_instance_profile", CURRENT_ADMIN_ROLE),
            Map.entry("new_role", ROLE_T4G1),
            Map.entry("new_instance_profile", ROLE_T4G1),
            Map.entry("permissions_boundary", BOUNDARY_NAME),
            Map.entry("apply_order", "1 (applied and verified via read APIs before t4g2)"),
            Map.entry("statement_count", String.valueOf(t4g1InstanceLint.statementCount())),
            Map.entry("compact_length", String.valueOf(t4g1InstanceLint.compactLength())),
            Map.entry("instance_role_lint_valid", String.valueOf(t4g1InstanceLint.valid())),
            Map.entry("session_lint_valid", String.valueOf(t4g1SessionLint.valid())),
            Map.entry("trust_policy_json", trustJson),
            Map.entry("policy_json", t4g1Json)
        ));
        rolePlans.put("t4g2", Map.ofEntries(
            Map.entry("instance_name", "t4g2"),
            Map.entry("role_tag", "m7g"),
            Map.entry("current_role", CURRENT_ADMIN_ROLE),
            Map.entry("current_instance_profile", CURRENT_ADMIN_ROLE),
            Map.entry("new_role", ROLE_T4G2),
            Map.entry("new_instance_profile", ROLE_T4G2),
            Map.entry("permissions_boundary", BOUNDARY_NAME),
            Map.entry("apply_order", "2 (applied only after t4g1 association is verified)"),
            Map.entry("statement_count", String.valueOf(t4g2InstanceLint.statementCount())),
            Map.entry("compact_length", String.valueOf(t4g2InstanceLint.compactLength())),
            Map.entry("instance_role_lint_valid", String.valueOf(t4g2InstanceLint.valid())),
            Map.entry("session_lint_valid", String.valueOf(t4g2SessionLint.valid())),
            Map.entry("trust_policy_json", trustJson),
            Map.entry("policy_json", t4g2Json)
        ));

        Map<String, String> out = new LinkedHashMap<>();
        out.put("kind", "fleet_roles_plan");
        out.put("mode", "dry_run_plan");
        out.put("applied", "false");
        out.put("profile", AwsBackend.activeProfile());
        out.put("region", REGION);
        out.put("t4g1_role", ROLE_T4G1);
        out.put("t4g2_role", ROLE_T4G2);
        out.put("boundary_name", BOUNDARY_NAME);
        out.put("t4g1_lint_valid", String.valueOf(t4g1InstanceLint.valid()));
        out.put("t4g2_lint_valid", String.valueOf(t4g2InstanceLint.valid()));
        out.put("boundary_lint_valid", String.valueOf(boundaryInstanceLint.valid()));
        out.put("t4g1_compact_length", String.valueOf(t4g1InstanceLint.compactLength()));
        out.put("t4g2_compact_length", String.valueOf(t4g2InstanceLint.compactLength()));
        out.put("boundary_compact_length", String.valueOf(boundaryInstanceLint.compactLength()));
        out.put("t4g1_statement_count", String.valueOf(t4g1InstanceLint.statementCount()));
        out.put("t4g2_statement_count", String.valueOf(t4g2InstanceLint.statementCount()));
        out.put("boundary_statement_count", String.valueOf(boundaryInstanceLint.statementCount()));
        out.put("trust_policy_json", trustJson);
        out.put("t4g1_policy_json", t4g1Json);
        out.put("t4g2_policy_json", t4g2Json);
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

        String trustJson = IamPolicies.compactJson(buildEc2TrustPolicyMap());
        String t4g1Compact = buildT4g1Policy().compactJson();
        String t4g2Compact = buildT4g2Policy().compactJson();
        String boundaryCompact = buildBoundaryPolicy().compactJson();

        IamPolicies.lintInstanceRole(t4g1Compact).requireValid();
        IamPolicies.lintInstanceRole(t4g2Compact).requireValid();
        IamPolicies.lintInstanceRole(boundaryCompact).requireValid();

        String account = backend.stsClient().getCallerIdentity().account();
        Jsons.knownAccount(account);
        IamClient iam = backend.iamClient();
        Ec2Client ec2 = backend.ec2Client();

        // 1. Create or update the mandatory permissions boundary policy
        String boundaryArn = "arn:aws:iam::" + account + ":policy/" + BOUNDARY_NAME;
        ensureManagedBoundaryPolicy(iam, boundaryArn, BOUNDARY_NAME, boundaryCompact);

        // 2. Create or update roles + inline policies + instance profiles
        ensureFleetInstanceRoleAndProfile(iam, ROLE_T4G1, trustJson, boundaryArn, t4g1Compact, "t4g1");
        ensureFleetInstanceRoleAndProfile(iam, ROLE_T4G2, trustJson, boundaryArn, t4g2Compact, "t4g2");

        // 3. Discover current associations for t4g1 and t4g2
        List<InstanceTarget> targets = discoverLiveInstanceTargets(ec2, true);
        List<Map<String, String>> rollbackEntries = new ArrayList<>();
        List<Map<String, String>> swapSteps = new ArrayList<>();

        // 4. Swap ONE instance at a time: t4g1 first, verify read-only, then t4g2
        for (InstanceTarget target : targets) {
            String newProfile = "t4g2".equals(target.instanceName) ? ROLE_T4G2 : ROLE_T4G1;
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
        rollbackReceipt.put("boundary_name", BOUNDARY_NAME);
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
        if (rollbackReceiptJson == null || rollbackReceiptJson.isBlank()) {
            throw new IllegalArgumentException("Rollback requires a non-empty rollback receipt JSON");
        }
        Object parsed = Json.parse(rollbackReceiptJson);
        if (!(parsed instanceof Map<?, ?> map) || !(map.get("associations") instanceof List<?> rawList) || rawList.isEmpty()) {
            throw new IllegalArgumentException("Rollback receipt JSON must contain a non-empty 'associations' list");
        }

        List<Map<String, String>> entries = new ArrayList<>();
        for (Object item : rawList) {
            if (!(item instanceof Map<?, ?> m)) continue;
            Map<String, String> entry = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                entry.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
            }
            entries.add(entry);
        }

        // Rollback in reverse order (t4g2 first, then t4g1)
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
                    "restore_profile", entry.getOrDefault("previous_profile_name", CURRENT_ADMIN_ROLE),
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
            String prevProfile = entry.getOrDefault("previous_profile_name", CURRENT_ADMIN_ROLE);
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
                .description("Mandatory permissions boundary for awsspot fleet operational instance roles"));
        } catch (AwsServiceException ex) {
            if (ex.statusCode() == 404 || "NoSuchEntity".equals(safeCode(ex))) {
                iam.createPolicy(r -> r
                    .policyName(policyName)
                    .policyDocument(compactDocument)
                    .description("Mandatory permissions boundary for awsspot fleet operational instance roles"));
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
            String instanceName) {
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
                .description("Least-privilege operational instance role for awsspot " + instanceName)
                .tags(
                    software.amazon.awssdk.services.iam.model.Tag.builder().key("Project").value("awsspot").build(),
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
            .policyName(INLINE_POLICY_NAME)
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
