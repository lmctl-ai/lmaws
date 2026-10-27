package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Typed fluent IAM policy builder that validates actions against {@link PolicyCatalog},
 * provides ARN and condition intent helpers, composes reusable sandbox/role blocks,
 * and compiles to canonical IAM policy JSON (2012-10-17).
 */
public final class PolicyBuilder {
    private static final Pattern PREFIX_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,32}$");
    private static final Pattern TAG_KEY_PATTERN = Pattern.compile("^[a-zA-Z0-9_.:/=+@-]{1,128}$");
    private static final Pattern SID_PATTERN = Pattern.compile("^[A-Za-z0-9]{1,64}$");

    private final String name;
    private final List<Map<String, Object>> statements = new ArrayList<>();

    public PolicyBuilder(String name) {
        String clean = (name == null || name.isBlank()) ? "lmaws_policy" : name.trim();
        this.name = clean;
    }

    public String name() {
        return name;
    }

    public List<Map<String, Object>> statements() {
        return statements;
    }

    // --- Core statement methods ---

    public PolicyBuilder allow(String sid, String actionsCsv, String resourcesCsv) {
        return addStatement(sid, "Allow", false, actionsCsv, resourcesCsv, null);
    }

    public PolicyBuilder allowCond(String sid, String actionsCsv, String resourcesCsv, String conditionJson) {
        return addStatement(sid, "Allow", false, actionsCsv, resourcesCsv, parseCondition(conditionJson));
    }

    public PolicyBuilder deny(String sid, String actionsCsv, String resourcesCsv) {
        return addStatement(sid, "Deny", false, actionsCsv, resourcesCsv, null);
    }

    public PolicyBuilder denyCond(String sid, String actionsCsv, String resourcesCsv, String conditionJson) {
        return addStatement(sid, "Deny", false, actionsCsv, resourcesCsv, parseCondition(conditionJson));
    }

    public PolicyBuilder denyNotAction(String sid, String notActionsCsv, String resourcesCsv, String conditionJson) {
        return addStatement(sid, "Deny", true, notActionsCsv, resourcesCsv, parseCondition(conditionJson));
    }

    // --- Catalog & ARN helpers ---

    public String arn(String service, String resourceType, String namePattern) {
        return PolicyCatalog.arn(service, resourceType, namePattern);
    }

    public String expandActions(String pattern) {
        return String.join(",", PolicyCatalog.expandPattern(pattern));
    }

    public String classifyAction(String action) {
        PolicyCatalog.validatePattern(action);
        return PolicyCatalog.classify(action);
    }

    // --- Intent helpers (instead of raw IAM conditions) ---

    /**
     * Grants wildcard or specified service actions on resource ARNs built from prefix + separators
     * (e.g., prefix="lmaws", separators="-,_" builds lmaws-* for S3 and both lmaws-* and lmaws_*
     * for SQS, SNS, DynamoDB, SSM, Logs, Lambda, Events), optionally locking aws:ResourceAccount
     * to ${aws:PrincipalAccount}.
     */
    public PolicyBuilder namePrefix(
            String sid,
            String servicesCsv,
            String prefix,
            String separatorsCsv,
            boolean principalAccountLock) {
        requirePrefix(prefix);
        List<String> services = splitCsv(servicesCsv);
        if (services.isEmpty()) {
            throw new IllegalArgumentException("name_prefix requires at least one service");
        }
        List<String> separators = splitCsv(separatorsCsv);
        if (separators.isEmpty()) {
            separators = List.of("-", "_");
        }
        List<String> actions = new ArrayList<>();
        for (String svc : services) {
            String lower = svc.toLowerCase(Locale.ROOT);
            actions.add(PolicyCatalog.validatePattern(lower + ":*"));
        }
        List<String> resources = new ArrayList<>();
        for (String sep : separators) {
            if (!"-".equals(sep) && !"_".equals(sep)) {
                throw new IllegalArgumentException("name_prefix separator must be '-' or '_', got: " + sep);
            }
            for (String svc : services) {
                String lower = svc.toLowerCase(Locale.ROOT);
                if ("_".equals(sep) && !PolicyCatalog.supportsUnderscoreNames(lower)) {
                    continue;
                }
                String pat = prefix + sep + "*";
                if ("s3".equals(lower)) {
                    resources.add(PolicyCatalog.arn("s3", "bucket", pat));
                    resources.add(PolicyCatalog.arn("s3", "object", pat + "/*"));
                } else if ("dynamodb".equals(lower)) {
                    resources.add(PolicyCatalog.arn("dynamodb", "table", pat));
                } else if ("ssm".equals(lower)) {
                    resources.add(PolicyCatalog.arn("ssm", "parameter", pat));
                } else if ("logs".equals(lower)) {
                    resources.add(PolicyCatalog.arn("logs", "log-group", pat));
                } else if ("lambda".equals(lower)) {
                    resources.add(PolicyCatalog.arn("lambda", "function", pat));
                } else if ("events".equals(lower)) {
                    resources.add(PolicyCatalog.arn("events", "rule", pat));
                } else {
                    resources.add(PolicyCatalog.arn(lower, "", pat));
                }
            }
        }
        Map<String, Object> cond = null;
        if (principalAccountLock) {
            cond = singleCond("StringEqualsIfExists", "aws:ResourceAccount", "${aws:PrincipalAccount}");
        }
        return addStatementMap(sid, "Allow", false, actions, resources, cond);
    }

    /**
     * Allows creation actions only when the request includes the specified tag key
     * (Condition: Null -> aws:RequestTag/<tagKey> = "false").
     */
    public PolicyBuilder requireTagOnCreate(String sid, String actionsCsv, String resourcesCsv, String tagKey) {
        requireTagKey(tagKey);
        Map<String, Object> cond = singleCond("Null", "aws:RequestTag/" + tagKey, "false");
        return addStatement(sid, "Allow", false, actionsCsv, resourcesCsv, cond);
    }

    /**
     * Allows actions only on resources that already carry the specified tag key
     * (Condition: Null -> <namespace>:ResourceTag/<tagKey> = "false", where namespace is "aws" or "ec2").
     */
    public PolicyBuilder onlyTagged(String sid, String actionsCsv, String resourcesCsv, String tagKey, String tagNamespace) {
        requireTagKey(tagKey);
        String ns = (tagNamespace == null || tagNamespace.isBlank()) ? "aws" : tagNamespace.trim().toLowerCase(Locale.ROOT);
        if (!"aws".equals(ns) && !"ec2".equals(ns)) {
            throw new IllegalArgumentException("only_tagged namespace must be 'aws' or 'ec2', got: " + ns);
        }
        Map<String, Object> cond = singleCond("Null", ns + ":ResourceTag/" + tagKey, "false");
        return addStatement(sid, "Allow", false, actionsCsv, resourcesCsv, cond);
    }

    /**
     * Allows ec2:CreateTags only during specified ec2:CreateAction operations (e.g., RunInstances,CreateSecurityGroup).
     */
    public PolicyBuilder tagOnCreateActions(String sid, String createActionsCsv, String resourcePattern) {
        List<String> createActs = splitCsv(createActionsCsv);
        if (createActs.isEmpty()) {
            throw new IllegalArgumentException("tag_on_create_actions requires at least one ec2:CreateAction");
        }
        Map<String, Object> cond = singleCond("StringEquals", "ec2:CreateAction", scalarOrList(createActs));
        String res = (resourcePattern == null || resourcePattern.isBlank()) ? "arn:aws:ec2:*:*:*/*" : resourcePattern.trim();
        return addStatement(sid, "Allow", false, "ec2:CreateTags", res, cond);
    }

    /**
     * Explicitly denies creation actions when the request omits the specified tag key
     * (Condition: Null -> aws:RequestTag/<tagKey> = "true").
     */
    public PolicyBuilder denyUntaggedCreate(String sid, String actionsCsv, String resourcesCsv, String tagKey) {
        requireTagKey(tagKey);
        Map<String, Object> cond = singleCond("Null", "aws:RequestTag/" + tagKey, "true");
        return addStatement(sid, "Deny", false, actionsCsv, resourcesCsv, cond);
    }

    /**
     * Explicitly denies destructive actions unless the resource carries the required tag key
     * (Condition: Null -> aws:ResourceTag/<tagKey> = "true").
     */
    public PolicyBuilder denyDeleteUnlessTagged(String sid, String actionsCsv, String resourcesCsv, String tagKey) {
        requireTagKey(tagKey);
        Map<String, Object> cond = singleCond("Null", "aws:ResourceTag/" + tagKey, "true");
        return addStatement(sid, "Deny", false, actionsCsv, resourcesCsv, cond);
    }

    /**
     * Locks regional actions to a single AWS region while exempting global actions,
     * plus locks s3:CreateBucket LocationConstraint to the same region.
     */
    public PolicyBuilder regionLock(String sid, String region, String globalActionsCsv) {
        if (region == null || !region.trim().matches("^[a-z]{2}(-[a-z]+)+-[0-9]+$")) {
            throw new IllegalArgumentException("Invalid AWS region for region_lock: " + region);
        }
        String reg = region.trim();
        List<String> globals = splitCsv(globalActionsCsv);
        if (globals.isEmpty()) {
            globals = List.of("sts:GetCallerIdentity", "cloudfront:*", "route53:*");
        }
        Map<String, Object> regionCond = singleCond("StringNotEquals", "aws:RequestedRegion", reg);
        addStatementMap(sid, "Deny", true, validateActions(globals), List.of("*"), regionCond);

        String s3Sid = sid.startsWith("Only") ? "S3" + sid : sid + "S3Location";
        Map<String, Object> s3Cond = new LinkedHashMap<>();
        s3Cond.put("Null", Map.of("s3:LocationConstraint", "false"));
        s3Cond.put("StringNotEquals", Map.of("s3:LocationConstraint", reg));
        addStatementMap(s3Sid, "Deny", false, List.of("s3:CreateBucket"), List.of("*"), s3Cond);
        return this;
    }

    /**
     * Denies ec2:RunInstances unless ec2:InstanceType is one of the allowed types.
     */
    public PolicyBuilder instanceTypes(String sid, String typesCsv) {
        List<String> types = splitCsv(typesCsv);
        if (types.isEmpty()) {
            throw new IllegalArgumentException("instance_types requires at least one EC2 instance type");
        }
        for (String t : types) {
            if (!t.matches("^[a-z0-9]+\\.[a-z0-9]+$")) {
                throw new IllegalArgumentException("Invalid EC2 instance type: " + t);
            }
        }
        Map<String, Object> cond = singleCond("StringNotEquals", "ec2:InstanceType", scalarOrList(types));
        return addStatement(sid, "Deny", false, "ec2:RunInstances", "arn:aws:ec2:*:*:instance/*", cond);
    }

    /**
     * Denies ec2:RunInstances when any volume exceeds maxGib GiB.
     */
    public PolicyBuilder maxVolumeGib(String sid, long maxGib) {
        if (maxGib < 1 || maxGib > 16384) {
            throw new IllegalArgumentException("max_volume_gib must be between 1 and 16384 GiB");
        }
        Map<String, Object> cond = singleCond("NumericGreaterThan", "ec2:VolumeSize", String.valueOf(maxGib));
        return addStatement(sid, "Deny", false, "ec2:RunInstances", "arn:aws:ec2:*:*:volume/*", cond);
    }

    /**
     * Allows route53:ChangeResourceRecordSets only for specific DNS name patterns and record types.
     */
    public PolicyBuilder route53Names(String sid, String patternsCsv, String recordTypesCsv) {
        List<String> patterns = splitCsv(patternsCsv);
        List<String> types = splitCsv(recordTypesCsv);
        if (patterns.isEmpty() || types.isEmpty()) {
            throw new IllegalArgumentException("route53_names requires non-empty name patterns and record types");
        }
        Map<String, Object> cond = new LinkedHashMap<>();
        cond.put("ForAllValues:StringLike",
            Map.of("route53:ChangeResourceRecordSetsNormalizedRecordNames", scalarOrList(patterns)));
        cond.put("ForAllValues:StringEquals",
            Map.of("route53:ChangeResourceRecordSetsRecordTypes", scalarOrList(types)));
        return addStatement(sid, "Allow", false, "route53:ChangeResourceRecordSets", "arn:aws:route53:::hostedzone/*", cond);
    }

    /**
     * Denies ec2:AuthorizeSecurityGroupIngress unless the CIDR suffix matches (e.g. "/32").
     */
    public PolicyBuilder cidrOnly(String sid, String cidrSuffix) {
        String suffix = (cidrSuffix == null || cidrSuffix.isBlank()) ? "/32" : cidrSuffix.trim();
        if (!suffix.startsWith("/")) suffix = "/" + suffix;
        Map<String, Object> cond = singleCond("StringNotLike", "ec2:IngressIpv4Cidr", "*" + suffix);
        return addStatement(sid, "Deny", false, "ec2:AuthorizeSecurityGroupIngress", "arn:aws:ec2:*:*:security-group/*", cond);
    }

    /**
     * Denies specified actions when MFA is not present on the session.
     */
    public PolicyBuilder mfaRequired(String sid, String actionsCsv, String resourcesCsv) {
        Map<String, Object> cond = singleCond("BoolIfExists", "aws:MultiFactorAuthPresent", "false");
        return addStatement(sid, "Deny", false, actionsCsv, resourcesCsv, cond);
    }

    /**
     * Denies all actions outside the specified ISO-8601 UTC [fromIso, toIso] time window.
     */
    public PolicyBuilder timeWindow(String sid, String fromIso, String toIso) {
        if (fromIso == null || fromIso.isBlank() || toIso == null || toIso.isBlank()) {
            throw new IllegalArgumentException("time_window requires non-empty from and to ISO timestamps");
        }
        Map<String, Object> beforeCond = singleCond("DateLessThan", "aws:CurrentTime", fromIso.trim());
        Map<String, Object> afterCond = singleCond("DateGreaterThan", "aws:CurrentTime", toIso.trim());
        addStatementMap(sid + "Before", "Deny", true, List.of("sts:GetCallerIdentity"), List.of("*"), beforeCond);
        addStatementMap(sid + "After", "Deny", true, List.of("sts:GetCallerIdentity"), List.of("*"), afterCond);
        return this;
    }

    /**
     * Denies all actions when aws:SourceIp is outside the specified CIDR list.
     */
    public PolicyBuilder sourceIp(String sid, String cidrsCsv) {
        List<String> cidrs = splitCsv(cidrsCsv);
        if (cidrs.isEmpty()) {
            throw new IllegalArgumentException("source_ip requires at least one CIDR block");
        }
        Map<String, Object> cond = singleCond("NotIpAddress", "aws:SourceIp", scalarOrList(cidrs));
        return addStatementMap(sid, "Deny", true, List.of("sts:GetCallerIdentity"), List.of("*"), cond);
    }

    // --- Composable Sandbox & Role Building Blocks ---

    public PolicyBuilder readOnlyInventory() {
        return allow("Reads", String.join(",",
            "sts:GetCallerIdentity",
            "s3:ListAllMyBuckets",
            "ec2:Describe*",
            "sqs:ListQueues",
            "sns:ListTopics",
            "dynamodb:ListTables",
            "logs:DescribeLogGroups",
            "ssm:DescribeParameters",
            "route53:List*",
            "cloudfront:List*",
            "cloudfront:Get*",
            "acm:ListCertificates",
            "acm:DescribeCertificate",
            "acm:ListTagsForCertificate",
            "route53:GetHostedZone",
            "route53:GetChange",
            "lambda:ListFunctions"
        ), "*");
    }

    public PolicyBuilder s3BucketSandbox(String prefix) {
        requirePrefix(prefix);
        allow("S3List", "sts:GetCallerIdentity,s3:ListAllMyBuckets", "*");
        return namePrefix("S3Sandbox", "s3", prefix, "-", true);
    }

    public PolicyBuilder queueSandbox(String prefix) {
        requirePrefix(prefix);
        allow("SqsList", "sts:GetCallerIdentity,sqs:ListQueues", "*");
        return namePrefix("SqsSandbox", "sqs", prefix, "-,_", true);
    }

    public PolicyBuilder topicSandbox(String prefix) {
        requirePrefix(prefix);
        allow("SnsList", "sts:GetCallerIdentity,sns:ListTopics", "*");
        return namePrefix("SnsSandbox", "sns", prefix, "-,_", true);
    }

    public PolicyBuilder tableSandbox(String prefix) {
        requirePrefix(prefix);
        allow("DdbList", "sts:GetCallerIdentity,dynamodb:ListTables", "*");
        return namePrefix("DdbSandbox", "dynamodb", prefix, "-,_", true);
    }

    public PolicyBuilder parameterSandbox(String prefix) {
        requirePrefix(prefix);
        allow("SsmList", "sts:GetCallerIdentity,ssm:DescribeParameters", "*");
        allow("PublicParams", "ssm:GetParameter", "arn:aws:ssm:*::parameter/aws/service/*");
        return namePrefix("SsmSandbox", "ssm", prefix, "-,_", true);
    }

    public PolicyBuilder logGroupSandbox(String prefix) {
        requirePrefix(prefix);
        allow("LogsList", "sts:GetCallerIdentity,logs:DescribeLogGroups", "*");
        return namePrefix("LogsSandbox", "logs", prefix, "-,_", true);
    }

    /**
     * Adds the EC2 spot nano sandbox allow statements (RunTagged, RunRefs, RunTaggedSg,
     * CreateSg, OwnEc2, TagOnCreate) and deny guardrails (NanoOnly, SmallDisks, SgMustBeTagged).
     */
    public PolicyBuilder spotNanoSandbox(String tagKey, String typesCsv, long maxGib) {
        spotNanoAllowBlock(tagKey);
        spotNanoDenyBlock(tagKey, typesCsv, maxGib);
        return this;
    }

    public PolicyBuilder spotNanoAllowBlock(String tagKey) {
        requireTagKey(tagKey);
        requireTagOnCreate("RunTagged", "ec2:RunInstances",
            "arn:aws:ec2:*:*:instance/*,arn:aws:ec2:*:*:volume/*", tagKey);
        allow("RunRefs", "ec2:RunInstances",
            "arn:aws:ec2:*:*:subnet/*,arn:aws:ec2:*::image/*,arn:aws:ec2:*:*:network-interface/*,arn:aws:ec2:*:*:spot-instances-request/*");
        onlyTagged("RunTaggedSg", "ec2:RunInstances",
            "arn:aws:ec2:*:*:security-group/*", tagKey, "ec2");
        allow("CreateSg", "ec2:CreateSecurityGroup",
            "arn:aws:ec2:*:*:vpc/*,arn:aws:ec2:*:*:security-group/*");
        onlyTagged("OwnEc2", String.join(",",
            "ec2:TerminateInstances",
            "ec2:StopInstances",
            "ec2:StartInstances",
            "ec2:DeleteSecurityGroup",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:RevokeSecurityGroupEgress"
        ), "arn:aws:ec2:*:*:instance/*,arn:aws:ec2:*:*:security-group/*", tagKey, "ec2");
        tagOnCreateActions("TagOnCreate", "RunInstances,CreateSecurityGroup", "arn:aws:ec2:*:*:*/*");
        return this;
    }

    public PolicyBuilder spotNanoDenyBlock(String tagKey, String typesCsv, long maxGib) {
        requireTagKey(tagKey);
        instanceTypes("NanoOnly", typesCsv);
        maxVolumeGib("SmallDisks", maxGib);
        denyUntaggedCreate("SgMustBeTagged", "ec2:CreateSecurityGroup", "arn:aws:ec2:*:*:security-group/*", tagKey);
        return this;
    }

    /**
     * Adds the static-site web stack statements (CfCreate, CfOwn, CfOac, Route53Names, AcmRequest, AcmOwn).
     */
    public PolicyBuilder staticSiteStack(String prefix, String tagKey, String domain, String acmRegion) {
        requirePrefix(prefix);
        requireTagKey(tagKey);
        String cleanDomain = (domain == null || domain.isBlank()) ? "example.com" : domain.trim().toLowerCase(Locale.ROOT);
        String certRegion = (acmRegion == null || acmRegion.isBlank()) ? "us-east-1" : acmRegion.trim();
        requireTagOnCreate("CfCreate",
            "cloudfront:CreateDistribution,cloudfront:CreateDistributionWithTags,cloudfront:TagResource",
            "arn:aws:cloudfront::*:distribution/*", tagKey);
        onlyTagged("CfOwn",
            "cloudfront:UpdateDistribution,cloudfront:DeleteDistribution,cloudfront:CreateInvalidation",
            "arn:aws:cloudfront::*:distribution/*", tagKey, "aws");
        allow("CfOac",
            "cloudfront:CreateOriginAccessControl,cloudfront:UpdateOriginAccessControl,cloudfront:DeleteOriginAccessControl",
            "arn:aws:cloudfront::*:origin-access-control/*");
        route53Names("Route53Names",
            prefix + "-*." + cleanDomain + ",_*." + prefix + "-*." + cleanDomain,
            "A,AAAA,CNAME");
        requireTagOnCreate("AcmRequest",
            "acm:RequestCertificate,acm:AddTagsToCertificate",
            "arn:aws:acm:" + certRegion + ":*:certificate/*", tagKey);
        onlyTagged("AcmOwn",
            "acm:DeleteCertificate,acm:AddTagsToCertificate,acm:GetCertificate",
            "arn:aws:acm:" + certRegion + ":*:certificate/*", tagKey, "aws");
        return this;
    }

    public PolicyBuilder billingViewer() {
        allow("BillingReads", String.join(",",
            "sts:GetCallerIdentity",
            "ce:GetCostAndUsage",
            "ce:GetDimensionValues",
            "ce:GetTags",
            "ce:GetReservationUtilization",
            "ce:GetReservationCoverage",
            "ce:GetSavingsPlansUtilization",
            "ce:GetSavingsPlansCoverage",
            "savingsplans:DescribeSavingsPlans",
            "savingsplans:DescribeSavingsPlansOfferingRates",
            "savingsplans:DescribeSavingsPlansOfferings",
            "pricing:DescribeServices",
            "pricing:GetAttributeValues",
            "pricing:GetProducts",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:ListMetrics",
            "cloudwatch:DescribeAlarms",
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "ec2:DescribeSnapshots",
            "ec2:DescribeAddresses"
        ), "*");
        return this;
    }

    public PolicyBuilder lambdaDeployerByName(String prefix) {
        requirePrefix(prefix);
        allow("Fn", "lambda:*", "arn:aws:lambda:*:*:function:" + prefix + "_*");
        allow("Ev", "events:*", "arn:aws:events:*:*:rule/" + prefix + "_*");
        return this;
    }

    /**
     * Adds an iam:PassRole statement scoped to roles matching {@code rolePrefix} and the
     * target AWS service principal via {@code StringEquals: {"iam:PassedToService": service}}.
     * Note: {@link IamPolicies#lint} and {@link IamPolicies#requirePassRolePolicyContext}
     * enforce the exact lmaws_session Lambda exception (arn:aws:iam::*:role/lmaws_* to lambda.amazonaws.com).
     */
    public PolicyBuilder passRoleToService(String rolePrefix, String service) {
        return passRoleToService("LambdaPassRole", rolePrefix, service);
    }

    public PolicyBuilder passRoleToService(String sid, String rolePrefix, String service) {
        String rawPrefix = rolePrefix == null ? "" : rolePrefix.trim();
        if (rawPrefix.isEmpty()) {
            throw new IllegalArgumentException("Role prefix must not be empty");
        }
        String svc = service == null ? "" : service.trim();
        if (svc.isEmpty()) {
            throw new IllegalArgumentException("Service principal must not be empty");
        }
        String rolePattern;
        if (rawPrefix.startsWith("arn:aws:iam::")) {
            rolePattern = rawPrefix;
        } else if (rawPrefix.endsWith("_*") || rawPrefix.endsWith("-*") || rawPrefix.endsWith("*")) {
            rolePattern = "arn:aws:iam::*:role/" + rawPrefix;
        } else {
            requirePrefix(rawPrefix);
            rolePattern = "arn:aws:iam::*:role/" + rawPrefix + "_*";
        }
        Map<String, Object> cond = new LinkedHashMap<>();
        cond.put("StringEquals", Map.of("iam:PassedToService", svc));
        return addStatementMap(sid, "Allow", false, List.of("iam:PassRole"), List.of(rolePattern), cond);
    }

    public PolicyBuilder ciBucketDeployer(String bucketName, String distributionId) {
        String bucket = (bucketName == null || bucketName.isBlank()) ? "lmaws-site-assets" : bucketName.trim();
        String dist = (distributionId == null || distributionId.isBlank()) ? "*" : distributionId.trim();
        allow("CiIdentity", "sts:GetCallerIdentity", "*");
        allow("CiBucketList", "s3:ListBucket,s3:GetBucketLocation", "arn:aws:s3:::" + bucket);
        allow("CiBucketObjects", "s3:PutObject,s3:GetObject,s3:DeleteObject", "arn:aws:s3:::" + bucket + "/*");
        onlyTagged("CiInvalidation", "cloudfront:CreateInvalidation,cloudfront:GetInvalidation",
            "arn:aws:cloudfront::*:distribution/" + dist, "lmaws_test", "aws");
        return this;
    }

    public PolicyBuilder permissionBoundary(String prefix, String tagKey, String region) {
        requirePrefix(prefix);
        requireTagKey(tagKey);
        readOnlyInventory();
        namePrefix("BoundaryNamedResources", "s3,sqs,sns,dynamodb,ssm,logs", prefix, "-,_", true);
        spotNanoAllowBlock(tagKey);
        spotNanoDenyBlock(tagKey, "t4g.nano,t3.nano", 8);
        regionLock("OnlyUsEast1", region, "sts:GetCallerIdentity,cloudfront:*,route53:*");
        return this;
    }

    /**
     * Composes the complete 23-statement lmaws_session customer-managed policy from the
     * reusable building blocks in exact statement order.
     */
    public PolicyBuilder lmawsSessionPolicy(
            String prefix,
            String tagKey,
            String domain,
            String region,
            String typesCsv,
            long maxGib) {
        requirePrefix(prefix);
        requireTagKey(tagKey);
        readOnlyInventory();
        allow("PublicParams", "ssm:GetParameter", "arn:aws:ssm:*::parameter/aws/service/*");
        namePrefix("NamedTestResources", "s3,sqs,sns,dynamodb,ssm,logs", prefix, "-,_", true);
        spotNanoAllowBlock(tagKey);
        staticSiteStack(prefix, tagKey, domain, region);
        spotNanoDenyBlock(tagKey, typesCsv, maxGib);
        regionLock("OnlyUsEast1", region, "sts:GetCallerIdentity,cloudfront:*,route53:*");
        lambdaDeployerByName(prefix);
        passRoleToService("LambdaPassRole", prefix, "lambda.amazonaws.com");
        return this;
    }

    public PolicyBuilder mergeFrom(PolicyBuilder other) {
        if (other != null) {
            for (Map<String, Object> stmt : other.statements) {
                this.statements.add(new LinkedHashMap<>(stmt));
            }
        }
        return this;
    }

    // --- Compilation & Analysis ---

    public Map<String, Object> toDocumentMap() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("Version", IamPolicies.EXPECTED_VERSION);
        doc.put("Statement", new ArrayList<>(statements));
        return doc;
    }

    public String json() {
        return IamPolicies.prettyJson(toDocumentMap());
    }

    public String compactJson() {
        return IamPolicies.compactJson(toDocumentMap());
    }

    public Map<String, String> lint() {
        return IamPolicies.lint(json()).toMap();
    }

    public Map<String, String> fitInline() {
        return PolicyAnalyzer.fitInline(json());
    }

    public List<Map<String, String>> splitManaged() {
        return PolicyAnalyzer.splitManaged(json(), IamPolicies.MANAGED_POLICY_LIMIT);
    }

    public List<Map<String, String>> diff(String otherJson) {
        IamPolicies.DiffResult d = IamPolicies.diff(otherJson, json());
        List<Map<String, String>> out = new ArrayList<>();
        for (Map<String, Object> row : d.statementDiffs()) {
            Map<String, String> m = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : row.entrySet()) {
                m.put(e.getKey(), String.valueOf(e.getValue()));
            }
            out.add(m);
        }
        return out;
    }

    public List<Map<String, String>> explain() {
        return PolicyAnalyzer.explain(json());
    }

    public List<Map<String, String>> matrix() {
        return PolicyAnalyzer.matrix(json());
    }

    public List<Map<String, String>> sizeReport() {
        return PolicyAnalyzer.sizeReport(json());
    }

    public List<Map<String, String>> cheatSheet() {
        return PolicyAnalyzer.cheatSheet();
    }

    public List<Map<String, String>> simulateRunInstances(
            String instanceType,
            long volumeGib,
            String tagKey,
            String tagValue,
            String region) {
        return PolicySimulator.simulateRunInstances(json(), instanceType, volumeGib, tagKey, tagValue, region, "allowed");
    }

    public List<Map<String, String>> simulateRunInstances(
            String instanceType,
            long volumeGib,
            String tagKey,
            String tagValue,
            String region,
            String expectedDecision) {
        return PolicySimulator.simulateRunInstances(json(), instanceType, volumeGib, tagKey, tagValue, region, expectedDecision);
    }

    public String runInstancesProbes(
            String instanceType,
            long volumeGib,
            String tagKey,
            String tagValue,
            String region) {
        return PolicySimulator.formatProbes(PolicySimulator.runInstancesProbes(instanceType, volumeGib, tagKey, tagValue, region));
    }

    public Map<String, String> summary() {
        String compact = compactJson();
        Map<String, String> out = new LinkedHashMap<>();
        out.put("name", name);
        out.put("version", IamPolicies.EXPECTED_VERSION);
        out.put("statement_count", String.valueOf(statements.size()));
        out.put("compact_length", String.valueOf(compact.length()));
        out.put("inline_limit", String.valueOf(IamPolicies.INLINE_SESSION_POLICY_LIMIT));
        out.put("managed_limit", String.valueOf(IamPolicies.MANAGED_POLICY_LIMIT));
        out.put("fits_inline", String.valueOf(compact.length() <= IamPolicies.INLINE_SESSION_POLICY_LIMIT));
        out.put("fits_managed", String.valueOf(compact.length() <= IamPolicies.MANAGED_POLICY_LIMIT));
        return out;
    }

    // --- Internal statement construction ---

    private PolicyBuilder addStatement(
            String sid,
            String effect,
            boolean notAction,
            String actionsCsv,
            String resourcesCsv,
            Map<String, Object> condition) {
        List<String> actions = validateActions(splitCsv(actionsCsv));
        List<String> resources = splitCsv(resourcesCsv);
        return addStatementMap(sid, effect, notAction, actions, resources, condition);
    }

    private PolicyBuilder addStatementMap(
            String sid,
            String effect,
            boolean notAction,
            List<String> actions,
            List<String> resources,
            Map<String, Object> condition) {
        if (sid != null && !sid.isBlank() && !SID_PATTERN.matcher(sid.trim()).matches()) {
            throw new IllegalArgumentException("IAM Sid must be alphanumeric (1..64 chars), got: " + sid);
        }
        if (!"Allow".equals(effect) && !"Deny".equals(effect)) {
            throw new IllegalArgumentException("IAM Effect must be Allow or Deny, got: " + effect);
        }
        if (actions.isEmpty()) {
            throw new IllegalArgumentException("IAM statement '" + sid + "' must have at least one action");
        }
        if (resources.isEmpty()) {
            throw new IllegalArgumentException("IAM statement '" + sid + "' must have at least one resource");
        }
        Map<String, Object> stmt = new LinkedHashMap<>();
        if (sid != null && !sid.isBlank()) {
            stmt.put("Sid", sid.trim());
        }
        stmt.put("Effect", effect);
        stmt.put(notAction ? "NotAction" : "Action", scalarOrList(actions));
        stmt.put("Resource", scalarOrList(resources));
        if (condition != null && !condition.isEmpty()) {
            stmt.put("Condition", condition);
        }
        statements.add(stmt);
        return this;
    }

    private static List<String> validateActions(List<String> rawActions) {
        List<String> out = new ArrayList<>(rawActions.size());
        for (String a : rawActions) {
            out.add(PolicyCatalog.validatePattern(a));
        }
        return out;
    }

    private static Object scalarOrList(List<String> items) {
        return items.size() == 1 ? items.get(0) : new ArrayList<>(items);
    }

    private static Map<String, Object> singleCond(String operator, String key, Object value) {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put(key, value);
        Map<String, Object> outer = new LinkedHashMap<>();
        outer.put(operator, inner);
        return outer;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseCondition(String conditionJson) {
        if (conditionJson == null || conditionJson.isBlank()) return null;
        Object parsed = Json.parse(conditionJson);
        if (!(parsed instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("Condition JSON must be an object");
        }
        return new LinkedHashMap<>((Map<String, Object>) parsed);
    }

    private static void requirePrefix(String prefix) {
        if (prefix == null || !PREFIX_PATTERN.matcher(prefix.trim()).matches()) {
            throw new IllegalArgumentException("Invalid resource name prefix: " + prefix);
        }
    }

    private static void requireTagKey(String tagKey) {
        if (tagKey == null || !TAG_KEY_PATTERN.matcher(tagKey.trim()).matches()) {
            throw new IllegalArgumentException("Invalid AWS tag key: " + tagKey);
        }
    }

    static List<String> splitCsv(String csv) {
        if (csv == null || csv.isBlank()) return List.of();
        String[] parts = csv.split("[,;\\n]+");
        List<String> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String p : parts) {
            String t = p.trim();
            if (!t.isEmpty() && seen.add(t)) {
                out.add(t);
            }
        }
        return out;
    }
}
