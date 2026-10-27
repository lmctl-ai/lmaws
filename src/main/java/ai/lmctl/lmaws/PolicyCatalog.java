package ai.lmctl.lmaws;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Bundled AWS IAM action catalog, action classification (list, read, write, tagging,
 * permissions_management), wildcard expansion, typo detection, ARN templates, and
 * ledger SDK-call-to-IAM mapping.
 */
public final class PolicyCatalog {
    public static final String CLASS_LIST = "list";
    public static final String CLASS_READ = "read";
    public static final String CLASS_WRITE = "write";
    public static final String CLASS_TAGGING = "tagging";
    public static final String CLASS_PERMISSIONS = "permissions_management";

    private static final Map<String, Map<String, String>> SERVICE_ACTIONS = new LinkedHashMap<>();
    private static final Set<String> UNDERSCORE_NAME_SERVICES = Set.of(
        "sqs", "sns", "dynamodb", "ssm", "logs", "lambda", "events", "cloudformation", "ecs"
    );

    static {
        register("sts", Map.ofEntries(
            Map.entry("GetCallerIdentity", CLASS_READ),
            Map.entry("GetSessionToken", CLASS_READ),
            Map.entry("GetFederationToken", CLASS_PERMISSIONS),
            Map.entry("AssumeRole", CLASS_PERMISSIONS),
            Map.entry("AssumeRoleWithWebIdentity", CLASS_PERMISSIONS),
            Map.entry("AssumeRoleWithSAML", CLASS_PERMISSIONS),
            Map.entry("TagSession", CLASS_TAGGING)
        ));
        register("s3", Map.ofEntries(
            Map.entry("ListAllMyBuckets", CLASS_LIST),
            Map.entry("ListBucket", CLASS_LIST),
            Map.entry("ListBucketVersions", CLASS_LIST),
            Map.entry("ListBucketMultipartUploads", CLASS_LIST),
            Map.entry("GetBucketLocation", CLASS_READ),
            Map.entry("GetBucketTagging", CLASS_READ),
            Map.entry("GetBucketPolicy", CLASS_READ),
            Map.entry("GetBucketAcl", CLASS_READ),
            Map.entry("GetBucketVersioning", CLASS_READ),
            Map.entry("GetBucketPublicAccessBlock", CLASS_READ),
            Map.entry("GetBucketEncryption", CLASS_READ),
            Map.entry("GetBucketWebsite", CLASS_READ),
            Map.entry("GetBucketCors", CLASS_READ),
            Map.entry("GetObject", CLASS_READ),
            Map.entry("GetObjectVersion", CLASS_READ),
            Map.entry("GetObjectTagging", CLASS_READ),
            Map.entry("HeadBucket", CLASS_READ),
            Map.entry("HeadObject", CLASS_READ),
            Map.entry("CreateBucket", CLASS_WRITE),
            Map.entry("DeleteBucket", CLASS_WRITE),
            Map.entry("PutObject", CLASS_WRITE),
            Map.entry("DeleteObject", CLASS_WRITE),
            Map.entry("DeleteObjectVersion", CLASS_WRITE),
            Map.entry("AbortMultipartUpload", CLASS_WRITE),
            Map.entry("PutBucketWebsite", CLASS_WRITE),
            Map.entry("DeleteBucketWebsite", CLASS_WRITE),
            Map.entry("PutBucketEncryption", CLASS_WRITE),
            Map.entry("PutBucketVersioning", CLASS_WRITE),
            Map.entry("PutBucketTagging", CLASS_TAGGING),
            Map.entry("DeleteBucketTagging", CLASS_TAGGING),
            Map.entry("PutObjectTagging", CLASS_TAGGING),
            Map.entry("DeleteObjectTagging", CLASS_TAGGING),
            Map.entry("PutBucketPolicy", CLASS_PERMISSIONS),
            Map.entry("DeleteBucketPolicy", CLASS_PERMISSIONS),
            Map.entry("PutBucketPublicAccessBlock", CLASS_PERMISSIONS),
            Map.entry("PutBucketAcl", CLASS_PERMISSIONS)
        ));
        register("ec2", Map.ofEntries(
            Map.entry("DescribeInstances", CLASS_LIST),
            Map.entry("DescribeInstanceStatus", CLASS_LIST),
            Map.entry("DescribeInstanceTypes", CLASS_LIST),
            Map.entry("DescribeImages", CLASS_LIST),
            Map.entry("DescribeVolumes", CLASS_LIST),
            Map.entry("DescribeSnapshots", CLASS_LIST),
            Map.entry("DescribeVpcs", CLASS_LIST),
            Map.entry("DescribeSubnets", CLASS_LIST),
            Map.entry("DescribeRouteTables", CLASS_LIST),
            Map.entry("DescribeInternetGateways", CLASS_LIST),
            Map.entry("DescribeSecurityGroups", CLASS_LIST),
            Map.entry("DescribeSecurityGroupRules", CLASS_LIST),
            Map.entry("DescribeNetworkInterfaces", CLASS_LIST),
            Map.entry("DescribeAddresses", CLASS_LIST),
            Map.entry("DescribeKeyPairs", CLASS_LIST),
            Map.entry("DescribeRegions", CLASS_LIST),
            Map.entry("DescribeAvailabilityZones", CLASS_LIST),
            Map.entry("DescribeSpotPriceHistory", CLASS_LIST),
            Map.entry("DescribeSpotInstanceRequests", CLASS_LIST),
            Map.entry("DescribeTags", CLASS_LIST),
            Map.entry("DescribeAccountAttributes", CLASS_LIST),
            Map.entry("GetConsoleOutput", CLASS_READ),
            Map.entry("RunInstances", CLASS_WRITE),
            Map.entry("StartInstances", CLASS_WRITE),
            Map.entry("StopInstances", CLASS_WRITE),
            Map.entry("RebootInstances", CLASS_WRITE),
            Map.entry("TerminateInstances", CLASS_WRITE),
            Map.entry("CreateSecurityGroup", CLASS_WRITE),
            Map.entry("DeleteSecurityGroup", CLASS_WRITE),
            Map.entry("CreateVpc", CLASS_WRITE),
            Map.entry("DeleteVpc", CLASS_WRITE),
            Map.entry("CreateSubnet", CLASS_WRITE),
            Map.entry("DeleteSubnet", CLASS_WRITE),
            Map.entry("AuthorizeSecurityGroupIngress", CLASS_WRITE),
            Map.entry("RevokeSecurityGroupIngress", CLASS_WRITE),
            Map.entry("AuthorizeSecurityGroupEgress", CLASS_WRITE),
            Map.entry("RevokeSecurityGroupEgress", CLASS_WRITE),
            Map.entry("CreateVolume", CLASS_WRITE),
            Map.entry("DeleteVolume", CLASS_WRITE),
            Map.entry("AttachVolume", CLASS_WRITE),
            Map.entry("DetachVolume", CLASS_WRITE),
            Map.entry("AllocateAddress", CLASS_WRITE),
            Map.entry("ReleaseAddress", CLASS_WRITE),
            Map.entry("AssociateAddress", CLASS_WRITE),
            Map.entry("DisassociateAddress", CLASS_WRITE),
            Map.entry("CancelSpotInstanceRequests", CLASS_WRITE),
            Map.entry("CreateTags", CLASS_TAGGING),
            Map.entry("DeleteTags", CLASS_TAGGING)
        ));
        register("sqs", Map.ofEntries(
            Map.entry("ListQueues", CLASS_LIST),
            Map.entry("ListQueueTags", CLASS_READ),
            Map.entry("GetQueueUrl", CLASS_READ),
            Map.entry("GetQueueAttributes", CLASS_READ),
            Map.entry("ReceiveMessage", CLASS_READ),
            Map.entry("CreateQueue", CLASS_WRITE),
            Map.entry("DeleteQueue", CLASS_WRITE),
            Map.entry("PurgeQueue", CLASS_WRITE),
            Map.entry("SendMessage", CLASS_WRITE),
            Map.entry("SendMessageBatch", CLASS_WRITE),
            Map.entry("DeleteMessage", CLASS_WRITE),
            Map.entry("DeleteMessageBatch", CLASS_WRITE),
            Map.entry("ChangeMessageVisibility", CLASS_WRITE),
            Map.entry("SetQueueAttributes", CLASS_WRITE),
            Map.entry("TagQueue", CLASS_TAGGING),
            Map.entry("UntagQueue", CLASS_TAGGING),
            Map.entry("AddPermission", CLASS_PERMISSIONS),
            Map.entry("RemovePermission", CLASS_PERMISSIONS)
        ));
        register("sns", Map.ofEntries(
            Map.entry("ListTopics", CLASS_LIST),
            Map.entry("ListSubscriptions", CLASS_LIST),
            Map.entry("ListSubscriptionsByTopic", CLASS_LIST),
            Map.entry("ListTagsForResource", CLASS_READ),
            Map.entry("GetTopicAttributes", CLASS_READ),
            Map.entry("GetSubscriptionAttributes", CLASS_READ),
            Map.entry("CreateTopic", CLASS_WRITE),
            Map.entry("DeleteTopic", CLASS_WRITE),
            Map.entry("Publish", CLASS_WRITE),
            Map.entry("PublishBatch", CLASS_WRITE),
            Map.entry("Subscribe", CLASS_WRITE),
            Map.entry("Unsubscribe", CLASS_WRITE),
            Map.entry("SetTopicAttributes", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING),
            Map.entry("AddPermission", CLASS_PERMISSIONS),
            Map.entry("RemovePermission", CLASS_PERMISSIONS)
        ));
        register("dynamodb", Map.ofEntries(
            Map.entry("ListTables", CLASS_LIST),
            Map.entry("DescribeLimits", CLASS_LIST),
            Map.entry("ListTagsOfResource", CLASS_READ),
            Map.entry("DescribeTable", CLASS_READ),
            Map.entry("DescribeTimeToLive", CLASS_READ),
            Map.entry("DescribeContinuousBackups", CLASS_READ),
            Map.entry("GetItem", CLASS_READ),
            Map.entry("BatchGetItem", CLASS_READ),
            Map.entry("Query", CLASS_READ),
            Map.entry("Scan", CLASS_READ),
            Map.entry("CreateTable", CLASS_WRITE),
            Map.entry("UpdateTable", CLASS_WRITE),
            Map.entry("DeleteTable", CLASS_WRITE),
            Map.entry("PutItem", CLASS_WRITE),
            Map.entry("UpdateItem", CLASS_WRITE),
            Map.entry("DeleteItem", CLASS_WRITE),
            Map.entry("BatchWriteItem", CLASS_WRITE),
            Map.entry("UpdateTimeToLive", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING),
            Map.entry("PutResourcePolicy", CLASS_PERMISSIONS),
            Map.entry("DeleteResourcePolicy", CLASS_PERMISSIONS)
        ));
        register("logs", Map.ofEntries(
            Map.entry("DescribeLogGroups", CLASS_LIST),
            Map.entry("DescribeLogStreams", CLASS_LIST),
            Map.entry("DescribeMetricFilters", CLASS_LIST),
            Map.entry("ListTagsForResource", CLASS_READ),
            Map.entry("ListTagsLogGroup", CLASS_READ),
            Map.entry("GetLogEvents", CLASS_READ),
            Map.entry("FilterLogEvents", CLASS_READ),
            Map.entry("StartLiveTail", CLASS_READ),
            Map.entry("CreateLogGroup", CLASS_WRITE),
            Map.entry("DeleteLogGroup", CLASS_WRITE),
            Map.entry("CreateLogStream", CLASS_WRITE),
            Map.entry("DeleteLogStream", CLASS_WRITE),
            Map.entry("PutLogEvents", CLASS_WRITE),
            Map.entry("PutRetentionPolicy", CLASS_WRITE),
            Map.entry("DeleteRetentionPolicy", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING),
            Map.entry("TagLogGroup", CLASS_TAGGING),
            Map.entry("UntagLogGroup", CLASS_TAGGING),
            Map.entry("PutResourcePolicy", CLASS_PERMISSIONS),
            Map.entry("DeleteResourcePolicy", CLASS_PERMISSIONS)
        ));
        register("ssm", Map.ofEntries(
            Map.entry("DescribeParameters", CLASS_LIST),
            Map.entry("ListTagsForResource", CLASS_READ),
            Map.entry("GetParameter", CLASS_READ),
            Map.entry("GetParameters", CLASS_READ),
            Map.entry("GetParametersByPath", CLASS_READ),
            Map.entry("GetParameterHistory", CLASS_READ),
            Map.entry("PutParameter", CLASS_WRITE),
            Map.entry("DeleteParameter", CLASS_WRITE),
            Map.entry("DeleteParameters", CLASS_WRITE),
            Map.entry("LabelParameterVersion", CLASS_WRITE),
            Map.entry("AddTagsToResource", CLASS_TAGGING),
            Map.entry("RemoveTagsFromResource", CLASS_TAGGING)
        ));
        register("route53", Map.ofEntries(
            Map.entry("ListHostedZones", CLASS_LIST),
            Map.entry("ListHostedZonesByName", CLASS_LIST),
            Map.entry("ListResourceRecordSets", CLASS_LIST),
            Map.entry("ListTagsForResource", CLASS_READ),
            Map.entry("ListTagsForResources", CLASS_READ),
            Map.entry("GetHostedZone", CLASS_READ),
            Map.entry("GetHostedZoneCount", CLASS_READ),
            Map.entry("GetChange", CLASS_READ),
            Map.entry("CreateHostedZone", CLASS_WRITE),
            Map.entry("DeleteHostedZone", CLASS_WRITE),
            Map.entry("ChangeResourceRecordSets", CLASS_WRITE),
            Map.entry("ChangeTagsForResource", CLASS_TAGGING)
        ));
        register("cloudfront", Map.ofEntries(
            Map.entry("ListDistributions", CLASS_LIST),
            Map.entry("ListOriginAccessControls", CLASS_LIST),
            Map.entry("ListInvalidations", CLASS_LIST),
            Map.entry("ListTagsForResource", CLASS_READ),
            Map.entry("GetDistribution", CLASS_READ),
            Map.entry("GetDistributionConfig", CLASS_READ),
            Map.entry("GetOriginAccessControl", CLASS_READ),
            Map.entry("GetOriginAccessControlConfig", CLASS_READ),
            Map.entry("GetInvalidation", CLASS_READ),
            Map.entry("CreateDistribution", CLASS_WRITE),
            Map.entry("CreateDistributionWithTags", CLASS_WRITE),
            Map.entry("UpdateDistribution", CLASS_WRITE),
            Map.entry("DeleteDistribution", CLASS_WRITE),
            Map.entry("CreateInvalidation", CLASS_WRITE),
            Map.entry("CreateOriginAccessControl", CLASS_WRITE),
            Map.entry("UpdateOriginAccessControl", CLASS_WRITE),
            Map.entry("DeleteOriginAccessControl", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING)
        ));
        register("acm", Map.ofEntries(
            Map.entry("ListCertificates", CLASS_LIST),
            Map.entry("ListTagsForCertificate", CLASS_READ),
            Map.entry("DescribeCertificate", CLASS_READ),
            Map.entry("GetCertificate", CLASS_READ),
            Map.entry("RequestCertificate", CLASS_WRITE),
            Map.entry("DeleteCertificate", CLASS_WRITE),
            Map.entry("RenewCertificate", CLASS_WRITE),
            Map.entry("ImportCertificate", CLASS_WRITE),
            Map.entry("AddTagsToCertificate", CLASS_TAGGING),
            Map.entry("RemoveTagsFromCertificate", CLASS_TAGGING)
        ));
        register("lambda", Map.ofEntries(
            Map.entry("ListFunctions", CLASS_LIST),
            Map.entry("ListVersionsByFunction", CLASS_LIST),
            Map.entry("ListAliases", CLASS_LIST),
            Map.entry("ListEventSourceMappings", CLASS_LIST),
            Map.entry("ListTags", CLASS_READ),
            Map.entry("GetFunction", CLASS_READ),
            Map.entry("GetFunctionConfiguration", CLASS_READ),
            Map.entry("GetPolicy", CLASS_READ),
            Map.entry("CreateFunction", CLASS_WRITE),
            Map.entry("UpdateFunctionCode", CLASS_WRITE),
            Map.entry("UpdateFunctionConfiguration", CLASS_WRITE),
            Map.entry("DeleteFunction", CLASS_WRITE),
            Map.entry("InvokeFunction", CLASS_WRITE),
            Map.entry("PublishVersion", CLASS_WRITE),
            Map.entry("CreateAlias", CLASS_WRITE),
            Map.entry("UpdateAlias", CLASS_WRITE),
            Map.entry("DeleteAlias", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING),
            Map.entry("AddPermission", CLASS_PERMISSIONS),
            Map.entry("RemovePermission", CLASS_PERMISSIONS)
        ));
        register("events", Map.ofEntries(
            Map.entry("ListRules", CLASS_LIST),
            Map.entry("ListTargetsByRule", CLASS_LIST),
            Map.entry("ListTagsForResource", CLASS_READ),
            Map.entry("DescribeRule", CLASS_READ),
            Map.entry("PutRule", CLASS_WRITE),
            Map.entry("DeleteRule", CLASS_WRITE),
            Map.entry("EnableRule", CLASS_WRITE),
            Map.entry("DisableRule", CLASS_WRITE),
            Map.entry("PutTargets", CLASS_WRITE),
            Map.entry("RemoveTargets", CLASS_WRITE),
            Map.entry("PutEvents", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING)
        ));
        register("ecs", Map.ofEntries(
            Map.entry("ListClusters", CLASS_LIST),
            Map.entry("ListServices", CLASS_LIST),
            Map.entry("ListTasks", CLASS_LIST),
            Map.entry("DescribeClusters", CLASS_READ),
            Map.entry("DescribeServices", CLASS_READ),
            Map.entry("DescribeTasks", CLASS_READ),
            Map.entry("CreateCluster", CLASS_WRITE),
            Map.entry("DeleteCluster", CLASS_WRITE),
            Map.entry("UpdateService", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING)
        ));
        register("tag", Map.ofEntries(
            Map.entry("GetResources", CLASS_LIST),
            Map.entry("GetTagKeys", CLASS_LIST),
            Map.entry("GetTagValues", CLASS_LIST),
            Map.entry("TagResources", CLASS_TAGGING),
            Map.entry("UntagResources", CLASS_TAGGING)
        ));
        register("cloudwatch", Map.ofEntries(
            Map.entry("DescribeAlarms", CLASS_LIST),
            Map.entry("ListMetrics", CLASS_LIST),
            Map.entry("ListTagsForResource", CLASS_READ),
            Map.entry("GetMetricData", CLASS_READ),
            Map.entry("GetMetricStatistics", CLASS_READ),
            Map.entry("PutMetricAlarm", CLASS_WRITE),
            Map.entry("DeleteAlarms", CLASS_WRITE),
            Map.entry("PutMetricData", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING)
        ));
        register("ce", Map.ofEntries(
            Map.entry("GetCostAndUsage", CLASS_READ),
            Map.entry("GetDimensionValues", CLASS_READ),
            Map.entry("GetTags", CLASS_READ),
            Map.entry("GetReservationUtilization", CLASS_READ),
            Map.entry("GetReservationCoverage", CLASS_READ),
            Map.entry("GetSavingsPlansUtilization", CLASS_READ),
            Map.entry("GetSavingsPlansCoverage", CLASS_READ),
            Map.entry("GetCostForecast", CLASS_READ)
        ));
        register("savingsplans", Map.ofEntries(
            Map.entry("DescribeSavingsPlans", CLASS_READ),
            Map.entry("DescribeSavingsPlansOfferingRates", CLASS_READ),
            Map.entry("DescribeSavingsPlansOfferings", CLASS_READ),
            Map.entry("ListTagsForResource", CLASS_READ)
        ));
        register("pricing", Map.ofEntries(
            Map.entry("DescribeServices", CLASS_LIST),
            Map.entry("GetAttributeValues", CLASS_READ),
            Map.entry("GetProducts", CLASS_READ)
        ));
        register("cloudformation", Map.ofEntries(
            Map.entry("DescribeStacks", CLASS_LIST),
            Map.entry("ListStacks", CLASS_LIST),
            Map.entry("DescribeStackResources", CLASS_READ),
            Map.entry("GetTemplate", CLASS_READ),
            Map.entry("CreateStack", CLASS_WRITE),
            Map.entry("UpdateStack", CLASS_WRITE),
            Map.entry("DeleteStack", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING)
        ));
        register("secretsmanager", Map.ofEntries(
            Map.entry("ListSecrets", CLASS_LIST),
            Map.entry("DescribeSecret", CLASS_READ),
            Map.entry("GetSecretValue", CLASS_READ),
            Map.entry("CreateSecret", CLASS_WRITE),
            Map.entry("PutSecretValue", CLASS_WRITE),
            Map.entry("DeleteSecret", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("UntagResource", CLASS_TAGGING)
        ));
        register("kms", Map.ofEntries(
            Map.entry("ListKeys", CLASS_LIST),
            Map.entry("ListAliases", CLASS_LIST),
            Map.entry("DescribeKey", CLASS_READ),
            Map.entry("Encrypt", CLASS_WRITE),
            Map.entry("Decrypt", CLASS_READ),
            Map.entry("GenerateDataKey", CLASS_WRITE),
            Map.entry("CreateKey", CLASS_WRITE),
            Map.entry("ScheduleKeyDeletion", CLASS_WRITE),
            Map.entry("TagResource", CLASS_TAGGING),
            Map.entry("PutKeyPolicy", CLASS_PERMISSIONS)
        ));
        register("iam", Map.ofEntries(
            Map.entry("ListRoles", CLASS_LIST),
            Map.entry("ListUsers", CLASS_LIST),
            Map.entry("ListPolicies", CLASS_LIST),
            Map.entry("ListPolicyVersions", CLASS_LIST),
            Map.entry("ListAttachedRolePolicies", CLASS_LIST),
            Map.entry("ListRolePolicies", CLASS_LIST),
            Map.entry("ListEntitiesForPolicy", CLASS_LIST),
            Map.entry("ListRoleTags", CLASS_READ),
            Map.entry("GetRole", CLASS_READ),
            Map.entry("GetRolePolicy", CLASS_READ),
            Map.entry("GetUser", CLASS_READ),
            Map.entry("GetPolicy", CLASS_READ),
            Map.entry("GetPolicyVersion", CLASS_READ),
            Map.entry("SimulateCustomPolicy", CLASS_READ),
            Map.entry("SimulatePrincipalPolicy", CLASS_READ),
            Map.entry("CreatePolicy", CLASS_PERMISSIONS),
            Map.entry("CreatePolicyVersion", CLASS_PERMISSIONS),
            Map.entry("DeletePolicy", CLASS_PERMISSIONS),
            Map.entry("DeletePolicyVersion", CLASS_PERMISSIONS),
            Map.entry("SetDefaultPolicyVersion", CLASS_PERMISSIONS),
            Map.entry("AttachRolePolicy", CLASS_PERMISSIONS),
            Map.entry("DetachRolePolicy", CLASS_PERMISSIONS),
            Map.entry("PutRolePolicy", CLASS_PERMISSIONS),
            Map.entry("PassRole", CLASS_PERMISSIONS)
        ));
        register("organizations", Map.ofEntries(
            Map.entry("DescribeOrganization", CLASS_READ),
            Map.entry("ListAccounts", CLASS_LIST),
            Map.entry("CloseAccount", CLASS_PERMISSIONS)
        ));
        register("account", Map.ofEntries(
            Map.entry("GetContactInformation", CLASS_READ),
            Map.entry("PutContactInformation", CLASS_PERMISSIONS)
        ));
    }

    private PolicyCatalog() {}

    private static void register(String service, Map<String, String> actions) {
        Map<String, String> ordered = new LinkedHashMap<>();
        List<String> keys = new ArrayList<>(actions.keySet());
        Collections.sort(keys);
        for (String key : keys) {
            ordered.put(key, actions.get(key));
        }
        SERVICE_ACTIONS.put(service, Collections.unmodifiableMap(ordered));
    }

    public static Set<String> services() {
        return Collections.unmodifiableSet(SERVICE_ACTIONS.keySet());
    }

    public static boolean supportsUnderscoreNames(String service) {
        return UNDERSCORE_NAME_SERVICES.contains(service.toLowerCase(Locale.ROOT));
    }

    /**
     * Validates an action or wildcard pattern against the bundled catalog and returns
     * the canonical-cased action pattern (e.g., "s3:ListAllMyBuckets" or "ec2:Describe*").
     */
    public static String validatePattern(String rawAction) {
        if (rawAction == null || rawAction.isBlank()) {
            throw new IllegalArgumentException("IAM action pattern must not be empty");
        }
        String trimmed = rawAction.trim();
        if ("*".equals(trimmed) || "*:*".equals(trimmed)) {
            return trimmed;
        }
        int colon = trimmed.indexOf(':');
        if (colon <= 0 || colon == trimmed.length() - 1) {
            throw new IllegalArgumentException("IAM action must have format '<service>:<Action>': " + trimmed);
        }
        String service = trimmed.substring(0, colon).toLowerCase(Locale.ROOT);
        String actionPart = trimmed.substring(colon + 1);
        Map<String, String> catalog = SERVICE_ACTIONS.get(service);
        if (catalog == null) {
            String suggestion = closestMatch(service, SERVICE_ACTIONS.keySet());
            throw new IllegalArgumentException(
                "Unknown AWS service prefix '" + service + "' in action '" + trimmed + "'"
                    + (suggestion != null ? " (did you mean '" + suggestion + "'?)" : ""));
        }
        if ("*".equals(actionPart)) {
            return service + ":*";
        }
        if (actionPart.contains("*")) {
            Pattern regex = wildcardToRegex(actionPart);
            List<String> matches = new ArrayList<>();
            for (String candidate : catalog.keySet()) {
                if (regex.matcher(candidate).matches()) {
                    matches.add(candidate);
                }
            }
            if (matches.isEmpty()) {
                String suggestion = closestMatch(actionPart.replace("*", ""), catalog.keySet());
                throw new IllegalArgumentException(
                    "Wildcard IAM action '" + trimmed + "' matches no known " + service + " actions in catalog"
                        + (suggestion != null ? " (closest action: '" + service + ":" + suggestion + "')" : ""));
            }
            return service + ":" + actionPart;
        }
        for (String canonical : catalog.keySet()) {
            if (canonical.equalsIgnoreCase(actionPart)) {
                return service + ":" + canonical;
            }
        }
        String suggestion = closestMatch(actionPart, catalog.keySet());
        throw new IllegalArgumentException(
            "Unknown IAM action '" + trimmed + "'"
                + (suggestion != null ? " (did you mean '" + service + ":" + suggestion + "'?)" : ""));
    }

    /**
     * Expands an action or wildcard pattern into all matching canonical actions from the catalog.
     */
    public static List<String> expandPattern(String rawAction) {
        String valid = validatePattern(rawAction);
        if ("*".equals(valid) || "*:*".equals(valid)) {
            List<String> all = new ArrayList<>();
            for (Map.Entry<String, Map<String, String>> entry : SERVICE_ACTIONS.entrySet()) {
                for (String act : entry.getValue().keySet()) {
                    all.add(entry.getKey() + ":" + act);
                }
            }
            return all;
        }
        int colon = valid.indexOf(':');
        String service = valid.substring(0, colon);
        String actionPart = valid.substring(colon + 1);
        Map<String, String> catalog = SERVICE_ACTIONS.get(service);
        if ("*".equals(actionPart)) {
            List<String> out = new ArrayList<>(catalog.size());
            for (String act : catalog.keySet()) {
                out.add(service + ":" + act);
            }
            return out;
        }
        if (actionPart.contains("*")) {
            Pattern regex = wildcardToRegex(actionPart);
            List<String> out = new ArrayList<>();
            for (String act : catalog.keySet()) {
                if (regex.matcher(act).matches()) {
                    out.add(service + ":" + act);
                }
            }
            return out;
        }
        return List.of(valid);
    }

    /**
     * Classifies an action or wildcard pattern into its primary access level:
     * list, read, tagging, write, or permissions_management.
     */
    public static String classify(String rawAction) {
        if (rawAction == null || rawAction.isBlank()) return "unknown";
        String trimmed = rawAction.trim();
        if ("*".equals(trimmed) || "*:*".equals(trimmed)) return CLASS_PERMISSIONS;
        int colon = trimmed.indexOf(':');
        if (colon <= 0) return "unknown";
        String service = trimmed.substring(0, colon).toLowerCase(Locale.ROOT);
        String actionPart = trimmed.substring(colon + 1);
        Map<String, String> catalog = SERVICE_ACTIONS.get(service);
        if (catalog != null) {
            if ("*".equals(actionPart)) {
                return CLASS_WRITE;
            }
            if (!actionPart.contains("*")) {
                for (Map.Entry<String, String> entry : catalog.entrySet()) {
                    if (entry.getKey().equalsIgnoreCase(actionPart)) {
                        return entry.getValue();
                    }
                }
            } else {
                Pattern regex = wildcardToRegex(actionPart);
                Set<String> classes = new LinkedHashSet<>();
                for (Map.Entry<String, String> entry : catalog.entrySet()) {
                    if (regex.matcher(entry.getKey()).matches()) {
                        classes.add(entry.getValue());
                    }
                }
                if (classes.contains(CLASS_PERMISSIONS)) return CLASS_PERMISSIONS;
                if (classes.contains(CLASS_WRITE)) return CLASS_WRITE;
                if (classes.contains(CLASS_TAGGING)) return CLASS_TAGGING;
                if (classes.contains(CLASS_READ)) return CLASS_READ;
                if (classes.contains(CLASS_LIST)) return CLASS_LIST;
            }
        }
        String lower = actionPart.toLowerCase(Locale.ROOT);
        if (lower.startsWith("list")) return CLASS_LIST;
        if (lower.startsWith("describe") || lower.startsWith("get") || lower.startsWith("head")) return CLASS_READ;
        if (lower.contains("tag")) return CLASS_TAGGING;
        if (lower.contains("policy") || lower.contains("permission") || lower.contains("role")) return CLASS_PERMISSIONS;
        return CLASS_WRITE;
    }

    /**
     * Builds a canonical service ARN pattern without requiring an account ID.
     */
    public static String arn(String service, String resourceType, String namePattern) {
        return arnInRegion(service, "*", resourceType, namePattern);
    }

    public static String arnInRegion(String service, String region, String resourceType, String namePattern) {
        String svc = service == null ? "" : service.trim().toLowerCase(Locale.ROOT);
        String reg = (region == null || region.isBlank()) ? "*" : region.trim();
        String type = resourceType == null ? "" : resourceType.trim().toLowerCase(Locale.ROOT);
        String name = (namePattern == null || namePattern.isBlank()) ? "*" : namePattern.trim();
        return switch (svc) {
            case "s3" -> "object".equals(type)
                ? "arn:aws:s3:::" + (name.contains("/") ? name : name + "/*")
                : "arn:aws:s3:::" + name;
            case "sqs" -> "arn:aws:sqs:" + reg + ":*:" + name;
            case "sns" -> "arn:aws:sns:" + reg + ":*:" + name;
            case "dynamodb" -> "arn:aws:dynamodb:" + reg + ":*:table/" + name;
            case "ssm" -> "public-parameter".equals(type) || name.startsWith("aws/service/") || name.startsWith("/aws/service/")
                ? "arn:aws:ssm:" + reg + "::parameter/" + (name.startsWith("/") ? name.substring(1) : name)
                : "arn:aws:ssm:" + reg + ":*:parameter/" + (name.startsWith("/") ? name.substring(1) : name);
            case "logs" -> "arn:aws:logs:" + reg + ":*:log-group:" + name;
            case "ec2" -> {
                if ("image".equals(type)) yield "arn:aws:ec2:" + reg + "::image/" + name;
                if ("*".equals(type) || type.isEmpty()) yield "arn:aws:ec2:" + reg + ":*:*/*";
                yield "arn:aws:ec2:" + reg + ":*:" + type + "/" + name;
            }
            case "cloudfront" -> "arn:aws:cloudfront::*:" + (type.isEmpty() ? "distribution" : type) + "/" + name;
            case "route53" -> "arn:aws:route53:::" + (type.isEmpty() ? "hostedzone" : type) + "/" + name;
            case "acm" -> "arn:aws:acm:" + ("*".equals(reg) ? "us-east-1" : reg) + ":*:certificate/" + name;
            case "lambda" -> "arn:aws:lambda:" + reg + ":*:function:" + name;
            case "events" -> "arn:aws:events:" + reg + ":*:rule/" + name;
            case "ecs" -> "arn:aws:ecs:" + reg + ":*:" + (type.isEmpty() ? "cluster" : type) + "/" + name;
            case "cloudformation" -> "arn:aws:cloudformation:" + reg + ":*:stack/" + name + "/*";
            case "iam" -> "arn:aws:iam::*:" + (type.isEmpty() ? "policy" : type) + "/" + name;
            default -> "arn:aws:" + svc + ":" + reg + ":*:" + (type.isEmpty() ? name : type + "/" + name);
        };
    }

    /**
     * Maps an SDK operation key recorded in lmaws ledgers (e.g., "sqs.CreateQueue", "s3.ListBuckets")
     * to its canonical IAM action name (e.g., "sqs:CreateQueue", "s3:ListAllMyBuckets").
     */
    public static String mapLedgerOperationToIamAction(String ledgerKey) {
        if (ledgerKey == null || ledgerKey.isBlank()) return null;
        String clean = ledgerKey.trim();
        int dot = clean.indexOf('.');
        if (dot <= 0) {
            int colon = clean.indexOf(':');
            if (colon > 0) return clean;
            return null;
        }
        String rawSvc = clean.substring(0, dot).toLowerCase(Locale.ROOT);
        String op = clean.substring(dot + 1);
        String svc = switch (rawSvc) {
            case "costexplorer" -> "ce";
            case "cloudwatchlogs" -> "logs";
            default -> rawSvc;
        };
        if ("s3".equals(svc) && "ListBuckets".equalsIgnoreCase(op)) {
            return "s3:ListAllMyBuckets";
        }
        if ("s3".equals(svc) && ("HeadBucket".equalsIgnoreCase(op) || "ListObjectsV2".equalsIgnoreCase(op))) {
            return "s3:ListBucket";
        }
        if ("s3".equals(svc) && ("HeadObject".equalsIgnoreCase(op) || "GetObject".equalsIgnoreCase(op))) {
            return "s3:GetObject";
        }
        Map<String, String> catalog = SERVICE_ACTIONS.get(svc);
        if (catalog != null) {
            for (String candidate : catalog.keySet()) {
                if (candidate.equalsIgnoreCase(op)) {
                    return svc + ":" + candidate;
                }
            }
        }
        return svc + ":" + op;
    }

    public static Pattern wildcardToRegex(String pattern) {
        StringBuilder sb = new StringBuilder("^");
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '*') sb.append(".*");
            else if (c == '?') sb.append('.');
            else if ("\\.[]{}()+-^$|".indexOf(c) >= 0) sb.append('\\').append(c);
            else sb.append(c);
        }
        sb.append('$');
        return Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE);
    }

    private static String closestMatch(String input, Iterable<String> candidates) {
        String lower = input.toLowerCase(Locale.ROOT);
        String best = null;
        int bestDist = Integer.MAX_VALUE;
        for (String c : candidates) {
            int d = levenshtein(lower, c.toLowerCase(Locale.ROOT));
            if (d < bestDist && d <= Math.max(3, input.length() / 2)) {
                bestDist = d;
                best = c;
            }
        }
        return best;
    }

    private static int levenshtein(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= b.length(); j++) dp[0][j] = j;
        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(
                    Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                    dp[i - 1][j - 1] + cost
                );
            }
        }
        return dp[a.length()][b.length()];
    }
}
