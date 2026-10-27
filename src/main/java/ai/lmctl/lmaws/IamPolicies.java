package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class IamPolicies {
    public static final int INLINE_SESSION_POLICY_LIMIT = 2048;
    public static final int MANAGED_POLICY_LIMIT = 6144;
    public static final int MAX_POLICY_VERSIONS = 5;
    public static final String EXPECTED_VERSION = "2012-10-17";

    private static final Pattern POLICY_NAME_PATTERN = Pattern.compile("^lmaws_[a-z0-9_-]{1,64}$");

    public static final String ALLOWLIST_STAR_READ = "STAR_READ_ALLOWLIST";
    public static final String RULE_STAR_READ = ALLOWLIST_STAR_READ;
    public static final String ALLOWLIST_SSM_PUBLIC_READ = "SSM_PUBLIC_PARAM_ALLOWLIST";
    public static final String ALLOWLIST_IAM_SCOPED_ROLE_READ = "IAM_SCOPED_ROLE_READ_ALLOWLIST";
    public static final String ALLOWLIST_IAM_SCOPED_POLICY_READ = "IAM_SCOPED_POLICY_READ_ALLOWLIST";
    public static final String RULE_TAG_SCOPED_SENSITIVE_READ = "TAG_SCOPED_SENSITIVE_READ";
    public static final String RULE_PASS_ROLE_LAMBDA_ONLY = "PASS_ROLE_LAMBDA_ONLY";
    public static final String RULE_LAMBDA_ESM_CREATE = "LAMBDA_ESM_CREATE_SCOPED";
    public static final String RULE_ESM_ARN_NO_POLICY_VAR = "ESM_ARN_NO_POLICY_VARIABLE";
    public static final String RULE_FORBIDDEN_BARE_WILDCARD = "FORBIDDEN_BARE_WILDCARD";
    public static final String RULE_FORBIDDEN_STS_WILDCARD = "FORBIDDEN_STS_WILDCARD";
    public static final String RULE_FORBIDDEN_ACTION_PREFIX = "FORBIDDEN_ACTION_PREFIX";
    public static final String RULE_SCOPED_WRITE_REQUIRED = "SCOPED_WRITE_REQUIRED";

    // Separate lint mode rule IDs for operational EC2 instance roles and boundaries
    public static final String RULE_INSTANCE_ROLE_NO_ADMIN = "INSTANCE_ROLE_NO_ADMIN_WILDCARD";
    public static final String RULE_INSTANCE_ROLE_FORBIDDEN_ESCALATION = "INSTANCE_ROLE_FORBIDDEN_ESCALATION";
    public static final String RULE_INSTANCE_ROLE_SELF_STOP_SCOPED = "INSTANCE_ROLE_SELF_STOP_SCOPED";
    public static final String RULE_INSTANCE_ROLE_WEBSITE_ASSUME_SCOPED = "INSTANCE_ROLE_WEBSITE_ASSUME_SCOPED";
    public static final String RULE_INSTANCE_ROLE_WWW_S3_SCOPED = "INSTANCE_ROLE_WWW_S3_SCOPED";
    public static final String RULE_INSTANCE_ROLE_CODECOMMIT_NO_DELETE = "INSTANCE_ROLE_CODECOMMIT_NO_DELETE";
    public static final String RULE_INSTANCE_ROLE_SECRETS_READ_ONLY = "INSTANCE_ROLE_SECRETS_READ_ONLY";
    public static final String RULE_INSTANCE_ROLE_COGNITO_NO_DELETE = "INSTANCE_ROLE_COGNITO_NO_DELETE";
    public static final String RULE_INSTANCE_ROLE_ORIGIN_GUARD = "INSTANCE_ROLE_ORIGIN_AND_REGION_GUARD";

    /**
     * Reviewable one-line-per-entry data table of read/inventory actions and their required scope.
     * Adding a new safe read is a one-line change here. Sensitive reads such as acm:GetCertificate
     * are explicitly listed under TAG_SCOPED_SENSITIVE_READ so they are never allowed on '*'.
     */
    public record ReadRuleEntry(String pattern, String allowlistId, String requiredScope, String rationale) {
        public String ruleId() {
            return allowlistId;
        }
        public boolean matches(String actionLower) {
            if (actionLower == null) return false;
            if (pattern.endsWith("*")) {
                return actionLower.startsWith(pattern.substring(0, pattern.length() - 1));
            }
            return pattern.equals(actionLower);
        }
    }

    private static final List<ReadRuleEntry> READ_ALLOWLIST_TABLE = List.of(
        // --- Safe inventory / metadata reads allowed on Resource: "*" (STAR_READ_ALLOWLIST) ---
        new ReadRuleEntry("sts:getcalleridentity", ALLOWLIST_STAR_READ, "*", "Caller identity ARN/account lookup"),
        new ReadRuleEntry("s3:listallmybuckets", ALLOWLIST_STAR_READ, "*", "Bucket inventory listing"),
        new ReadRuleEntry("s3:getbucketlocation", ALLOWLIST_STAR_READ, "*", "Bucket region discovery"),
        new ReadRuleEntry("s3:getbuckettagging", ALLOWLIST_STAR_READ, "*", "Bucket ownership tag inspection"),
        new ReadRuleEntry("ec2:describe*", ALLOWLIST_STAR_READ, "*", "EC2 read-only fleet/network/volume/price metadata"),
        new ReadRuleEntry("sqs:listqueues", ALLOWLIST_STAR_READ, "*", "SQS queue URL inventory"),
        new ReadRuleEntry("sns:listtopics", ALLOWLIST_STAR_READ, "*", "SNS topic ARN inventory"),
        new ReadRuleEntry("sns:listsubscriptions", ALLOWLIST_STAR_READ, "*", "SNS subscription metadata inventory"),
        new ReadRuleEntry("dynamodb:listtables", ALLOWLIST_STAR_READ, "*", "DynamoDB table name inventory"),
        new ReadRuleEntry("dynamodb:describelimits", ALLOWLIST_STAR_READ, "*", "DynamoDB account capacity limits"),
        new ReadRuleEntry("logs:describeloggroups", ALLOWLIST_STAR_READ, "*", "CloudWatch log group metadata inventory"),
        new ReadRuleEntry("logs:describelogstreams", ALLOWLIST_STAR_READ, "*", "CloudWatch log stream metadata inventory"),
        new ReadRuleEntry("ssm:describeparameters", ALLOWLIST_STAR_READ, "*", "SSM parameter metadata listing (no values)"),
        new ReadRuleEntry("ssm:getparameters", ALLOWLIST_STAR_READ, "*", "SSM batch parameter metadata"),
        new ReadRuleEntry("ssm:getparametersbypath", ALLOWLIST_STAR_READ, "*", "SSM path parameter hierarchy"),
        new ReadRuleEntry("route53:list*", ALLOWLIST_STAR_READ, "*", "Route53 hosted zone and record listing"),
        new ReadRuleEntry("route53:get*", ALLOWLIST_STAR_READ, "*", "Route53 hosted zone and change status readback"),
        new ReadRuleEntry("cloudfront:list*", ALLOWLIST_STAR_READ, "*", "CloudFront distribution and OAC listing"),
        new ReadRuleEntry("cloudfront:get*", ALLOWLIST_STAR_READ, "*", "CloudFront distribution and OAC config readback"),
        new ReadRuleEntry("acm:list*", ALLOWLIST_STAR_READ, "*", "ACM certificate and tag metadata listing"),
        new ReadRuleEntry("acm:describe*", ALLOWLIST_STAR_READ, "*", "ACM certificate metadata description (not PEM body)"),
        new ReadRuleEntry("ecs:listclusters", ALLOWLIST_STAR_READ, "*", "ECS cluster ARN inventory"),
        new ReadRuleEntry("ecs:describeclusters", ALLOWLIST_STAR_READ, "*", "ECS cluster metadata inspection"),
        new ReadRuleEntry("lambda:list*", ALLOWLIST_STAR_READ, "*", "Lambda function and version inventory"),
        new ReadRuleEntry("events:list*", ALLOWLIST_STAR_READ, "*", "EventBridge rule and target inventory"),
        new ReadRuleEntry("cloudwatch:describealarms", ALLOWLIST_STAR_READ, "*", "CloudWatch alarm state inventory"),
        new ReadRuleEntry("cloudwatch:getmetricdata", ALLOWLIST_STAR_READ, "*", "CloudWatch metric time-series read"),
        new ReadRuleEntry("cloudwatch:getmetricstatistics", ALLOWLIST_STAR_READ, "*", "CloudWatch metric statistics read"),
        new ReadRuleEntry("cloudwatch:listmetrics", ALLOWLIST_STAR_READ, "*", "CloudWatch metric dimension listing"),
        new ReadRuleEntry("tag:getresources", ALLOWLIST_STAR_READ, "*", "Resource Groups Tagging API search"),
        new ReadRuleEntry("tag:gettagkeys", ALLOWLIST_STAR_READ, "*", "Resource Groups Tagging API key listing"),
        new ReadRuleEntry("tag:gettagvalues", ALLOWLIST_STAR_READ, "*", "Resource Groups Tagging API value listing"),
        new ReadRuleEntry("ce:get*", ALLOWLIST_STAR_READ, "*", "Cost Explorer read-only billing reports"),
        new ReadRuleEntry("savingsplans:describe*", ALLOWLIST_STAR_READ, "*", "Savings Plans utilization and rates read"),
        new ReadRuleEntry("pricing:describeservices", ALLOWLIST_STAR_READ, "*", "AWS Price List service catalog"),
        new ReadRuleEntry("pricing:getattributevalues", ALLOWLIST_STAR_READ, "*", "AWS Price List attribute catalog"),
        new ReadRuleEntry("pricing:getproducts", ALLOWLIST_STAR_READ, "*", "AWS Price List SKU pricing lookup"),

        // --- Sensitive reads explicitly excluded from '*' (TAG_SCOPED_SENSITIVE_READ) ---
        new ReadRuleEntry("acm:getcertificate", RULE_TAG_SCOPED_SENSITIVE_READ, "arn:aws:acm:us-east-1:*:certificate/* with Condition Null aws:ResourceTag/lmaws_test=false", "acm:GetCertificate exports certificate/chain PEM material and must stay tag-scoped in AcmOwn, never on '*'"),

        // --- Scoped public SSM parameter reads (SSM_PUBLIC_PARAM_ALLOWLIST) ---
        new ReadRuleEntry("ssm:getparameter", ALLOWLIST_SSM_PUBLIC_READ, "arn:aws:ssm:*::parameter/aws/service/* or :parameter/lmaws*", "Single parameter value read must be scoped to public /aws/service/* AMIs or lmaws* parameters"),

        // --- Scoped IAM role / policy metadata reads (IAM_SCOPED_*_READ_ALLOWLIST) ---
        new ReadRuleEntry("iam:getrole", ALLOWLIST_IAM_SCOPED_ROLE_READ, "arn:aws:iam::<account|*>:role/lmaws_*", "IAM role read must be scoped to lmaws_* roles"),
        new ReadRuleEntry("iam:listattachedrolepolicies", ALLOWLIST_IAM_SCOPED_ROLE_READ, "arn:aws:iam::<account|*>:role/lmaws_*", "IAM attached role policy listing must be scoped to lmaws_* roles"),
        new ReadRuleEntry("iam:getpolicy", ALLOWLIST_IAM_SCOPED_POLICY_READ, "arn:aws:iam::<account|*>:policy/lmaws_*", "IAM policy read must be scoped to lmaws_* policies")
    );

    public static List<ReadRuleEntry> readAllowlistTable() {
        return READ_ALLOWLIST_TABLE;
    }

    private static final Set<String> FORBIDDEN_ACTION_PREFIXES = Set.of(
        "iam:",
        "sts:assumerole",
        "organizations:",
        "account:",
        "kms:",
        "secretsmanager:"
    );

    private static final String LAMBDA_PASS_ROLE = "iam:passrole";

    private IamPolicies() {}

    public static void requireValidPolicyName(String policyName) {
        if (policyName == null || !POLICY_NAME_PATTERN.matcher(policyName).matches()) {
            throw new IllegalArgumentException(
                "IAM managed policy name must start with 'lmaws_' and match ^lmaws_[a-z0-9_-]{1,64}$: "
                    + Jsons.mask(String.valueOf(policyName)));
        }
    }

    public static void checkMutationGuard(
            boolean iamPolicyWrite,
            String profile,
            boolean live,
            boolean adminGrant,
            boolean applyFlag,
            String policyName) {
        String cleanProfile = profile == null ? "" : profile.trim();
        if (!iamPolicyWrite) {
            if ("admin".equals(cleanProfile)) {
                throw new IllegalStateException(
                    "The 'admin' profile is reserved exclusively for lmaws_ IAM policy grants; refusing regular resource mutation");
            }
            if (!live) {
                throw new IllegalStateException("live writes require LMAWS_LIVE=1");
            }
            if (!AwsBackend.MUTATING_PROFILES.contains(cleanProfile)) {
                throw new IllegalStateException(
                    "live mutations require AWS_PROFILE=lmaws or lmaws-ec2 (active profile: " + cleanProfile + ")");
            }
            return;
        }
        requireValidPolicyName(policyName);
        if (!applyFlag) {
            throw new IllegalStateException(
                "IAM policy writes require --apply (or LMAWS_APPLY=1); dry-run is the default");
        }
        if (!live) {
            throw new IllegalStateException("Live IAM policy writes require LMAWS_LIVE=1");
        }
        if (!"admin".equals(cleanProfile)) {
            throw new IllegalStateException(
                "IAM policy writes require AWS_PROFILE=admin; refusing profile '" + cleanProfile + "'");
        }
        if (!adminGrant) {
            throw new IllegalStateException(
                "IAM policy writes with the admin profile require LMAWS_ADMIN_GRANT=1");
        }
    }

    public static String decodeAwsDocument(String rawDocument) {
        if (rawDocument == null) return "";
        String trimmed = rawDocument.trim();
        if (trimmed.startsWith("%7B") || trimmed.startsWith("%7b") || trimmed.startsWith("%20") || trimmed.startsWith("%0A")) {
            return URLDecoder.decode(trimmed.replace("+", "%2B"), StandardCharsets.UTF_8);
        }
        return rawDocument;
    }

    /**
     * PassRole is a session-policy exception, never an inline/customer role
     * policy capability. Callers use this before linting a policy document so
     * role-context names cannot accidentally acquire it.
     */
    @SuppressWarnings("unchecked")
    public static void requirePassRolePolicyContext(String policyName, String documentJson) {
        if (documentJson == null || documentJson.isBlank()) return;
        final Object parsed;
        try {
            parsed = Json.parse(decodeAwsDocument(documentJson));
        } catch (RuntimeException ignored) {
            return; // lint owns malformed-document diagnostics
        }
        if (!(parsed instanceof Map<?, ?> doc)) return;
        Object statements = doc.get("Statement");
        if (!(statements instanceof List<?> list)) return;
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> raw)) continue;
            Object actions = raw.get("Action");
            for (String action : stringList(actions)) {
                if (LAMBDA_PASS_ROLE.equals(action.trim().toLowerCase(Locale.ROOT))
                        && !"lmaws_session".equals(policyName)) {
                    throw new IllegalArgumentException(
                        "iam:PassRole is permitted only in the lmaws_session policy; refusing policy '"
                            + Jsons.mask(String.valueOf(policyName)) + "'");
                }
            }
        }
    }

    public static String compactJson(Object value) {
        StringBuilder sb = new StringBuilder();
        writeCompactJson(sb, value);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeCompactJson(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String str) {
            sb.append(Jsons.encodeRaw(str));
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(Jsons.encodeRaw(String.valueOf(entry.getKey()))).append(':');
                writeCompactJson(sb, entry.getValue());
            }
            sb.append('}');
        } else if (value instanceof Iterable<?> list) {
            sb.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) sb.append(',');
                first = false;
                writeCompactJson(sb, item);
            }
            sb.append(']');
        } else {
            sb.append(Jsons.encodeRaw(String.valueOf(value)));
        }
    }

    public static String prettyJson(Object value) {
        StringBuilder sb = new StringBuilder();
        writePrettyJson(sb, value, 0);
        sb.append('\n');
        return sb.toString();
    }

    private static void writePrettyJson(StringBuilder sb, Object value, int indent) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String str) {
            sb.append(Jsons.encodeRaw(str));
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map<?, ?> map) {
            if (map.isEmpty()) {
                sb.append("{}");
                return;
            }
            sb.append("{\n");
            int idx = 0;
            int size = map.size();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                indent(sb, indent + 2);
                sb.append(Jsons.encodeRaw(String.valueOf(entry.getKey()))).append(": ");
                writePrettyJson(sb, entry.getValue(), indent + 2);
                if (++idx < size) sb.append(',');
                sb.append('\n');
            }
            indent(sb, indent);
            sb.append('}');
        } else if (value instanceof List<?> list) {
            if (list.isEmpty()) {
                sb.append("[]");
                return;
            }
            sb.append("[\n");
            for (int i = 0; i < list.size(); i++) {
                indent(sb, indent + 2);
                writePrettyJson(sb, list.get(i), indent + 2);
                if (i + 1 < list.size()) sb.append(',');
                sb.append('\n');
            }
            indent(sb, indent);
            sb.append(']');
        } else {
            sb.append(Jsons.encodeRaw(String.valueOf(value)));
        }
    }

    private static void indent(StringBuilder sb, int spaces) {
        for (int i = 0; i < spaces; i++) sb.append(' ');
    }

    public record StatementCheck(
        String sid,
        String effect,
        String category,
        int actionCount,
        int resourceCount,
        boolean valid,
        String detail
    ) {
        public Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("sid", sid);
            out.put("effect", effect);
            out.put("category", category);
            out.put("action_count", String.valueOf(actionCount));
            out.put("resource_count", String.valueOf(resourceCount));
            out.put("valid", String.valueOf(valid));
            out.put("detail", detail);
            out.put("count", 1);
            return out;
        }
    }

    public record LintResult(
        boolean valid,
        int compactLength,
        String version,
        int statementCount,
        int allowReadStatements,
        int allowScopedStatements,
        int denyStatements,
        List<String> checksPerformed,
        List<String> findings,
        List<StatementCheck> statementChecks,
        String compactDocument,
        String prettyDocument
    ) {
        public void requireValid() {
            if (!valid) {
                throw new IllegalArgumentException(
                    "IAM policy lint failed (" + findings.size() + " finding(s)): " + String.join("; ", findings));
            }
        }

        public String summaryLine() {
            return "IAM policy lint: valid=" + valid
                + ", compact_length=" + compactLength + "/" + MANAGED_POLICY_LIMIT
                + " (inline_limit=" + INLINE_SESSION_POLICY_LIMIT + ")"
                + ", version=" + version
                + ", statements=" + statementCount
                + " (allow_read=" + allowReadStatements
                + ", allow_scoped=" + allowScopedStatements
                + ", deny=" + denyStatements + ")"
                + ", findings=" + findings.size();
        }

        public Map<String, String> toMap() {
            Map<String, String> map = new LinkedHashMap<>();
            map.put("kind", "iam_policy_lint");
            map.put("valid", String.valueOf(valid));
            map.put("compact_length", String.valueOf(compactLength));
            map.put("max_length", String.valueOf(MANAGED_POLICY_LIMIT));
            map.put("inline_limit", String.valueOf(INLINE_SESSION_POLICY_LIMIT));
            map.put("exceeds_inline_limit", String.valueOf(compactLength > INLINE_SESSION_POLICY_LIMIT));
            map.put("version", version);
            map.put("statement_count", String.valueOf(statementCount));
            map.put("allow_read_statements", String.valueOf(allowReadStatements));
            map.put("allow_scoped_statements", String.valueOf(allowScopedStatements));
            map.put("deny_statements", String.valueOf(denyStatements));
            map.put("finding_count", String.valueOf(findings.size()));
            map.put("findings", Jsons.encode(findings));
            map.put("checks_performed", Jsons.encode(checksPerformed));
            map.put("statements", Jsons.encode(statementChecks.stream().map(StatementCheck::toMap).toList()));
            map.put("normalized_json", compactDocument);
            map.put("pretty_json", prettyDocument);
            map.put("summary", summaryLine());
            return map;
        }
    }

    @SuppressWarnings("unchecked")
    public static LintResult lint(String rawJson) {
        List<String> checks = new ArrayList<>();
        List<String> findings = new ArrayList<>();
        List<StatementCheck> statementChecks = new ArrayList<>();

        checks.add("json_syntax");
        if (rawJson == null || rawJson.isBlank()) {
            findings.add("Policy document is empty");
            return new LintResult(false, 0, "", 0, 0, 0, 0, checks, findings, statementChecks, "", "");
        }

        Object parsedObj;
        try {
            parsedObj = Json.parse(decodeAwsDocument(rawJson));
        } catch (RuntimeException ex) {
            findings.add("Invalid JSON document: " + Jsons.mask(ex.getMessage()));
            return new LintResult(false, 0, "", 0, 0, 0, 0, checks, findings, statementChecks, "", "");
        }
        if (!(parsedObj instanceof Map<?, ?> rawMap)) {
            findings.add("Policy document root must be a JSON object");
            return new LintResult(false, 0, "", 0, 0, 0, 0, checks, findings, statementChecks, "", "");
        }

        Map<String, Object> doc = (Map<String, Object>) rawMap;
        String compact = compactJson(doc);
        String pretty = prettyJson(doc);
        int compactLen = compact.length();

        checks.add("compact_size <= " + MANAGED_POLICY_LIMIT + " (inline_cap=" + INLINE_SESSION_POLICY_LIMIT + ")");
        if (compactLen > MANAGED_POLICY_LIMIT) {
            findings.add("Compact policy length " + compactLen + " exceeds managed policy limit " + MANAGED_POLICY_LIMIT);
        }

        String version = String.valueOf(doc.getOrDefault("Version", ""));
        checks.add("version == " + EXPECTED_VERSION);
        if (!EXPECTED_VERSION.equals(version)) {
            findings.add("Policy Version must be '" + EXPECTED_VERSION + "', got '" + version + "'");
        }

        checks.add("statements_non_empty");
        Object stmtObj = doc.get("Statement");
        if (!(stmtObj instanceof List<?> stmtList) || stmtList.isEmpty()) {
            findings.add("Policy Statement must be a non-empty JSON array");
            return new LintResult(false, compactLen, version, 0, 0, 0, 0, checks, findings, statementChecks, compact, pretty);
        }

        checks.add("no_forbidden_actions(iam:*,sts:AssumeRole*,organizations:*,account:*,kms:*,secretsmanager:*,*)");
        checks.add("no_wildcard_resource_on_write_actions");
        checks.add("allow_statements_read_or_scoped_by_name_tag_or_condition");

        // Pre-scan for companion guardrails in the same document
        boolean hasRunTaggedAllow = false;
        boolean hasNanoOnlyDeny = false;
        boolean hasSgMustBeTaggedDeny = false;
        for (Object item : stmtList) {
            if (!(item instanceof Map<?, ?> rawStmt)) continue;
            Map<String, Object> m = (Map<String, Object>) rawStmt;
            String eff = String.valueOf(m.getOrDefault("Effect", ""));
            List<String> acts = stringList(m.get("Action"));
            String condCompact = compactJson(m.get("Condition")).toLowerCase(Locale.ROOT);
            if ("Allow".equals(eff) && hasActionIgnoreCase(acts, "ec2:RunInstances")
                    && condCompact.contains("aws:requesttag/lmaws_test")) {
                hasRunTaggedAllow = true;
            }
            if ("Deny".equals(eff) && hasActionIgnoreCase(acts, "ec2:RunInstances")
                    && condCompact.contains("ec2:instancetype")) {
                hasNanoOnlyDeny = true;
            }
            if ("Deny".equals(eff) && hasActionIgnoreCase(acts, "ec2:CreateSecurityGroup")
                    && condCompact.contains("aws:requesttag/lmaws_test")) {
                hasSgMustBeTaggedDeny = true;
            }
        }

        int allowRead = 0;
        int allowScoped = 0;
        int denyCount = 0;

        for (int i = 0; i < stmtList.size(); i++) {
            Object item = stmtList.get(i);
            if (!(item instanceof Map<?, ?> rawStmtMap)) {
                findings.add("Statement[" + i + "] is not a JSON object");
                statementChecks.add(new StatementCheck("Statement[" + i + "]", "", "violation", 0, 0, false, "not a JSON object"));
                continue;
            }
            Map<String, Object> stmtMap = (Map<String, Object>) rawStmtMap;
            String sid = String.valueOf(stmtMap.getOrDefault("Sid", "Statement[" + i + "]"));
            String effect = String.valueOf(stmtMap.getOrDefault("Effect", ""));
            if (stmtMap.containsKey("Principal") || stmtMap.containsKey("NotPrincipal")) {
                findings.add("statement " + sid + ": Principal/NotPrincipal is not allowed in a managed session policy");
            }
            if ("Deny".equals(effect)) {
                List<String> actions = stringList(stmtMap.getOrDefault("Action", stmtMap.get("NotAction")));
                List<String> resources = stringList(stmtMap.getOrDefault("Resource", stmtMap.get("NotResource")));
                if (actions.isEmpty() || resources.isEmpty()) {
                    findings.add("statement " + sid + ": Deny statement must specify Action/NotAction and Resource/NotResource");
                    statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, "incomplete Deny statement"));
                } else {
                    denyCount++;
                    statementChecks.add(new StatementCheck(sid, effect, "deny_guardrail", actions.size(), resources.size(), true, "deny guardrail"));
                }
                continue;
            }
            if (!"Allow".equals(effect)) {
                findings.add("statement " + sid + ": Effect must be 'Allow' or 'Deny', got '" + effect + "'");
                statementChecks.add(new StatementCheck(sid, effect, "violation", 0, 0, false, "invalid Effect"));
                continue;
            }
            if (stmtMap.containsKey("NotAction") || stmtMap.containsKey("NotResource")) {
                findings.add("statement " + sid + ": Allow statement must not use NotAction or NotResource");
                statementChecks.add(new StatementCheck(sid, effect, "violation", 0, 0, false, "uses NotAction or NotResource"));
                continue;
            }

            List<String> actions = stringList(stmtMap.get("Action"));
            List<String> resources = stringList(stmtMap.get("Resource"));
            if (actions.isEmpty() || resources.isEmpty()) {
                findings.add("statement " + sid + ": Allow statement must have non-empty Action and Resource");
                statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, "empty Action or Resource"));
                continue;
            }

            List<String> stmtFindings = new ArrayList<>();
            for (String res : resources) {
                if (res.contains(":event-source-mapping:") && res.contains("${")) {
                    stmtFindings.add("statement " + sid + " [rule=" + RULE_ESM_ARN_NO_POLICY_VAR
                        + "]: AWS IAM rejects policy variables (${...}) inside Lambda event-source-mapping ARNs with MalformedPolicyDocument ('"
                        + res + "'); use wildcard account '*' (arn:aws:lambda:us-east-1:*:event-source-mapping:*)");
                }
            }
            if (stmtMap.get("Condition") != null
                    && compactJson(stmtMap.get("Condition")).contains("${")
                    && actions.stream().anyMatch(a -> a.toLowerCase(Locale.ROOT).contains("eventsourcemapping"))) {
                stmtFindings.add("statement " + sid + " [rule=" + RULE_ESM_ARN_NO_POLICY_VAR
                    + "]: AWS IAM rejects policy variables (${...}) in Lambda event-source-mapping FunctionArn condition with MalformedPolicyDocument; use wildcard account '*' (arn:aws:lambda:us-east-1:*:function:lmaws_*)");
            }
            boolean scopedIamRead = isScopedIamRead(actions, resources);
            for (String action : actions) {
                String lower = action.trim().toLowerCase(Locale.ROOT);
                if (lower.equals("*") || lower.equals("*:*")) {
                    stmtFindings.add("statement " + sid + " [rule=" + RULE_FORBIDDEN_BARE_WILDCARD + "]: refuses bare wildcard action '" + action + "'");
                    continue;
                }
                if (lower.equals("sts:*")) {
                    stmtFindings.add("statement " + sid + " [rule=" + RULE_FORBIDDEN_STS_WILDCARD + "]: refuses wildcard STS action '" + action + "'");
                    continue;
                }
                // Exactly one IAM action is safe for the session policy: passing
                // the pre-built lmaws_* execution role to Lambda under the exact
                // service condition checked below. Every other iam: action remains
                // forbidden, including role creation and policy administration.
                if ((LAMBDA_PASS_ROLE.equals(lower) && isExactLambdaPassRole(stmtMap, actions, resources))
                        || (lower.startsWith("iam:") && scopedIamRead)) {
                    continue;
                }
                if (LAMBDA_PASS_ROLE.equals(lower)) {
                    stmtFindings.add("statement " + sid + " [rule=" + RULE_PASS_ROLE_LAMBDA_ONLY
                        + "]: refuses forbidden action '" + action
                        + "' (iam:PassRole is only allowed as the exact lmaws_session Lambda exception on arn:aws:iam::*:role/lmaws_* with StringEquals iam:PassedToService=lambda.amazonaws.com)");
                    continue;
                }
                for (String forbiddenPrefix : FORBIDDEN_ACTION_PREFIXES) {
                    if (lower.startsWith(forbiddenPrefix)) {
                        ReadRuleEntry scopedEntry = matchReadRule(lower);
                        String ruleTag = scopedEntry != null
                            ? "rule=" + RULE_FORBIDDEN_ACTION_PREFIX + ", allowlist=" + scopedEntry.allowlistId()
                            : "rule=" + RULE_FORBIDDEN_ACTION_PREFIX + " (" + forbiddenPrefix + ")";
                        stmtFindings.add("statement " + sid + " [" + ruleTag + "]: refuses forbidden action '" + action + "'"
                            + (scopedEntry != null ? " (" + scopedEntry.rationale() + "; required scope: " + scopedEntry.requiredScope() + ")" : ""));
                        break;
                    }
                }
            }

            boolean hasStarResource = resources.stream().anyMatch(r -> "*".equals(r.trim()));
            boolean allInReadAllowlist = actions.stream()
                .allMatch(IamPolicies::isInventoryReadAction)
                && actions.stream().noneMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("iam:"));
            boolean isScopedSsmPublicRead = actions.stream()
                .allMatch(a -> "ssm:getparameter".equalsIgnoreCase(a.trim())
                    || "ssm:getparameters".equalsIgnoreCase(a.trim())
                    || "ssm:getparametersbypath".equalsIgnoreCase(a.trim()))
                && !hasStarResource
                && resources.stream().allMatch(r -> r.contains(":parameter/aws/service/") || r.contains(":parameter/lmaws"));

            if (hasStarResource && isExactLambdaCreateEventSourceMapping(actions, resources, stmtMap.get("Condition"))) {
                if (stmtFindings.isEmpty()) {
                    allowScoped++;
                    statementChecks.add(new StatementCheck(sid, effect, "allow_scoped_write", actions.size(), resources.size(), true,
                        "scoped lambda:CreateEventSourceMapping on * by lambda:FunctionArn + aws:RequestTag/lmaws_test + aws:TagKeys (" + RULE_LAMBDA_ESM_CREATE + ")"));
                } else {
                    findings.addAll(stmtFindings);
                    statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, String.join("; ", stmtFindings)));
                }
                continue;
            }

            if (hasStarResource) {
                if (!allInReadAllowlist) {
                    for (String action : actions) {
                        if (!isInventoryReadAction(action)) {
                            stmtFindings.add(explainStarReadRejection(sid, action));
                        }
                    }
                }
                if (stmtFindings.isEmpty()) {
                    allowRead++;
                    statementChecks.add(new StatementCheck(sid, effect, "allow_read", actions.size(), resources.size(), true, "inventory/read allow-list on * (" + ALLOWLIST_STAR_READ + ")"));
                } else {
                    findings.addAll(stmtFindings);
                    statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, String.join("; ", stmtFindings)));
                }
                continue;
            }

            if (allInReadAllowlist || isScopedSsmPublicRead || scopedIamRead) {
                if (stmtFindings.isEmpty()) {
                    allowRead++;
                    statementChecks.add(new StatementCheck(sid, effect, "allow_read", actions.size(), resources.size(), true, "scoped read/inventory"));
                } else {
                    findings.addAll(stmtFindings);
                    statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, String.join("; ", stmtFindings)));
                }
                continue;
            }

            // Write or non-read action: must be scoped by resource name, tag condition, or bounded guardrail condition
            String scopeReason = checkWriteScope(sid, actions, resources, stmtMap.get("Condition"),
                hasRunTaggedAllow && hasNanoOnlyDeny, hasSgMustBeTaggedDeny);
            if (scopeReason == null) {
                stmtFindings.add("statement " + sid + " [rule=" + RULE_SCOPED_WRITE_REQUIRED + "]: write action(s) " + actions
                    + " on resource(s) " + resources
                    + " must be scoped by lmaws-*/lmaws_* resource name, lmaws_test tag condition, or bounded guardrail condition");
            }
            if (stmtFindings.isEmpty()) {
                allowScoped++;
                statementChecks.add(new StatementCheck(sid, effect, "allow_scoped_write", actions.size(), resources.size(), true, scopeReason));
            } else {
                findings.addAll(stmtFindings);
                statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, String.join("; ", stmtFindings)));
            }
        }

        boolean valid = findings.isEmpty();
        return new LintResult(
            valid,
            compactLen,
            version,
            stmtList.size(),
            allowRead,
            allowScoped,
            denyCount,
            checks,
            findings,
            statementChecks,
            compact,
            pretty
        );
    }

    /**
     * Separate lint mode for least-privilege EC2 fleet instance roles ({@code example-ops-role-1},
     * {@code example-ops-role-2}) and their mandatory permissions boundary ({@code example-ops-boundary}).
     * Keeps {@link #lint(String)} (for {@code lmaws_session}) completely unweakened while validating
     * legitimate operational capabilities (self-stop by instance tag/ARN, dedicated deploy-role AssumeRole,
     * single-bucket S3 sync, CodeCommit sync with delete deny, SecretsManager read-only, Cognito
     * operational access with unconditional delete deny, and mandatory EC2 instance-origin + us-east-1
     * region guardrails).
     */
    @SuppressWarnings("unchecked")
    public static LintResult lintInstanceRole(String rawJson) {
        List<String> checks = new ArrayList<>();
        List<String> findings = new ArrayList<>();
        List<StatementCheck> statementChecks = new ArrayList<>();

        checks.add("json_syntax");
        if (rawJson == null || rawJson.isBlank()) {
            findings.add("Policy document is empty");
            return new LintResult(false, 0, "", 0, 0, 0, 0, checks, findings, statementChecks, "", "");
        }

        Object parsedObj;
        try {
            parsedObj = Json.parse(decodeAwsDocument(rawJson));
        } catch (RuntimeException ex) {
            findings.add("Invalid JSON document: " + Jsons.mask(ex.getMessage()));
            return new LintResult(false, 0, "", 0, 0, 0, 0, checks, findings, statementChecks, "", "");
        }
        if (!(parsedObj instanceof Map<?, ?> rawMap)) {
            findings.add("Policy document root must be a JSON object");
            return new LintResult(false, 0, "", 0, 0, 0, 0, checks, findings, statementChecks, "", "");
        }

        Map<String, Object> doc = (Map<String, Object>) rawMap;
        String compact = compactJson(doc);
        String pretty = prettyJson(doc);
        int compactLen = compact.length();

        checks.add("compact_size <= " + MANAGED_POLICY_LIMIT);
        if (compactLen > MANAGED_POLICY_LIMIT) {
            findings.add("Compact policy length " + compactLen + " exceeds managed policy limit " + MANAGED_POLICY_LIMIT);
        }

        String version = String.valueOf(doc.getOrDefault("Version", ""));
        checks.add("version == " + EXPECTED_VERSION);
        if (!EXPECTED_VERSION.equals(version)) {
            findings.add("Policy Version must be '" + EXPECTED_VERSION + "', got '" + version + "'");
        }

        checks.add("statements_non_empty");
        Object stmtObj = doc.get("Statement");
        if (!(stmtObj instanceof List<?> stmtList) || stmtList.isEmpty()) {
            findings.add("Policy Statement must be a non-empty JSON array");
            return new LintResult(false, compactLen, version, 0, 0, 0, 0, checks, findings, statementChecks, compact, pretty);
        }

        checks.add("instance_role_no_admin_wildcard(" + RULE_INSTANCE_ROLE_NO_ADMIN + ")");
        checks.add("instance_role_no_privilege_escalation(" + RULE_INSTANCE_ROLE_FORBIDDEN_ESCALATION + ")");
        checks.add("instance_role_scoped_ops(" + RULE_INSTANCE_ROLE_SELF_STOP_SCOPED + ","
            + RULE_INSTANCE_ROLE_WEBSITE_ASSUME_SCOPED + "," + RULE_INSTANCE_ROLE_WWW_S3_SCOPED + ","
            + RULE_INSTANCE_ROLE_CODECOMMIT_NO_DELETE + "," + RULE_INSTANCE_ROLE_SECRETS_READ_ONLY + ","
            + RULE_INSTANCE_ROLE_COGNITO_NO_DELETE + ")");
        checks.add("instance_role_origin_and_region_guard(" + RULE_INSTANCE_ROLE_ORIGIN_GUARD + ")");

        boolean hasCodeCommitAllow = false;
        boolean hasCodeCommitDeleteDeny = false;
        boolean hasCognitoAllow = false;
        boolean hasCognitoDeleteDeny = false;
        boolean hasOriginGuardDeny = false;
        boolean hasRegionGuardDeny = false;

        for (Object item : stmtList) {
            if (!(item instanceof Map<?, ?> rawStmt)) continue;
            Map<String, Object> m = (Map<String, Object>) rawStmt;
            String eff = String.valueOf(m.getOrDefault("Effect", ""));
            List<String> acts = stringList(m.getOrDefault("Action", m.get("NotAction")));
            List<String> resList = stringList(m.getOrDefault("Resource", m.get("NotResource")));
            String condLower = compactJson(m.get("Condition")).toLowerCase(Locale.ROOT);
            if ("Allow".equals(eff)) {
                if (acts.stream().anyMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("codecommit:"))) {
                    hasCodeCommitAllow = true;
                }
                if (acts.stream().anyMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("cognito-idp:"))) {
                    hasCognitoAllow = true;
                }
            } else if ("Deny".equals(eff)) {
                boolean starRes = resList.stream().anyMatch(r -> "*".equals(r.trim()) || r.contains(":codecommit:"));
                if (starRes
                        && hasActionIgnoreCase(acts, "codecommit:DeleteRepository")
                        && hasActionIgnoreCase(acts, "codecommit:DeleteBranch")) {
                    hasCodeCommitDeleteDeny = true;
                }
                if (resList.stream().anyMatch(r -> "*".equals(r.trim()))
                        && hasActionIgnoreCase(acts, "cognito-idp:*Delete*")
                        && hasActionIgnoreCase(acts, "cognito-idp:ForgetDevice")
                        && hasActionIgnoreCase(acts, "cognito-idp:AdminForgetDevice")
                        && (m.get("Condition") == null || condLower.equals("null") || condLower.equals("{}"))) {
                    hasCognitoDeleteDeny = true;
                }
                if (condLower.contains("\"ec2:sourceinstancearn\":\"true\"")) {
                    hasOriginGuardDeny = true;
                }
                if (condLower.contains("\"aws:requestedregion\":\"us-east-1\"")) {
                    hasRegionGuardDeny = true;
                }
            }
        }

        int allowRead = 0;
        int allowScoped = 0;
        int denyCount = 0;

        for (int i = 0; i < stmtList.size(); i++) {
            Object item = stmtList.get(i);
            if (!(item instanceof Map<?, ?> rawStmtMap)) {
                findings.add("Statement[" + i + "] is not a JSON object");
                statementChecks.add(new StatementCheck("Statement[" + i + "]", "", "violation", 0, 0, false, "not a JSON object"));
                continue;
            }
            Map<String, Object> stmtMap = (Map<String, Object>) rawStmtMap;
            String sid = String.valueOf(stmtMap.getOrDefault("Sid", "Statement[" + i + "]"));
            String effect = String.valueOf(stmtMap.getOrDefault("Effect", ""));
            if (stmtMap.containsKey("Principal") || stmtMap.containsKey("NotPrincipal")) {
                findings.add("statement " + sid + ": Principal/NotPrincipal is not allowed in an instance permissions policy");
            }
            if ("Deny".equals(effect)) {
                List<String> actions = stringList(stmtMap.getOrDefault("Action", stmtMap.get("NotAction")));
                List<String> resources = stringList(stmtMap.getOrDefault("Resource", stmtMap.get("NotResource")));
                if (actions.isEmpty() || resources.isEmpty()) {
                    findings.add("statement " + sid + ": Deny statement must specify Action/NotAction and Resource/NotResource");
                    statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, "incomplete Deny statement"));
                } else {
                    denyCount++;
                    statementChecks.add(new StatementCheck(sid, effect, "deny_guardrail", actions.size(), resources.size(), true, "instance-role deny guardrail"));
                }
                continue;
            }
            if (!"Allow".equals(effect)) {
                findings.add("statement " + sid + ": Effect must be 'Allow' or 'Deny', got '" + effect + "'");
                statementChecks.add(new StatementCheck(sid, effect, "violation", 0, 0, false, "invalid Effect"));
                continue;
            }
            if (stmtMap.containsKey("NotAction") || stmtMap.containsKey("NotResource")) {
                findings.add("statement " + sid + ": Allow statement must not use NotAction or NotResource");
                statementChecks.add(new StatementCheck(sid, effect, "violation", 0, 0, false, "uses NotAction or NotResource"));
                continue;
            }

            List<String> actions = stringList(stmtMap.get("Action"));
            List<String> resources = stringList(stmtMap.get("Resource"));
            if (actions.isEmpty() || resources.isEmpty()) {
                findings.add("statement " + sid + ": Allow statement must have non-empty Action and Resource");
                statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, "empty Action or Resource"));
                continue;
            }

            String categoryOrError = checkInstanceRoleAllowStatement(
                sid, actions, resources, stmtMap.get("Condition"),
                hasCodeCommitDeleteDeny, hasCognitoDeleteDeny);
            if (categoryOrError.startsWith("ERROR:")) {
                String err = categoryOrError.substring("ERROR:".length());
                findings.add(err);
                statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, err));
            } else if (categoryOrError.startsWith("READ:")) {
                allowRead++;
                statementChecks.add(new StatementCheck(sid, effect, "allow_read", actions.size(), resources.size(), true, categoryOrError.substring("READ:".length())));
            } else {
                allowScoped++;
                statementChecks.add(new StatementCheck(sid, effect, "allow_scoped_write", actions.size(), resources.size(), true, categoryOrError.substring("SCOPED:".length())));
            }
        }

        if (hasCodeCommitAllow && !hasCodeCommitDeleteDeny) {
            findings.add("policy [rule=" + RULE_INSTANCE_ROLE_CODECOMMIT_NO_DELETE
                + "]: CodeCommit Allow statements require a companion Deny on codecommit:DeleteRepository and codecommit:DeleteBranch");
        }
        if (hasCognitoAllow && !hasCognitoDeleteDeny) {
            findings.add("policy [rule=" + RULE_INSTANCE_ROLE_COGNITO_NO_DELETE
                + "]: Cognito Allow statements require an unconditional companion Deny on cognito-idp:*Delete*, cognito-idp:ForgetDevice, and cognito-idp:AdminForgetDevice");
        }
        if (!hasOriginGuardDeny || !hasRegionGuardDeny) {
            findings.add("policy [rule=" + RULE_INSTANCE_ROLE_ORIGIN_GUARD
                + "]: instance-role policy must include explicit Deny guardrails for non-EC2 credential origin (Null ec2:SourceInstanceArn=true) and non-us-east-1 regions");
        }

        boolean valid = findings.isEmpty();
        return new LintResult(
            valid,
            compactLen,
            version,
            stmtList.size(),
            allowRead,
            allowScoped,
            denyCount,
            checks,
            findings,
            statementChecks,
            compact,
            pretty
        );
    }

    private static String checkInstanceRoleAllowStatement(
            String sid,
            List<String> actions,
            List<String> resources,
            Object conditionObj,
            boolean hasCodeCommitDeleteDeny,
            boolean hasCognitoDeleteDeny) {
        String condCompact = conditionObj == null ? "" : compactJson(conditionObj);
        String condLower = condCompact.toLowerCase(Locale.ROOT);

        // 1. Refuse admin wildcards and privilege escalation actions unconditionally
        Set<String> forbiddenExact = Set.of(
            "*", "*:*", "iam:*", "sts:*", "ec2:*", "s3:*", "organizations:*", "account:*", "kms:*", "secretsmanager:*"
        );
        Set<String> forbiddenEscalationPrefixes = Set.of("iam:", "organizations:", "account:");
        Set<String> forbiddenFleetActions = Set.of(
            "kms:createkey",
            "kms:schedulekeydeletion",
            "kms:putkeypolicy",
            "kms:encrypt",
            "kms:generatedatakey",
            "ec2:terminateinstances",
            "ec2:deletevolume",
            "ec2:releaseaddress",
            "ec2:associateaddress",
            "ec2:disassociateaddress",
            "ec2:runinstances",
            "ec2:startinstances",
            "ec2:rebootinstances",
            "ec2:associateiaminstanceprofile",
            "ec2:disassociateiaminstanceprofile",
            "ec2:replaceiaminstanceprofileassociation",
            "cloudtrail:deletetrail",
            "cloudtrail:stoplogging",
            "cloudtrail:updatetrail",
            "config:deleteconfigurationrecorder",
            "config:stopconfigurationrecorder",
            "config:deletedeliverychannel",
            "s3:deletebucket",
            "s3:putbucketpolicy",
            "s3:deletebucketpolicy",
            "codecommit:deleterepository",
            "codecommit:deletebranch",
            "secretsmanager:createsecret",
            "secretsmanager:putsecretvalue",
            "secretsmanager:deletesecret"
        );
        for (String action : actions) {
            String lower = action.trim().toLowerCase(Locale.ROOT);
            if (forbiddenExact.contains(lower)) {
                return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_NO_ADMIN
                    + "]: refuses admin/wildcard action '" + action + "' in instance role";
            }
            for (String prefix : forbiddenEscalationPrefixes) {
                if (lower.startsWith(prefix)) {
                    return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_FORBIDDEN_ESCALATION
                        + "]: refuses privilege escalation or admin action '" + action + "' in instance role (agents must never hold or create admin)";
                }
            }
            if (forbiddenFleetActions.contains(lower)) {
                return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_FORBIDDEN_ESCALATION
                    + "]: refuses destructive or fleet-controller action '" + action + "' in instance role";
            }
        }

        // 2. Self-stop watchdog: ec2:StopInstances
        if (actions.size() == 1 && "ec2:stopinstances".equalsIgnoreCase(actions.get(0).trim())) {
            boolean validResource = resources.stream().allMatch(r ->
                r.trim().matches("arn:aws:ec2:us-east-1:(?:\\$\\{aws:PrincipalAccount\\}|\\*|[0-9]{12}):instance/\\*"));
            boolean hasProjectTag = condLower.contains("\"aws:resourcetag/project\":\"")
                && !condLower.contains("\"aws:resourcetag/project\":\"\"");
            boolean hasRoleOrInstanceScope = condLower.contains("aws:resourcetag/role")
                || condLower.contains("aws:resourcetag/name")
                || condLower.contains("ec2:sourceinstancearn");
            boolean hasRegion = condLower.contains("\"aws:requestedregion\":\"us-east-1\"");
            if (validResource && hasProjectTag && hasRoleOrInstanceScope && hasRegion) {
                return "SCOPED:scoped self-stop on tagged fleet instance (" + RULE_INSTANCE_ROLE_SELF_STOP_SCOPED + ")";
            }
            return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_SELF_STOP_SCOPED
                + "]: ec2:StopInstances must be scoped to arn:aws:ec2:us-east-1:${aws:PrincipalAccount}:instance/* with aws:ResourceTag/Project, Role/Name tag, and aws:RequestedRegion=us-east-1";
        }

        // 3. Dedicated deploy role assumption: sts:AssumeRole on an explicit non-admin *-deploy role ARN
        if (actions.size() == 1 && "sts:assumerole".equalsIgnoreCase(actions.get(0).trim())) {
            String roleArn = resources.size() == 1 ? resources.get(0).trim() : "";
            boolean validRoleArn = roleArn.matches("arn:aws:iam::(?:\\$\\{aws:PrincipalAccount\\}|\\*|[0-9]{12}):role/[a-z0-9-]+-deploy")
                && !roleArn.toLowerCase(Locale.ROOT).contains("admin");
            if (validRoleArn) {
                return "SCOPED:scoped sts:AssumeRole on dedicated deploy role (" + RULE_INSTANCE_ROLE_WEBSITE_ASSUME_SCOPED + ")";
            }
            return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_WEBSITE_ASSUME_SCOPED
                + "]: sts:AssumeRole in instance role is only permitted for an explicit non-admin *-deploy role ARN, got " + resources;
        }

        // 4. Single named S3 bucket & object sync (no wildcards in bucket name)
        if (actions.stream().allMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("s3:"))) {
            Set<String> bucketRead = Set.of("s3:listbucket", "s3:getbucketlocation");
            Set<String> objectSync = Set.of(
                "s3:getobject", "s3:getobjecttagging", "s3:getobjectattributes",
                "s3:putobject", "s3:putobjecttagging",
                "s3:deleteobject", "s3:deleteobjecttagging", "s3:abortmultipartupload"
            );
            String res = resources.size() == 1 ? resources.get(0).trim() : "";
            if (actions.stream().allMatch(a -> bucketRead.contains(a.trim().toLowerCase(Locale.ROOT)))
                    && res.matches("arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")) {
                return "READ:scoped S3 bucket read on explicit bucket ARN (" + RULE_INSTANCE_ROLE_WWW_S3_SCOPED + ")";
            }
            if (actions.stream().allMatch(a -> objectSync.contains(a.trim().toLowerCase(Locale.ROOT)))
                    && res.matches("arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/\\*")) {
                return "SCOPED:scoped S3 object sync on explicit bucket/* ARN (" + RULE_INSTANCE_ROLE_WWW_S3_SCOPED + ")";
            }
            return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_WWW_S3_SCOPED
                + "]: S3 actions in instance role must be scoped strictly to a single explicit bucket ARN (arn:aws:s3:::<bucket> or arn:aws:s3:::<bucket>/*)";
        }

        // 5. CodeCommit git pull/push and repository metadata (with companion delete deny)
        if (actions.stream().allMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("codecommit:"))) {
            Set<String> allowedCc = Set.of(
                "codecommit:gitpull", "codecommit:gitpush",
                "codecommit:getrepository", "codecommit:getbranch", "codecommit:getcommit",
                "codecommit:listrepositories", "codecommit:listbranches"
            );
            boolean validActions = actions.stream().allMatch(a -> allowedCc.contains(a.trim().toLowerCase(Locale.ROOT)));
            boolean validResources = resources.size() == 1
                && resources.get(0).trim().matches("arn:aws:codecommit:us-east-1:(?:\\$\\{aws:PrincipalAccount\\}|\\*|[0-9]{12}):\\*");
            boolean hasRegion = condLower.contains("\"aws:requestedregion\":\"us-east-1\"");
            if (validActions && validResources && hasRegion && hasCodeCommitDeleteDeny) {
                return "SCOPED:scoped CodeCommit sync with delete guardrail (" + RULE_INSTANCE_ROLE_CODECOMMIT_NO_DELETE + ")";
            }
            return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_CODECOMMIT_NO_DELETE
                + "]: CodeCommit actions must be limited to GitPull/GitPush/Get*/List* on arn:aws:codecommit:us-east-1:${aws:PrincipalAccount}:* with aws:RequestedRegion=us-east-1 and a companion delete Deny";
        }

        // 6. Secrets Manager read-only & KMS Decrypt via Secrets Manager
        if (actions.stream().allMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("secretsmanager:"))) {
            boolean hasRegion = condLower.contains("\"aws:requestedregion\":\"us-east-1\"");
            if (actions.size() == 1 && "secretsmanager:listsecrets".equalsIgnoreCase(actions.get(0).trim())
                    && resources.equals(List.of("*")) && hasRegion) {
                return "READ:scoped SecretsManager ListSecrets in us-east-1 (" + RULE_INSTANCE_ROLE_SECRETS_READ_ONLY + ")";
            }
            Set<String> secretReads = Set.of("secretsmanager:getsecretvalue", "secretsmanager:describesecret");
            boolean validReadActs = actions.stream().allMatch(a -> secretReads.contains(a.trim().toLowerCase(Locale.ROOT)));
            boolean validSecretArn = resources.size() == 1
                && resources.get(0).trim().matches("arn:aws:secretsmanager:us-east-1:(?:\\$\\{aws:PrincipalAccount\\}|\\*|[0-9]{12}):secret:\\*");
            if (validReadActs && validSecretArn && hasRegion) {
                return "READ:scoped SecretsManager read-only in us-east-1 (" + RULE_INSTANCE_ROLE_SECRETS_READ_ONLY + ")";
            }
            return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_SECRETS_READ_ONLY
                + "]: SecretsManager in instance role must be read-only (ListSecrets or GetSecretValue/DescribeSecret on arn:aws:secretsmanager:us-east-1:${aws:PrincipalAccount}:secret:*) with aws:RequestedRegion=us-east-1";
        }
        if (actions.stream().anyMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("kms:"))) {
            boolean onlyDecrypt = actions.size() == 1 && "kms:decrypt".equalsIgnoreCase(actions.get(0).trim());
            boolean validKeyArn = resources.size() == 1
                && resources.get(0).trim().matches("arn:aws:kms:us-east-1:(?:\\$\\{aws:PrincipalAccount\\}|\\*|[0-9]{12}):key/\\*");
            boolean hasRegion = condLower.contains("\"aws:requestedregion\":\"us-east-1\"");
            boolean hasViaService = condLower.contains("\"kms:viaservice\":\"secretsmanager.us-east-1.amazonaws.com\"");
            if (onlyDecrypt && validKeyArn && hasRegion && hasViaService) {
                return "READ:scoped KMS Decrypt via SecretsManager in us-east-1 (" + RULE_INSTANCE_ROLE_SECRETS_READ_ONLY + ")";
            }
            return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_FORBIDDEN_ESCALATION
                + "]: kms actions in instance role are restricted to kms:Decrypt on arn:aws:kms:us-east-1:${aws:PrincipalAccount}:key/* conditioned on kms:ViaService=secretsmanager.us-east-1.amazonaws.com";
        }

        // 7. Cognito User Pools non-destructive operational access
        if (actions.stream().anyMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("cognito-idp:"))) {
            boolean allCognito = actions.stream().allMatch(a -> a.trim().toLowerCase(Locale.ROOT).startsWith("cognito-idp:"));
            boolean noDeleteInAllow = actions.stream().noneMatch(a -> {
                String l = a.trim().toLowerCase(Locale.ROOT);
                return l.contains("delete") || l.contains("forgetdevice");
            });
            boolean hasRegion = condLower.contains("\"aws:requestedregion\":\"us-east-1\"");
            boolean hasAccountLock = condLower.contains("\"aws:resourceaccount\":\"${aws:principalaccount}\"");
            if (allCognito && noDeleteInAllow && hasRegion && hasAccountLock && hasCognitoDeleteDeny) {
                return "SCOPED:scoped Cognito User Pools operational access with unconditional delete Deny (" + RULE_INSTANCE_ROLE_COGNITO_NO_DELETE + ")";
            }
            return "ERROR:statement " + sid + " [rule=" + RULE_INSTANCE_ROLE_COGNITO_NO_DELETE
                + "]: Cognito actions require aws:RequestedRegion=us-east-1, aws:ResourceAccount=${aws:PrincipalAccount}, and an unconditional companion Deny on cognito-idp:*Delete*/ForgetDevice/AdminForgetDevice";
        }

        // 8. Scoped public SSM Ubuntu AMI lookup & Ubuntu SSM Agent heartbeat
        if (actions.stream().allMatch(a -> "ssm:getparameter".equalsIgnoreCase(a.trim()) || "ssm:getparameters".equalsIgnoreCase(a.trim()))
                && resources.stream().allMatch(r -> r.trim().startsWith("arn:aws:ssm:us-east-1::parameter/aws/service/canonical/ubuntu/"))) {
            return "READ:scoped public Ubuntu AMI SSM parameter lookup (" + ALLOWLIST_SSM_PUBLIC_READ + ")";
        }
        Set<String> ssmHeartbeatActs = Set.of(
            "ssm:updateinstanceinformation", "ssm:listinstanceassociations", "ssm:listassociations"
        );
        if (actions.stream().allMatch(a -> ssmHeartbeatActs.contains(a.trim().toLowerCase(Locale.ROOT)))
                && resources.equals(List.of("*"))
                && condLower.contains("\"aws:requestedregion\":\"us-east-1\"")) {
            return "SCOPED:scoped SSM agent heartbeat in us-east-1 (" + ALLOWLIST_SSM_PUBLIC_READ + ")";
        }

        // 9. Safe inventory/status/CPU monitor reads on '*'
        boolean allSafeStarReads = actions.stream().allMatch(IamPolicies::isInventoryReadAction);
        if (allSafeStarReads && resources.equals(List.of("*"))) {
            return "READ:read-only fleet status and CloudWatch CPU monitor (" + ALLOWLIST_STAR_READ + ")";
        }

        return "ERROR:statement " + sid + " [rule=" + RULE_SCOPED_WRITE_REQUIRED
            + "]: unapproved action(s) " + actions + " on resource(s) " + resources + " for fleet instance role";
    }

    private static String checkWriteScope(
            String sid,
            List<String> actions,
            List<String> resources,
            Object conditionObj,
            boolean hasEc2RunGuardrails,
            boolean hasEc2SgGuardrail) {
        if (isExactLambdaPassRoleForScope(actions, resources, conditionObj)) {
            return "scoped iam:PassRole to lmaws_* Lambda roles";
        }
        // 1. Every resource ARN explicitly scoped to lmaws-* or lmaws_*
        boolean allResourcesNamedLmaws = !resources.isEmpty() && resources.stream().allMatch(IamPolicies::isResourceNamedLmaws);
        if (allResourcesNamedLmaws) {
            return "scoped by lmaws-*/lmaws_* resource name";
        }

        // 2. Scoped by Condition block
        if (conditionObj instanceof Map<?, ?> condMap && !condMap.isEmpty()) {
            String condCompact = compactJson(condMap);
            String condLower = condCompact.toLowerCase(Locale.ROOT);
            if (condLower.contains("\"aws:requesttag/lmaws_test\":\"false\"")
                    || condLower.contains("\"aws:resourcetag/lmaws_test\":\"false\"")
                    || condLower.contains("\"ec2:resourcetag/lmaws_test\":\"false\"")
                    || condLower.contains("\"aws:requesttag/lmaws_test\":\"true\"")
                    || condLower.contains("\"aws:resourcetag/lmaws_test\":\"true\"")
                    || condLower.contains("\"ec2:resourcetag/lmaws_test\":\"true\"")
                    || condLower.contains("\"aws:requesttag/lmaws_test\":\"?*\"")
                    || condLower.contains("\"aws:resourcetag/lmaws_test\":\"?*\"")
                    || condLower.contains("\"ec2:resourcetag/lmaws_test\":\"?*\"")) {
                if (resources.stream().anyMatch(r -> r.contains(":event-source-mapping:"))
                        && actions.stream().anyMatch("lambda:tagresource"::equalsIgnoreCase)) {
                    return "scoped by lmaws_test tag condition (note: Lambda has no CreateAction condition key; host only tags mappings at creation inside CreateEventSourceMapping and verifies queue+function run tags before delete)";
                }
                return "scoped by lmaws_test tag condition";
            }
            if (actions.size() == 1 && "ec2:createtags".equalsIgnoreCase(actions.get(0).trim())
                    && condLower.contains("\"ec2:createaction\"")) {
                return "scoped by ec2:CreateAction condition";
            }
            if (actions.size() == 1 && "route53:changeresourcerecordsets".equalsIgnoreCase(actions.get(0).trim())
                    && condLower.contains("route53:changeresourcerecordsetsnormalizedrecordnames")
                    && hasOnlyLmawsRoute53Patterns(condMap)) {
                return "scoped by route53 lmaws-* record name condition";
            }
        }

        // 3. Companion-guarded typed sub-resource ARNs
        if (actions.size() == 1 && "ec2:runinstances".equalsIgnoreCase(actions.get(0).trim())
                && hasEc2RunGuardrails
                && resources.stream().allMatch(r -> "arn:aws:ec2:*:*:subnet/*".equals(r)
                    || "arn:aws:ec2:*::image/*".equals(r)
                    || "arn:aws:ec2:*:*:network-interface/*".equals(r)
                    || "arn:aws:ec2:*:*:spot-instances-request/*".equals(r))) {
            return "scoped by companion RunTagged + NanoOnly guardrails";
        }
        if (actions.size() == 1 && "ec2:createsecuritygroup".equalsIgnoreCase(actions.get(0).trim())
                && hasEc2SgGuardrail
                && resources.stream().allMatch(r -> "arn:aws:ec2:*:*:vpc/*".equals(r) || "arn:aws:ec2:*:*:security-group/*".equals(r))) {
            return "scoped by companion SgMustBeTagged deny guardrail";
        }
        Set<String> cfOacActions = Set.of(
            "cloudfront:createoriginaccesscontrol",
            "cloudfront:updateoriginaccesscontrol",
            "cloudfront:deleteoriginaccesscontrol"
        );
        if (actions.stream().allMatch(a -> cfOacActions.contains(a.trim().toLowerCase(Locale.ROOT)))
                && resources.size() == 1
                && "arn:aws:cloudfront::*:origin-access-control/*".equals(resources.get(0))) {
            return "scoped to CloudFront origin-access-control sub-resource";
        }

        return null;
    }

    public static ReadRuleEntry matchReadRule(String action) {
        String a = action == null ? "" : action.trim().toLowerCase(Locale.ROOT);
        // Check explicit exact rules (such as TAG_SCOPED_SENSITIVE_READ for acm:getcertificate) before wildcard prefix rules
        for (ReadRuleEntry entry : READ_ALLOWLIST_TABLE) {
            if (!entry.pattern().endsWith("*") && entry.matches(a)) {
                return entry;
            }
        }
        for (ReadRuleEntry entry : READ_ALLOWLIST_TABLE) {
            if (entry.pattern().endsWith("*") && entry.matches(a)) {
                return entry;
            }
        }
        return null;
    }

    private static boolean isInventoryReadAction(String action) {
        ReadRuleEntry matched = matchReadRule(action);
        return matched != null && ALLOWLIST_STAR_READ.equals(matched.allowlistId());
    }

    private static String explainStarReadRejection(String sid, String action) {
        if ("lambda:createeventsourcemapping".equalsIgnoreCase(action == null ? "" : action.trim())) {
            return "statement " + sid + " [rule=" + RULE_LAMBDA_ESM_CREATE + ", rejected_by=" + ALLOWLIST_STAR_READ
                + "]: lambda:CreateEventSourceMapping on Resource '*' requires Condition ArnLike lambda:FunctionArn=arn:aws:lambda:us-east-1:*:function:lmaws_*, "
                + "StringLike aws:RequestTag/lmaws_test=?*, and ForAllValues:StringEquals aws:TagKeys=[lmaws_test]";
        }
        ReadRuleEntry matched = matchReadRule(action);
        if (matched != null) {
            return "statement " + sid + " [rule=" + matched.allowlistId() + ", rejected_by=" + ALLOWLIST_STAR_READ
                + "]: Resource '*' is not allowed with action '" + action + "' (" + matched.rationale()
                + "; required scope: " + matched.requiredScope() + ")";
        }
        return "statement " + sid + " [rule=" + ALLOWLIST_STAR_READ + "]: Resource '*' is not allowed with non-inventory/write action '"
            + action + "' (rejected by " + ALLOWLIST_STAR_READ + ")";
    }

    private static boolean isExactLambdaCreateEventSourceMapping(
            List<String> actions,
            List<String> resources,
            Object condition) {
        if (actions.size() != 1 || resources.size() != 1) return false;
        if (!"lambda:createeventsourcemapping".equalsIgnoreCase(actions.get(0).trim())) return false;
        if (!"*".equals(resources.get(0).trim())) return false;
        if (!(condition instanceof Map<?, ?> operators) || operators.size() != 3) return false;
        Object arnLikeObj = operators.get("ArnLike");
        Object strLikeObj = operators.get("StringLike");
        Object tagKeysObj = operators.get("ForAllValues:StringEquals");
        if (!(arnLikeObj instanceof Map<?, ?> arnLike) || arnLike.size() != 1) return false;
        if (!(strLikeObj instanceof Map<?, ?> strLike) || strLike.size() != 1) return false;
        if (!(tagKeysObj instanceof Map<?, ?> tagKeysMap) || tagKeysMap.size() != 1) return false;
        Object fnArnObj = arnLike.get("lambda:FunctionArn");
        if (!(fnArnObj instanceof String fnArn)) return false;
        if (!fnArn.trim().matches("arn:aws:lambda:(?:us-east-1|\\*):\\*:function:lmaws_[a-z0-9_*?-]+")) {
            return false;
        }
        Object reqTagObj = strLike.get("aws:RequestTag/lmaws_test");
        if (!"?*".equals(reqTagObj)) return false;
        List<String> tagKeys = stringList(tagKeysMap.get("aws:TagKeys"));
        return tagKeys.equals(List.of("lmaws_test"));
    }

    private static boolean isScopedIamRead(List<String> actions, List<String> resources) {
        if (actions.isEmpty() || resources.isEmpty()) return false;
        Set<String> kinds = new LinkedHashSet<>();
        for (String action : actions) {
            ReadRuleEntry matched = matchReadRule(action);
            String kind = matched == null ? null : switch (matched.allowlistId()) {
                case ALLOWLIST_IAM_SCOPED_ROLE_READ -> "role";
                case ALLOWLIST_IAM_SCOPED_POLICY_READ -> "policy";
                default -> null;
            };
            if (kind == null) return false;
            kinds.add(kind);
        }
        Set<String> covered = new LinkedHashSet<>();
        for (String resource : resources) {
            boolean matched = false;
            for (String kind : kinds) if (resource.trim().matches("arn:aws:iam::(?:[0-9]{12}|\\*):" + kind + "/lmaws_[a-z0-9_*?-]+")) {
                matched = true; covered.add(kind);
            }
            if (!matched) return false;
        }
        if (!covered.containsAll(kinds)) return false;
        return true;
    }

    private static boolean isExactLambdaPassRole(Map<String, Object> stmt, List<String> actions, List<String> resources) {
        return actions.size() == 1 && resources.size() == 1
            && LAMBDA_PASS_ROLE.equals(actions.get(0).trim().toLowerCase(Locale.ROOT))
            && isExactLambdaPassRoleCondition(stmt.get("Condition"))
            && "arn:aws:iam::*:role/lmaws_*".equals(resources.get(0).trim());
    }

    private static boolean isExactLambdaPassRoleForScope(List<String> actions, List<String> resources, Object condition) {
        return actions.size() == 1 && resources.size() == 1
            && LAMBDA_PASS_ROLE.equals(actions.get(0).trim().toLowerCase(Locale.ROOT))
            && "arn:aws:iam::*:role/lmaws_*".equals(resources.get(0).trim())
            && isExactLambdaPassRoleCondition(condition);
    }

    private static boolean isExactLambdaPassRoleCondition(Object condition) {
        if (!(condition instanceof Map<?, ?> operators) || operators.size() != 1) return false;
        Object equals = operators.get("StringEquals");
        if (!(equals instanceof Map<?, ?> values) || values.size() != 1) return false;
        Object service = values.get("iam:PassedToService");
        return service instanceof String s && "lambda.amazonaws.com".equals(s);
    }

    private static boolean isResourceNamedLmaws(String resource) {
        if (resource == null) return false;
        String r = resource.trim();
        if (r.equals("*") || !r.startsWith("arn:aws:")) return false;
        return r.contains(":lmaws-")
            || r.contains(":lmaws_")
            || r.contains("/lmaws-")
            || r.contains("/lmaws_");
    }

    private static boolean hasOnlyLmawsRoute53Patterns(Map<?, ?> condMap) {
        List<String> patterns = new ArrayList<>();
        collectConditionValues(condMap, "route53:changeresourcerecordsetsnormalizedrecordnames", patterns);
        if (patterns.isEmpty()) return false;
        for (String pattern : patterns) {
            String p = pattern.trim().toLowerCase(Locale.ROOT);
            if (!p.startsWith("lmaws-") && !p.startsWith("_*.lmaws-")) {
                return false;
            }
        }
        return true;
    }

    private static void collectConditionValues(Object node, String targetKeyLower, List<String> out) {
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String k = String.valueOf(entry.getKey()).toLowerCase(Locale.ROOT);
                if (k.equals(targetKeyLower)) {
                    out.addAll(stringList(entry.getValue()));
                } else {
                    collectConditionValues(entry.getValue(), targetKeyLower, out);
                }
            }
        }
    }

    private static boolean hasActionIgnoreCase(List<String> actions, String target) {
        for (String a : actions) {
            if (target.equalsIgnoreCase(a.trim())) return true;
        }
        return false;
    }

    private static List<String> stringList(Object value) {
        if (value == null) return List.of();
        if (value instanceof String s) return s.isBlank() ? List.of() : List.of(s);
        if (value instanceof List<?> list) {
            List<String> out = new ArrayList<>(list.size());
            for (Object item : list) {
                if (item != null) out.add(String.valueOf(item));
            }
            return out;
        }
        return List.of(String.valueOf(value));
    }

    public record DiffResult(
        boolean changed,
        int addedCount,
        int modifiedCount,
        int removedCount,
        int unchangedCount,
        List<String> lines,
        List<Map<String, Object>> statementDiffs
    ) {
        public String summary() {
            return "added=" + addedCount + ", modified=" + modifiedCount
                + ", removed=" + removedCount + ", unchanged=" + unchangedCount
                + ", changed=" + changed;
        }

        public String formattedLines() {
            return String.join("\n", lines);
        }
    }

    @SuppressWarnings("unchecked")
    public static DiffResult diff(String currentJson, String desiredJson) {
        Map<String, Map<String, Object>> currentStmts = extractStatementsBySid(currentJson);
        Map<String, Map<String, Object>> desiredStmts = extractStatementsBySid(desiredJson);

        Set<String> allKeys = new LinkedHashSet<>();
        allKeys.addAll(desiredStmts.keySet());
        allKeys.addAll(currentStmts.keySet());

        int added = 0;
        int modified = 0;
        int removed = 0;
        int unchanged = 0;
        List<String> lines = new ArrayList<>();
        List<Map<String, Object>> rows = new ArrayList<>();

        for (String sid : allKeys) {
            Map<String, Object> cur = currentStmts.get(sid);
            Map<String, Object> des = desiredStmts.get(sid);
            String status;
            String effect;
            String symbol;
            if (cur == null && des != null) {
                added++;
                status = "added";
                symbol = "+";
                effect = String.valueOf(des.getOrDefault("Effect", "Allow"));
            } else if (cur != null && des == null) {
                removed++;
                status = "removed";
                symbol = "-";
                effect = String.valueOf(cur.getOrDefault("Effect", "Allow"));
            } else {
                effect = String.valueOf(des.getOrDefault("Effect", "Allow"));
                if (compactJson(cur).equals(compactJson(des))) {
                    unchanged++;
                    status = "unchanged";
                    symbol = "=";
                } else {
                    modified++;
                    status = "modified";
                    symbol = "~";
                }
            }
            lines.add(symbol + " " + sid + " [" + effect + "] (" + status + ")");
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sid", sid);
            row.put("effect", effect);
            row.put("status", status);
            row.put("kind", status);
            row.put("count", 1);
            rows.add(row);
        }

        boolean changed = added > 0 || modified > 0 || removed > 0 || currentStmts.isEmpty();
        return new DiffResult(changed, added, modified, removed, unchanged, lines, rows);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> extractStatementsBySid(String rawJson) {
        Map<String, Map<String, Object>> map = new LinkedHashMap<>();
        if (rawJson == null || rawJson.isBlank()) return map;
        Object parsed;
        try {
            parsed = Json.parse(decodeAwsDocument(rawJson));
        } catch (RuntimeException ex) {
            return map;
        }
        if (!(parsed instanceof Map<?, ?> doc)) return map;
        Object stmts = doc.get("Statement");
        if (!(stmts instanceof List<?> list)) return map;
        for (int i = 0; i < list.size(); i++) {
            Object item = list.get(i);
            if (item instanceof Map<?, ?> stmt) {
                String sid = String.valueOf(((Map<String, Object>) stmt).getOrDefault("Sid", "Statement[" + i + "]"));
                map.put(sid, (Map<String, Object>) stmt);
            }
        }
        return map;
    }

    public static String sanitizedTemplatePolicyJson() {
        return """
            {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Sid": "Reads",
                  "Effect": "Allow",
                  "Action": [
                    "sts:GetCallerIdentity",
                    "s3:ListAllMyBuckets",
                    "ec2:Describe*",
                    "sqs:ListQueues",
                    "sns:ListTopics",
                    "dynamodb:ListTables",
                    "logs:DescribeLogGroups",
                    "ssm:DescribeParameters",
                    "route53:List*",
                    "route53:GetHostedZone",
                    "route53:GetChange",
                    "cloudfront:List*",
                    "cloudfront:Get*",
                    "acm:ListCertificates",
                    "acm:DescribeCertificate",
                    "acm:ListTagsForCertificate"
                  ],
                  "Resource": "*"
                },
                {
                  "Sid": "PublicParams",
                  "Effect": "Allow",
                  "Action": "ssm:GetParameter",
                  "Resource": "arn:aws:ssm:*::parameter/aws/service/*"
                },
                {
                  "Sid": "NamedTestResources",
                  "Effect": "Allow",
                  "Action": [
                    "s3:*",
                    "sqs:*",
                    "sns:*",
                    "dynamodb:*",
                    "ssm:*",
                    "logs:*"
                  ],
                  "Resource": [
                    "arn:aws:s3:::lmaws-*",
                    "arn:aws:s3:::lmaws-*/*",
                    "arn:aws:sqs:*:*:lmaws-*",
                    "arn:aws:sqs:*:*:lmaws_*",
                    "arn:aws:sns:*:*:lmaws-*",
                    "arn:aws:sns:*:*:lmaws_*",
                    "arn:aws:dynamodb:*:*:table/lmaws-*",
                    "arn:aws:dynamodb:*:*:table/lmaws_*",
                    "arn:aws:ssm:*:*:parameter/lmaws-*",
                    "arn:aws:ssm:*:*:parameter/lmaws_*",
                    "arn:aws:logs:*:*:log-group:lmaws-*",
                    "arn:aws:logs:*:*:log-group:lmaws_*"
                  ],
                  "Condition": {
                    "StringEquals": {
                      "aws:ResourceAccount": "${aws:PrincipalAccount}"
                    }
                  }
                },
                {
                  "Sid": "RunTagged",
                  "Effect": "Allow",
                  "Action": "ec2:RunInstances",
                  "Resource": [
                    "arn:aws:ec2:*:*:instance/*",
                    "arn:aws:ec2:*:*:volume/*",
                    "arn:aws:ec2:*:*:network-interface/*",
                    "arn:aws:ec2:*:*:spot-instances-request/*"
                  ],
                  "Condition": {
                    "Null": {
                      "aws:RequestTag/lmaws_test": "false"
                    }
                  }
                },
                {
                  "Sid": "Route53Names",
                  "Effect": "Allow",
                  "Action": "route53:ChangeResourceRecordSets",
                  "Resource": "arn:aws:route53:::hostedzone/*",
                  "Condition": {
                    "ForAllValues:StringLike": {
                      "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
                        "lmaws-*.example.com",
                        "_*.lmaws-*.example.com"
                      ]
                    }
                  }
                },
                {
                  "Sid": "NanoOnly",
                  "Effect": "Deny",
                  "Action": "ec2:RunInstances",
                  "Resource": "arn:aws:ec2:*:*:instance/*",
                  "Condition": {
                    "StringNotEquals": {
                      "ec2:InstanceType": [
                        "t3.nano",
                        "t4g.nano"
                      ]
                    }
                  }
                },
                {
                  "Sid": "SgMustBeTagged",
                  "Effect": "Deny",
                  "Action": "ec2:CreateSecurityGroup",
                  "Resource": "arn:aws:ec2:*:*:security-group/*",
                  "Condition": {
                    "Null": {
                      "aws:RequestTag/lmaws_test": "true"
                    }
                  }
                },
                {
                  "Sid": "OnlyUsEast1",
                  "Effect": "Deny",
                  "NotAction": [
                    "sts:*",
                    "s3:*",
                    "route53:*",
                    "cloudfront:*",
                    "acm:*"
                  ],
                  "Resource": "*",
                  "Condition": {
                    "StringNotEquals": {
                      "aws:RequestedRegion": "us-east-1"
                    }
                  }
                }
              ]
            }
            """;
    }

    public static String sanitizedBaselinePolicyJson() {
        return """
            {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Sid": "Reads",
                  "Effect": "Allow",
                  "Action": [
                    "sts:GetCallerIdentity",
                    "s3:ListAllMyBuckets",
                    "ec2:Describe*",
                    "sqs:ListQueues"
                  ],
                  "Resource": "*"
                },
                {
                  "Sid": "NamedTestResources",
                  "Effect": "Allow",
                  "Action": [
                    "s3:*",
                    "sqs:*",
                    "sns:*",
                    "dynamodb:*",
                    "ssm:*",
                    "logs:*"
                  ],
                  "Resource": [
                    "arn:aws:s3:::lmaws-*",
                    "arn:aws:s3:::lmaws-*/*",
                    "arn:aws:sqs:*:*:lmaws-*",
                    "arn:aws:sqs:*:*:lmaws_*",
                    "arn:aws:sns:*:*:lmaws-*",
                    "arn:aws:sns:*:*:lmaws_*",
                    "arn:aws:dynamodb:*:*:table/lmaws-*",
                    "arn:aws:dynamodb:*:*:table/lmaws_*",
                    "arn:aws:ssm:*:*:parameter/lmaws-*",
                    "arn:aws:ssm:*:*:parameter/lmaws_*",
                    "arn:aws:logs:*:*:log-group:lmaws-*",
                    "arn:aws:logs:*:*:log-group:lmaws_*"
                  ],
                  "Condition": {
                    "StringEquals": {
                      "aws:ResourceAccount": "${aws:PrincipalAccount}"
                    }
                  }
                },
                {
                  "Sid": "OnlyUsEast1",
                  "Effect": "Deny",
                  "NotAction": [
                    "sts:*",
                    "s3:*",
                    "route53:*",
                    "cloudfront:*",
                    "acm:*"
                  ],
                  "Resource": "*",
                  "Condition": {
                    "StringNotEquals": {
                      "aws:RequestedRegion": "us-east-1"
                    }
                  }
                }
              ]
            }
            """;
    }
}
