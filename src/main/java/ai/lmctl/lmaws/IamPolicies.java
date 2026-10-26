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

    private static final Set<String> READ_INVENTORY_ALLOWLIST = Set.of(
        "sts:getcalleridentity",
        "s3:listallmybuckets",
        "s3:getbucketlocation",
        "s3:getbuckettagging",
        "ec2:describe*",
        "ec2:describeinstances",
        "ec2:describevolumes",
        "ec2:describesnapshots",
        "ec2:describeaddresses",
        "ec2:describetags",
        "sqs:listqueues",
        "sns:listtopics",
        "sns:listsubscriptions",
        "dynamodb:listtables",
        "dynamodb:describelimits",
        "logs:describeloggroups",
        "logs:describelogstreams",
        "ssm:describeparameters",
        "ssm:getparameters",
        "ssm:getparametersbypath",
        "route53:list*",
        "route53:gethostedzone",
        "route53:getchange",
        "cloudfront:list*",
        "cloudfront:get*",
        "acm:listcertificates",
        "acm:describecertificate",
        "acm:listtagsforcertificate",
        "ecs:listclusters",
        "ecs:describeclusters",
        "lambda:listfunctions",
        "cloudwatch:describealarms",
        "cloudwatch:getmetricdata",
        "cloudwatch:getmetricstatistics",
        "cloudwatch:listmetrics",
        "tag:getresources",
        "tag:gettagkeys",
        "tag:gettagvalues",
        "ce:get*",
        "ce:getcostandusage",
        "ce:getdimensionvalues",
        "ce:gettags",
        "ce:getreservationutilization",
        "ce:getreservationcoverage",
        "ce:getsavingsplansutilization",
        "ce:getsavingsplanscoverage",
        "savingsplans:describe*",
        "savingsplans:describesavingsplans",
        "savingsplans:describesavingsplansofferingrates",
        "savingsplans:describesavingsplansofferings",
        "pricing:describeservices",
        "pricing:getattributevalues",
        "pricing:getproducts"
    );

    private static final Set<String> FORBIDDEN_ACTION_PREFIXES = Set.of(
        "iam:",
        "sts:assumerole",
        "organizations:",
        "account:",
        "kms:",
        "secretsmanager:"
    );

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
            for (String action : actions) {
                String lower = action.trim().toLowerCase(Locale.ROOT);
                if (lower.equals("*") || lower.equals("*:*")) {
                    stmtFindings.add("statement " + sid + ": refuses bare wildcard action '" + action + "'");
                    continue;
                }
                if (lower.equals("sts:*")) {
                    stmtFindings.add("statement " + sid + ": refuses wildcard STS action '" + action + "'");
                    continue;
                }
                for (String forbiddenPrefix : FORBIDDEN_ACTION_PREFIXES) {
                    if (lower.startsWith(forbiddenPrefix)) {
                        stmtFindings.add("statement " + sid + ": refuses forbidden action '" + action + "'");
                        break;
                    }
                }
            }

            boolean hasStarResource = resources.stream().anyMatch(r -> "*".equals(r.trim()));
            boolean allInReadAllowlist = actions.stream()
                .allMatch(a -> READ_INVENTORY_ALLOWLIST.contains(a.trim().toLowerCase(Locale.ROOT)));
            boolean isScopedSsmPublicRead = actions.stream()
                .allMatch(a -> "ssm:getparameter".equalsIgnoreCase(a.trim())
                    || "ssm:getparameters".equalsIgnoreCase(a.trim())
                    || "ssm:getparametersbypath".equalsIgnoreCase(a.trim()))
                && !hasStarResource
                && resources.stream().allMatch(r -> r.contains(":parameter/aws/service/") || r.contains(":parameter/lmaws"));

            if (hasStarResource) {
                if (!allInReadAllowlist) {
                    for (String action : actions) {
                        if (!READ_INVENTORY_ALLOWLIST.contains(action.trim().toLowerCase(Locale.ROOT))) {
                            stmtFindings.add("statement " + sid + ": Resource '*' is not allowed with non-inventory/write action '" + action + "'");
                        }
                    }
                }
                if (stmtFindings.isEmpty()) {
                    allowRead++;
                    statementChecks.add(new StatementCheck(sid, effect, "allow_read", actions.size(), resources.size(), true, "inventory/read allow-list on *"));
                } else {
                    findings.addAll(stmtFindings);
                    statementChecks.add(new StatementCheck(sid, effect, "violation", actions.size(), resources.size(), false, String.join("; ", stmtFindings)));
                }
                continue;
            }

            if (allInReadAllowlist || isScopedSsmPublicRead) {
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
                stmtFindings.add("statement " + sid + ": write action(s) " + actions
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

    private static String checkWriteScope(
            String sid,
            List<String> actions,
            List<String> resources,
            Object conditionObj,
            boolean hasEc2RunGuardrails,
            boolean hasEc2SgGuardrail) {
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
                    || condLower.contains("\"ec2:resourcetag/lmaws_test\":\"true\"")) {
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
