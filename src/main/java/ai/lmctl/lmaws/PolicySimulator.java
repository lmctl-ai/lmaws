package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.ContextEntry;
import software.amazon.awssdk.services.iam.model.ContextKeyTypeEnum;
import software.amazon.awssdk.services.iam.model.EvaluationResult;
import software.amazon.awssdk.services.iam.model.SimulateCustomPolicyRequest;
import software.amazon.awssdk.services.iam.model.SimulateCustomPolicyResponse;
import software.amazon.awssdk.services.iam.model.SimulatePrincipalPolicyRequest;
import software.amazon.awssdk.services.iam.model.SimulatePrincipalPolicyResponse;
import software.amazon.awssdk.services.iam.model.Statement;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * IAM Policy Simulator integration (SimulateCustomPolicy and SimulatePrincipalPolicy)
 * via AWS SDK for Java v2, plus a deterministic offline IAM evaluation engine for
 * synthetic/demo mode. Live IAM calls require AWS_PROFILE=admin.
 */
public final class PolicySimulator {
    public record Probe(
        String id,
        String action,
        String resource,
        Map<String, String> context,
        String expected
    ) {}

    private PolicySimulator() {}

    public static List<Map<String, String>> simulateCustom(
            IamClient iamClient,
            CostLedger cost,
            boolean demo,
            boolean liveWithoutFakeEndpoint,
            String activeProfile,
            String policyJson,
            String probesSpec) {
        IamPolicies.LintResult lint = IamPolicies.lint(policyJson);
        if (lint.compactDocument().isEmpty()) {
            throw new IllegalArgumentException("Invalid policy JSON for simulation: " + String.join("; ", lint.findings()));
        }
        List<Probe> probes = parseProbes(probesSpec);
        if (demo) {
            return evaluateOffline(policyJson, probes);
        }
        if (liveWithoutFakeEndpoint && !"admin".equals(activeProfile)) {
            throw new IllegalStateException(
                "Live IAM policy simulation requires AWS_PROFILE=admin (active profile: " + activeProfile + ")");
        }
        List<Map<String, String>> out = new ArrayList<>();
        for (Probe probe : probes) {
            cost.request("iam", "SimulateCustomPolicy");
            SimulateCustomPolicyRequest req = SimulateCustomPolicyRequest.builder()
                .policyInputList(lint.compactDocument())
                .actionNames(probe.action())
                .resourceArns(probe.resource())
                .contextEntries(toContextEntries(probe.context()))
                .build();
            SimulateCustomPolicyResponse resp = iamClient.simulateCustomPolicy(req);
            out.add(toResultRow(probe, resp.evaluationResults()));
        }
        return out;
    }

    public static List<Map<String, String>> simulatePrincipal(
            IamClient iamClient,
            CostLedger cost,
            boolean demo,
            boolean liveWithoutFakeEndpoint,
            String activeProfile,
            String policySourceArn,
            String fallbackPolicyJson,
            String probesSpec) {
        if (policySourceArn == null || policySourceArn.isBlank()) {
            throw new IllegalArgumentException("Principal ARN or policy name must not be empty");
        }
        List<Probe> probes = parseProbes(probesSpec);
        if (demo) {
            return evaluateOffline(fallbackPolicyJson, probes);
        }
        if (liveWithoutFakeEndpoint && !"admin".equals(activeProfile)) {
            throw new IllegalStateException(
                "Live IAM principal simulation requires AWS_PROFILE=admin (active profile: " + activeProfile + ")");
        }
        List<Map<String, String>> out = new ArrayList<>();
        for (Probe probe : probes) {
            cost.request("iam", "SimulatePrincipalPolicy");
            SimulatePrincipalPolicyRequest req = SimulatePrincipalPolicyRequest.builder()
                .policySourceArn(policySourceArn)
                .actionNames(probe.action())
                .resourceArns(probe.resource())
                .contextEntries(toContextEntries(probe.context()))
                .build();
            SimulatePrincipalPolicyResponse resp = iamClient.simulatePrincipalPolicy(req);
            out.add(toResultRow(probe, resp.evaluationResults()));
        }
        return out;
    }

    private static List<ContextEntry> toContextEntries(Map<String, String> context) {
        List<ContextEntry> entries = new ArrayList<>();
        if (context == null) return entries;
        for (Map.Entry<String, String> e : context.entrySet()) {
            String key = e.getKey();
            String val = e.getValue();
            ContextKeyTypeEnum type = inferContextType(key, val);
            entries.add(ContextEntry.builder()
                .contextKeyName(key)
                .contextKeyValues(List.of(val.split("\\|")))
                .contextKeyType(type)
                .build());
        }
        return entries;
    }

    private static ContextKeyTypeEnum inferContextType(String key, String val) {
        String lowerKey = key.toLowerCase(Locale.ROOT);
        if ("true".equalsIgnoreCase(val) || "false".equalsIgnoreCase(val) || lowerKey.contains("multifactorauthpresent")) {
            return ContextKeyTypeEnum.BOOLEAN;
        }
        if (val.matches("^-?[0-9]+(\\.[0-9]+)?$") && (lowerKey.contains("size") || lowerKey.contains("numeric"))) {
            return ContextKeyTypeEnum.NUMERIC;
        }
        if (lowerKey.contains("sourceip")) {
            return ContextKeyTypeEnum.IP;
        }
        if (lowerKey.contains("currenttime")) {
            return ContextKeyTypeEnum.DATE;
        }
        return ContextKeyTypeEnum.STRING;
    }

    private static Map<String, String> toResultRow(Probe probe, List<EvaluationResult> evals) {
        String decision = "implicitDeny";
        List<String> matched = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        if (evals != null && !evals.isEmpty()) {
            EvaluationResult first = evals.get(0);
            if (first.evalDecisionAsString() != null && !first.evalDecisionAsString().isBlank()) {
                decision = first.evalDecisionAsString();
            }
            if (first.hasMatchedStatements()) {
                for (Statement ms : first.matchedStatements()) {
                    matched.add(ms.sourcePolicyId() != null ? ms.sourcePolicyId() : "PolicyInputList.1");
                }
            }
            if (first.hasMissingContextValues()) {
                missing.addAll(first.missingContextValues());
            }
        }
        boolean passed = probe.expected().isEmpty() || probe.expected().equalsIgnoreCase(decision);
        Map<String, String> row = new LinkedHashMap<>();
        row.put("probe_id", probe.id());
        row.put("action", probe.action());
        row.put("resource", Jsons.mask(probe.resource()));
        row.put("context", formatContext(probe.context()));
        row.put("decision", decision);
        row.put("expected", probe.expected().isEmpty() ? decision : probe.expected());
        row.put("passed", String.valueOf(passed));
        row.put("matched_statements", matched.isEmpty() ? "none" : String.join(",", matched));
        row.put("missing_context", missing.isEmpty() ? "none" : String.join(",", missing));
        row.put("status", passed ? "ok" : "mismatch");
        row.put("detail", probe.action() + " -> " + decision + (matched.isEmpty() ? "" : " [" + String.join(",", matched) + "]"));
        row.put("count", "1");
        return row;
    }

    /**
     * Parses probe table specifications from either JSON array format or pipe-delimited rows,
     * falling back to a comprehensive 8-probe suite when probesSpec is empty or "default".
     */
    @SuppressWarnings("unchecked")
    public static List<Probe> parseProbes(String probesSpec) {
        if (probesSpec == null || probesSpec.isBlank() || "default".equalsIgnoreCase(probesSpec.trim())) {
            return defaultProbes();
        }
        String trimmed = probesSpec.trim();
        if (trimmed.startsWith("[")) {
            Object parsed = Json.parse(trimmed);
            if (!(parsed instanceof List<?> list)) {
                throw new IllegalArgumentException("Probes JSON must be an array");
            }
            List<Probe> out = new ArrayList<>();
            int idx = 1;
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> rawMap)) continue;
                Map<String, Object> m = (Map<String, Object>) rawMap;
                String id = String.valueOf(m.getOrDefault("id", "probe_" + idx));
                String action = String.valueOf(m.getOrDefault("action", "sts:GetCallerIdentity"));
                String resource = String.valueOf(m.getOrDefault("resource", "*"));
                String expected = String.valueOf(m.getOrDefault("expected", ""));
                Map<String, String> ctx = new LinkedHashMap<>();
                if (m.get("context") instanceof Map<?, ?> rawCtx) {
                    for (Map.Entry<?, ?> e : rawCtx.entrySet()) {
                        ctx.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
                    }
                }
                out.add(new Probe(id, action, resource, ctx, expected));
                idx++;
            }
            return out;
        }

        List<Probe> out = new ArrayList<>();
        String[] lines = trimmed.split("[;\\n]+");
        int idx = 1;
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            String[] cols = t.split("\\|", -1);
            String action = cols[0].trim();
            String resource = cols.length > 1 && !cols[1].isBlank() ? cols[1].trim() : "*";
            Map<String, String> ctx = new LinkedHashMap<>();
            if (cols.length > 2 && !cols[2].isBlank()) {
                for (String kv : cols[2].split(",")) {
                    int eq = kv.indexOf('=');
                    if (eq > 0) {
                        ctx.put(kv.substring(0, eq).trim(), kv.substring(eq + 1).trim());
                    }
                }
            }
            String expected = cols.length > 3 ? cols[3].trim() : "";
            out.add(new Probe("probe_" + idx, action, resource, ctx, expected));
            idx++;
        }
        return out;
    }

    public static List<Probe> defaultProbes() {
        return List.of(
            new Probe("probe_1", "sts:GetCallerIdentity", "*",
                Map.of("aws:RequestedRegion", "us-east-1"), "allowed"),
            new Probe("probe_2", "s3:PutObject", "arn:aws:s3:::lmaws-demo-bucket/item.json",
                Map.of("aws:RequestedRegion", "us-east-1", "aws:PrincipalAccount", "000000000000", "aws:ResourceAccount", "000000000000"),
                "allowed"),
            new Probe("probe_3", "s3:PutObject", "arn:aws:s3:::production-customer-bucket/item.json",
                Map.of("aws:RequestedRegion", "us-east-1", "aws:PrincipalAccount", "000000000000", "aws:ResourceAccount", "000000000000"),
                "implicitDeny"),
            new Probe("probe_4", "ec2:RunInstances", "arn:aws:ec2:us-east-1:000000000000:instance/i-demo",
                Map.of("aws:RequestedRegion", "us-east-1", "aws:RequestTag/lmaws_test", "run1", "ec2:InstanceType", "t4g.nano"),
                "allowed"),
            new Probe("probe_5", "ec2:RunInstances", "arn:aws:ec2:us-east-1:000000000000:instance/i-demo",
                Map.of("aws:RequestedRegion", "us-east-1", "aws:RequestTag/lmaws_test", "run1", "ec2:InstanceType", "t4g.large"),
                "explicitDeny"),
            new Probe("probe_6", "ec2:CreateSecurityGroup", "arn:aws:ec2:us-east-1:000000000000:security-group/sg-demo",
                Map.of("aws:RequestedRegion", "us-east-1"),
                "explicitDeny"),
            new Probe("probe_7", "sqs:CreateQueue", "arn:aws:sqs:us-west-2:000000000000:lmaws_demo_queue",
                Map.of("aws:RequestedRegion", "us-west-2", "aws:PrincipalAccount", "000000000000", "aws:ResourceAccount", "000000000000"),
                "explicitDeny"),
            new Probe("probe_8", "route53:ChangeResourceRecordSets", "arn:aws:route53:::hostedzone/ZDEMO",
                Map.of("aws:RequestedRegion", "us-east-1",
                    "route53:ChangeResourceRecordSetsNormalizedRecordNames", "lmaws-demo.example.com",
                    "route53:ChangeResourceRecordSetsRecordTypes", "A"),
                "allowed")
        );
    }

    public static final List<String> RUN_INSTANCES_SUB_RESOURCES = List.of(
        "instance",
        "volume",
        "subnet",
        "image",
        "network-interface",
        "spot-instances-request"
    );

    /**
     * Expands an EC2 RunInstances launch into all six AWS IAM RunInstances sub-resource probes
     * (instance, volume, subnet, image, network-interface, spot-instances-request) with the exact
     * condition keys evaluated by EC2 on each sub-resource:
     *   - instance: aws:RequestedRegion, ec2:InstanceType, and aws:RequestTag/<tagKey> (when tagValue is non-empty)
     *   - volume: aws:RequestedRegion, ec2:VolumeSize, and aws:RequestTag/<tagKey> (when tagValue is non-empty)
     *   - subnet: aws:RequestedRegion (referenced existing resource; no RequestTag)
     *   - image: aws:RequestedRegion (referenced public/account AMI; no RequestTag)
     *   - network-interface: aws:RequestedRegion (implicit launch ENI; no RequestTag required)
     *   - spot-instances-request: aws:RequestedRegion (implicit spot request; no RequestTag required)
     */
    public static List<Probe> runInstancesProbes(
            String instanceType,
            long volumeGib,
            String tagKey,
            String tagValue,
            String region) {
        String reg = (region == null || region.isBlank()) ? "us-east-1" : region.trim();
        String iType = (instanceType == null || instanceType.isBlank()) ? "t4g.nano" : instanceType.trim();
        long gib = volumeGib <= 0 ? 8L : volumeGib;
        boolean hasTag = tagKey != null && !tagKey.isBlank() && tagValue != null && !tagValue.isBlank();

        Map<String, String> instanceCtx = new LinkedHashMap<>();
        instanceCtx.put("aws:RequestedRegion", reg);
        instanceCtx.put("ec2:InstanceType", iType);
        if (hasTag) {
            instanceCtx.put("aws:RequestTag/" + tagKey.trim(), tagValue.trim());
        }

        Map<String, String> volumeCtx = new LinkedHashMap<>();
        volumeCtx.put("aws:RequestedRegion", reg);
        volumeCtx.put("ec2:VolumeSize", String.valueOf(gib));
        if (hasTag) {
            volumeCtx.put("aws:RequestTag/" + tagKey.trim(), tagValue.trim());
        }

        Map<String, String> refCtx = Map.of("aws:RequestedRegion", reg);

        return List.of(
            new Probe("run_instance", "ec2:RunInstances",
                "arn:aws:ec2:" + reg + ":000000000000:instance/i-0demo", instanceCtx, "allowed"),
            new Probe("run_volume", "ec2:RunInstances",
                "arn:aws:ec2:" + reg + ":000000000000:volume/vol-0demo", volumeCtx, "allowed"),
            new Probe("run_subnet", "ec2:RunInstances",
                "arn:aws:ec2:" + reg + ":000000000000:subnet/subnet-0demo", refCtx, "allowed"),
            new Probe("run_image", "ec2:RunInstances",
                "arn:aws:ec2:" + reg + "::image/ami-0demo", refCtx, "allowed"),
            new Probe("run_network_interface", "ec2:RunInstances",
                "arn:aws:ec2:" + reg + ":000000000000:network-interface/eni-0demo", refCtx, "allowed"),
            new Probe("run_spot_instances_request", "ec2:RunInstances",
                "arn:aws:ec2:" + reg + ":000000000000:spot-instances-request/sir-0demo", refCtx, "allowed")
        );
    }

    public static String formatProbes(List<Probe> probes) {
        List<String> specs = new ArrayList<>(probes.size());
        for (Probe p : probes) {
            specs.add(p.action() + "|" + p.resource() + "|" + formatContext(p.context()) + "|" + p.expected());
        }
        return String.join(";", specs);
    }

    public static List<Map<String, String>> simulateRunInstances(
            String policyJson,
            String instanceType,
            long volumeGib,
            String tagKey,
            String tagValue,
            String region,
            String expectedLaunchDecision) {
        List<Probe> probes = runInstancesProbes(instanceType, volumeGib, tagKey, tagValue, region);
        List<Map<String, String>> rows = evaluateOffline(policyJson, probes);
        boolean anyExplicitDeny = rows.stream().anyMatch(r -> "explicitDeny".equals(r.get("decision")));
        boolean anyImplicitDeny = rows.stream().anyMatch(r -> "implicitDeny".equals(r.get("decision")));
        String launchDecision = anyExplicitDeny
            ? "explicitDeny"
            : (anyImplicitDeny ? "implicitDeny" : "allowed");
        String expectedOverall = (expectedLaunchDecision == null || expectedLaunchDecision.isBlank())
            ? "allowed"
            : expectedLaunchDecision.trim();
        boolean launchPassed = expectedOverall.equalsIgnoreCase(launchDecision);

        List<String> failedSubs = new ArrayList<>();
        for (int i = 0; i < rows.size(); i++) {
            String subRes = RUN_INSTANCES_SUB_RESOURCES.get(i);
            String dec = rows.get(i).get("decision");
            if (!"allowed".equals(dec)) {
                failedSubs.add(subRes + "(" + dec + ")");
            }
        }
        String failedSummary = failedSubs.isEmpty() ? "none" : String.join(",", failedSubs);

        for (int i = 0; i < rows.size(); i++) {
            Map<String, String> row = rows.get(i);
            String subRes = RUN_INSTANCES_SUB_RESOURCES.get(i);
            row.put("sub_resource", subRes);
            row.put("launch_decision", launchDecision);
            row.put("launch_allowed", String.valueOf("allowed".equals(launchDecision)));
            row.put("expected_launch_decision", expectedOverall);
            row.put("launch_passed", String.valueOf(launchPassed));
            row.put("failed_sub_resources", failedSummary);
            if (!"allowed".equalsIgnoreCase(expectedOverall)) {
                row.put("expected", expectedOverall);
                row.put("passed", String.valueOf(launchPassed));
                row.put("status", launchPassed ? "ok" : "mismatch");
            }
        }
        return rows;
    }

    /**
     * Deterministic IAM policy evaluator for offline/demo mode.
     * Evaluates explicit Deny first, then Allow, defaulting to implicitDeny.
     */
    public static List<Map<String, String>> evaluateOffline(String policyJson, List<Probe> probes) {
        Map<String, Object> doc = PolicyAnalyzer.parseDoc(policyJson);
        List<Map<String, Object>> stmts = PolicyAnalyzer.getStatements(doc);
        List<Map<String, String>> out = new ArrayList<>();

        for (Probe probe : probes) {
            List<String> matchedDenies = new ArrayList<>();
            List<String> matchedAllows = new ArrayList<>();

            for (int i = 0; i < stmts.size(); i++) {
                Map<String, Object> s = stmts.get(i);
                String sid = String.valueOf(s.getOrDefault("Sid", "Statement[" + i + "]"));
                String effect = String.valueOf(s.getOrDefault("Effect", "Allow"));
                if (statementMatches(s, probe.action(), probe.resource(), probe.context())) {
                    if ("Deny".equals(effect)) {
                        matchedDenies.add(sid);
                    } else if ("Allow".equals(effect)) {
                        matchedAllows.add(sid);
                    }
                }
            }

            String decision;
            List<String> matched;
            if (!matchedDenies.isEmpty()) {
                decision = "explicitDeny";
                matched = matchedDenies;
            } else if (!matchedAllows.isEmpty()) {
                decision = "allowed";
                matched = matchedAllows;
            } else {
                decision = "implicitDeny";
                matched = List.of();
            }

            boolean passed = probe.expected().isEmpty() || probe.expected().equalsIgnoreCase(decision);
            Map<String, String> row = new LinkedHashMap<>();
            row.put("probe_id", probe.id());
            row.put("action", probe.action());
            row.put("resource", Jsons.mask(probe.resource()));
            row.put("context", formatContext(probe.context()));
            row.put("decision", decision);
            row.put("expected", probe.expected().isEmpty() ? decision : probe.expected());
            row.put("passed", String.valueOf(passed));
            row.put("matched_statements", matched.isEmpty() ? "none" : String.join(",", matched));
            row.put("missing_context", "none");
            row.put("status", passed ? "ok" : "mismatch");
            row.put("detail", probe.action() + " -> " + decision + (matched.isEmpty() ? "" : " [" + String.join(",", matched) + "]"));
            row.put("count", "1");
            out.add(row);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static boolean statementMatches(
            Map<String, Object> stmt,
            String action,
            String resource,
            Map<String, String> context) {
        // 1. Check Action or NotAction
        if (stmt.containsKey("NotAction")) {
            List<String> notActions = PolicyAnalyzer.stringList(stmt.get("NotAction"));
            boolean anyMatch = notActions.stream().anyMatch(pat -> wildcardMatches(pat, action));
            if (anyMatch) return false;
        } else {
            List<String> actions = PolicyAnalyzer.stringList(stmt.get("Action"));
            boolean anyMatch = actions.stream().anyMatch(pat -> wildcardMatches(pat, action));
            if (!anyMatch) return false;
        }

        // 2. Check Resource or NotResource
        String pa = getCaseInsensitive(context == null ? Map.of() : context, "aws:PrincipalAccount");
        String principalAcct = pa != null ? pa : "000000000000";
        if (stmt.containsKey("NotResource")) {
            List<String> notRes = PolicyAnalyzer.stringList(stmt.get("NotResource"));
            boolean anyMatch = notRes.stream().anyMatch(pat -> resourceMatches(pat, resource, principalAcct));
            if (anyMatch) return false;
        } else {
            List<String> res = PolicyAnalyzer.stringList(stmt.get("Resource"));
            boolean anyMatch = res.stream().anyMatch(pat -> resourceMatches(pat, resource, principalAcct));
            if (!anyMatch) return false;
        }

        // 3. Check Condition
        Object condObj = stmt.get("Condition");
        if (condObj instanceof Map<?, ?> condMap && !condMap.isEmpty()) {
            for (Map.Entry<?, ?> opEntry : condMap.entrySet()) {
                String operator = String.valueOf(opEntry.getKey());
                if (!(opEntry.getValue() instanceof Map<?, ?> kvMap)) continue;
                for (Map.Entry<?, ?> kv : kvMap.entrySet()) {
                    String key = String.valueOf(kv.getKey());
                    List<String> expectedVals = PolicyAnalyzer.stringList(kv.getValue());
                    if (!evaluateConditionClause(operator, key, expectedVals, context)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private static boolean resourceMatches(String pattern, String resource, String principalAccount) {
        String resolved = pattern.replace("${aws:PrincipalAccount}", principalAccount);
        if (wildcardMatches(resolved, resource)) {
            return true;
        }
        if (pattern.contains("${aws:PrincipalAccount}") && resource != null && resource.contains(":*:")) {
            return wildcardMatches(pattern.replace("${aws:PrincipalAccount}", "*"), resource);
        }
        return false;
    }

    private static boolean evaluateConditionClause(
            String operator,
            String key,
            List<String> rawExpectedVals,
            Map<String, String> context) {
        Map<String, String> ctx = context == null ? Map.of() : context;
        String actual = getCaseInsensitive(ctx, key);
        String pa = getCaseInsensitive(ctx, "aws:PrincipalAccount");
        String principalAcct = pa != null ? pa : "000000000000";
        List<String> expectedVals = new ArrayList<>(rawExpectedVals.size());
        for (String v : rawExpectedVals) {
            if (v.contains("${aws:PrincipalAccount}")) {
                expectedVals.add(v.replace("${aws:PrincipalAccount}", principalAcct));
                if (actual != null && actual.contains(":*:")) {
                    expectedVals.add(v.replace("${aws:PrincipalAccount}", "*"));
                }
            } else {
                expectedVals.add(v);
            }
        }

        String opLower = operator.toLowerCase(Locale.ROOT);
        boolean ifExists = opLower.endsWith("ifexists");
        String baseOp = ifExists ? opLower.substring(0, opLower.length() - "ifexists".length()) : opLower;
        if (baseOp.startsWith("forallvalues:")) {
            baseOp = baseOp.substring("forallvalues:".length());
        } else if (baseOp.startsWith("foranyvalue:")) {
            baseOp = baseOp.substring("foranyvalue:".length());
        }

        if ("null".equals(baseOp)) {
            boolean wantNull = expectedVals.stream().anyMatch("true"::equalsIgnoreCase);
            boolean isNull = actual == null || actual.isEmpty();
            return wantNull == isNull;
        }
        if (actual == null) {
            return ifExists;
        }

        return switch (baseOp) {
            case "stringequals", "arnequals", "bool", "ipaddress" ->
                expectedVals.stream().anyMatch(e -> e.equalsIgnoreCase(actual));
            case "stringnotequals", "arnnotequals", "notipaddress" ->
                expectedVals.stream().noneMatch(e -> e.equalsIgnoreCase(actual));
            case "stringlike", "arnlike" ->
                expectedVals.stream().anyMatch(e -> wildcardMatches(e, actual));
            case "stringnotlike", "arnnotlike" ->
                expectedVals.stream().noneMatch(e -> wildcardMatches(e, actual));
            case "numericgreaterthan" -> {
                try {
                    double actNum = Double.parseDouble(actual);
                    yield expectedVals.stream().anyMatch(e -> actNum > Double.parseDouble(e));
                } catch (NumberFormatException ex) {
                    yield false;
                }
            }
            case "numericlessthanequals" -> {
                try {
                    double actNum = Double.parseDouble(actual);
                    yield expectedVals.stream().anyMatch(e -> actNum <= Double.parseDouble(e));
                } catch (NumberFormatException ex) {
                    yield false;
                }
            }
            case "datelessthan" ->
                expectedVals.stream().anyMatch(e -> actual.compareTo(e) < 0);
            case "dategreaterthan" ->
                expectedVals.stream().anyMatch(e -> actual.compareTo(e) > 0);
            default -> true;
        };
    }

    private static String getCaseInsensitive(Map<String, String> map, String targetKey) {
        for (Map.Entry<String, String> e : map.entrySet()) {
            if (e.getKey().equalsIgnoreCase(targetKey)) {
                return e.getValue();
            }
        }
        return null;
    }

    private static boolean wildcardMatches(String pattern, String value) {
        if ("*".equals(pattern)) return true;
        Pattern regex = PolicyCatalog.wildcardToRegex(pattern);
        return regex.matcher(value).matches();
    }

    private static String formatContext(Map<String, String> context) {
        if (context == null || context.isEmpty()) return "{}";
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, String> e : context.entrySet()) {
            parts.add(e.getKey() + "=" + Jsons.mask(e.getValue()));
        }
        return String.join(", ", parts);
    }
}
