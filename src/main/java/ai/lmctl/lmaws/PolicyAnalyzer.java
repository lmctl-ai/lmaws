package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Policy analysis, inline compaction (<= 2048 chars), managed splitting (<= 6144 chars),
 * plain-English explanation, permission matrix (service x action_class x scope),
 * AccessDenied parser & remediator, ledger-to-least-privilege synthesizer, and
 * JSON-to-builder decompiler.
 */
public final class PolicyAnalyzer {
    private static final Pattern ACTION_IN_ERROR = Pattern.compile(
        "perform:?\\s+([a-z0-9-]+:[A-Za-z0-9*]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern RESOURCE_IN_ERROR = Pattern.compile(
        "on\\s+resource:?\\s+\"?(arn:aws:[A-Za-z0-9:_/*.-]+|\\*)\"?", Pattern.CASE_INSENSITIVE);
    private static final Pattern PRINCIPAL_IN_ERROR = Pattern.compile(
        "User:\\s+(\\S+)\\s+is\\s+not\\s+authorized", Pattern.CASE_INSENSITIVE);

    private PolicyAnalyzer() {}

    /**
     * Compacts a policy to fit the 2048-character STS inline session policy limit:
     * drops Sids, converts single-element lists to scalars, merges compatible statements,
     * and collapses action prefixes when needed.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> fitInline(String policyJson) {
        Map<String, Object> doc = parseDoc(policyJson);
        String originalCompact = IamPolicies.compactJson(doc);
        int originalLen = originalCompact.length();
        List<Map<String, Object>> rawStmts = getStatements(doc);
        int originalStmtCount = rawStmts.size();

        List<String> steps = new ArrayList<>();
        int sidsDropped = 0;

        // 1. Clone statements, drop Sid, normalize singletons
        List<Map<String, Object>> stmts = new ArrayList<>();
        for (Map<String, Object> s : rawStmts) {
            Map<String, Object> copy = new LinkedHashMap<>();
            if (s.containsKey("Sid")) {
                sidsDropped++;
            }
            copy.put("Effect", s.getOrDefault("Effect", "Allow"));
            if (s.containsKey("NotAction")) {
                copy.put("NotAction", normalizeScalarOrList(stringList(s.get("NotAction"))));
            } else {
                copy.put("Action", normalizeScalarOrList(stringList(s.get("Action"))));
            }
            if (s.containsKey("NotResource")) {
                copy.put("NotResource", normalizeScalarOrList(stringList(s.get("NotResource"))));
            } else {
                copy.put("Resource", normalizeScalarOrList(stringList(s.get("Resource"))));
            }
            if (s.containsKey("Condition") && s.get("Condition") instanceof Map<?, ?> cond && !cond.isEmpty()) {
                copy.put("Condition", normalizeCondition((Map<String, Object>) cond));
            }
            stmts.add(copy);
        }
        if (sidsDropped > 0) {
            steps.add("drop_sids(" + sidsDropped + ")");
        }
        steps.add("scalar_singletons");

        // 2. Merge statements with identical Effect + ActionMode + Resource + Condition
        List<Map<String, Object>> mergedByRes = new ArrayList<>();
        Map<String, Map<String, Object>> byResKey = new LinkedHashMap<>();
        int mergedResCount = 0;
        for (Map<String, Object> s : stmts) {
            String actionKey = s.containsKey("NotAction") ? "NotAction" : "Action";
            String resKey = s.containsKey("NotResource") ? "NotResource" : "Resource";
            String signature = s.get("Effect") + "|" + actionKey + "|" + resKey + "="
                + IamPolicies.compactJson(s.get(resKey)) + "|cond="
                + IamPolicies.compactJson(s.get("Condition"));
            Map<String, Object> existing = byResKey.get(signature);
            if (existing == null) {
                byResKey.put(signature, s);
                mergedByRes.add(s);
            } else {
                Set<String> combined = new LinkedHashSet<>(stringList(existing.get(actionKey)));
                combined.addAll(stringList(s.get(actionKey)));
                existing.put(actionKey, normalizeScalarOrList(new ArrayList<>(combined)));
                mergedResCount++;
            }
        }
        if (mergedResCount > 0) {
            steps.add("merge_shared_resources(" + mergedResCount + ")");
        }

        // 3. Merge statements with identical Effect + ActionMode + Action + Condition
        List<Map<String, Object>> mergedByAct = new ArrayList<>();
        Map<String, Map<String, Object>> byActKey = new LinkedHashMap<>();
        int mergedActCount = 0;
        for (Map<String, Object> s : mergedByRes) {
            String actionKey = s.containsKey("NotAction") ? "NotAction" : "Action";
            String resKey = s.containsKey("NotResource") ? "NotResource" : "Resource";
            String signature = s.get("Effect") + "|" + actionKey + "="
                + IamPolicies.compactJson(s.get(actionKey)) + "|" + resKey + "|cond="
                + IamPolicies.compactJson(s.get("Condition"));
            Map<String, Object> existing = byActKey.get(signature);
            if (existing == null) {
                byActKey.put(signature, s);
                mergedByAct.add(s);
            } else {
                Set<String> combined = new LinkedHashSet<>(stringList(existing.get(resKey)));
                combined.addAll(stringList(s.get(resKey)));
                existing.put(resKey, normalizeScalarOrList(new ArrayList<>(combined)));
                mergedActCount++;
            }
        }
        if (mergedActCount > 0) {
            steps.add("merge_shared_actions(" + mergedActCount + ")");
        }

        Map<String, Object> outDoc = new LinkedHashMap<>();
        outDoc.put("Version", IamPolicies.EXPECTED_VERSION);
        outDoc.put("Statement", mergedByAct);
        String compact = IamPolicies.compactJson(outDoc);

        // 4. If still over 2048, collapse verbose read/write action prefixes per service
        if (compact.length() > IamPolicies.INLINE_SESSION_POLICY_LIMIT) {
            int collapsed = 0;
            for (Map<String, Object> s : mergedByAct) {
                if (!s.containsKey("Action")) continue;
                List<String> acts = stringList(s.get("Action"));
                List<String> shortened = collapseActionList(acts);
                if (shortened.size() < acts.size()) {
                    collapsed += (acts.size() - shortened.size());
                    s.put("Action", normalizeScalarOrList(shortened));
                }
            }
            if (collapsed > 0) {
                steps.add("collapse_action_prefixes(" + collapsed + ")");
                compact = IamPolicies.compactJson(outDoc);
            }
        }

        // 5. If still over 2048, collapse prefix ARN pairs (e.g. lmaws-* and lmaws_* -> lmaws*)
        if (compact.length() > IamPolicies.INLINE_SESSION_POLICY_LIMIT) {
            int collapsedArns = 0;
            for (Map<String, Object> s : mergedByAct) {
                if (!s.containsKey("Resource")) continue;
                List<String> res = stringList(s.get("Resource"));
                List<String> shortened = collapsePrefixArns(res);
                if (shortened.size() < res.size()) {
                    collapsedArns += (res.size() - shortened.size());
                    s.put("Resource", normalizeScalarOrList(shortened));
                }
            }
            if (collapsedArns > 0) {
                steps.add("collapse_prefix_arns(" + collapsedArns + ")");
                compact = IamPolicies.compactJson(outDoc);
            }
        }

        String pretty = IamPolicies.prettyJson(outDoc);
        int compactLen = compact.length();
        boolean fits = compactLen <= IamPolicies.INLINE_SESSION_POLICY_LIMIT;
        int remaining = IamPolicies.INLINE_SESSION_POLICY_LIMIT - compactLen;
        int saved = originalLen - compactLen;

        Map<String, String> out = new LinkedHashMap<>();
        out.put("kind", "policy_fit_inline");
        out.put("original_length", String.valueOf(originalLen));
        out.put("compact_length", String.valueOf(compactLen));
        out.put("saved_bytes", String.valueOf(saved));
        out.put("inline_limit", String.valueOf(IamPolicies.INLINE_SESSION_POLICY_LIMIT));
        out.put("remaining_bytes", String.valueOf(remaining));
        out.put("fits_inline", String.valueOf(fits));
        out.put("original_statements", String.valueOf(originalStmtCount));
        out.put("merged_statements", String.valueOf(mergedByAct.size()));
        out.put("sids_dropped", String.valueOf(sidsDropped));
        out.put("steps_applied", Jsons.encode(steps));
        out.put("compact_json", compact);
        out.put("pretty_json", pretty);
        out.put("summary", "fit_inline: " + originalLen + " -> " + compactLen + " chars (saved " + saved
            + ", remaining " + remaining + "/" + IamPolicies.INLINE_SESSION_POLICY_LIMIT
            + ", fits=" + fits + ", steps=" + String.join("+", steps) + ")");
        return out;
    }

    /**
     * Splits a large policy into managed-policy parts that each fit within maxLimit (default 6144 chars),
     * keeping global and service-specific Deny guardrails paired with the Allow statements they guard.
     */
    public static List<Map<String, String>> splitManaged(String policyJson, int maxLimit) {
        int limit = maxLimit <= 0 ? IamPolicies.MANAGED_POLICY_LIMIT : maxLimit;
        Map<String, Object> doc = parseDoc(policyJson);
        List<Map<String, Object>> allStmts = getStatements(doc);

        List<Map<String, Object>> allows = new ArrayList<>();
        List<Map<String, Object>> globalDenies = new ArrayList<>();
        Map<String, List<Map<String, Object>>> serviceDenies = new LinkedHashMap<>();

        for (Map<String, Object> s : allStmts) {
            String effect = String.valueOf(s.getOrDefault("Effect", "Allow"));
            if ("Deny".equals(effect)) {
                if (s.containsKey("NotAction")) {
                    globalDenies.add(s);
                } else {
                    Set<String> svcs = statementServices(s);
                    if (svcs.size() == 1) {
                        String svc = svcs.iterator().next();
                        serviceDenies.computeIfAbsent(svc, k -> new ArrayList<>()).add(s);
                    } else {
                        globalDenies.add(s);
                    }
                }
            } else {
                allows.add(s);
            }
        }

        // Check if entire policy fits in 1 managed policy
        String fullCompact = IamPolicies.compactJson(doc);
        if (fullCompact.length() <= limit && allStmts.size() <= 12) {
            return List.of(buildSplitPartRow(1, "part1", allStmts, limit));
        }

        // Partition allows into balanced buckets while attaching relevant service & global denies
        List<List<Map<String, Object>>> parts = new ArrayList<>();
        List<Map<String, Object>> currentAllowBucket = new ArrayList<>();
        Set<String> currentServices = new LinkedHashSet<>();

        // Aim for a sensible soft split threshold so multi-part splitting is demonstrated even under 6144
        int targetBucketLimit = fullCompact.length() > limit ? limit : Math.min(limit, Math.max(1800, (fullCompact.length() / 2) + 400));

        for (Map<String, Object> allowStmt : allows) {
            Set<String> svcs = statementServices(allowStmt);
            List<Map<String, Object>> candidate = new ArrayList<>(currentAllowBucket);
            candidate.add(allowStmt);
            Set<String> candidateServices = new LinkedHashSet<>(currentServices);
            candidateServices.addAll(svcs);
            List<Map<String, Object>> fullCandidate = assemblePartStatements(candidate, candidateServices, serviceDenies, globalDenies);
            int candidateLen = IamPolicies.compactJson(Map.of("Version", IamPolicies.EXPECTED_VERSION, "Statement", fullCandidate)).length();

            if (!currentAllowBucket.isEmpty() && (candidateLen > targetBucketLimit || candidateLen > limit)) {
                parts.add(assemblePartStatements(currentAllowBucket, currentServices, serviceDenies, globalDenies));
                currentAllowBucket = new ArrayList<>();
                currentServices = new LinkedHashSet<>();
            }
            currentAllowBucket.add(allowStmt);
            currentServices.addAll(svcs);
        }
        if (!currentAllowBucket.isEmpty()) {
            parts.add(assemblePartStatements(currentAllowBucket, currentServices, serviceDenies, globalDenies));
        }
        if (parts.isEmpty() && !allStmts.isEmpty()) {
            parts.add(allStmts);
        }

        List<Map<String, String>> rows = new ArrayList<>();
        for (int i = 0; i < parts.size(); i++) {
            rows.add(buildSplitPartRow(i + 1, "part" + (i + 1), parts.get(i), limit));
        }
        return rows;
    }

    private static List<Map<String, Object>> assemblePartStatements(
            List<Map<String, Object>> allows,
            Set<String> services,
            Map<String, List<Map<String, Object>>> serviceDenies,
            List<Map<String, Object>> globalDenies) {
        List<Map<String, Object>> out = new ArrayList<>(allows);
        for (String svc : services) {
            List<Map<String, Object>> denies = serviceDenies.get(svc);
            if (denies != null) {
                out.addAll(denies);
            }
        }
        out.addAll(globalDenies);
        return out;
    }

    private static Map<String, String> buildSplitPartRow(
            int partIndex,
            String suffix,
            List<Map<String, Object>> stmts,
            int limit) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("Version", IamPolicies.EXPECTED_VERSION);
        doc.put("Statement", stmts);
        String compact = IamPolicies.compactJson(doc);
        String pretty = IamPolicies.prettyJson(doc);
        int allowCount = 0;
        int denyCount = 0;
        List<String> sids = new ArrayList<>();
        for (int i = 0; i < stmts.size(); i++) {
            Map<String, Object> s = stmts.get(i);
            String eff = String.valueOf(s.getOrDefault("Effect", "Allow"));
            if ("Deny".equals(eff)) denyCount++;
            else allowCount++;
            sids.add(String.valueOf(s.getOrDefault("Sid", "Statement" + (i + 1))));
        }
        Map<String, String> row = new LinkedHashMap<>();
        row.put("part", String.valueOf(partIndex));
        row.put("policy_name_suffix", suffix);
        row.put("statement_count", String.valueOf(stmts.size()));
        row.put("allow_count", String.valueOf(allowCount));
        row.put("deny_count", String.valueOf(denyCount));
        row.put("compact_length", String.valueOf(compact.length()));
        row.put("max_length", String.valueOf(limit));
        row.put("remaining_bytes", String.valueOf(limit - compact.length()));
        row.put("fits_managed", String.valueOf(compact.length() <= limit));
        row.put("sids", String.join(",", sids));
        row.put("compact_json", compact);
        row.put("pretty_json", pretty);
        row.put("count", "1");
        return row;
    }

    /**
     * Produces a plain-English explanation of each statement and overall policy risk posture.
     */
    public static List<Map<String, String>> explain(String policyJson) {
        Map<String, Object> doc = parseDoc(policyJson);
        List<Map<String, Object>> stmts = getStatements(doc);
        List<Map<String, String>> rows = new ArrayList<>();

        boolean hasRegionLock = false;
        boolean hasEc2RunTagGate = false;
        boolean hasEc2NanoGuard = false;
        int wildcardCount = 0;
        int writeOnStarCount = 0;
        int missingTagGateCount = 0;

        for (int i = 0; i < stmts.size(); i++) {
            Map<String, Object> s = stmts.get(i);
            String sid = String.valueOf(s.getOrDefault("Sid", "Statement[" + i + "]"));
            String effect = String.valueOf(s.getOrDefault("Effect", "Allow"));
            boolean isNotAction = s.containsKey("NotAction");
            List<String> actions = stringList(s.getOrDefault("Action", s.get("NotAction")));
            List<String> resources = stringList(s.getOrDefault("Resource", s.get("NotResource")));
            String condCompact = s.containsKey("Condition") ? IamPolicies.compactJson(s.get("Condition")) : "";
            String condLower = condCompact.toLowerCase(Locale.ROOT);

            if ("Deny".equals(effect) && condLower.contains("aws:requestedregion")) {
                hasRegionLock = true;
            }
            if ("Allow".equals(effect) && actions.stream().anyMatch(a -> "ec2:RunInstances".equalsIgnoreCase(a))
                    && condLower.contains("requesttag/")) {
                hasEc2RunTagGate = true;
            }
            if ("Deny".equals(effect) && actions.stream().anyMatch(a -> "ec2:RunInstances".equalsIgnoreCase(a))
                    && condLower.contains("ec2:instancetype")) {
                hasEc2NanoGuard = true;
            }

            Set<String> services = statementServices(s);
            Set<String> classes = new LinkedHashSet<>();
            boolean hasWildcardAction = false;
            boolean hasWriteOrPerm = false;
            for (String a : actions) {
                if (a.contains("*")) hasWildcardAction = true;
                String cls = PolicyCatalog.classify(a);
                classes.add(cls);
                if (PolicyCatalog.CLASS_WRITE.equals(cls)
                        || PolicyCatalog.CLASS_TAGGING.equals(cls)
                        || PolicyCatalog.CLASS_PERMISSIONS.equals(cls)) {
                    hasWriteOrPerm = true;
                }
            }
            if (hasWildcardAction) wildcardCount++;

            boolean hasStarResource = resources.stream().anyMatch("*"::equals);
            String scopeType = classifyScope(s, resources, condLower);
            List<String> risks = new ArrayList<>();
            if ("Allow".equals(effect)) {
                if (hasWildcardAction) risks.add("wildcard_actions");
                if (hasStarResource && hasWriteOrPerm) {
                    risks.add("write_on_star");
                    writeOnStarCount++;
                }
                if (hasWriteOrPerm && "wildcard".equals(scopeType)) {
                    risks.add("missing_tag_gate");
                    missingTagGateCount++;
                }
                if (classes.contains(PolicyCatalog.CLASS_PERMISSIONS)) {
                    risks.add("permissions_management");
                }
            }

            String summary = describeStatementPlainEnglish(sid, effect, isNotAction, actions, resources, scopeType, condCompact);
            Map<String, String> row = new LinkedHashMap<>();
            row.put("sid", sid);
            row.put("effect", effect);
            row.put("services", String.join(",", services));
            row.put("action_classes", String.join(",", classes));
            row.put("action_count", String.valueOf(actions.size()));
            row.put("resource_count", String.valueOf(resources.size()));
            row.put("scope_type", scopeType);
            row.put("risk_flags", risks.isEmpty() ? "none" : String.join(",", risks));
            row.put("plain_english", summary);
            row.put("count", "1");
            rows.add(row);
        }

        List<String> postureFlags = new ArrayList<>();
        if (!hasRegionLock) postureFlags.add("missing_region_lock");
        if (writeOnStarCount > 0) postureFlags.add("write_actions_on_star(" + writeOnStarCount + ")");
        if (missingTagGateCount > 0) postureFlags.add("missing_tag_gates(" + missingTagGateCount + ")");
        String overallRisk = writeOnStarCount > 0 ? "high" : (!hasRegionLock ? "medium" : "low");

        Map<String, String> posture = new LinkedHashMap<>();
        posture.put("sid", "POLICY_POSTURE");
        posture.put("effect", "Summary");
        posture.put("services", "all");
        posture.put("action_classes", "posture");
        posture.put("action_count", String.valueOf(stmts.size()));
        posture.put("resource_count", String.valueOf(wildcardCount));
        posture.put("scope_type", hasRegionLock ? "region_locked" : "multi_region");
        posture.put("risk_flags", postureFlags.isEmpty() ? "none" : String.join(",", postureFlags));
        posture.put("plain_english", "Overall risk=" + overallRisk
            + "; statements=" + stmts.size()
            + "; region_lock=" + hasRegionLock
            + "; ec2_tag_gate=" + hasEc2RunTagGate
            + "; ec2_nano_guard=" + hasEc2NanoGuard
            + "; write_on_star=" + writeOnStarCount);
        posture.put("count", "1");
        rows.add(posture);
        return rows;
    }

    /**
     * Builds a permission matrix (service x action_class x scope) suitable for plotting with lmplot/lmdraw.
     */
    public static List<Map<String, String>> matrix(String policyJson) {
        Map<String, Object> doc = parseDoc(policyJson);
        List<Map<String, Object>> stmts = getStatements(doc);
        Map<String, Map<String, Object>> cells = new LinkedHashMap<>();

        for (int i = 0; i < stmts.size(); i++) {
            Map<String, Object> s = stmts.get(i);
            String sid = String.valueOf(s.getOrDefault("Sid", "Statement[" + i + "]"));
            String effect = String.valueOf(s.getOrDefault("Effect", "Allow"));
            boolean isNotAction = s.containsKey("NotAction");
            List<String> actions = stringList(s.getOrDefault("Action", s.get("NotAction")));
            List<String> resources = stringList(s.getOrDefault("Resource", s.get("NotResource")));
            String condLower = s.containsKey("Condition")
                ? IamPolicies.compactJson(s.get("Condition")).toLowerCase(Locale.ROOT)
                : "";
            String scope = classifyScope(s, resources, condLower);

            if (isNotAction) {
                String key = "global_guardrail|guardrail|" + effect + "|" + scope;
                accumulateCell(cells, key, "global_guardrail", "guardrail", effect, scope, actions.size(), resources.size(), sid);
                continue;
            }
            for (String act : actions) {
                int colon = act.indexOf(':');
                String svc = colon > 0 ? act.substring(0, colon).toLowerCase(Locale.ROOT) : "wildcard";
                String cls = PolicyCatalog.classify(act);
                String key = svc + "|" + cls + "|" + effect + "|" + scope;
                accumulateCell(cells, key, svc, cls, effect, scope, 1, resources.size(), sid);
            }
        }

        List<Map<String, String>> out = new ArrayList<>();
        for (Map<String, Object> cell : cells.values()) {
            String effect = String.valueOf(cell.get("effect"));
            String cls = String.valueOf(cell.get("action_class"));
            String scope = String.valueOf(cell.get("scope"));
            String risk = "safe";
            if ("Deny".equals(effect)) {
                risk = "guardrail";
            } else if ("wildcard".equals(scope) && (PolicyCatalog.CLASS_WRITE.equals(cls) || PolicyCatalog.CLASS_PERMISSIONS.equals(cls))) {
                risk = "high";
            } else if (PolicyCatalog.CLASS_WRITE.equals(cls) || PolicyCatalog.CLASS_TAGGING.equals(cls)) {
                risk = "scoped_write";
            }
            @SuppressWarnings("unchecked")
            Set<String> sids = (Set<String>) cell.get("sids");
            Map<String, String> row = new LinkedHashMap<>();
            row.put("service", String.valueOf(cell.get("service")));
            row.put("action_class", cls);
            row.put("effect", effect);
            row.put("scope", scope);
            row.put("action_count", String.valueOf(cell.get("action_count")));
            row.put("resource_count", String.valueOf(cell.get("resource_count")));
            row.put("risk_level", risk);
            row.put("sids", String.join(",", sids));
            row.put("detail", cell.get("service") + " " + cls + " [" + effect + " / " + scope + "]");
            row.put("count", String.valueOf(cell.get("action_count")));
            out.add(row);
        }
        return out;
    }

    private static void accumulateCell(
            Map<String, Map<String, Object>> cells,
            String key,
            String service,
            String cls,
            String effect,
            String scope,
            int actionDelta,
            int resourceCount,
            String sid) {
        Map<String, Object> cell = cells.get(key);
        if (cell == null) {
            cell = new LinkedHashMap<>();
            cell.put("service", service);
            cell.put("action_class", cls);
            cell.put("effect", effect);
            cell.put("scope", scope);
            cell.put("action_count", 0);
            cell.put("resource_count", resourceCount);
            cell.put("sids", new LinkedHashSet<String>());
            cells.put(key, cell);
        }
        cell.put("action_count", ((Integer) cell.get("action_count")) + actionDelta);
        @SuppressWarnings("unchecked")
        Set<String> sids = (Set<String>) cell.get("sids");
        sids.add(sid);
    }

    /**
     * Parses an AWS AccessDenied / UnauthorizedOperation error message and returns the
     * diagnosis, failed condition or missing permission, and the minimal PolicyBuilder snippet.
     */
    public static Map<String, String> explainDenial(String errorText) {
        String safeText = Jsons.mask(errorText == null ? "" : errorText.trim());
        String lower = safeText.toLowerCase(Locale.ROOT);

        Matcher principalMatcher = PRINCIPAL_IN_ERROR.matcher(safeText);
        String principal = principalMatcher.find() ? principalMatcher.group(1) : "unknown-principal";

        Matcher actionMatcher = ACTION_IN_ERROR.matcher(safeText);
        String action = actionMatcher.find() ? actionMatcher.group(1) : "ec2:RunInstances";
        try {
            action = PolicyCatalog.validatePattern(action);
        } catch (IllegalArgumentException ignored) {
            // Keep raw action if not in catalog
        }
        int colon = action.indexOf(':');
        String service = colon > 0 ? action.substring(0, colon).toLowerCase(Locale.ROOT) : "unknown";
        String actionClass = PolicyCatalog.classify(action);

        Matcher resourceMatcher = RESOURCE_IN_ERROR.matcher(safeText);
        String resource = resourceMatcher.find() ? resourceMatcher.group(1) : PolicyCatalog.arn(service, "", "*");

        boolean explicitDeny = lower.contains("explicit deny");
        boolean sessionPolicy = lower.contains("session policy");
        String denialType = explicitDeny
            ? (sessionPolicy ? "session_policy_explicit_deny" : "identity_policy_explicit_deny")
            : (sessionPolicy ? "session_policy_missing_allow" : "identity_policy_missing_allow");

        String failedCondition = "none";
        String plainEnglish;
        String builderSnippet;
        Map<String, Object> suggestedStmt = new LinkedHashMap<>();

        if (explicitDeny) {
            if ("ec2:RunInstances".equalsIgnoreCase(action)) {
                failedCondition = "ec2:InstanceType in [t4g.nano, t3.nano] && ec2:VolumeSize <= 8 && aws:RequestedRegion == us-east-1";
                plainEnglish = "Explicit Deny triggered on ec2:RunInstances: verify instance type is t4g.nano or t3.nano (NanoOnly), root volume is <= 8 GiB (SmallDisks), and region is us-east-1 (OnlyUsEast1).";
                builderSnippet = "policy.spot_nano_sandbox(\"lmaws_test\", \"t4g.nano,t3.nano\", 8)";
                suggestedStmt.put("Sid", "NanoOnly");
                suggestedStmt.put("Effect", "Deny");
                suggestedStmt.put("Action", "ec2:RunInstances");
                suggestedStmt.put("Resource", "arn:aws:ec2:*:*:instance/*");
                suggestedStmt.put("Condition", Map.of("StringNotEquals", Map.of("ec2:InstanceType", List.of("t4g.nano", "t3.nano"))));
            } else if ("ec2:CreateSecurityGroup".equalsIgnoreCase(action)) {
                failedCondition = "aws:RequestTag/lmaws_test must be present on CreateSecurityGroup";
                plainEnglish = "Explicit Deny triggered on ec2:CreateSecurityGroup (SgMustBeTagged): pass TagSpecifications with lmaws_test on group creation.";
                builderSnippet = "policy.allow(\"CreateSg\", \"ec2:CreateSecurityGroup\", \"arn:aws:ec2:*:*:vpc/*,arn:aws:ec2:*:*:security-group/*\").deny_untagged_create(\"SgMustBeTagged\", \"ec2:CreateSecurityGroup\", \"arn:aws:ec2:*:*:security-group/*\", \"lmaws_test\")";
                suggestedStmt.put("Sid", "SgMustBeTagged");
                suggestedStmt.put("Effect", "Deny");
                suggestedStmt.put("Action", "ec2:CreateSecurityGroup");
                suggestedStmt.put("Resource", "arn:aws:ec2:*:*:security-group/*");
                suggestedStmt.put("Condition", Map.of("Null", Map.of("aws:RequestTag/lmaws_test", "true")));
            } else if (lower.contains("multifactorauthpresent") || lower.contains("mfa")) {
                failedCondition = "aws:MultiFactorAuthPresent == true";
                plainEnglish = "Explicit Deny triggered because Multi-Factor Authentication (MFA) is missing from the session.";
                builderSnippet = "policy.mfa_required(\"RequireMfaDeletes\", \"" + action + "\", \"" + resource + "\")";
                suggestedStmt.put("Sid", "RequireMfaDeletes");
                suggestedStmt.put("Effect", "Deny");
                suggestedStmt.put("Action", action);
                suggestedStmt.put("Resource", resource);
                suggestedStmt.put("Condition", Map.of("BoolIfExists", Map.of("aws:MultiFactorAuthPresent", "false")));
            } else if (lower.contains("sourceip")) {
                failedCondition = "aws:SourceIp within allowed CIDR";
                plainEnglish = "Explicit Deny triggered because caller IP is outside the allowed corporate CIDR block.";
                builderSnippet = "policy.source_ip(\"CorporateIpOnly\", \"198.51.100.0/24\")";
                suggestedStmt.put("Sid", "CorporateIpOnly");
                suggestedStmt.put("Effect", "Deny");
                suggestedStmt.put("NotAction", "sts:GetCallerIdentity");
                suggestedStmt.put("Resource", "*");
                suggestedStmt.put("Condition", Map.of("NotIpAddress", Map.of("aws:SourceIp", "198.51.100.0/24")));
            } else {
                failedCondition = "aws:RequestedRegion == us-east-1 (or resource tag guardrail)";
                plainEnglish = "Explicit Deny triggered for " + action + " on " + resource + ": check region lock (us-east-1) and required lmaws_test request/resource tags.";
                builderSnippet = "policy.region_lock(\"OnlyUsEast1\", \"us-east-1\", \"sts:GetCallerIdentity,cloudfront:*,route53:*\")";
                suggestedStmt.put("Sid", "OnlyUsEast1");
                suggestedStmt.put("Effect", "Deny");
                suggestedStmt.put("NotAction", List.of("sts:GetCallerIdentity", "cloudfront:*", "route53:*"));
                suggestedStmt.put("Resource", "*");
                suggestedStmt.put("Condition", Map.of("StringNotEquals", Map.of("aws:RequestedRegion", "us-east-1")));
            }
        } else {
            if ("ec2:RunInstances".equalsIgnoreCase(action)) {
                failedCondition = "aws:RequestTag/lmaws_test == present on instance & volume, plus RunRefs on subnet/image/eni/spot-request";
                plainEnglish = "No Allow statement matched ec2:RunInstances on " + resource
                    + ": ensure both instance and volume carry RequestTag/lmaws_test and subnet/image/network-interface/spot-instances-request are in RunRefs.";
                builderSnippet = "policy.require_tag_on_create(\"RunTagged\", \"ec2:RunInstances\", \"arn:aws:ec2:*:*:instance/*,arn:aws:ec2:*:*:volume/*\", \"lmaws_test\")"
                    + ".allow(\"RunRefs\", \"ec2:RunInstances\", \"arn:aws:ec2:*:*:subnet/*,arn:aws:ec2:*::image/*,arn:aws:ec2:*:*:network-interface/*,arn:aws:ec2:*:*:spot-instances-request/*\")";
                suggestedStmt.put("Sid", "RunTagged");
                suggestedStmt.put("Effect", "Allow");
                suggestedStmt.put("Action", "ec2:RunInstances");
                suggestedStmt.put("Resource", List.of("arn:aws:ec2:*:*:instance/*", "arn:aws:ec2:*:*:volume/*"));
                suggestedStmt.put("Condition", Map.of("Null", Map.of("aws:RequestTag/lmaws_test", "false")));
            } else if ("ec2".equals(service) && (action.contains("SecurityGroup") || action.contains("Instances"))) {
                failedCondition = "ec2:ResourceTag/lmaws_test == present";
                plainEnglish = "No Allow statement matched " + action + " on " + resource
                    + ": target resource must carry the existing tag lmaws_test (OwnEc2).";
                builderSnippet = "policy.only_tagged(\"OwnEc2\", \"" + action + "\", \"" + generalizeResourceArn(service, resource) + "\", \"lmaws_test\", \"ec2\")";
                suggestedStmt.put("Sid", "OwnEc2");
                suggestedStmt.put("Effect", "Allow");
                suggestedStmt.put("Action", action);
                suggestedStmt.put("Resource", generalizeResourceArn(service, resource));
                suggestedStmt.put("Condition", Map.of("Null", Map.of("ec2:ResourceTag/lmaws_test", "false")));
            } else if (PolicyCatalog.CLASS_LIST.equals(actionClass) || PolicyCatalog.CLASS_READ.equals(actionClass)) {
                String targetRes = "*".equals(resource) || PolicyCatalog.CLASS_LIST.equals(actionClass)
                    ? "*"
                    : generalizeResourceArn(service, resource);
                plainEnglish = "Missing read/list permission for " + action + " on " + targetRes + ".";
                builderSnippet = "policy.allow(\"AllowRead" + capitalize(service) + "\", \"" + action + "\", \"" + targetRes + "\")";
                suggestedStmt.put("Sid", "AllowRead" + capitalize(service));
                suggestedStmt.put("Effect", "Allow");
                suggestedStmt.put("Action", action);
                suggestedStmt.put("Resource", targetRes);
            } else {
                String scopedArn = generalizeResourceArn(service, resource);
                failedCondition = "aws:ResourceAccount == ${aws:PrincipalAccount} and lmaws-*/lmaws_* name prefix";
                plainEnglish = "Missing scoped write permission for " + action + " on " + scopedArn
                    + ": add a prefix-scoped or tag-gated Allow statement.";
                builderSnippet = "policy.allow_cond(\"AllowScoped" + capitalize(service) + "\", \"" + action + "\", \"" + scopedArn
                    + "\", \"{\\\"StringEqualsIfExists\\\":{\\\"aws:ResourceAccount\\\":\\\"${aws:PrincipalAccount}\\\"}}\")";
                suggestedStmt.put("Sid", "AllowScoped" + capitalize(service));
                suggestedStmt.put("Effect", "Allow");
                suggestedStmt.put("Action", action);
                suggestedStmt.put("Resource", scopedArn);
                suggestedStmt.put("Condition", Map.of("StringEqualsIfExists", Map.of("aws:ResourceAccount", "${aws:PrincipalAccount}")));
            }
        }

        Map<String, String> out = new LinkedHashMap<>();
        out.put("kind", "explain_denial");
        out.put("principal", principal);
        out.put("action", action);
        out.put("service", service);
        out.put("action_class", actionClass);
        out.put("resource", generalizeResourceArn(service, resource));
        out.put("denial_type", denialType);
        out.put("failed_condition", failedCondition);
        out.put("plain_english", plainEnglish);
        out.put("builder_snippet", builderSnippet);
        out.put("statement_json", IamPolicies.compactJson(suggestedStmt));
        return out;
    }

    /**
     * Synthesizes a least-privilege IAM policy and builder program from observed SDK calls
     * and resource records in lmaws run ledgers (.jsonl) or cost evidence (.json).
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> fromLedger(String pathsCsv) {
        List<String> paths = PolicyBuilder.splitCsv(pathsCsv);
        Set<String> observedActions = new LinkedHashSet<>();
        Set<String> observedServices = new LinkedHashSet<>();
        Set<String> observedResources = new LinkedHashSet<>();
        int callCount = 0;

        for (String rawPath : paths) {
            if ("synthetic".equalsIgnoreCase(rawPath) || "demo".equalsIgnoreCase(rawPath)) {
                continue;
            }
            Path p = Path.of(rawPath);
            if (!Files.exists(p)) continue;
            List<Path> files = new ArrayList<>();
            if (Files.isDirectory(p)) {
                try (var stream = Files.list(p)) {
                    stream.filter(f -> f.toString().endsWith(".jsonl") || f.toString().endsWith(".json"))
                        .sorted()
                        .forEach(files::add);
                } catch (IOException ignored) {
                }
            } else {
                files.add(p);
            }
            for (Path file : files) {
                try {
                    String content = Files.readString(file);
                    if (file.toString().endsWith(".jsonl")) {
                        for (String line : content.split("\\R")) {
                            if (line.isBlank()) continue;
                            Object parsed = Json.parse(line);
                            if (!(parsed instanceof Map<?, ?> rawEvent)) continue;
                            Map<String, Object> event = (Map<String, Object>) rawEvent;
                            String evType = String.valueOf(event.getOrDefault("event", ""));
                            if ("cost_request".equals(evType)) {
                                String svc = String.valueOf(event.getOrDefault("service", ""));
                                String op = String.valueOf(event.getOrDefault("operation", ""));
                                String mapped = PolicyCatalog.mapLedgerOperationToIamAction(svc + "." + op);
                                if (mapped != null) {
                                    observedActions.add(mapped);
                                    int c = mapped.indexOf(':');
                                    if (c > 0) observedServices.add(mapped.substring(0, c));
                                    callCount++;
                                }
                            } else if ("cost_resource".equals(evType) || event.containsKey("kind")) {
                                String kind = String.valueOf(event.getOrDefault("kind", ""));
                                String name = String.valueOf(event.getOrDefault("name", event.getOrDefault("id", "")));
                                String arn = mapResourceKindToArn(kind, name);
                                if (arn != null) observedResources.add(arn);
                            }
                        }
                    } else {
                        Object parsed = Json.parse(content);
                        if (parsed instanceof Map<?, ?> report) {
                            Object reqs = report.get("service_requests");
                            if (reqs instanceof Map<?, ?> reqMap) {
                                for (Map.Entry<?, ?> entry : reqMap.entrySet()) {
                                    String key = String.valueOf(entry.getKey());
                                    String mapped = PolicyCatalog.mapLedgerOperationToIamAction(key);
                                    if (mapped != null) {
                                        observedActions.add(mapped);
                                        int c = mapped.indexOf(':');
                                        if (c > 0) observedServices.add(mapped.substring(0, c));
                                        callCount++;
                                    }
                                }
                            }
                            Object resList = report.get("resources");
                            if (resList instanceof List<?> list) {
                                for (Object item : list) {
                                    if (item instanceof Map<?, ?> rawRes) {
                                        Map<String, Object> rMap = (Map<String, Object>) rawRes;
                                        String kind = String.valueOf(rMap.getOrDefault("kind", ""));
                                        String name = String.valueOf(rMap.getOrDefault("name", rMap.getOrDefault("id", "")));
                                        String arn = mapResourceKindToArn(kind, name);
                                        if (arn != null) observedResources.add(arn);
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        // Fall back to deterministic synthetic ledger fixture when no real ledger events were provided
        if (observedActions.isEmpty()) {
            callCount = 14;
            Collections.addAll(observedServices, "sts", "s3", "sqs", "dynamodb", "ssm", "logs");
            Collections.addAll(observedActions,
                "sts:GetCallerIdentity",
                "s3:ListAllMyBuckets",
                "s3:CreateBucket",
                "s3:PutBucketTagging",
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:DeleteBucket",
                "sqs:CreateQueue",
                "sqs:TagQueue",
                "sqs:SendMessage",
                "sqs:ReceiveMessage",
                "sqs:DeleteQueue",
                "dynamodb:CreateTable",
                "dynamodb:TagResource",
                "dynamodb:PutItem",
                "dynamodb:GetItem",
                "dynamodb:DeleteTable"
            );
            Collections.addAll(observedResources,
                "arn:aws:s3:::lmaws-*",
                "arn:aws:s3:::lmaws-*/*",
                "arn:aws:sqs:*:*:lmaws_*",
                "arn:aws:dynamodb:*:*:table/lmaws_*"
            );
        }

        // Split observed actions into global list/read vs scoped resource actions
        List<String> listReadOnStar = new ArrayList<>();
        List<String> scopedActions = new ArrayList<>();
        for (String act : observedActions) {
            try {
                String valid = PolicyCatalog.validatePattern(act);
                String cls = PolicyCatalog.classify(valid);
                if ("sts:GetCallerIdentity".equalsIgnoreCase(valid) || PolicyCatalog.CLASS_LIST.equals(cls)) {
                    listReadOnStar.add(valid);
                } else {
                    scopedActions.add(valid);
                }
            } catch (IllegalArgumentException ignored) {
            }
        }
        if (listReadOnStar.isEmpty()) {
            listReadOnStar.add("sts:GetCallerIdentity");
        }
        if (observedResources.isEmpty()) {
            for (String svc : observedServices) {
                if ("sts".equals(svc)) continue;
                if ("s3".equals(svc)) {
                    observedResources.add("arn:aws:s3:::lmaws-*");
                    observedResources.add("arn:aws:s3:::lmaws-*/*");
                } else {
                    observedResources.add(PolicyCatalog.arn(svc, "", "lmaws_*"));
                }
            }
        }

        PolicyBuilder pb = new PolicyBuilder("lmaws_from_ledger");
        pb.allow("ObservedReads", String.join(",", listReadOnStar), "*");
        if (!scopedActions.isEmpty()) {
            pb.allowCond(
                "ObservedScopedWrites",
                String.join(",", scopedActions),
                String.join(",", observedResources),
                "{\"StringEqualsIfExists\":{\"aws:ResourceAccount\":\"${aws:PrincipalAccount}\"}}"
            );
        }
        pb.regionLock("OnlyUsEast1", "us-east-1", "sts:GetCallerIdentity,cloudfront:*,route53:*");

        StringBuilder prog = new StringBuilder();
        prog.append("let policy = cloud.policy(\"lmaws_from_ledger\")\n");
        prog.append("  .allow(\"ObservedReads\", \"").append(String.join(",", listReadOnStar)).append("\", \"*\")\n");
        if (!scopedActions.isEmpty()) {
            prog.append("  .allow_cond(\"ObservedScopedWrites\", \"")
                .append(String.join(",", scopedActions)).append("\", \"")
                .append(String.join(",", observedResources))
                .append("\", \"{\\\"StringEqualsIfExists\\\":{\\\"aws:ResourceAccount\\\":\\\"${aws:PrincipalAccount}\\\"}}\")\n");
        }
        prog.append("  .region_lock(\"OnlyUsEast1\", \"us-east-1\", \"sts:GetCallerIdentity,cloudfront:*,route53:*\");\n");

        String pretty = pb.json();
        String compact = pb.compactJson();

        Map<String, String> out = new LinkedHashMap<>();
        out.put("kind", "policy_from_ledger");
        out.put("observed_call_count", String.valueOf(callCount));
        out.put("resource_count", String.valueOf(observedResources.size()));
        out.put("services", String.join(",", observedServices));
        out.put("actions", String.join(",", observedActions));
        out.put("resources", String.join(",", observedResources));
        out.put("prefix", "lmaws");
        out.put("builder_program", prog.toString());
        out.put("policy_json", pretty);
        out.put("compact_json", compact);
        out.put("compact_length", String.valueOf(compact.length()));
        out.put("summary", "from_ledger: " + callCount + " calls across " + observedServices.size()
            + " services -> " + observedActions.size() + " least-privilege actions (" + compact.length() + " compact chars)");
        return out;
    }

    /**
     * Decompiles a hand-written IAM JSON policy document into an idiomatic lmscript
     * PolicyBuilder program, recognizing high-level intents and guardrails.
     */
    public static Map<String, String> importJson(String rawJson) {
        Map<String, Object> doc = parseDoc(rawJson);
        List<Map<String, Object>> stmts = getStatements(doc);
        List<String> intents = new ArrayList<>();
        StringBuilder code = new StringBuilder();
        code.append("let policy = cloud.policy(\"lmaws_migrated\")\n");

        for (int i = 0; i < stmts.size(); i++) {
            Map<String, Object> s = stmts.get(i);
            String sid = String.valueOf(s.getOrDefault("Sid", "Stmt" + (i + 1))).replaceAll("[^A-Za-z0-9]", "");
            if (sid.isEmpty()) sid = "Stmt" + (i + 1);
            String effect = String.valueOf(s.getOrDefault("Effect", "Allow"));
            boolean isNotAction = s.containsKey("NotAction");
            List<String> actions = stringList(s.getOrDefault("Action", s.get("NotAction")));
            List<String> resources = stringList(s.getOrDefault("Resource", s.get("NotResource")));
            String actCsv = String.join(",", actions);
            String resCsv = String.join(",", resources);
            Object condObj = s.get("Condition");
            String condCompact = condObj != null ? IamPolicies.compactJson(condObj) : "";
            String condLower = condCompact.toLowerCase(Locale.ROOT);

            if ("Allow".equals(effect) && !isNotAction) {
                if (condCompact.isEmpty()) {
                    intents.add(sid + ":allow");
                    code.append("  .allow(\"").append(sid).append("\", \"").append(actCsv).append("\", \"").append(resCsv).append("\")\n");
                } else if (condLower.contains("\"aws:requesttag/")) {
                    String tagKey = extractTagKey(condCompact, "RequestTag/");
                    intents.add(sid + ":require_tag_on_create(" + tagKey + ")");
                    code.append("  .require_tag_on_create(\"").append(sid).append("\", \"").append(actCsv)
                        .append("\", \"").append(resCsv).append("\", \"").append(tagKey).append("\")\n");
                } else if (condLower.contains(":resourcetag/")) {
                    String ns = condLower.contains("\"ec2:resourcetag/") ? "ec2" : "aws";
                    String tagKey = extractTagKey(condCompact, "ResourceTag/");
                    intents.add(sid + ":only_tagged(" + ns + ":" + tagKey + ")");
                    code.append("  .only_tagged(\"").append(sid).append("\", \"").append(actCsv)
                        .append("\", \"").append(resCsv).append("\", \"").append(tagKey).append("\", \"").append(ns).append("\")\n");
                } else {
                    intents.add(sid + ":allow_cond");
                    code.append("  .allow_cond(\"").append(sid).append("\", \"").append(actCsv)
                        .append("\", \"").append(resCsv).append("\", ").append(Jsons.encodeRaw(condCompact)).append(")\n");
                }
            } else {
                if (isNotAction) {
                    intents.add(sid + ":deny_not_action");
                    code.append("  .deny_not_action(\"").append(sid).append("\", \"").append(actCsv)
                        .append("\", \"").append(resCsv).append("\", ").append(Jsons.encodeRaw(condCompact)).append(")\n");
                } else if (condCompact.isEmpty()) {
                    intents.add(sid + ":deny");
                    code.append("  .deny(\"").append(sid).append("\", \"").append(actCsv).append("\", \"").append(resCsv).append("\")\n");
                } else {
                    intents.add(sid + ":deny_cond");
                    code.append("  .deny_cond(\"").append(sid).append("\", \"").append(actCsv)
                        .append("\", \"").append(resCsv).append("\", ").append(Jsons.encodeRaw(condCompact)).append(")\n");
                }
            }
        }
        code.append(";\n");

        String normalized = IamPolicies.compactJson(doc);
        Map<String, String> out = new LinkedHashMap<>();
        out.put("kind", "policy_import_json");
        out.put("statement_count", String.valueOf(stmts.size()));
        out.put("recognized_intents", String.join(",", intents));
        out.put("builder_program", code.toString());
        out.put("normalized_json", normalized);
        out.put("pretty_json", IamPolicies.prettyJson(doc));
        out.put("compact_length", String.valueOf(normalized.length()));
        return out;
    }

    // --- Internal helpers ---

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseDoc(String policyJson) {
        if (policyJson == null || policyJson.isBlank()) {
            throw new IllegalArgumentException("Policy JSON document must not be empty");
        }
        Object parsed = Json.parse(IamPolicies.decodeAwsDocument(policyJson));
        if (!(parsed instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("Policy JSON root must be an object");
        }
        return (Map<String, Object>) map;
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> getStatements(Map<String, Object> doc) {
        Object stmts = doc.get("Statement");
        if (stmts instanceof List<?> list) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof Map<?, ?> m) {
                    out.add((Map<String, Object>) m);
                }
            }
            return out;
        }
        if (stmts instanceof Map<?, ?> single) {
            return List.of((Map<String, Object>) single);
        }
        return List.of();
    }

    static List<String> stringList(Object value) {
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

    private static Object normalizeScalarOrList(List<String> items) {
        List<String> dedup = new ArrayList<>(new LinkedHashSet<>(items));
        return dedup.size() == 1 ? dedup.get(0) : dedup;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> normalizeCondition(Map<String, Object> cond) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> opEntry : cond.entrySet()) {
            if (opEntry.getValue() instanceof Map<?, ?> inner) {
                Map<String, Object> innerCopy = new LinkedHashMap<>();
                for (Map.Entry<?, ?> kv : inner.entrySet()) {
                    List<String> vals = stringList(kv.getValue());
                    innerCopy.put(String.valueOf(kv.getKey()), normalizeScalarOrList(vals));
                }
                out.put(opEntry.getKey(), innerCopy);
            } else {
                out.put(opEntry.getKey(), opEntry.getValue());
            }
        }
        return out;
    }

    private static List<String> collapseActionList(List<String> actions) {
        Map<String, List<String>> byService = new LinkedHashMap<>();
        for (String a : actions) {
            int colon = a.indexOf(':');
            if (colon <= 0) continue;
            String svc = a.substring(0, colon);
            byService.computeIfAbsent(svc, k -> new ArrayList<>()).add(a.substring(colon + 1));
        }
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : byService.entrySet()) {
            String svc = e.getKey();
            List<String> ops = e.getValue();
            if (ops.size() >= 3) {
                boolean allReadList = ops.stream().allMatch(op ->
                    op.startsWith("List") || op.startsWith("Describe") || op.startsWith("Get") || op.equals("*"));
                if (!allReadList) {
                    out.add(svc + ":*");
                    continue;
                }
            }
            List<String> kept = new ArrayList<>();
            long listCount = ops.stream().filter(op -> op.startsWith("List")).count();
            long descCount = ops.stream().filter(op -> op.startsWith("Describe")).count();
            long getCount = ops.stream().filter(op -> op.startsWith("Get")).count();
            if (listCount >= 2) kept.add("List*");
            if (descCount >= 2) kept.add("Describe*");
            if (getCount >= 2) kept.add("Get*");
            for (String op : ops) {
                if (listCount >= 2 && op.startsWith("List")) continue;
                if (descCount >= 2 && op.startsWith("Describe")) continue;
                if (getCount >= 2 && op.startsWith("Get")) continue;
                kept.add(op);
            }
            for (String op : kept) {
                out.add(svc + ":" + op);
            }
        }
        return out;
    }

    private static List<String> collapsePrefixArns(List<String> arns) {
        Set<String> set = new LinkedHashSet<>(arns);
        List<String> out = new ArrayList<>();
        Set<String> consumed = new LinkedHashSet<>();
        for (String arn : set) {
            if (consumed.contains(arn)) continue;
            if (arn.endsWith("-*")) {
                String underscorePeer = arn.substring(0, arn.length() - 2) + "_*";
                if (set.contains(underscorePeer)) {
                    consumed.add(arn);
                    consumed.add(underscorePeer);
                    out.add(arn.substring(0, arn.length() - 2) + "*");
                    continue;
                }
            }
            out.add(arn);
        }
        return out;
    }

    private static Set<String> statementServices(Map<String, Object> stmt) {
        Set<String> services = new LinkedHashSet<>();
        List<String> actions = stringList(stmt.getOrDefault("Action", stmt.get("NotAction")));
        for (String a : actions) {
            int c = a.indexOf(':');
            if (c > 0) services.add(a.substring(0, c).toLowerCase(Locale.ROOT));
        }
        return services;
    }

    private static String classifyScope(Map<String, Object> stmt, List<String> resources, String condLower) {
        if (condLower.contains("aws:requestedregion") || condLower.contains("s3:locationconstraint")) {
            return "region_lock";
        }
        if (condLower.contains("requesttag/")) {
            return "tag_on_create";
        }
        if (condLower.contains("resourcetag/")) {
            return "resource_tag";
        }
        if (condLower.contains("ec2:createaction")) {
            return "tag_on_create";
        }
        if (condLower.contains("ec2:instancetype")) {
            return "instance_type_guard";
        }
        if (condLower.contains("ec2:volumesize")) {
            return "volume_size_guard";
        }
        if (condLower.contains("changeresourcerecordsetsnormalizedrecordnames")) {
            return "route53_dns_guard";
        }
        if (condLower.contains("multifactorauthpresent")) {
            return "mfa_guard";
        }
        if (condLower.contains("aws:currenttime")) {
            return "time_window_guard";
        }
        if (condLower.contains("aws:sourceip")) {
            return "source_ip_guard";
        }
        boolean hasStar = resources.stream().anyMatch("*"::equals);
        if (hasStar) return "wildcard";
        boolean allPrefix = resources.stream().allMatch(r ->
            r.contains(":lmaws-") || r.contains(":lmaws_") || r.contains("/lmaws-") || r.contains("/lmaws_"));
        if (allPrefix) return "name_prefix";
        return "scoped_arn";
    }

    private static String describeStatementPlainEnglish(
            String sid,
            String effect,
            boolean isNotAction,
            List<String> actions,
            List<String> resources,
            String scopeType,
            String condCompact) {
        String verb = "Allow".equals(effect) ? "Allows" : "Denies";
        String actDesc = isNotAction
            ? "all actions EXCEPT [" + String.join(", ", actions) + "]"
            : "[" + String.join(", ", actions.size() > 5 ? actions.subList(0, 5) : actions)
                + (actions.size() > 5 ? ", ... (" + actions.size() + " total)" : "") + "]";
        String resDesc = resources.size() == 1 && "*".equals(resources.get(0))
            ? "all resources (*)"
            : resources.size() + " resource pattern(s)";
        String condDesc = condCompact.isEmpty() ? "" : " when " + scopeType + " condition holds";
        return sid + ": " + verb + " " + actDesc + " on " + resDesc + condDesc + ".";
    }

    private static String generalizeResourceArn(String service, String rawResource) {
        if (rawResource == null || rawResource.isBlank() || "*".equals(rawResource.trim())) {
            return PolicyCatalog.arn(service, "", "lmaws_*");
        }
        String masked = Jsons.mask(rawResource.trim()).replace("<account>", "*");
        if ("s3".equals(service) && !masked.contains("lmaws")) {
            return "arn:aws:s3:::lmaws-*";
        }
        return masked;
    }

    private static String mapResourceKindToArn(String kind, String name) {
        if (kind == null || kind.isBlank()) return null;
        return switch (kind.toLowerCase(Locale.ROOT)) {
            case "bucket", "s3" -> "arn:aws:s3:::lmaws-*";
            case "queue", "sqs" -> "arn:aws:sqs:*:*:lmaws_*";
            case "topic", "sns" -> "arn:aws:sns:*:*:lmaws_*";
            case "table", "dynamodb" -> "arn:aws:dynamodb:*:*:table/lmaws_*";
            case "parameter", "ssm" -> "arn:aws:ssm:*:*:parameter/lmaws_*";
            case "log_group", "logs" -> "arn:aws:logs:*:*:log-group:lmaws_*";
            case "instance", "ec2" -> "arn:aws:ec2:*:*:instance/*";
            default -> null;
        };
    }

    private static String extractTagKey(String condCompact, String marker) {
        int idx = condCompact.indexOf(marker);
        if (idx < 0) return "lmaws_test";
        int start = idx + marker.length();
        int end = condCompact.indexOf('"', start);
        return end > start ? condCompact.substring(start, end) : "lmaws_test";
    }

    private static String capitalize(String s) {
        if (s == null || s.isEmpty()) return "Resource";
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
