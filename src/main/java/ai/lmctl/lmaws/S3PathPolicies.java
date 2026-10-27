package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Pure, conservative policy inspection for the read-only S3 path diagnostic. */
public final class S3PathPolicies {
    private S3PathPolicies() {}

    public static String session(String policy, String action, String resource, Map<String, Object> context) {
        Map<String, String> ctx = new LinkedHashMap<>();
        if (context != null) for (Map.Entry<String, Object> e : context.entrySet()) ctx.put(e.getKey(), String.valueOf(e.getValue()));
        Map<String, Object> document = parse(policy); boolean uncertain = false; List<Object> certain = new ArrayList<>();
        for (Object item : statements(document)) if (item instanceof Map<?, ?> raw) {
            Map<String, Object> statement = cast(raw);
            if(!actionMatches(statement,action)) continue;
            if(unresolvedResource(statement,ctx.get("aws:PrincipalAccount"))) {uncertain=true;continue;}
            if(!resourceMatches(statement,resource,ctx.get("aws:PrincipalAccount"))) continue;
            int condition = evaluateConditions(statement, ctx);
            if(condition==1) {var copy=new LinkedHashMap<>(statement);copy.remove("Condition");copy.remove("NotAction");copy.remove("NotResource");copy.put("Action",action);copy.put("Resource",resource);certain.add(copy);}
            if (condition < 0) uncertain = true;
            if (condition == 1 && "Deny".equalsIgnoreCase(String.valueOf(statement.getOrDefault("Effect", "Allow")))) return "denied: explicit session-policy Deny";
        }
        if (uncertain) return "unknown: needs session-policy request context";
        var rows = PolicySimulator.evaluateOffline(Jsons.encodeRaw(Map.of("Statement",certain)), List.of(new PolicySimulator.Probe("s3-path", action, resource, ctx, "")));
        if (rows.isEmpty()) return "unknown: session policy simulation returned no result";
        return switch (rows.get(0).getOrDefault("decision", "implicitDeny")) {
            case "allowed" -> "allowed";
            case "explicitDeny" -> "denied: explicit session-policy Deny";
            default -> "unknown: needs managed-session policy evaluation; no inline Allow";
        };
    }

    /** Resource-policy verdict; this never grants identity permissions. */
    public static List<Map<String, String>> bucket(String policy, String resource, String principalArn, String account) {
        Map<String, Object> doc = parse(policy); List<Object> statements = statements(doc); List<Map<String, String>> rows = new ArrayList<>();
        boolean matched = false, allow = false, deny = false, uncertain = false;
        for (int i = 0; i < statements.size(); i++) {
            if (!(statements.get(i) instanceof Map<?, ?> raw)) continue;
            Map<String, Object> statement = cast(raw); String sid = String.valueOf(statement.getOrDefault("Sid", "Statement[" + i + "]"));
            String effect = String.valueOf(statement.getOrDefault("Effect", "Allow")); String actions = joined(statement.get("Action"), statement.get("NotAction"));
            boolean actionMatch = actionMatches(statement, "s3:PutObject"); boolean unresolved=unresolvedResource(statement,account); boolean resourceMatch = unresolved || resourceMatches(statement, resource, account);
            int principal = principalState(statement, principalArn, account); int condition = unresolved?-1:conditionState(statement, principalArn, account);
            String statementStatus = "unknown: needs request context";
            if (!actionMatch || !resourceMatch) statementStatus = "unknown: statement does not match this action/resource";
            else if (principal < 0 || condition < 0) statementStatus = "unknown: needs request context";
            else if (principal == 0 || condition == 0) statementStatus = "unknown: statement principal/condition does not apply";
            else statementStatus = "Deny".equalsIgnoreCase(effect) ? "denied: matching bucket-policy explicit Deny" : "allowed: bucket-policy statement";
            if (actionMatch || effect.equalsIgnoreCase("Deny")) rows.add(row("layer", "bucket_policy_statement", "status", statementStatus, "sid", sid, "effect", effect, "action", mask(actions), "resource", mask(joined(statement.get("Resource"), statement.get("NotResource"))), "principal", mask(String.valueOf(statement.getOrDefault("Principal", statement.getOrDefault("NotPrincipal", "")))), "principal_field",statement.containsKey("NotPrincipal")?"NotPrincipal":"Principal", "conditions",mask(Jsons.encodeRaw(statement.getOrDefault("Condition",Map.of()))), "condition_keys", conditionKeys(statement.get("Condition")), "mentions_put_object", String.valueOf(actionMatch)));
            if (!actionMatch || !resourceMatch || principal == 0 || condition == 0) continue;
            matched = true; if (principal < 0 || condition < 0) { uncertain = true; continue; }
            if ("Deny".equalsIgnoreCase(effect)) deny = true; else if ("Allow".equalsIgnoreCase(effect)) allow = true;
        }
        String status = deny ? "denied: matching bucket-policy explicit Deny" : uncertain ? "unknown: needs bucket-policy request context" : allow ? "allowed: bucket-policy layer" : matched ? "unknown: bucket-policy statement is not applicable to this principal/context" : "allowed: no applicable bucket-policy Deny";
        rows.add(row("layer", "bucket_policy", "status", status, "principal_arn", mask(principalArn), "account", mask(account)));
        return rows;
    }

    private static Map<String, Object> parse(String raw) { Object value = Json.parse(raw == null ? "{}" : raw); if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException("policy must be a JSON object"); return cast(map); }
    private static List<Object> statements(Map<String, Object> doc) { Object value = doc.get("Statement"); if (value instanceof List<?> list) return new ArrayList<>(list); return value == null ? List.of() : List.of(value); }
    private static boolean actionMatches(Map<String, Object> s, String action) { return s.containsKey("NotAction") ? !wildcardActionAny(s.get("NotAction"), action) : wildcardActionAny(s.get("Action"), action); }
    private static boolean unresolvedResource(Map<String,Object> statement,String account) {
        for(String pattern:strings(statement.containsKey("NotResource")?statement.get("NotResource"):statement.get("Resource"))) {
            String rendered=account==null||account.isBlank()?pattern:pattern.replace("${aws:PrincipalAccount}",account);
            if(rendered.contains("${"))return true;
        }
        return false;
    }
    private static boolean resourceMatches(Map<String, Object> s, String resource, String account) { boolean m = wildcardAny(s.containsKey("NotResource") ? s.get("NotResource") : s.get("Resource"), resource, account); return s.containsKey("NotResource") ? !m : m; }
    private static int principalState(Map<String, Object> s, String arn, String account) {
        if (s.containsKey("NotPrincipal")) return -1;
        Object p = s.get("Principal"); if (p == null || "*".equals(p)) return 1;
        if (p instanceof String x) return arn == null || arn.isBlank() ? -1 : (wildcard(x, arn) ? 1 : 0);
        if (p instanceof Map<?, ?> m) { if(arn==null || arn.isBlank() || account==null || account.isBlank())return -1; Object aws = m.get("AWS"); if (aws == null) return -1; boolean known = false; for (String x : strings(aws)) { known = true; if ("*".equals(x) || (arn != null && wildcard(x, arn)) || (account != null && x.endsWith(":root") && x.contains(account))) return 1; } return known ? 0 : -1; }
        return -1;
    }
    private static int conditionState(Map<String, Object> s, String arn, String account) { Map<String, String> ctx = new LinkedHashMap<>(); if (arn != null && !arn.isBlank()) ctx.put("aws:PrincipalArn", arn); if (account != null && !account.isBlank()) ctx.put("aws:PrincipalAccount", account); ctx.put("aws:SecureTransport", "true"); return evaluateConditions(s, ctx); }
    private static int evaluateConditions(Map<String, Object> s, Map<String, String> ctx) {
        Object raw = s.get("Condition"); if (!(raw instanceof Map<?, ?> map)) return 1;
        int result = 1;
        for (Map.Entry<?, ?> op : map.entrySet()) {
            if (!(op.getValue() instanceof Map<?, ?> nested)) return -1;
            String operator = String.valueOf(op.getKey()); String base = operator.replace("IfExists", "");
            boolean negated = base.endsWith("NotEquals") || base.endsWith("NotLike");
            if (!(base.equals("StringEquals") || base.equals("ArnEquals") || base.equals("StringLike") || base.equals("ArnLike") || base.equals("StringNotEquals") || base.equals("ArnNotEquals") || base.equals("StringNotLike") || base.equals("ArnNotLike") || base.equals("Bool") || base.equals("Null"))) return -1;
            for (Map.Entry<?, ?> kv : nested.entrySet()) { String key = String.valueOf(kv.getKey()); String actual = ctx.entrySet().stream().filter(e->e.getKey().equalsIgnoreCase(key)).map(Map.Entry::getValue).findFirst().orElse(null); if (actual == null || actual.isEmpty()) return -1; boolean clause;
                if (base.equals("Null")) clause = (actual == null) == Boolean.parseBoolean(strings(kv.getValue()).stream().findFirst().orElse("false"));
                else if (base.equals("Bool")) clause = Boolean.parseBoolean(actual) == Boolean.parseBoolean(strings(kv.getValue()).stream().findFirst().orElse("false"));
                else { clause = false; for (String pattern : strings(kv.getValue())) {String expected=pattern;String pa=ctx.entrySet().stream().filter(e->e.getKey().equalsIgnoreCase("aws:PrincipalAccount")).map(Map.Entry::getValue).findFirst().orElse("");if(!pa.isBlank())expected=expected.replace("${aws:PrincipalAccount}",pa);if(expected.contains("${"))return -1;if ((base.contains("Like") ? wildcard(expected, actual) : expected.equals(actual))) { clause = true; break; }} if (negated) clause = !clause; }
                if (!clause) return 0;
            }
        }
        return result;
    }
    private static List<String> strings(Object value) { if (value instanceof List<?> list) { List<String> out = new ArrayList<>(); for (Object x : list) out.add(String.valueOf(x)); return out; } return value == null ? List.of() : List.of(String.valueOf(value)); }
    private static boolean wildcardAny(Object value, String candidate, String account) { for (String pattern : strings(value)) if (wildcard(pattern.replace("${aws:PrincipalAccount}", account == null ? "" : account), candidate)) return true; return false; }
    private static boolean wildcardActionAny(Object value, String candidate) { for (String pattern : strings(value)) if (wildcard(pattern.toLowerCase(Locale.ROOT), candidate.toLowerCase(Locale.ROOT))) return true; return false; }
    private static boolean wildcard(String pattern, String value) {
        if (pattern == null || value == null) return false;
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '*') regex.append(".*");
            else if (c == '?') regex.append('.');
            else regex.append(Pattern.quote(String.valueOf(c)));
        }
        return Pattern.compile(regex.append('$').toString()).matcher(value).matches();
    }
    private static String joined(Object action, Object notAction) { return String.join(",", strings(action == null ? notAction : action)); }
    private static String conditionKeys(Object value) { if (!(value instanceof Map<?, ?> map)) return ""; List<String> out = new ArrayList<>(); for (Map.Entry<?, ?> e : map.entrySet()) if (e.getValue() instanceof Map<?, ?> nested) for (Object k : nested.keySet()) out.add(e.getKey() + ":" + k); else out.add(String.valueOf(e.getKey())); return String.join(",", out); }
    @SuppressWarnings("unchecked") private static Map<String, Object> cast(Map<?, ?> map) { return (Map<String, Object>) map; }
    private static String mask(String value) { if (value == null) return ""; return value.replaceAll("(?<!\\d)\\d{12}(?!\\d)", "************").replaceAll("(?i)([0-9a-f]{8})-[0-9a-f-]{27,}", "$1-************"); }
    private static Map<String, String> row(String... values) { Map<String, String> out = new LinkedHashMap<>(); for (int i = 0; i + 1 < values.length; i += 2) out.put(values[i], values[i + 1]); return out; }
}
