package ai.lmctl.lmaws;

import io.lmctl.lmcode.Reports;
import java.util.*;
import java.util.regex.Pattern;

/** Serialization never falls back to SDK object toString(), which may contain payloads. */
public final class Jsons {
    private Jsons() {}
    static final String MASK = "************";
    /** The account field of an ARN: arn:partition:service:region:ACCOUNT:resource. */
    private static final Pattern ARN_ACCOUNT = Pattern.compile("(arn:aws[a-z-]*:[A-Za-z0-9-]*:[a-z0-9-]*:)[0-9]{12}(?=[:/]|$)");
    /** A value that says it is an account ("account 1234...", "AccountId": "1234..."). */
    private static final Pattern LABELLED = Pattern.compile("(?i)(\\b(?:account|owner)(?:[ _-]?id)?[\"']?\\s*[:=]?\\s*[\"']?)[0-9]{12}(?![0-9])");
    private static final Pattern ACCESS = Pattern.compile("(?:AKIA|ASIA)[A-Z0-9]{16}");
    /** Map fields whose values are account ids. */
    private static final Set<String> ACCOUNT_KEYS = Set.of("account", "account_id", "accountid", "owner", "owner_id", "ownerid");
    private static final Set<String> KNOWN = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** The current identity's account id is masked wherever it appears, not only in ARNs. */
    static void knownAccount(String id) { if (id != null && id.matches("[0-9]{12}")) KNOWN.add(id); }

    /**
     * Masks account ids in ARNs, labelled account/owner values and the known identity account;
     * access-key ids are redacted. Plain numbers (balances, byte counts, other 12-digit values)
     * are left unchanged.
     */
    public static String mask(String text) {
        if (text == null) return "";
        String out = ARN_ACCOUNT.matcher(text).replaceAll("$1" + MASK);
        out = LABELLED.matcher(out).replaceAll("$1" + MASK);
        for (String id : KNOWN) out = out.replaceAll("(?<![0-9])" + id + "(?![0-9])", MASK);
        return ACCESS.matcher(out).replaceAll("[redacted-key]");
    }
    /** Masks one field value: account-id fields by name, everything else with mask(text). */
    public static String mask(String field, String value) { return maskField(field, value == null ? "" : value); }
    private static String maskField(Object key, String value) {
        String k = key.toString().toLowerCase(Locale.ROOT);
        if (ACCOUNT_KEYS.contains(k) && value.matches("[0-9]{12}")) return MASK;
        return mask(value);
    }
    public static String encode(Object value) {return encode(value,true);}
    static String encodeRaw(Object value) {return encode(value,false);}
    private static String encode(Object value,boolean redact) {
        if (value == null) return "null";
        if (value instanceof String s) return Reports.escape(redact?mask(s):s);
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?,?> m) {
            List<String> fields=new ArrayList<>();
            m.forEach((k,v)->fields.add(Reports.escape(k.toString())+":"+(redact && v instanceof String text ? Reports.escape(maskField(k,text)) : encode(v,redact))));
            return "{"+String.join(",",fields)+"}";
        }
        if (value instanceof Collection<?> c) return "["+String.join(",",c.stream().map(v->encode(v,redact)).toList())+"]";
        throw new IllegalArgumentException("unsupported JSON type");
    }
}
