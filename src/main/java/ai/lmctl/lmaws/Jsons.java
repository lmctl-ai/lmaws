package ai.lmctl.lmaws;

import io.lmctl.lmcode.Reports;
import java.util.*;
import java.util.regex.Pattern;

/** Serialization never falls back to SDK object toString(), which may contain payloads. */
public final class Jsons {
    private Jsons() {}
    private static final Pattern ACCOUNT = Pattern.compile("(?<![0-9])[0-9]{12}(?![0-9])");
    private static final Pattern ACCESS = Pattern.compile("(?:AKIA|ASIA)[A-Z0-9]{16}");
    public static String mask(String text) {
        if (text == null) return "";
        return ACCESS.matcher(ACCOUNT.matcher(text).replaceAll("************")).replaceAll("[redacted-key]");
    }
    public static String encode(Object value) {return encode(value,true);}
    static String encodeRaw(Object value) {return encode(value,false);}
    private static String encode(Object value,boolean redact) {
        if (value == null) return "null";
        if (value instanceof String s) return Reports.escape(redact?mask(s):s);
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?,?> m) {
            List<String> fields=new ArrayList<>();
            m.forEach((k,v)->fields.add(Reports.escape(k.toString())+":"+encode(v,redact)));
            return "{"+String.join(",",fields)+"}";
        }
        if (value instanceof Collection<?> c) return "["+String.join(",",c.stream().map(v->encode(v,redact)).toList())+"]";
        throw new IllegalArgumentException("unsupported JSON type");
    }
}
