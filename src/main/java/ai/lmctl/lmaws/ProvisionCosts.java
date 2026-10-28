package ai.lmctl.lmaws;

import java.math.*;
import java.time.Instant;
import java.util.*;

/** Pure cost accounting for on-demand provisioning; it never contacts AWS. */
final class ProvisionCosts {
    static final BigDecimal INSTANCE_HOURLY = new BigDecimal("0.0042");
    static final BigDecimal GP3_GIB_MONTH = new BigDecimal("0.08");
    static final BigDecimal IPV4_HOURLY = new BigDecimal("0.005");
    static final long MONTH_SECONDS = 30L * 24 * 3600;
    static final BigDecimal HARD_CAP = new BigDecimal("0.25");

    private ProvisionCosts() {}
    private static long longValue(Map<String,Object> m,String k,long d) {
        Object v=m.get(k); if(v instanceof Number n) return n.longValue();
        try{return v==null?d:Long.parseLong(String.valueOf(v));}catch(Exception e){return d;}
    }
    private static BigDecimal decimal(Map<String,Object> m,String k,BigDecimal d) {
        Object v=m.get(k); try{return v==null?d:new BigDecimal(String.valueOf(v));}catch(Exception e){return d;}
    }
    private static BigDecimal money(BigDecimal x) { return x.max(BigDecimal.ZERO).setScale(8,RoundingMode.UP); }
    private static boolean active(String state) { return Set.of("running","pending","started","stopping","shutting-down").contains(state); }
    private static boolean disk(String state) { return !Set.of("requested","absent","failed","terminated").contains(state); }

    static BigDecimal quote(Map<String,Object> cfg,int seconds) {
        int s=Math.max(60,seconds); long gib=longValue(cfg,"volume_gib",10); boolean ip=Boolean.TRUE.equals(cfg.get("public_ipv4"));
        BigDecimal result=INSTANCE_HOURLY.multiply(BigDecimal.valueOf(s)).divide(BigDecimal.valueOf(3600),12,RoundingMode.UP)
            .add(GP3_GIB_MONTH.multiply(BigDecimal.valueOf(gib)).multiply(BigDecimal.valueOf(s)).divide(BigDecimal.valueOf(MONTH_SECONDS),12,RoundingMode.UP));
        if(ip) result=result.add(IPV4_HOURLY.multiply(BigDecimal.valueOf(s)).divide(BigDecimal.valueOf(3600),12,RoundingMode.UP));
        return money(result);
    }

    static void admit(Map<String,Object> state,Map<String,Object> cfg,Instant now) {
        Map<String,Object> snapshot=new HashMap<>(state); settle(snapshot,String.valueOf(state.getOrDefault("state","requested")),now);
        BigDecimal cap=decimal(cfg,"cap_usd",new BigDecimal("0.25")).min(HARD_CAP);
        long max=Math.max(60,Math.min(3600,longValue(cfg,"max_runtime_seconds",3600)));
        BigDecimal projected=decimal(snapshot,"estimated_cost_usd",BigDecimal.ZERO).add(quote(cfg,(int)max));
        if(projected.compareTo(cap)>0) throw new IllegalStateException("provision cost cap would be exceeded");
        state.put("cap_usd",cap.toPlainString());
    }

    static BigDecimal settle(Map<String,Object> state,String newState,Instant now) {
        long current=now.getEpochSecond(); long previous=longValue(state,"last_settled_epoch",longValue(state,"started_epoch",current));
        long elapsed=Math.max(0,current-previous); String old=String.valueOf(state.getOrDefault("state",newState));
        long gib=longValue(state,"volume_gib",10); boolean ip=Boolean.parseBoolean(String.valueOf(state.getOrDefault("public_ipv4",false)));
        long segment=longValue(state,"active_segment_seconds",0);
        if(active(old)) segment+=elapsed;
        long minimumExtra=active(old)&&!active(newState)?Math.max(0,60-segment):0;
        long billedActive=elapsed+minimumExtra;
        BigDecimal add=BigDecimal.ZERO;
        if(active(old)) add=add.add(INSTANCE_HOURLY.multiply(BigDecimal.valueOf(billedActive)).divide(BigDecimal.valueOf(3600),12,RoundingMode.UP));
        if(disk(old)) add=add.add(GP3_GIB_MONTH.multiply(BigDecimal.valueOf(gib)).multiply(BigDecimal.valueOf(elapsed)).divide(BigDecimal.valueOf(MONTH_SECONDS),12,RoundingMode.UP));
        if(active(old)&&ip) add=add.add(IPV4_HOURLY.multiply(BigDecimal.valueOf(billedActive)).divide(BigDecimal.valueOf(3600),12,RoundingMode.UP));
        BigDecimal total=money(decimal(state,"estimated_cost_usd",BigDecimal.ZERO).add(add));
        state.put("active_segment_seconds",active(newState)?(active(old)?segment:0):0);
        state.put("estimated_cost_usd",total.toPlainString()); state.put("last_settled_epoch",current); state.put("state",newState); state.put("last_settled_at",now.toString());
        return total;
    }

    static Map<String,Object> summary(Map<String,Object> state,Map<String,Object> cfg,Instant now) {
        Map<String,Object> copy=new LinkedHashMap<>(state); BigDecimal total=settle(copy,String.valueOf(state.getOrDefault("state","requested")),now);
        BigDecimal cap=decimal(cfg,"cap_usd",new BigDecimal("0.25")).min(HARD_CAP); long max=Math.max(60,Math.min(3600,longValue(cfg,"max_runtime_seconds",3600)));
        String current=String.valueOf(copy.getOrDefault("state",""));
        BigDecimal reminder=active(current)?quote(cfg,(int)max):("stopped".equals(current)?money(GP3_GIB_MONTH.multiply(BigDecimal.valueOf(longValue(cfg,"volume_gib",10))).multiply(BigDecimal.valueOf(max)).divide(BigDecimal.valueOf(MONTH_SECONDS),12,RoundingMode.UP)):BigDecimal.ZERO);
        return new LinkedHashMap<>(Map.of("estimated_cost_usd",total.toPlainString(),"remaining_cap_usd",money(cap.subtract(total)).toPlainString(),"reminder_estimate_usd",reminder.toPlainString(),"cap_usd",cap.toPlainString(),"cap_exceeded",total.compareTo(cap)>0,"state",String.valueOf(copy.getOrDefault("state","")),"price_table",Map.of("instance_hour_usd",INSTANCE_HOURLY.toPlainString(),"gp3_gib_month_usd",GP3_GIB_MONTH.toPlainString(),"public_ipv4_hour_usd",IPV4_HOURLY.toPlainString())));
    }
}
