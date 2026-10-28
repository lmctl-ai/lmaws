package ai.lmctl.lmaws;

import java.time.Instant;
import java.util.*;

/** Offline regression checks for provisioning price accounting and caps. */
final class ProvisionCostChecks {
    private static void ok(boolean v,String m){if(!v)throw new IllegalStateException("ProvisionCostChecks: "+m);}
    private static Map<String,Object> cfg(){return new HashMap<>(Map.of("volume_gib",10,"cap_usd","0.25","max_runtime_seconds",3600,"public_ipv4",true));}
    static void run(){
        Map<String,Object> c=cfg(); ok(ProvisionCosts.quote(c,1).compareTo(ProvisionCosts.quote(c,60))==0,"minimum minute");
        Map<String,Object> s=new HashMap<>(Map.of("state","running","started_epoch",0L,"last_settled_epoch",0L,"volume_gib",10,"public_ipv4",true,"estimated_cost_usd","0"));
        ProvisionCosts.settle(s,"running",Instant.ofEpochSecond(3600)); String first=String.valueOf(s.get("estimated_cost_usd")); ok(new java.math.BigDecimal(first).compareTo(java.math.BigDecimal.ZERO)>0,"running accrues");
        ProvisionCosts.settle(s,"stopped",Instant.ofEpochSecond(7200)); String stopped=String.valueOf(s.get("estimated_cost_usd")); ProvisionCosts.settle(s,"stopped",Instant.ofEpochSecond(10800)); ok(new java.math.BigDecimal(String.valueOf(s.get("estimated_cost_usd"))).compareTo(new java.math.BigDecimal(stopped))>0,"stopped disk accrues");
        ProvisionCosts.settle(s,"running",Instant.ofEpochSecond(14400)); ok(new java.math.BigDecimal(String.valueOf(s.get("estimated_cost_usd"))).compareTo(new java.math.BigDecimal(stopped))>0,"resume accrues");
        Map<String,Object> summary=ProvisionCosts.summary(s,c,Instant.ofEpochSecond(14400)); ok(summary.containsKey("reminder_estimate_usd")&&summary.containsKey("price_table"),"reminder summary");
        Map<String,Object> capped=new HashMap<>(Map.of("state","requested","estimated_cost_usd","0.249","started_epoch",0L,"last_settled_epoch",0L,"volume_gib",20)); boolean refused=false; try{ProvisionCosts.admit(capped,Map.of("volume_gib",20,"cap_usd","0.25","max_runtime_seconds",3600),Instant.ofEpochSecond(0));}catch(IllegalStateException e){refused=true;} ok(refused,"cap refusal");
        ProvisionCosts.settle(s,"terminated",Instant.ofEpochSecond(20000)); String done=String.valueOf(s.get("estimated_cost_usd")); ProvisionCosts.settle(s,"terminated",Instant.ofEpochSecond(30000)); ok(done.equals(String.valueOf(s.get("estimated_cost_usd"))),"terminated no further charge");
        System.out.println("PASS provisioning cost quote, running/stopped/resumed settlement, reminders and cap");
    }
    public static void main(String[] args){run();}
}
