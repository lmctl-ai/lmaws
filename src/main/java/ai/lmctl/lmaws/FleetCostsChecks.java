package ai.lmctl.lmaws;
import java.math.*;
import java.nio.file.*;
import java.util.*;

/** Arithmetic, attribution and unknown-data regressions without credentials. */
public final class FleetCostsChecks {
    private static final String SPEC="{\"region\":\"us-east-1\",\"project\":\"synthetic\",\"targets\":[{\"name\":\"node1\",\"role\":\"current\"},{\"name\":\"node2\",\"role\":\"standby\"}],\"savings_plan_id\":\"11111111-1111-1111-1111-111111111111\"}";
    private static int count;
    private static void check(boolean yes,String what){count++;if(!yes)throw new AssertionError(what);}
    private static Map<String,Object> report(FleetCostsDemo source)throws Exception{
        Path dir=Files.createTempDirectory("fleet-cost-check-");
        try{
            CostLedger ledger=new CostLedger("fleet-test","fleet-costs","us-east-1",dir.resolve("ledger.jsonl"),new BigDecimal("0.10"),false);
            return (Map<String,Object>)io.lmctl.lmcode.Json.parse(FleetCosts.collect(source,SPEC,"2026-10-01","2026-10-30",ledger,true));
        }finally{try(var files=Files.walk(dir)){for(var p:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
    private static List<Map<String,Object>> hosts(Map<String,Object> report){return (List<Map<String,Object>>)report.get("hosts");}
    private static Map<String,String> totals(Map<String,Object> report){return (Map<String,String>)report.get("totals");}
    public static void main(String[] args)throws Exception{
        var report=report(new FleetCostsDemo(SPEC));var h=hosts(report);var totals=totals(report);
        check(h.size()==2,"two exact tag-selected hosts");
        check(h.getFirst().get("disk_monthly_usd").equals("16"),"200 GiB gp3 baseline costs 16");
        check(((Map<?,?>)h.getFirst().get("public_ips")).size()==1,"same EIP in instance/ENI/address inventories is counted once");
        check(h.getFirst().get("public_ipv4_monthly_usd").equals("3.65"),"one public IP costs 3.65");
        check(h.get(1).get("public_ipv4_monthly_usd").equals("3.65"),"auto-assigned public IPv4 also costs 3.65");
        check(totals.get("ondemand_base_monthly_usd").equals("235.524"),"on-demand compute+disk+IPv4 arithmetic");
        check(totals.get("savings_plan_commitment_monthly_usd").equals("114.902"),"fixed commitment amortized once");
        check(totals.get("with_plan_base_monthly_usd").equals("154.202"),"plan+disk+IP excludes upfront, account 99 USD and EC2 billed 2 USD");
        check(totals.get("additional_recurring_base_if_plan_prepaid_usd").equals("39.3"),"already-paid upfront plan is not billed again each month");
        check(h.getFirst().get("cpu_surplus_charged_usd").equals("0.4"),"600 charged credits is 10 vCPU-hours at 0.04");
        check(totals.get("cpu_surplus_charged_period_usd").equals("1.2"),"period CPU kept separate from monthly base");
        check(h.getFirst().get("ec2_resource_amortized_usd").equals("1"),"resource billing preserved but never added twice");
        check(report.get("resource_billing_start").equals("2026-10-16"),"resource lookback clamps to last 14 days");
        var source=new FleetCostsDemo(SPEC);source.resourceDisabled=true;
        var disabled=report(source);
        check(hosts(disabled).getFirst().get("ec2_resource_amortized_usd").equals("unknown"),"disabled CE is not zero");
        check(totals(disabled).get("with_plan_base_monthly_usd").equals("154.202"),"missing history does not erase current inventory estimates");
        source=new FleetCostsDemo(SPEC);source.missingMetrics=true;
        check(totals(report(source)).get("cpu_surplus_charged_period_usd").equals("unknown"),"missing metrics unknown");
        source=new FleetCostsDemo(SPEC);source.partialMetrics=true;
        check(totals(report(source)).get("cpu_surplus_charged_period_usd").equals("unknown"),"partial metrics unknown");
        source=new FleetCostsDemo(SPEC);source.missingRates=true;
        check(totals(report(source)).get("with_plan_base_monthly_usd").equals("unknown"),"missing plan rates are not assumed covered");
        source=new FleetCostsDemo(SPEC);source.planInactive=true;
        check(totals(report(source)).get("with_plan_base_monthly_usd").equals("unknown"),"inactive plan cannot discount compute");
        source=new FleetCostsDemo(SPEC);source.missingPrice=true;
        check(totals(report(source)).get("ondemand_base_monthly_usd").equals("unknown"),"missing catalog price unknown");
        source=new FleetCostsDemo(SPEC);source.instanceType="t3.xlarge";
        check(totals(report(source)).get("cpu_surplus_charged_period_usd").equals("unknown"),"do not guess Linux T4g surplus rate for T3");
        check(report.get("mode").equals("synthetic"),"synthetic data marked");
        source=new FleetCostsDemo(SPEC);source.commitment="0.3";
        var unused=totals(report(source));
        check(unused.get("with_plan_base_monthly_usd").equals("258.3"),"unused fixed commitment remains a cost");
        check(unused.get("unused_commitment_monthly_reference_usd").equals("104.098"),"unused commitment shown separately");
        source=new FleetCostsDemo(SPEC);source.commitment="0.1";
        check(totals(report(source)).get("with_plan_base_monthly_usd").equals("unknown"),"insufficient commitment is not assumed fully covering hosts");
        System.out.println("PASS "+count+" fleet cost arithmetic, attribution, deduplication, SP double-count and missing-data checks; no AWS");
    }
}
