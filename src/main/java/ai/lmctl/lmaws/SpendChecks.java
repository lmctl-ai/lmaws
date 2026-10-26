package ai.lmctl.lmaws;

import java.math.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Offline arithmetic, cap, unknown-state and privacy controls; never authenticates. */
public final class SpendChecks {
    private static int checks;
    private SpendChecks(){}
    private static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError("spend: "+message);}
    private static void eq(String actual,String expected,String message){check(SpendReport.known(actual)&&new BigDecimal(actual).subtract(new BigDecimal(expected)).abs().compareTo(new BigDecimal("0.000001"))<0,message+" actual="+actual);}
    private static CostLedger ledger(Path dir,String name,String cap)throws Exception{return new CostLedger(name,name,"us-east-1",dir.resolve(name+".jsonl"),new BigDecimal(cap),false);}
    public static void run() throws Exception {
        checks=0;Path dir=Files.createTempDirectory("lmaws-spend-check-").toRealPath();LocalDate end=LocalDate.of(2026,10,26);
        CostLedger ledger=ledger(dir,"all","0.25");
        SpendReport all;try(var source=new SpendFakeSource(ledger)){all=SpendReport.collect(source,"all",end,30,10,ledger);}
        eq(all.summary().get("total_spend_usd").toString(),"123.60","account-wide total sums all daily services");
        check(all.section("services").size()==7,"all seven synthetic services retained");check(all.section("ce_daily").size()==210,"30 complete daily groups, no top-N truncation");
        check(all.section("ce_monthly").size()==14,"two monthly partial buckets");
        check(all.section("ce_mtd_service").size()==7,"MTD excludes current UTC day");
        check(all.section("ec2_resource_14d").getFirst().get("date").equals("2026-10-12"),"resource lookback clamped to14");
        check(all.section("ec2_resources").size()==2,"running and stopped instances");
        eq(all.section("ec2_resources").getFirst().get("ondemand_monthly_usd"),"7.592","hourly to 730-hour monthly");
        eq(all.section("ec2_resources").get(1).get("current_compute_monthly_usd"),"0","stopped compute zero while price reference remains");
        eq(all.section("eip_audit").getFirst().get("monthly_usd"),"3.65","idle public IPv4 charged");eq(all.section("eip_audit").get(1).get("monthly_usd"),"3.65","associated public IPv4 also charged");
        check(all.section("eip_audit").size()==3,"deduplicated EIP/instance IP plus managed interface IPv4");
        eq(all.section("ebs_audit").getFirst().get("monthly_estimate_usd"),"4","40GiB gp2 storage reference");
        eq(all.section("ebs_audit").get(1).get("migration_saving_usd"),"2","100GiB attached gp2 to gp3 saving");
        eq(all.section("snapshots").getFirst().get("monthly_upper_bound_usd"),"5","snapshot estimate explicitly upper bound");
        check(all.section("transfers").size()==4,"internet,regional,inter-region,NAT breakdown");check(all.section("network").size()==4,"NetworkIn/out for each instance");
        eq(all.section("lambda_spend").getFirst().get("gb_seconds"),"120000","Lambda milliseconds and current memory conversion");
        eq(all.section("lambda_spend").getFirst().get("average_duration_ms"),"2000","Lambda average duration");
        check(all.section("lambda_spend").get(1).get("unused_candidate").equals("true"),"unused Lambda only from observed zeros");
        eq(all.section("dynamodb_spend").getFirst().get("provisioned_monthly_usd"),"33.215","RCU/WCU hourly prices not off by1000");
        eq(all.section("dynamodb_spend").getFirst().get("ondemand_equivalent_usd"),"24.6375","normalize30 days to730 hours");
        eq(all.section("dynamodb_spend").getFirst().get("storage_reference_monthly_usd"),"2.5","DynamoDB10GiB storage reference");
        check(all.section("savings_plans").size()==1&&all.section("reserved_instances").size()==1,"plan inventories");
        check(all.section("opportunities").size()>=4,"ranked concrete opportunities");
        check(SpendReport.number(all.section("opportunities").getFirst().get("monthly_saving_usd")).compareTo(SpendReport.number(all.section("opportunities").getLast().get("monthly_saving_usd")))>=0,"opportunity descending order");
        eq(ledger.total().toPlainString(),"0.10018","actual CE and18 requested metrics charged");check(ledger.ceRequests()==10&&ledger.metricUnits()==18,"CE calls and metric units exact");
        Path output=dir.resolve("exports");all.write(output);String json=Files.readString(output.resolve("report.json"));
        check(!json.contains("123456789012")&&!json.contains("AKIA"),"account IDs masked in complete JSON including ARNs");
        for(var path:Files.list(output).toList())check(!Files.readString(path).contains("123456789012"),"masked export "+path.getFileName());
        eq(all.section("network").getFirst().get("total"),"107374182400","12-digit metric quantity preserved in scientific notation, account still masked");
        CostLedger repeat=new CostLedger("repeat","all","us-east-1",dir.resolve("repeat.jsonl"),new BigDecimal("0.25"),false);
        var same=SpendReport.collect(new SpendFakeSource(repeat),"all",end,30,10,repeat);
        check(all.json().equals(same.json()),"synthetic JSON byte deterministic across run IDs");
        CostLedger emptyLedger=ledger(dir,"empty","0.25");var empty=SpendReport.collect(new SpendFakeSource("empty",emptyLedger),"all",end,30,5,emptyLedger);
        eq(empty.summary().get("total_spend_usd").toString(),"0","successful empty CE response has no cost rows");check(empty.section("lambda_spend").getFirst().get("status").equals("no_data"),"empty functions explicit");
        CostLedger deniedLedger=ledger(dir,"denied","0.25");var denied=SpendReport.collect(new SpendFakeSource("denied",deniedLedger),"all",end,30,5,deniedLedger);
        check(denied.summary().get("total_spend_usd").equals("unavailable"),"AccessDenied never becomes zero spend");
        CostLedger disabledLedger=ledger(dir,"disabled","0.25");var disabled=SpendReport.collect(new SpendFakeSource("not_enabled",disabledLedger),"all",end,30,5,disabledLedger);
        check(disabled.section("ec2_resource_14d").getFirst().get("status").equals("unavailable"),"resource-level opt-in disabled is explicit");
        CostLedger absentLedger=ledger(dir,"absent","0.25");var absent=SpendReport.collect(new SpendFakeSource("savings_absent",absentLedger),"savings_plans",end,30,5,absentLedger);
        check(absent.section("savings_plans").getFirst().get("status").equals("no_data"),"absent Savings Plans explicit");
        CostLedger unknownLedger=ledger(dir,"unknown","0.25");var unknown=SpendReport.collect(new SpendFakeSource("metrics_missing",unknownLedger),"lambda_spend",end,30,5,unknownLedger);
        check(unknown.section("lambda_spend").getFirst().get("unused_candidate").equals("unknown"),"missing metrics do not prove unused");
        CostLedger capped=ledger(dir,"cap","0.05");var cap=SpendReport.collect(new SpendFakeSource(capped),"all",end,30,5,capped);
        check(cap.summary().get("status").equals("incomplete_cap")&&capped.total().compareTo(new BigDecimal("0.05"))<=0,"cap blocks next billed request");
        CostLedger duplicateLedger=ledger(dir,"duplicates","0.25");var duplicate=SpendReport.collect(new SpendFakeSource("duplicates",duplicateLedger),"all",end,30,10,duplicateLedger);
        check(duplicate.section("eip_audit").size()==3,"duplicate allocations cannot inflate IPv4 charges");
        CostLedger sizesLedger=ledger(dir,"sizes","0.25");var sizes=SpendReport.collect(new SpendFakeSource("unknown_sizes",sizesLedger),"ebs_audit",end,30,10,sizesLedger);
        check(sizes.section("snapshots").getFirst().get("monthly_upper_bound_usd").equals("unknown"),"unknown snapshot size is not zero");
        check(sizes.section("ebs_audit").getFirst().get("monthly_estimate_usd").equals("unknown"),"unknown EBS size is not free storage");
        CostLedger twentyFive=ledger(dir,"twentyfive","0.25");for(int i=0;i<25;i++)twentyFive.request("costexplorer","GetCostAndUsage");
        boolean refused=false;try{twentyFive.request("costexplorer","GetCostAndUsage");}catch(CostLedger.BudgetExceeded expected){refused=true;}
        check(refused&&twentyFive.ceRequests()==25,"26th CE call refused before dispatch");check(!twentyFive.displayCost().equals("$0.00"),"read-only billable request cost displayed");
        CostLedger batch=ledger(dir,"batch","0.25");batch.metricRequest("GetMetricData",100);eq(batch.total().toPlainString(),"0.001","100 requested metrics charged even in one HTTP call");
        CostLedger cached=ledger(dir,"cached","0.25");var source=new SpendFakeSource(cached);source.costs(end.minusDays(1),end,"DAILY","SERVICE","",false);source.costs(end.minusDays(1),end,"DAILY","SERVICE","",false);check(cached.ceRequests()==1,"cached grouped CE query not charged twice");
        boolean outside=false;try{SpendOutputs.requirePrivate(dir);}catch(IllegalArgumentException expected){outside=true;}check(outside,"live output cannot use public path");
        System.out.println("PASS "+checks+" spend arithmetic, cap, cache, empty/denied/disabled, export and mask checks");
    }
}
