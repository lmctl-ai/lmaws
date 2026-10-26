package ai.lmctl.lmaws;

import java.nio.file.*;
import java.io.IOException;
import java.math.*;
import java.util.*;

/** Stable chart inputs from report evidence, not hard-coded picture numbers. */
final class SpendCharts {
    private SpendCharts(){}
    static void write(SpendReport report,Path dir,String topic,int top)throws IOException{
        List<Map<String,String>> services=report.section("services").stream().filter(x->SpendReport.known(x.get("amount_usd"))).toList();
        List<String> topServices=services.stream().limit(Math.min(top,8)).map(x->x.get("service")).toList();
        boolean hasOther=services.size()>topServices.size();List<String> names=new ArrayList<>(topServices);if(hasOther)names.add("Other");
        Map<String,Map<String,BigDecimal>> daily=new TreeMap<>();
        for(var row:report.section("daily"))if(SpendReport.known(row.get("amount_usd"))){String service=row.getOrDefault("service","unknown"),date=row.getOrDefault("date","");if(date.length()<10)continue;
            String key=topServices.contains(service)?service:"Other";daily.computeIfAbsent(date,k->new TreeMap<>()).merge(key,SpendReport.number(row.get("amount_usd")),BigDecimal::add);}
        List<List<String>> series=new ArrayList<>();List<String> header=new ArrayList<>();header.add("date");names.forEach(n->header.add(label(n)));if(names.isEmpty()){header.add("No data");names.add("No data");}series.add(header);
        for(var entry:daily.entrySet()){List<String> row=new ArrayList<>();row.add(entry.getKey().substring(5));for(String name:names)row.add(SpendReport.money(entry.getValue().getOrDefault(name,BigDecimal.ZERO)));series.add(row);}
        if(series.size()==1)series.add(List.of("Unavailable","0"));csv(dir.resolve("daily_chart.csv"),series);
        List<List<String>> bars=new ArrayList<>();bars.add(List.of("label","value"));for(var row:services.stream().limit(top).toList())bars.add(List.of(label(row.get("service")),row.get("amount_usd")));placeholder(bars);csv(dir.resolve("services_chart.csv"),bars);
        List<List<String>> idle=new ArrayList<>();idle.add(List.of("resource","status","monthly_usd"));
        for(var row:report.section("eip_audit"))if(row.getOrDefault("status","").equals("idle"))idle.add(List.of(row.getOrDefault("allocation_id","IPv4 allocation"),"idle IPv4",row.getOrDefault("monthly_usd","unknown")));
        for(var row:report.section("ebs_audit"))if(row.getOrDefault("attachment","").equals("unattached"))idle.add(List.of(row.getOrDefault("volume_id","EBS volume"),"unattached EBS",row.getOrDefault("monthly_estimate_usd","unknown")));
        if(idle.size()==1)idle.add(List.of("No confirmed idle resources","review report status","unknown"));
        // IDs/status/numbers in this table have no commas; bare cells let the host std split lines safely.
        StringBuilder bare=new StringBuilder();for(var row:idle.stream().limit(11).toList())bare.append(String.join(",",row.stream().map(x->Jsons.mask(x).replace(","," ").replace("\n"," ").replace("\r"," ")).toList())).append('\n');Files.writeString(dir.resolve("idle_chart.csv"),bare);
        BigDecimal covered=BigDecimal.ZERO,uncovered=BigDecimal.ZERO;boolean coverageKnown=false;
        for(var row:report.section("sp_coverage"))if(SpendReport.known(row.get("covered_spend_usd"))&&SpendReport.known(row.get("ondemand_spend_usd"))){coverageKnown=true;covered=covered.add(SpendReport.number(row.get("covered_spend_usd")));uncovered=uncovered.add(SpendReport.number(row.get("ondemand_spend_usd")));}
        BigDecimal total=covered.add(uncovered);String coverage=coverageKnown&&total.signum()>0?SpendReport.money(covered.multiply(new BigDecimal("100")).divide(total,6,RoundingMode.HALF_UP)):"0";
        csv(dir.resolve("gauge_chart.csv"),List.of(List.of("label","value","status"),List.of("SP coverage",coverage,coverageKnown&&total.signum()>0?"observed":"unknown")));
        Map<String,BigDecimal> paths=new TreeMap<>();for(var row:report.section("transfers"))if(SpendReport.known(row.get("amount_usd")))paths.merge(row.getOrDefault("category","other"),SpendReport.number(row.get("amount_usd")),BigDecimal::add);
        List<List<String>> transfer=new ArrayList<>();transfer.add(List.of("label","value"));paths.forEach((key,value)->transfer.add(List.of(key,SpendReport.money(value))));placeholder(transfer);csv(dir.resolve("transfer_chart.csv"),transfer);
        List<List<String>> topicBars=new ArrayList<>();topicBars.add(List.of("label","value"));
        if(topic.equals("all"))topicBars.addAll(bars.subList(1,bars.size()));
        else if(topic.equals("savings_plans"))topicBars.add(List.of("Savings Plan coverage (%)",coverage));
        else if(topic.equals("bandwidth"))topicBars.addAll(transfer.subList(1,transfer.size()));
        else {
            String section=switch(topic){case "ec2_spend"->"ec2_spend";case "eip_audit"->"eip_audit";case "ebs_audit"->"ebs_audit";case "lambda_spend"->"lambda_spend";case "dynamodb_spend"->"dynamodb_spend";default->"opportunities";};
            for(var row:report.section(section)){
                String value=SpendReport.first(row,"amount_usd","monthly_estimate_usd","monthly_usd","provisioned_monthly_usd");if(!SpendReport.known(value))continue;
                String name=SpendReport.first(row,"instance_type","function_name","table_name","volume_id","allocation_id","status");topicBars.add(List.of(name,value));if(topicBars.size()>top)break;
            }
        }
        placeholder(topicBars);csv(dir.resolve("topic_chart.csv"),topicBars);
    }
    private static void placeholder(List<List<String>> rows){if(rows.size()==1)rows.add(List.of("No complete data — see report","0"));}
    private static String label(String name){return name.replace("Amazon Elastic Compute Cloud - Compute","EC2 compute").replace("Amazon Simple Storage Service","S3").replace("Amazon DynamoDB","DynamoDB").replace("Savings Plans for AWS Compute usage","Savings Plans").replace("AWS Lambda","Lambda").replace("AmazonCloudWatch","CloudWatch");}
    private static void csv(Path path,List<List<String>> rows)throws IOException{StringBuilder text=new StringBuilder();for(var row:rows)text.append(String.join(",",row.stream().map(x->"\""+Jsons.mask(x).replace("\"","\"\"")+"\"").toList())).append('\n');Files.writeString(path,text);}
}
