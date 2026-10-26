package ai.lmctl.lmaws;

import java.math.*;
import java.time.*;
import java.util.*;

/** Batched metric joins: no metric expression or price changes the AWS account. */
final class SpendWorkloads {
    private static final BigDecimal MONTH_SECONDS=new BigDecimal("2628000");
    private SpendWorkloads(){}
    static List<Map<String,String>> lambda(SpendSource source,LocalDate start,LocalDate end){
        var inventory=source.inventory("lambda");List<SpendSource.Metric> queries=new ArrayList<>();
        for(int n=0;n<inventory.size();n++){var fn=inventory.get(n);String name=first(fn,"function_name","name","resource_id"),region=fn.getOrDefault("region","us-east-1");
            for(String metric:List.of("Invocations","Duration","Errors"))queries.add(new SpendSource.Metric("l"+n+"_"+metric.toLowerCase(Locale.ROOT),region,"AWS/Lambda",metric,"FunctionName",name,"Sum",3600));}
        var values=metrics(source,queries,start,end);List<Map<String,String>> out=new ArrayList<>();BigDecimal factor=MONTH_SECONDS.divide(seconds(start,end),12,RoundingMode.HALF_UP);
        for(int n=0;n<inventory.size();n++){
            var fn=inventory.get(n);Map<String,String> row=new LinkedHashMap<>();copy(row,fn,"function_name","region","memory_mb","architecture");
            BigDecimal inv=values.get("l"+n+"_invocations"),dur=values.get("l"+n+"_duration"),err=values.get("l"+n+"_errors");
            BigDecimal mb=known(fn.get("memory_mb"))?number(fn.get("memory_mb")):null;
            boolean complete=inv!=null&&dur!=null&&err!=null;
            row.put("metric_status",complete?"complete":"unknown");put(row,"invocations",inv);put(row,"duration_ms",dur);put(row,"errors",err);
            put(row,"average_duration_ms",inv!=null&&dur!=null&&inv.signum()>0?dur.divide(inv,8,RoundingMode.HALF_UP):null);
            BigDecimal gb=dur!=null&&mb!=null?dur.multiply(mb).divide(new BigDecimal("1024000"),12,RoundingMode.HALF_UP):null;put(row,"gb_seconds",gb);
            BigDecimal rate=new BigDecimal(fn.getOrDefault("architecture","").contains("arm")?"0.0000133334":"0.0000166667");
            BigDecimal period=gb!=null&&inv!=null?gb.multiply(rate).add(inv.multiply(new BigDecimal("0.0000002"))):null;
            put(row,"period_estimate_usd",period);put(row,"monthly_estimate_usd",period==null?null:period.multiply(factor));
            row.put("unused_candidate",complete?Boolean.toString(inv.signum()==0&&dur.signum()==0&&err.signum()==0):"unknown");
            row.put("assumption","current configured memory; reference us-east-1 request/GB-second rates; excludes free tier, discounts, ephemeral storage and historical configuration changes");out.add(row);
        }
        out.sort(Comparator.comparing((Map<String,String>x)->number(x.get("period_estimate_usd"))).reversed());return out;
    }
    static List<Map<String,String>> dynamodb(SpendSource source,LocalDate start,LocalDate end){
        var inventory=source.inventory("dynamodb");List<SpendSource.Metric> queries=new ArrayList<>();
        for(int n=0;n<inventory.size();n++){var table=inventory.get(n);String name=first(table,"table_name","name"),region=table.getOrDefault("region","us-east-1");
            for(String metric:List.of("ConsumedReadCapacityUnits","ConsumedWriteCapacityUnits","ProvisionedReadCapacityUnits","ProvisionedWriteCapacityUnits"))queries.add(new SpendSource.Metric("d"+n+"_"+metric.toLowerCase(Locale.ROOT),region,"AWS/DynamoDB",metric,"TableName",name,metric.startsWith("Consumed")?"Sum":"Average",3600));}
        var values=metrics(source,queries,start,end);List<Map<String,String>> out=new ArrayList<>();BigDecimal periodSeconds=seconds(start,end),factor=MONTH_SECONDS.divide(periodSeconds,12,RoundingMode.HALF_UP);
        for(int n=0;n<inventory.size();n++){
            var table=inventory.get(n);Map<String,String> row=new LinkedHashMap<>();copy(row,table,"table_name","region","billing_mode","size_bytes","item_count","read_capacity","write_capacity");
            BigDecimal cr=values.get("d"+n+"_consumedreadcapacityunits"),cw=values.get("d"+n+"_consumedwritecapacityunits"),pr=values.get("d"+n+"_provisionedreadcapacityunits"),pw=values.get("d"+n+"_provisionedwritecapacityunits");
            put(row,"consumed_read_units",cr);put(row,"consumed_write_units",cw);
            BigDecimal rr=cr==null?null:cr.divide(periodSeconds,12,RoundingMode.HALF_UP),wr=cw==null?null:cw.divide(periodSeconds,12,RoundingMode.HALF_UP);
            put(row,"average_read_units_per_second",rr);put(row,"average_write_units_per_second",wr);
            if(pr==null&&table.getOrDefault("billing_mode","").equals("PROVISIONED")&&known(table.get("read_capacity")))pr=number(table.get("read_capacity"));
            if(pw==null&&table.getOrDefault("billing_mode","").equals("PROVISIONED")&&known(table.get("write_capacity")))pw=number(table.get("write_capacity"));
            put(row,"provisioned_read_capacity",pr);put(row,"provisioned_write_capacity",pw);
            BigDecimal readCost=pr==null?null:pr.multiply(new BigDecimal("0.00013")).multiply(new BigDecimal("730"));
            BigDecimal writeCost=pw==null?null:pw.multiply(new BigDecimal("0.00065")).multiply(new BigDecimal("730"));
            BigDecimal provisioned=readCost==null||writeCost==null?null:readCost.add(writeCost);
            BigDecimal demand=cr==null||cw==null?null:cr.multiply(new BigDecimal("0.000000125")).add(cw.multiply(new BigDecimal("0.000000625"))).multiply(factor);
            put(row,"provisioned_monthly_usd",provisioned);put(row,"ondemand_equivalent_usd",demand);
            put(row,"read_utilization_percent",rr==null||pr==null||pr.signum()==0?null:rr.multiply(new BigDecimal("100")).divide(pr,8,RoundingMode.HALF_UP));
            put(row,"write_utilization_percent",wr==null||pw==null||pw.signum()==0?null:wr.multiply(new BigDecimal("100")).divide(pw,8,RoundingMode.HALF_UP));
            put(row,"breakeven_read_units_per_second",readCost==null?null:readCost.divide(new BigDecimal("0.000000125").multiply(MONTH_SECONDS),12,RoundingMode.HALF_UP));
            put(row,"breakeven_write_units_per_second",writeCost==null?null:writeCost.divide(new BigDecimal("0.000000625").multiply(MONTH_SECONDS),12,RoundingMode.HALF_UP));
            BigDecimal storage=known(table.get("size_bytes"))?number(table.get("size_bytes")).divide(new BigDecimal("1073741824"),12,RoundingMode.HALF_UP).multiply(new BigDecimal("0.25")):null;
            put(row,"storage_reference_monthly_usd",storage);
            row.put("metric_status",cr!=null&&cw!=null?"complete":"unknown");row.put("unused_candidate",cr==null||cw==null?"unknown":Boolean.toString(cr.signum()==0&&cw.signum()==0));
            row.put("breakeven_hint",demand==null||provisioned==null?"unknown; review workload and peak requirements":demand.compareTo(provisioned)<0?"on-demand reference cheaper at observed average; validate peaks before changing":"provisioned reference cheaper at observed average; validate peaks and autoscaling");
            row.put("assumption","us-east-1 illustrative $0.125/million reads, $0.625/million writes, $0.00013/RCU-hour, $0.00065/WCU-hour; no free tier or discounts; current size/count can be stale");out.add(row);
        }return out;
    }
    private static Map<String,BigDecimal> metrics(SpendSource source,List<SpendSource.Metric> queries,LocalDate start,LocalDate end){
        List<Map<String,String>> rows=source.metrics(queries,start.atStartOfDay(ZoneOffset.UTC).toInstant(),end.atStartOfDay(ZoneOffset.UTC).toInstant());
        Map<String,BigDecimal> totals=new HashMap<>(),weights=new HashMap<>();Set<String> unknown=new HashSet<>();
        Map<String,String> statistics=new HashMap<>();queries.forEach(q->statistics.put(q.id(),q.statistic()));
        for(var r:rows){String id=r.getOrDefault("metric_id","");String status=r.getOrDefault("status","");
            if(!(status.equalsIgnoreCase("Complete")||status.equalsIgnoreCase("observed"))||!known(r.get("total"))||number(r.get("datapoints")).signum()<=0){unknown.add(id);continue;}
            BigDecimal weight=number(r.get("datapoints"));
            totals.merge(id,number(r.get("total")).multiply(statistics.getOrDefault(id,"Sum").equals("Average")?weight:BigDecimal.ONE),BigDecimal::add);weights.merge(id,weight,BigDecimal::add);
        }
        totals.replaceAll((id,value)->statistics.getOrDefault(id,"Sum").equals("Average")?value.divide(weights.get(id),12,RoundingMode.HALF_UP):value);
        unknown.forEach(totals::remove);return totals;
    }
    private static BigDecimal seconds(LocalDate start,LocalDate end){return BigDecimal.valueOf(Duration.between(start.atStartOfDay(ZoneOffset.UTC),end.atStartOfDay(ZoneOffset.UTC)).getSeconds());}
    private static boolean known(String x){return SpendReport.known(x);}
    private static BigDecimal number(String x){return SpendReport.number(x);}
    private static String first(Map<String,String> x,String...keys){return SpendReport.first(x,keys);}
    private static void put(Map<String,String>x,String key,BigDecimal value){x.put(key,value==null?"unknown":SpendReport.money(value));}
    private static void copy(Map<String,String> x,Map<String,String> from,String...keys){for(String key:keys)x.put(key,Jsons.mask(from.getOrDefault(key,"")));}
}
