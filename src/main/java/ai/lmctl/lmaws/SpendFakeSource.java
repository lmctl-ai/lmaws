package ai.lmctl.lmaws;

import java.time.*;
import java.util.*;

/** Synthetic fixtures only: no credentials, HTTP client or SDK response objects. */
public final class SpendFakeSource implements SpendSource {
    private final String scenario;
    private final CostLedger ledger;
    private final Map<String,List<Map<String,String>>> cache=new LinkedHashMap<>();
    private int cacheHits;private boolean closed;
    public SpendFakeSource(){this("normal",null);}
    public SpendFakeSource(String scenario){this(scenario,null);}
    public SpendFakeSource(CostLedger ledger){this("normal",ledger);}
    public SpendFakeSource(String scenario,CostLedger ledger){this.scenario=scenario;this.ledger=ledger;}
    private void ready(){if(closed)throw new IllegalStateException("source closed");}
    private void bill(String service,String operation){ready();if(ledger!=null)ledger.request(service,operation);}
    private void available(String feature){if(scenario.equals("denied"))throw new Unavailable(feature,"AccessDeniedException");}
    private boolean empty(){return scenario.equals("empty");}
    private List<Map<String,String>> cached(String key){ready();if(cache.containsKey(key)){cacheHits++;return cache.get(key);}return null;}
    private List<Map<String,String>> save(String key,List<Map<String,String>> rows){cache.put(key,List.copyOf(rows));return rows;}
    private static Map<String,String> row(String...pairs){Map<String,String>x=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)x.put(pairs[i],pairs[i+1]);return x;}
    @Override public List<Map<String,String>> costs(LocalDate start,LocalDate end,String gran,String dimension,String service,boolean resources){
        String key="cost:"+start+":"+end+":"+gran+":"+dimension+":"+service+":"+resources;var hit=cached(key);if(hit!=null)return hit;
        bill("costexplorer",resources?"GetCostAndUsageWithResources":"GetCostAndUsage");available("costs");
        if(resources&&scenario.equals("not_enabled"))throw new Unavailable("resource_level","DataUnavailableException: opt-in resource data not enabled");
        if(scenario.equals("pagination"))bill("costexplorer",resources?"GetCostAndUsageWithResources":"GetCostAndUsage");
        if(empty())return save(key,List.of());
        List<Map<String,String>> rows=new ArrayList<>();
        if(dimension.equals("SERVICE")){
            List<String> services=List.of("Amazon Elastic Compute Cloud - Compute","EC2 - Other","Amazon Simple Storage Service","AWS Lambda","Amazon DynamoDB","Savings Plans for AWS Compute usage","AmazonCloudWatch");
            List<String> daily=List.of("2.31","0.72","0.31","0.27","0.18","0.25","0.08");
            if(gran.equals("DAILY")){for(LocalDate date=start;date.isBefore(end);date=date.plusDays(1))for(int i=0;i<services.size();i++)rows.add(row("date",date.toString(),"start",date.toString(),"end",date.plusDays(1).toString(),"service",services.get(i),"key",services.get(i),"amount_usd",daily.get(i),"amortized_usd",daily.get(i),"status","observed"));}
            else{for(LocalDate date=start;date.isBefore(end);){LocalDate next=date.withDayOfMonth(1).plusMonths(1);if(next.isAfter(end))next=end;long days=java.time.temporal.ChronoUnit.DAYS.between(date,next);for(int i=0;i<services.size();i++)rows.add(row("date",date.toString(),"service",services.get(i),"key",services.get(i),"amount_usd",new java.math.BigDecimal(daily.get(i)).multiply(java.math.BigDecimal.valueOf(days)).toPlainString(),"status","observed"));date=next;}}
        }else if(dimension.equals("INSTANCE_TYPE"))rows.add(row("date",start.toString(),"instance_type","t3.micro","key","t3.micro","amount_usd","69.30","status","observed"));
        else if(dimension.equals("RESOURCE_ID"))rows.add(row("date",start.toString(),"resource_id","i-demo-active","key","i-demo-active","amount_usd","32.34","status","observed"));
        else if(dimension.equals("SERVICE_USAGE_TYPE")){for(String[] values:new String[][]{{"USE1-DataTransfer-Out-Bytes","4.50","50","GB"},{"USE1-DataTransfer-Regional-Bytes","1.20","120","GB"},{"USE1-AWS-Out-Bytes","0.80","40","GB"},{"USE1-NatGateway-Bytes","2.25","50","GB"}})rows.add(row("date",start.toString(),"service","EC2 - Other","usage_type",values[0],"key","EC2 - Other/"+values[0],"amount_usd",values[1],"usage_quantity",values[2],"unit",values[3],"status","observed"));}
        return save(key,rows);
    }
    @Override public List<Map<String,String>> inventory(String kind){
        String key="inventory:"+kind;var hit=cached(key);if(hit!=null)return hit;bill("ec2","Describe"+kind);available(kind);if(empty())return save(key,List.of());
        List<Map<String,String>> rows=switch(kind){
            case "ec2"->List.of(row("region","us-east-1","instance_id","i-demo-active","instance_type","t3.micro","state","running","platform","Linux/UNIX","public_ip","198.51.100.8"),row("region","us-east-1","instance_id","i-demo-idle","instance_type","t3.small","state","stopped","platform","Linux/UNIX","public_ip",""));
            case "eips"->List.of(row("region","us-east-1","allocation_id","eipalloc-demo-idle","public_ip","198.51.100.7","association_id","","instance_id",""),row("region","us-east-1","allocation_id","eipalloc-demo-used","public_ip","198.51.100.8","association_id","eipassoc-demo","instance_id","i-demo-active"));
            case "ebs"->List.of(row("region","us-east-1","volume_id","vol-demo-idle","volume_type","gp2","size_gib","40","iops","120","throughput_mib_s","0","state","available","attached_instance_id",""),row("region","us-east-1","volume_id","vol-demo-active","volume_type","gp2","size_gib","100","iops","300","throughput_mib_s","0","state","in-use","attached_instance_id","i-demo-active"));
            case "snapshots"->List.of(row("region","us-east-1","snapshot_id","snap-demo","size_gib","100","owner_id","123456789012","start_time","2026-10-01T00:00:00Z","state","completed"));
            case "lambda"->List.of(row("region","us-east-1","function_name","demo-active","resource_id","arn:aws:lambda:us-east-1:123456789012:function:demo-active","memory_mb","512","architecture","x86_64"),row("region","us-east-1","function_name","demo-idle","resource_id","arn:aws:lambda:us-east-1:123456789012:function:demo-idle","memory_mb","128","architecture","arm64"));
            case "dynamodb"->List.of(row("region","us-east-1","table_name","demo-active","table_id","arn:aws:dynamodb:us-east-1:123456789012:table/demo-active","billing_mode","PROVISIONED","size_bytes","10737418240","item_count","1000000","read_capacity","100","write_capacity","50"),row("region","us-east-1","table_name","demo-idle","table_id","arn:aws:dynamodb:us-east-1:123456789012:table/demo-idle","billing_mode","PAY_PER_REQUEST","size_bytes","0","item_count","0","read_capacity","0","write_capacity","0"));
            case "savings_plans"->scenario.equals("savings_absent")?List.of():List.of(row("region","us-east-1","plan_id","sp-demo","state","active","plan_type","Compute","commitment_hourly","1.00","start","2026-01-01","end","2027-01-01"));
            case "reserved_instances"->scenario.equals("savings_absent")?List.of():List.of(row("region","us-east-1","reserved_id","ri-demo","state","active","instance_type","t3.micro","instance_count","2","fixed_price","0","recurring_hourly","0.01"));
            default->throw new Unavailable(kind,"unsupported inventory");};return save(key,rows);
    }
    @Override public List<Map<String,String>> commitment(String kind,LocalDate start,LocalDate end){
        String key=kind+start+end;var hit=cached(key);if(hit!=null)return hit;bill("costexplorer",kind);available(kind);
        if(empty()||scenario.equals("savings_absent"))return save(key,List.of());
        if(scenario.equals("not_enabled"))throw new Unavailable(kind,"DataUnavailableException");
        List<Map<String,String>> result=switch(kind){
            case "sp_utilization"->List.of(row("total_commitment_usd","720","used_commitment_usd","690","unused_commitment_usd","30","utilization_percent","95.833333"));
            case "sp_coverage"->List.of(row("covered_spend_usd","100","ondemand_spend_usd","20","coverage_percent","83.333333"));
            case "ri_utilization"->List.of(row("purchased_hours","1440","used_hours","1152","unused_hours","288","unused_amortized_usd","20","utilization_percent","80"));
            case "ri_coverage"->List.of(row("coverage_percent","62.5","covered_hours","900","ondemand_hours","540"));
            default->List.of(row("recommendation","synthetic recommendation; review before purchase","estimated_monthly_savings_usd","7.50","status","observed"));};return save(key,result);
    }
    @Override public List<Map<String,String>> metrics(List<Metric> queries,Instant start,Instant end){
        ready();if(queries.isEmpty())return List.of();
        if(ledger!=null)for(int n=0;n<queries.size();n+=100)ledger.metricRequest("GetMetricData",Math.min(100,queries.size()-n));available("metrics");
        if(empty())return List.of();List<Map<String,String>> out=new ArrayList<>();
        for(Metric q:queries){boolean idle=q.resource().contains("idle");String total=idle?"0":switch(q.name()){
            case "Invocations"->"120000";case "Duration"->"240000000";case "Errors"->"240";case "NetworkIn"->"107374182400";case "NetworkOut"->"26843545600";case "ConsumedReadCapacityUnits"->"129600000";case "ConsumedWriteCapacityUnits"->"12960000";case "ProvisionedReadCapacityUnits"->"100";case "ProvisionedWriteCapacityUnits"->"50";default->"0";};
            out.add(row("metric_id",q.id(),"resource_id",q.resource(),"region",q.region(),"metric",q.name(),"statistic",q.statistic(),"total",total,"datapoints","30","status",scenario.equals("metrics_missing")?"no_data":"Complete"));
        }return out;
    }
    @Override public Map<String,String> ec2Price(String region,String type,String platform){bill("pricing","GetProducts");available("ec2_price");return row("hourly_usd",type.equals("t3.small")?"0.0208":"0.0104","pricing_status","observed","pricing_basis","synthetic shared Linux on-demand rate");}
    @Override public Map<String,Object> diagnostics(){return Map.of("synthetic",true,"scenario",scenario,"inventory_regions",List.of("us-east-1"),"cache_hits",cacheHits);}
    @Override public void close(){closed=true;}
}
