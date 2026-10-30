package ai.lmctl.lmaws;
import java.time.*;
import java.util.*;

/** Credentials-free fixture for fleet cost examples and regression tests. */
final class FleetCostsDemo implements SpendSource {
    final Map<String,Object> spec;
    boolean resourceDisabled,missingMetrics,partialMetrics,missingPrice,missingRates,planInactive;
    String instanceType="t4g.xlarge";
    String commitment="0.1574";
    FleetCostsDemo(String json){spec=(Map<String,Object>)io.lmctl.lmcode.Json.parse(json);}
    private List<Map<String,String>> instances(){
        List<Map<String,String>> rows=new ArrayList<>();int n=0;
        for(Object target:(List<?>)spec.get("targets")){
            var t=(Map<?,?>)target;n++;
            rows.add(row("region","us-east-1","instance_id","i-synthetic-"+n,"instance_type",instanceType,"state","running","platform","Linux/UNIX","public_ip","198.51.100."+n,"tag_project",String.valueOf(spec.get("project")),"tag_role",String.valueOf(t.get("role")),"name",String.valueOf(t.get("name")),"launch_time","2026-10-01T00:00:00Z"));
        }return rows;
    }
    public List<Map<String,String>> inventory(String kind){
        List<Map<String,String>> out=new ArrayList<>();
        if(kind.equals("ec2"))return instances();
        if(kind.equals("savings_plans"))return List.of(row("plan_id",String.valueOf(spec.get("savings_plan_id")),"state",planInactive?"retired":"active","plan_type","EC2Instance","region","us-east-1","ec2_instance_family","t4g","payment_option","All Upfront","commitment_hourly",commitment,"upfront_payment_usd","1378.824","recurring_payment_usd","0","currency","USD","start","2026-10-22T23:20:25Z","end","2027-10-22T23:20:24Z"));
        int n=0;for(var i:instances()){n++;
            switch(kind){
                case "ebs"->out.add(row("region","us-east-1","attached_instance_id",i.get("instance_id"),"volume_id","vol-synthetic-"+n,"volume_type","gp3","size_gib","200","iops","3000","throughput_mib_s","125","state","in-use"));
                case "public_ipv4"->out.add(row("region","us-east-1","instance_id",i.get("instance_id"),"public_ip",i.get("public_ip")));
                case "eips"->{if(n==1)out.add(row("region","us-east-1","instance_id",i.get("instance_id"),"public_ip",i.get("public_ip"),"allocation_id","eipalloc-synthetic","association_id","eipassoc-synthetic"));}
                default->throw new Unavailable(kind,"UNSUPPORTED_DEMO_INVENTORY");
            }
        }return out;
    }
    public List<Map<String,String>> costs(LocalDate a,LocalDate b,String gran,String dimension,String service,boolean resources){
        if(resources&&resourceDisabled)throw new Unavailable("resource_level","RESOURCE_LEVEL_NOT_ENABLED");
        if(!resources)return List.of(row("service","Amazon Elastic Compute Cloud - Compute","usage_type","USE1-BoxUsage:t4g.xlarge","amount_usd","99","amortized_usd","80","status","observed"));
        List<Map<String,String>> rows=new ArrayList<>();for(var i:instances())rows.add(row("key",i.get("instance_id"),"date",a.toString(),"amount_usd","1.5","amortized_usd","1","estimated","true","status","observed"));return rows;
    }
    public List<Map<String,String>> metrics(List<Metric> q,Instant start,Instant end){
        if(missingMetrics)return List.of();
        List<Map<String,String>> rows=new ArrayList<>();int n=0;
        for(var x:q){n++;rows.add(row("resource_id",x.resource(),"metric",x.name(),"total",String.valueOf(n*600),"datapoints","24","status",partialMetrics?"PartialData":"Complete"));}
        return rows;
    }
    public Map<String,String> ec2Price(String region,String type,String platform){return row("hourly_usd",missingPrice?"unknown":"0.1344","pricing_status","synthetic");}
    public List<Map<String,String>> savingsPlanRates(String id){return missingRates?List.of():List.of(row("instance_type","t4g.xlarge","region","us-east-1","operating_system","Linux","tenancy","shared","unit","Hrs","product_type","EC2","rate","0.0787"));}
    public List<Map<String,String>> commitment(String kind,LocalDate a,LocalDate b){return List.of();}
    public Map<String,Object> diagnostics(){return Map.of("endpoint","synthetic","read_only",true);}
    public void close(){}
    static Map<String,String> row(String...pairs){Map<String,String> r=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)r.put(pairs[i],pairs[i+1]);return r;}
}
