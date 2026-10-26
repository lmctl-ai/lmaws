package ai.lmctl.lmaws;

import java.io.IOException;
import java.math.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.Supplier;

/** A read-only materialized report. Unknown data is kept separate from observed zero. */
public final class SpendReport {
    private final Map<String,List<Map<String,String>>> sections=new LinkedHashMap<>();
    private final Map<String,Object> metadata=new LinkedHashMap<>();
    private final List<String> assumptions=new ArrayList<>();
    private final List<Map<String,String>> opportunities=new ArrayList<>();
    private final CostLedger ledger;
    private final LocalDate start,end;
    private final int top;
    private boolean serviceAvailable;
    private SpendReport(String topic,LocalDate end,int days,int top,CostLedger ledger){
        this.ledger=ledger;this.end=end;this.start=end.minusDays(days);this.top=top;
        metadata.put("topic",topic);metadata.put("start_inclusive",start.toString());metadata.put("end_exclusive",end.toString());metadata.put("days",days);metadata.put("top_n",top);metadata.put("query_cap_usd",ledger.cap());
        metadata.put("mode",ledger.live()?"live_read_only":"synthetic");metadata.put("account","************");metadata.put("status","complete");
        assumptions.addAll(List.of("UTC dates; the current incomplete UTC day is excluded. Cost Explorer data can lag and be estimated.",
            "Unblended cost totals include credits/refunds; amortized costs are exported separately. Historical spend is not the current inventory run-rate.",
            "Cost Explorer scope is the configured primary billing view, across regions. Inventory/metrics scope is stated in source diagnostics; it may be narrower.",
            "Reference estimates use 730 hours/month, exclude tax, free tiers, credits and discounts. Regional tariffs and workload history can change results.",
            "Current stopped EC2 compute run-rate is zero, but disks and public IPv4 remain billable. On-demand prices are reference Linux/Windows shared-tenancy prices, not Savings Plan rates.",
            "EBS snapshot logical volume size is an upper bound, not the incremental stored bytes billed by AWS. Review retention before any manual deletion.",
            "Network counters do not identify billable internet/inter-AZ/NAT paths. Only CE usage-type costs support those classifications.",
            "CloudWatch missing/partial metrics do not prove inactivity. Lambda GB-seconds use current memory configuration; DynamoDB size/count can be stale.",
            "Savings Plan/RI unused commitment is an optimization signal, not a cancellable charge or an immediately recoverable saving. Recommendations are AWS estimates."));
    }
    public static SpendReport collect(SpendSource source,String topic,LocalDate end,int days,int top,CostLedger ledger){
        if(days<1||days>366||top<1||top>100||!Set.of("all","ec2_spend","savings_plans","eip_audit","ebs_audit","bandwidth","lambda_spend","dynamodb_spend").contains(topic))throw new IllegalArgumentException("invalid spend report parameters");
        SpendReport r=new SpendReport(topic,end,days,top,ledger);
        r.metadata.put("source",source.diagnostics());
        // Get the account-wide headline first, before optional features consume the budget.
        r.serviceSpend(source,topic.equals("all"));
        if(topic.equals("all")||topic.equals("ec2_spend"))r.ec2(source);
        if(topic.equals("all")||topic.equals("savings_plans"))r.commitments(source);
        if(topic.equals("all")||topic.equals("eip_audit"))r.eips(source);
        if(topic.equals("all")||topic.equals("ebs_audit"))r.ebs(source);
        if(topic.equals("all")||topic.equals("bandwidth"))r.bandwidth(source);
        if(topic.equals("all")||topic.equals("lambda_spend"))r.safe("lambda_spend",()->SpendWorkloads.lambda(source,r.start,r.end));
        if(topic.equals("all")||topic.equals("dynamodb_spend")){
            var tables=r.safe("dynamodb_spend",()->SpendWorkloads.dynamodb(source,r.start,r.end));
            for(var table:tables)if(table.getOrDefault("billing_mode","").equals("PROVISIONED")&&known(table.get("provisioned_monthly_usd"))&&known(table.get("ondemand_equivalent_usd"))){
                BigDecimal difference=number(table.get("provisioned_monthly_usd")).subtract(number(table.get("ondemand_equivalent_usd")));
                if(difference.signum()>0)r.opportunity("dynamodb","review DynamoDB billing mode",difference,"reference cost at observed average only; verify peaks, autoscaling, tier and regional rates");
            }
        }
        r.opportunities.sort(Comparator.comparing((Map<String,String> x)->number(x.get("monthly_saving_usd"))).reversed());
        r.sections.put("opportunities",List.copyOf(r.opportunities.subList(0,Math.min(top,r.opportunities.size()))));
        r.sections.put("resources",r.section("opportunities"));
        // Keep large numeric counters readable without confusing a 12-digit quantity
        // with an account ID in the host's conservative string redactor.
        for(var entry:new ArrayList<>(r.sections.entrySet())){
            List<Map<String,String>> rows=new ArrayList<>();for(var original:entry.getValue()){
                Map<String,String> row=new LinkedHashMap<>();original.forEach((key,value)->{
                    String v=value==null?"unknown":value;
                    if(numericField(key)&&v.matches("-?[0-9]{12}"))v=new BigDecimal(v).movePointLeft(3).stripTrailingZeros().toPlainString()+"E3";
                    row.put(key,maskSpendValue(key,v));
                });rows.add(Collections.unmodifiableMap(row));
            }r.sections.put(entry.getKey(),List.copyOf(rows));
        }
        r.metadata.put("source",source.diagnostics());
        Object warnings=source.diagnostics().get("warnings");
        if(warnings instanceof List<?> list&&!list.isEmpty()){
            if(!r.metadata.get("status").equals("incomplete_cap"))r.metadata.put("status","partial");
            List<Map<String,String>> statusRows=new ArrayList<>();
            for(Object item:list)if(item instanceof Map<?,?> warning){Map<String,String> status=new LinkedHashMap<>();warning.forEach((key,value)->status.put(key.toString(),Jsons.mask(String.valueOf(value))));statusRows.add(status);}
            r.sections.put("section_scope",List.copyOf(statusRows));
        }
        return r;
    }
    private List<Map<String,String>> safe(String name,Supplier<List<Map<String,String>>> query){
        List<Map<String,String>> result;
        try {result=query.get();if(result.isEmpty())result=List.of(row("status","no_data"));}
        catch(CostLedger.BudgetExceeded e){metadata.put("status","incomplete_cap");result=List.of(row("status","budget_exhausted","reason","request refused before dispatch"));}
        catch(SpendSource.Unavailable e){if(!metadata.get("status").equals("incomplete_cap"))metadata.put("status","partial");result=List.of(row("status","unavailable","feature",e.feature,"reason",e.reason));}
        catch(RuntimeException e){if(!metadata.get("status").equals("incomplete_cap"))metadata.put("status","partial");result=List.of(row("status","error","reason",e.getClass().getSimpleName()));}
        sections.put(name,List.copyOf(result));return result;
    }
    private List<Map<String,String>> costs(SpendSource s,LocalDate a,LocalDate b,String gran,String dim,String service,boolean resources){
        if(!a.isBefore(b))return List.of();
        List<Map<String,String>> out=new ArrayList<>();
        for(var raw:s.costs(a,b,gran,dim,service,resources)){
            Map<String,String> x=new LinkedHashMap<>(raw);String key=first(raw,"key","group");
            x.put("date",first(raw,"date","start"));x.put("amount_usd",first(raw,"amount_usd","unblended_cost"));
            x.put("amortized_usd",first(raw,"amortized_usd","amortized_cost"));
            if(dim.equals("SERVICE"))x.put("service",firstNonempty(first(raw,"service"),key));
            if(dim.equals("INSTANCE_TYPE"))x.put("instance_type",firstNonempty(first(raw,"instance_type"),key));
            if(dim.equals("RESOURCE_ID"))x.put("resource_id",firstNonempty(first(raw,"resource_id"),key));
            if(dim.equals("SERVICE_USAGE_TYPE")){
                String[] split=key.split("/",2);x.put("service",firstNonempty(first(raw,"service"),split.length>0?split[0]:""));
                x.put("usage_type",firstNonempty(first(raw,"usage_type"),split.length>1?split[1]:key));
            }
            x.putIfAbsent("status","observed");out.add(x);
        }return out;
    }
    private void serviceSpend(SpendSource s,boolean all){
        List<Map<String,String>> daily=safe("ce_daily",()->costs(s,start,end,"DAILY","SERVICE","",false));
        serviceAvailable=!failed(daily)&&daily.stream().filter(r->!r.getOrDefault("status","").equals("no_data")).allMatch(r->known(r.get("amount_usd")));
        if(!serviceAvailable&&metadata.get("status").equals("complete"))metadata.put("status","partial");
        List<Map<String,String>> services=aggregate(daily,"service");services.sort(byAmount());
        sections.put("services",services.isEmpty()?daily:services);sections.put("service_spend",section("services"));
        sections.put("daily",daily); // full source rows, never truncate time series to top-N
        if(all){
            if(failed(daily)){sections.put("ce_monthly",daily);sections.put("ce_mtd_service",daily);}
            else {
                Map<String,java.math.BigDecimal> monthly=new TreeMap<>();
                for(var row:daily)if(known(row.get("amount_usd"))&&row.getOrDefault("date","").length()>=7)monthly.merge(row.get("date").substring(0,7)+"|"+row.getOrDefault("service","unknown"),number(row.get("amount_usd")),java.math.BigDecimal::add);
                List<Map<String,String>> months=new ArrayList<>();monthly.forEach((key,value)->{String[] parts=key.split(java.util.regex.Pattern.quote("|"),2);months.add(row("date",parts[0]+"-01","service",parts[1],"amount_usd",money(value)));});
                sections.put("ce_monthly",months.isEmpty()?List.of(row("status","no_data")):months);
                LocalDate monthStart=end.withDayOfMonth(1);
                if(!monthStart.isBefore(start)){
                    var mtd=daily.stream().filter(x->x.getOrDefault("date","").compareTo(monthStart.toString())>=0).toList();var totals=aggregate(mtd,"service");totals.sort(byAmount());sections.put("ce_mtd_service",totals.isEmpty()?List.of(row("status","no_data")):totals);
                }else safe("ce_mtd_service",()->aggregate(costs(s,monthStart,end,"DAILY","SERVICE","",false),"service"));
            }
            assumptions.add("Monthly and month-to-date totals reuse grouped daily rows when the requested days include month start, avoiding duplicate paid CE calls.");
        }
    }
    private void ec2(SpendSource s){
        safe("ec2_spend",()->costs(s,start,end,"MONTHLY","INSTANCE_TYPE","Amazon Elastic Compute Cloud - Compute",false));
        safe("ec2_resource_14d",()->costs(s,start.isAfter(end.minusDays(14))?start:end.minusDays(14),end,"DAILY","RESOURCE_ID","Amazon Elastic Compute Cloud - Compute",true));
        safe("ec2_resources",()->{
            List<Map<String,String>> out=new ArrayList<>();
            for(var raw:s.inventory("ec2")){
                Map<String,String>x=new LinkedHashMap<>(raw);String state=raw.getOrDefault("state","unknown");
                try{x.putAll(s.ec2Price(raw.getOrDefault("region",""),raw.getOrDefault("instance_type",""),raw.getOrDefault("platform","Linux/UNIX")));}
                catch(SpendSource.Unavailable e){x.put("hourly_usd","unknown");x.put("pricing_status",e.reason);}
                String price=x.getOrDefault("hourly_usd","unknown");
                x.put("ondemand_monthly_usd",known(price)?money(number(price).multiply(new BigDecimal("730"))):"unknown");
                x.put("current_compute_monthly_usd",state.equals("stopped")?"0":state.equals("running")?x.get("ondemand_monthly_usd"):"unknown");out.add(x);
            }return out;
        });
    }
    private void commitments(SpendSource s){
        safe("savings_plans",()->s.inventory("savings_plans"));
        safe("reserved_instances",()->s.inventory("reserved_instances"));
        for(String key:List.of("sp_utilization","sp_coverage","sp_recommendations","ri_utilization","ri_coverage","ri_recommendations")){
            var rows=safe(key,()->s.commitment(key,start,end));
            if(key.endsWith("utilization"))for(var x:rows){
                String unused=first(x,"unused_commitment_usd","unused_amortized_usd");
                if(known(unused)&&number(unused).signum()>0)opportunity(key,"review unused commitment",number(unused).multiply(new BigDecimal("30")).divide(new BigDecimal(metadata.get("days").toString()),8,RoundingMode.HALF_UP),"not cancellable; avoid extra commitment and review eligible workloads");
            }
        }
        sections.put("commitments",section("sp_coverage"));
    }
    private void eips(SpendSource s){
        var allocations=safe("eip_allocations",()->s.inventory("eips"));
        var interfaces=safe("public_ipv4_interfaces",()->s.inventory("public_ipv4"));
        safe("eip_audit",()->{
            List<Map<String,String>> out=new ArrayList<>();Set<String> ips=new HashSet<>(),allocationKeys=new HashSet<>();
            for(var raw:allocations){
                if(raw.containsKey("status")&&Set.of("unavailable","error","budget_exhausted","no_data").contains(raw.get("status")))continue;
                String allocationKey=raw.getOrDefault("region","")+"/"+raw.getOrDefault("allocation_id",raw.getOrDefault("public_ip","unknown"));
                if(!allocationKeys.add(allocationKey))continue;
                String publicIp=raw.getOrDefault("public_ip","");if(!publicIp.isBlank()&&ips.contains(publicIp))continue;
                Map<String,String>x=new LinkedHashMap<>(raw);boolean associated=!raw.getOrDefault("association_id","").isBlank()||!raw.getOrDefault("instance_id","").isBlank();
                x.put("status",associated?"associated":"idle");x.put("hourly_usd","0.005");x.put("monthly_usd","3.65");
                x.put("monthly_saving_usd",associated?"0":"3.65");out.add(x);ips.add(raw.getOrDefault("public_ip",""));
                if(!associated)opportunity("eip","idle allocated IPv4",new BigDecimal("3.65"),"review before releasing; no changes made");
            }
            for(var raw:interfaces){String ip=raw.getOrDefault("public_ip","");if(ip.isBlank()||ips.contains(ip))continue;Map<String,String> x=new LinkedHashMap<>(raw);x.put("status","associated_interface");x.put("hourly_usd","0.005");x.put("monthly_usd","3.65");x.put("monthly_saving_usd","0");out.add(x);ips.add(ip);}
            for(var raw:s.inventory("ec2")){
                String ip=raw.getOrDefault("public_ip","");if(ip.isBlank()||ips.contains(ip))continue;
                out.add(row("region",raw.getOrDefault("region",""),"instance_id",raw.getOrDefault("instance_id",""),"public_ip",ip,"status","auto_assigned_associated","hourly_usd","0.005","monthly_usd","3.65","monthly_saving_usd","0"));ips.add(ip);
            }return out;
        });
    }
    private void ebs(SpendSource s){
        safe("ebs_audit",()->{
            List<Map<String,String>> out=new ArrayList<>();
            for(var raw:s.inventory("ebs")){
                Map<String,String>x=new LinkedHashMap<>(raw);BigDecimal size=number(raw.get("size_gib"));String type=raw.getOrDefault("volume_type","");
                BigDecimal gp3=size.multiply(new BigDecimal("0.08")).add(number(raw.get("iops")).subtract(new BigDecimal("3000")).max(BigDecimal.ZERO).multiply(new BigDecimal("0.005"))).add(number(raw.get("throughput_mib_s")).subtract(new BigDecimal("125")).max(BigDecimal.ZERO).multiply(new BigDecimal("0.04")));
                BigDecimal cost=switch(type){case "io1"->size.multiply(new BigDecimal("0.125")).add(number(raw.get("iops")).multiply(new BigDecimal("0.065")));case "io2"->size.multiply(new BigDecimal("0.125")).add(number(raw.get("iops")).min(new BigDecimal("32000")).multiply(new BigDecimal("0.065"))).add(number(raw.get("iops")).subtract(new BigDecimal("32000")).max(BigDecimal.ZERO).min(new BigDecimal("32000")).multiply(new BigDecimal("0.046"))).add(number(raw.get("iops")).subtract(new BigDecimal("64000")).max(BigDecimal.ZERO).multiply(new BigDecimal("0.032")));case "gp2"->size.multiply(new BigDecimal("0.10"));case "gp3"->gp3;case "st1"->size.multiply(new BigDecimal("0.045"));case "sc1"->size.multiply(new BigDecimal("0.015"));case "standard"->size.multiply(new BigDecimal("0.05"));default->null;};
                if(!known(raw.get("size_gib"))||Set.of("gp3","io1","io2").contains(type)&&!known(raw.get("iops"))||type.equals("gp3")&&!known(raw.get("throughput_mib_s")))cost=null;
                boolean attached=!raw.getOrDefault("attached_instance_id","").isBlank()||raw.getOrDefault("state","").equals("in-use");x.put("attachment",attached?"attached":"unattached");
                x.put("monthly_estimate_usd",cost==null?"unknown":money(cost));x.put("gp3_equivalent_monthly_usd",known(raw.get("size_gib"))&&known(raw.get("iops"))&&known(raw.get("throughput_mib_s"))?money(gp3):"unknown");
                x.put("gp2_to_gp3_candidate",Boolean.toString(type.equals("gp2")));BigDecimal saving=cost==null?BigDecimal.ZERO:cost.subtract(gp3).max(BigDecimal.ZERO);
                x.put("storage_only_gp2_saving_usd",type.equals("gp2")&&known(raw.get("size_gib"))?money(size.multiply(new BigDecimal("0.02"))):"unknown");
                x.put("migration_saving_usd",type.equals("gp2")?(known(x.get("gp3_equivalent_monthly_usd"))?money(saving):"unknown"):"0");x.put("price_basis","illustrative us-east-1 storage/IOPS/throughput rates; excludes discounts and burst differences");out.add(x);
                if(!attached&&cost!=null)opportunity("ebs","unattached EBS volume",cost,"confirm retention/backup needs before deleting");
                else if(type.equals("gp2")&&known(x.get("gp3_equivalent_monthly_usd"))&&saving.signum()>0)opportunity("ebs","gp2 to gp3 candidate",saving,"preserve required IOPS and throughput; estimate only");
            }return out;
        });
        safe("snapshots",()->{
            List<Map<String,String>> out=new ArrayList<>();for(var raw:s.inventory("snapshots")){
                Map<String,String>x=new LinkedHashMap<>(raw);x.put("monthly_upper_bound_usd",known(raw.get("size_gib"))?money(number(raw.get("size_gib")).multiply(new BigDecimal("0.05"))):"unknown");
                x.put("basis","logical full volume size upper bound; incremental billed snapshot bytes unavailable");out.add(x);
            }return out;
        });
    }
    private void bandwidth(SpendSource s){
        var usage=safe("transfer_usage",()->costs(s,start,end,"MONTHLY","SERVICE_USAGE_TYPE","",false));
        List<Map<String,String>> selected=new ArrayList<>();
        for(var raw:usage){String type=raw.getOrDefault("usage_type","").toLowerCase(Locale.ROOT);String category=type.contains("natgateway")?"NAT":type.contains("regional")||type.contains("interzone")||type.contains("interaz")?"inter-AZ":type.contains("interregion")||type.contains("aws-out")||type.contains("aws-in")?"inter-region":type.contains("datatransfer-out")?"internet-out":type.contains("datatransfer")?"other-transfer":null;
            if(category!=null){Map<String,String>x=new LinkedHashMap<>(raw);x.put("category",category);selected.add(x);}}
        sections.put("transfers",selected.isEmpty()?(failed(usage)?usage:List.of(row("status","no_data"))):selected);sections.put("bandwidth",section("transfers"));
        safe("network",()->{
            List<SpendSource.Metric> queries=new ArrayList<>();int index=0;
            for(var instance:s.inventory("ec2"))for(String metric:List.of("NetworkIn","NetworkOut"))queries.add(new SpendSource.Metric("m"+index++,instance.getOrDefault("region","us-east-1"),"AWS/EC2",metric,"InstanceId",instance.getOrDefault("instance_id",""),"Sum",3600));
            return s.metrics(queries,start.atStartOfDay(ZoneOffset.UTC).toInstant(),end.atStartOfDay(ZoneOffset.UTC).toInstant());
        });
    }
    private void opportunity(String section,String action,BigDecimal amount,String note){opportunities.add(row("section",section,"action",action,"monthly_saving_usd",money(amount),"assumption",note));}
    private static boolean failed(List<Map<String,String>> rows){return rows.stream().anyMatch(x->Set.of("unavailable","error","budget_exhausted").contains(x.getOrDefault("status","")));}
    private static List<Map<String,String>> aggregate(List<Map<String,String>> rows,String key){
        Map<String,BigDecimal> totals=new TreeMap<>();for(var r:rows)if(known(r.get("amount_usd")))totals.merge(r.getOrDefault(key,"unknown"),number(r.get("amount_usd")),BigDecimal::add);
        List<Map<String,String>> out=new ArrayList<>();totals.forEach((k,v)->out.add(row(key,k,"amount_usd",money(v))));return out;
    }
    static Comparator<Map<String,String>> byAmount(){return Comparator.comparing((Map<String,String> x)->number(x.get("amount_usd"))).reversed();}
    static boolean known(String x){try{return x!=null&&!x.isBlank()&&new BigDecimal(x).abs().compareTo(new BigDecimal("1e30"))<0;}catch(NumberFormatException e){return false;}}
    static BigDecimal number(String x){return known(x)?new BigDecimal(x):BigDecimal.ZERO;}
    static String money(BigDecimal x){return x.setScale(8,RoundingMode.HALF_UP).stripTrailingZeros().toPlainString();}
    static String first(Map<String,String> x,String...keys){for(String k:keys)if(x.get(k)!=null&&!x.get(k).isBlank())return x.get(k);return "";}
    static String firstNonempty(String x,String y){return x==null||x.isBlank()?y:x;}
    static Map<String,String> row(String...pairs){Map<String,String> m=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)m.put(pairs[i],Jsons.mask(pairs[i+1]));return m;}
    public List<Map<String,String>> section(String name){return sections.getOrDefault(name,List.of());}
    public Map<String,Object> summary(){
        Map<String,Object>x=new LinkedHashMap<>();x.put("status",metadata.get("status"));x.put("mode",ledger.live()?"live_read_only":"synthetic");x.put("account","************");
        x.put("total_spend_usd",serviceAvailable?money(section("services").stream().map(r->number(r.get("amount_usd"))).reduce(BigDecimal.ZERO,BigDecimal::add)):"unavailable");
        x.put("top5_services",section("services").stream().filter(r->known(r.get("amount_usd"))).limit(5).toList());
        x.put("opportunities",section("opportunities"));x.put("idle_resource_monthly_estimate_usd",money(opportunities.stream().filter(r->r.get("action").startsWith("idle allocated")||r.get("action").startsWith("unattached EBS")).map(r->number(r.get("monthly_saving_usd"))).reduce(BigDecimal.ZERO,BigDecimal::add)));x.put("estimated_cost_usd",ledger.total());x.put("ce_requests",ledger.ceRequests());x.put("metric_requests",ledger.metricRequests());x.put("metric_units",ledger.metricUnits());return x;
    }
    public BigDecimal estimatedCost(){return ledger.total();}
    private static final java.util.regex.Pattern ACCOUNT_IN_TEXT=java.util.regex.Pattern.compile("(?<![0-9])[0-9]{12}(?![0-9])");
    // Spend inventories need no STS identity lookup: conservatively mask account-like
    // identifiers in names while preserving fields explicitly known to be numeric.
    private static String maskSpendValue(String field,String value){
        String masked=Jsons.mask(field,value);
        return numericField(field)?masked:ACCOUNT_IN_TEXT.matcher(masked).replaceAll("************");
    }
    private static boolean numericField(String key){return key.endsWith("_usd")||key.endsWith("_percent")||key.endsWith("_hourly")||key.endsWith("_hours")||key.equals("fixed_price")||key.startsWith("consumed_")||key.startsWith("provisioned_")||Set.of("total","datapoints","usage_quantity","size_gib","size_bytes","item_count","memory_mb","read_capacity","write_capacity","iops","throughput_mib_s","duration_ms","invocations","errors","gb_seconds").contains(key);}
    private static Object canonical(Object value){if(value instanceof Map<?,?> map){Map<String,Object> out=new TreeMap<>();map.forEach((key,item)->out.put(key.toString(),canonical(item)));return out;}if(value instanceof List<?> list)return list.stream().map(SpendReport::canonical).toList();return value;}
    public String json(){Map<String,Object> cost=new LinkedHashMap<>(ledger.report(0));cost.remove("run_id");return Jsons.encode(canonical(Map.of("metadata",metadata,"assumptions",assumptions,"sections",sections,"summary",summary(),"request_ledger",cost)))+"\n";}
    public void write(Path directory){
        if(ledger.live())SpendOutputs.createPrivate(directory);
        try{Files.createDirectories(directory);Files.writeString(directory.resolve("report.json"),json());
            for(var e:sections.entrySet()){Files.writeString(directory.resolve(e.getKey()+".json"),Jsons.encode(e.getValue())+"\n");StringBuilder csv=new StringBuilder();LinkedHashSet<String> fields=new LinkedHashSet<>();e.getValue().forEach(r->fields.addAll(r.keySet()));csv.append(String.join(",",fields)).append('\n');
                for(var row:e.getValue()){List<String> cells=new ArrayList<>();for(String field:fields){String value=maskSpendValue(field,row.getOrDefault(field,""));if(!value.isEmpty()&&"=+-@\t\r".indexOf(value.charAt(0))>=0)value="'"+value;cells.add("\""+value.replace("\"","\"\"")+"\"");}csv.append(String.join(",",cells)).append('\n');}
                Files.writeString(directory.resolve(e.getKey()+".csv"),csv);}
            SpendCharts.write(this,directory,metadata.get("topic").toString(),top);
        }catch(IOException e){throw new IllegalStateException("cannot write spend report");}
    }
}
