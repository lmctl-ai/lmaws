package ai.lmctl.lmaws;

import java.math.*;
import java.time.*;
import java.util.*;
import java.util.function.Supplier;

/** Read-only fleet attribution, with estimates and billing evidence kept separate. */
final class FleetCosts {
    private static final BigDecimal HOURS=new BigDecimal("730");
    private final SpendSource source;
    private final List<Map<String,String>> warnings=new ArrayList<>();
    private FleetCosts(SpendSource source){this.source=source;}
    static String collect(SpendSource source,String specification,String from,String to,CostLedger ledger,boolean demo){
        return Jsons.encode(new FleetCosts(source).report(specification,from,to,ledger,demo));
    }
    private Map<String,Object> report(String specification,String from,String to,CostLedger ledger,boolean demo){
        Object parsed=io.lmctl.lmcode.Json.parse(specification);
        if(!(parsed instanceof Map<?,?> spec)||!spec.keySet().equals(Set.of("region","project","targets","savings_plan_id")))throw new IllegalArgumentException("fleet spec needs exactly region, project, targets, savings_plan_id");
        String region=String.valueOf(spec.get("region")),project=String.valueOf(spec.get("project")),planId=String.valueOf(spec.get("savings_plan_id"));
        if(!region.equals("us-east-1"))throw new IllegalArgumentException("reference tariffs currently support us-east-1 only");
        if(project.isBlank()||!(spec.get("targets") instanceof List<?> targets)||targets.isEmpty()||targets.size()>10)throw new IllegalArgumentException("select 1..10 explicit project/role targets");
        if(!planId.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw new IllegalArgumentException("select one literal Savings Plan UUID");
        Set<String> names=new HashSet<>(),roles=new HashSet<>();
        for(Object item:targets){
            if(!(item instanceof Map<?,?> target)||!target.keySet().equals(Set.of("name","role")))throw new IllegalArgumentException("each target needs name and role");
            String name=String.valueOf(target.get("name")),role=String.valueOf(target.get("role"));
            if(name.isBlank()||role.isBlank()||!names.add(name)||!roles.add(role))throw new IllegalArgumentException("target names and roles must be unique and nonempty");
        }
        LocalDate today=demo?LocalDate.of(2026,10,30):LocalDate.now(ZoneOffset.UTC);
        LocalDate end=to.isBlank()?today:LocalDate.parse(to),start=from.isBlank()?end.withDayOfMonth(1):LocalDate.parse(from);
        if(end.isAfter(today)||start.isAfter(end)||start.isBefore(end.minusDays(366)))throw new IllegalArgumentException("UTC dates must cover 0..366 completed days, end exclusive");
        Map<String,Object> report=new LinkedHashMap<>();
        report.put("mode",demo?"synthetic":"live_read_only");report.put("start_inclusive",start.toString());report.put("end_exclusive",end.toString());report.put("monthly_reference_hours",730);
        report.put("assumptions",List.of("Billing period excludes the incomplete current UTC day; AWS billing can lag.",
            "Monthly estimates use current configuration, not historical disk sizes/IP associations or a forecast of CPU load.",
            "CloudWatch surplus cost = charged vCPU-minutes / 60 * USD 0.04 for Linux T4g; pending borrowing is not charged.",
            "Savings Plan monthly commitment is amortized economic cost, not another monthly payment on an All Upfront plan.",
            "Plan-rate monthly references assume this plan covers the selected eligible hosts; account-wide sharing can change actual allocation.",
            "No amortized EC2 billing amount is added to the plan commitment again.",
            "Excludes tax, bandwidth, snapshots, unrelated unattached disks and unassociated EIPs. Public IP charges include auto-assigned IPv4."));
        List<Map<String,String>> inventory=read("instances",()->source.inventory("ec2"));
        Map<String,Map<String,String>> discovered=new LinkedHashMap<>();
        for(Object item:targets){
            var target=(Map<?,?>)item;String name=String.valueOf(target.get("name")),role=String.valueOf(target.get("role"));
            var matches=inventory.stream().filter(x->region.equals(x.get("region"))&&project.equals(x.get("tag_project"))&&role.equals(x.get("tag_role"))&&!Set.of("terminated","shutting-down").contains(x.getOrDefault("state",""))).toList();
            if(matches.size()!=1)throw new IllegalStateException("expected exactly one "+project+"/"+role+" instance, found "+matches.size());
            discovered.put(name,matches.getFirst());
        }
        List<Map<String,String>> volumes=read("volumes",()->source.inventory("ebs"));
        List<Map<String,String>> ips=read("public_ipv4",()->source.inventory("public_ipv4"));
        List<Map<String,String>> addresses=read("elastic_ips",()->source.inventory("eips"));
        List<Map<String,String>> plans=read("savings_plans",()->source.inventory("savings_plans"));
        List<Map<String,String>> selectedPlans=plans.stream().filter(p->planId.equals(p.get("plan_id"))).toList();
        if(selectedPlans.size()>1)throw new IllegalStateException("duplicate Savings Plan id");
        Map<String,String> plan=selectedPlans.isEmpty()?Map.of("plan_id",planId,"state","unknown"):selectedPlans.getFirst();
        List<Map<String,String>> rates=selectedPlans.isEmpty()?List.of():read("plan_rates",()->source.savingsPlanRates(planId));
        report.put("savings_plan",plan);
        report.put("savings_plan_rates",rates);
        List<Map<String,String>> billing=new ArrayList<>();LocalDate resourceCandidate=start.isAfter(today.minusDays(14))?start:today.minusDays(14);
        LocalDate resourceStart=resourceCandidate.isAfter(end)?end:resourceCandidate;
        boolean resourceAvailable=false;
        if(resourceStart.isBefore(end)){
            billing=read("resource_billing",()->source.costs(resourceStart,end,"DAILY","RESOURCE_ID","Amazon Elastic Compute Cloud - Compute",true));
            resourceAvailable=warnings.stream().noneMatch(w->w.get("section").equals("resource_billing"));
        }
        report.put("resource_billing_start",resourceStart.toString());report.put("resource_billing_end",end.toString());
        List<Map<String,String>> monthCosts=start.isBefore(end)?read("account_billing_reference",()->source.costs(start,end,"MONTHLY","SERVICE_USAGE_TYPE","",false)):List.of();
        report.put("account_billing_reference",monthCosts.stream().filter(x->{
            String s=x.getOrDefault("service",""),u=x.getOrDefault("usage_type","").toLowerCase(Locale.ROOT);
            return s.contains("Elastic Compute Cloud")||s.equals("EC2 - Other")||s.contains("Savings Plans")||u.contains("publicipv4");
        }).toList());
        report.put("account_billing_reference_scope","whole account, never summed into host totals");
        List<Map<String,Object>> hosts=new ArrayList<>();List<SpendSource.Metric> queries=new ArrayList<>();
        for(Object item:targets){
            var target=(Map<?,?>)item;
            String name=String.valueOf(target.get("name")),role=String.valueOf(target.get("role"));
            Map<String,String> instance=discovered.get(name);String id=instance.get("instance_id"),type=instance.get("instance_type");
            Map<String,Object> h=new LinkedHashMap<>();h.put("name",name);h.put("instance",instance);
            BigDecimal price=null;
            try{price=number(source.ec2Price(region,type,instance.getOrDefault("platform","Linux/UNIX")).get("hourly_usd"));}catch(RuntimeException error){warn("price_"+name,error);}
            BigDecimal running=instance.getOrDefault("state","").equals("running")?BigDecimal.ONE:instance.getOrDefault("state","").equals("stopped")?BigDecimal.ZERO:null;
            h.put("ondemand_compute_monthly_usd",money(multiply(multiply(price,HOURS),running)));
            List<Map<String,String>> attached=volumes.stream().filter(v->region.equals(v.get("region"))&&id.equals(v.get("attached_instance_id"))).toList();
            h.put("disks",attached);BigDecimal disk=BigDecimal.ZERO;
            if(attached.isEmpty()||hasWarning("volumes"))disk=null;
            else for(var volume:attached)disk=add(disk,gp3(volume));
            h.put("disk_monthly_usd",money(disk));
            Map<String,String> ipKinds=new TreeMap<>();
            if(!instance.getOrDefault("public_ip","").isBlank())ipKinds.put(instance.get("public_ip"),"auto-assigned");
            for(var ip:ips)if(id.equals(ip.get("instance_id"))&&region.equals(ip.get("region"))&&!ip.getOrDefault("public_ip","").isBlank())ipKinds.putIfAbsent(ip.get("public_ip"),"public IPv4");
            for(var ip:addresses)if(id.equals(ip.get("instance_id"))&&region.equals(ip.get("region"))&&!ip.getOrDefault("public_ip","").isBlank())ipKinds.put(ip.get("public_ip"),"Elastic IP");
            h.put("public_ips",ipKinds);
            BigDecimal ipCost=hasWarning("public_ipv4")||hasWarning("elastic_ips")?null:new BigDecimal(ipKinds.size()).multiply(new BigDecimal("0.005")).multiply(HOURS);
            h.put("public_ipv4_monthly_usd",money(ipCost));
            h.put("ondemand_base_monthly_usd",money(add(add(multiply(multiply(price,HOURS),running),disk),ipCost)));
            BigDecimal spRate=planRate(plan,rates,instance,region);
            h.put("savings_plan_rate_hourly_usd",money(spRate));
            h.put("savings_plan_compute_monthly_reference_usd",money(multiply(multiply(spRate,HOURS),running)));
            h.put("plan_rate_base_monthly_reference_usd",money(add(add(multiply(multiply(spRate,HOURS),running),disk),ipCost)));
            List<Map<String,String>> history=billing.stream().filter(x->id.equals(x.getOrDefault("key",""))||x.getOrDefault("key","").endsWith("/"+id)).toList();
            h.put("resource_billing_status",resourceAvailable&&!history.isEmpty()?"observed":"unavailable_or_no_resource_rows");
            h.put("ec2_resource_unblended_usd",history.isEmpty()?"unknown":money(sum(history,"amount_usd")));
            h.put("ec2_resource_amortized_usd",history.isEmpty()?"unknown":money(sum(history,"amortized_usd")));
            h.put("ec2_resource_daily",history);
            if(type.startsWith("t4g.")&&instance.getOrDefault("platform","Linux/UNIX").matches("(?i).*(linux|unix).*")&&start.isBefore(end))
                queries.add(new SpendSource.Metric("surplus"+hosts.size(),region,"AWS/EC2","CPUSurplusCreditsCharged","InstanceId",id,"Sum",3600));
            hosts.add(h);
        }
        List<Map<String,String>> metrics=queries.isEmpty()?List.of():read("cpu_surplus",()->source.metrics(queries,start.atStartOfDay(ZoneOffset.UTC).toInstant(),end.atStartOfDay(ZoneOffset.UTC).toInstant()));
        for(var h:hosts){
            var instance=(Map<String,String>)h.get("instance");String id=instance.get("instance_id");
            List<Map<String,String>> samples=metrics.stream().filter(m->id.equals(m.get("resource_id"))).toList();
            boolean complete=!samples.isEmpty()&&samples.stream().allMatch(m->m.getOrDefault("status","").equals("Complete"))&&samples.stream().mapToInt(m->Integer.parseInt(m.getOrDefault("datapoints","0"))).sum()>0;
            BigDecimal credits=complete?sum(samples,"total"):null;
            h.put("cpu_surplus_charged_credits",money(credits));h.put("cpu_surplus_charged_usd",money(credits==null?null:credits.multiply(new BigDecimal("0.04")).divide(new BigDecimal("60"),12,RoundingMode.HALF_UP)));
            h.put("cpu_surplus_status",complete?"cloudwatch_derived":"unknown_missing_or_partial_metrics");
        }
        report.put("hosts",hosts);
        Map<String,String> totals=new LinkedHashMap<>();
        totals.put("ondemand_base_monthly_usd",money(sumObjects(hosts,"ondemand_base_monthly_usd")));
        totals.put("disks_monthly_usd",money(sumObjects(hosts,"disk_monthly_usd")));totals.put("public_ipv4_monthly_usd",money(sumObjects(hosts,"public_ipv4_monthly_usd")));
        BigDecimal commitment=plan.getOrDefault("state","").equals("active")?number(plan.get("commitment_hourly")):null;
        totals.put("savings_plan_commitment_monthly_usd",money(multiply(commitment,HOURS)));
        totals.put("plan_rate_base_monthly_reference_usd",money(sumObjects(hosts,"plan_rate_base_monthly_reference_usd")));
        BigDecimal coveredDemand=sumObjects(hosts,"savings_plan_compute_monthly_reference_usd"),fixedCommitment=multiply(commitment,HOURS);
        boolean enough=coveredDemand!=null&&fixedCommitment!=null&&coveredDemand.compareTo(fixedCommitment)<=0;
        totals.put("with_plan_base_monthly_usd",enough?money(add(add(fixedCommitment,sumObjects(hosts,"disk_monthly_usd")),sumObjects(hosts,"public_ipv4_monthly_usd"))):"unknown");
        totals.put("additional_recurring_base_if_plan_prepaid_usd",enough&&plan.getOrDefault("payment_option","").replace(" ","").equalsIgnoreCase("AllUpfront")?money(add(sumObjects(hosts,"disk_monthly_usd"),sumObjects(hosts,"public_ipv4_monthly_usd"))):"unknown");
        totals.put("unused_commitment_monthly_reference_usd",enough?money(fixedCommitment.subtract(coveredDemand)):"unknown");
        report.put("plan_scenario",enough?"assumes selected hosts receive this plan; fixed commitment counted once, including unused commitment":"unknown: rates/plan unavailable or commitment cannot cover selected demand");
        totals.put("cpu_surplus_charged_period_usd",money(sumObjects(hosts,"cpu_surplus_charged_usd")));
        report.put("totals",totals);report.put("warnings",warnings);report.put("source",source.diagnostics());
        report.put("query_estimate_usd",ledger.total().toPlainString());report.put("ce_requests",ledger.ceRequests());
        boolean incomplete=hosts.stream().anyMatch(h->h.get("cpu_surplus_status").toString().startsWith("unknown")||h.get("resource_billing_status").toString().startsWith("unavailable")||h.get("ondemand_base_monthly_usd").equals("unknown"));
        report.put("status",warnings.isEmpty()&&!incomplete&&enough?"complete":"partial");
        return report;
    }
    private List<Map<String,String>> read(String section,Supplier<List<Map<String,String>>> action){
        try{return action.get();}catch(RuntimeException e){warn(section,e);return List.of();}
    }
    private void warn(String section,RuntimeException e){warnings.add(Map.of("section",section,"reason",e instanceof SpendSource.Unavailable u?u.reason:e instanceof CostLedger.BudgetExceeded?"query_cap_exhausted":e.getClass().getSimpleName()));}
    private boolean hasWarning(String section){return warnings.stream().anyMatch(x->section.equals(x.get("section")));}
    private static BigDecimal planRate(Map<String,String> plan,List<Map<String,String>> rates,Map<String,String> instance,String region){
        if(!plan.getOrDefault("state","").equals("active")||!plan.getOrDefault("currency","USD").equals("USD"))return null;
        String type=instance.get("instance_type");
        if(!instance.getOrDefault("platform","").matches("(?i).*(linux|unix).*"))return null;
        if(plan.getOrDefault("plan_type","").equals("EC2Instance")&&(!region.equals(plan.get("region"))||!type.startsWith(plan.getOrDefault("ec2_instance_family","?")+".")))return null;
        List<BigDecimal> found=rates.stream().filter(r->type.equals(r.get("instance_type"))&&region.equals(r.get("region"))&&r.getOrDefault("operating_system","").matches("(?i)linux(/unix)?")&&r.getOrDefault("tenancy","").equalsIgnoreCase("shared")&&r.getOrDefault("unit","").equalsIgnoreCase("Hrs")&&r.getOrDefault("product_type","").equals("EC2")).map(r->number(r.get("rate"))).filter(Objects::nonNull).distinct().toList();
        return found.size()==1?found.getFirst():null;
    }
    private static BigDecimal gp3(Map<String,String> v){
        BigDecimal size=number(v.get("size_gib")),iops=number(v.get("iops")),throughput=number(v.get("throughput_mib_s"));
        if(!v.getOrDefault("volume_type","").equals("gp3")||size==null||iops==null||throughput==null)return null;
        return size.multiply(new BigDecimal("0.08")).add(iops.subtract(new BigDecimal("3000")).max(BigDecimal.ZERO).multiply(new BigDecimal("0.005"))).add(throughput.subtract(new BigDecimal("125")).max(BigDecimal.ZERO).multiply(new BigDecimal("0.04")));
    }
    private static BigDecimal number(String x){try{return x==null?null:new BigDecimal(x);}catch(NumberFormatException e){return null;}}
    private static BigDecimal add(BigDecimal a,BigDecimal b){return a==null||b==null?null:a.add(b);}
    private static BigDecimal multiply(BigDecimal a,BigDecimal b){return a==null||b==null?null:a.multiply(b);}
    private static String money(BigDecimal value){return value==null?"unknown":value.setScale(6,RoundingMode.HALF_UP).stripTrailingZeros().toPlainString();}
    private static BigDecimal sum(List<Map<String,String>> rows,String key){BigDecimal sum=BigDecimal.ZERO;for(var r:rows)sum=add(sum,number(r.get(key)));return sum;}
    private static BigDecimal sumObjects(List<Map<String,Object>> rows,String key){BigDecimal sum=BigDecimal.ZERO;for(var r:rows)sum=add(sum,number(String.valueOf(r.get(key))));return sum;}
}
