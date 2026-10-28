package ai.lmctl.lmaws;

import java.math.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.LongSupplier;

/** Local request/storage estimates with admission before every billed dispatch. */
public final class CostLedger {
    public static final class BudgetExceeded extends IllegalStateException { public BudgetExceeded(String message){super(message);} }
    public static final BigDecimal DEFAULT_CAP=new BigDecimal("0.05"), HARD_CEILING=new BigDecimal("0.25");
    private static final BigDecimal HEADROOM=new BigDecimal("0.002"), GIB=new BigDecimal("1073741824"), MONTH_MINUTES=new BigDecimal("43200");
    private static final Map<String,BigDecimal> PRICES=Map.ofEntries(
        Map.entry("s3.write_or_list_request",new BigDecimal("0.000005")),
        Map.entry("s3.get_or_head_request",new BigDecimal("0.0000004")),
        Map.entry("s3.storage_gb_month",new BigDecimal("0.023")),
        Map.entry("sqs.request_64kib",new BigDecimal("0.0000004")),
        Map.entry("sns.request_64kib",new BigDecimal("0.0000005")),
        Map.entry("dynamodb.write_1kib",new BigDecimal("0.000000625")),
        Map.entry("dynamodb.storage_gb_month",new BigDecimal("0.25")),
        Map.entry("secretsmanager.api_request",new BigDecimal("0.000005")),
        Map.entry("conservative_unknown_api_request",new BigDecimal("0.000005")),
        Map.entry("costexplorer.primary_view_request",new BigDecimal("0.01")),
        Map.entry("cloudwatch.metric_requested",new BigDecimal("0.00001")),
        Map.entry("cloudwatch.statistics_request",new BigDecimal("0.00001")));
    private final String runId,example,region; private final Path path; private final BigDecimal cap; private final boolean live; private final LongSupplier clock;
    private final Map<String,Resource> resources=new LinkedHashMap<>();
    private final Map<String,Charge> requests=new LinkedHashMap<>();
    private final List<Map<String,Object>> failedCreates=new ArrayList<>();
    private final List<Map<String,String>> accessDeniedPatches=new ArrayList<>();
    private BigDecimal requestTotal=BigDecimal.ZERO; private Resource current,pending; private String lastService="",lastOperation=""; private int cleanupDepth; private int refusals; private long lastCeDispatch;
    private static final class Charge {
        long requests,units; BigDecimal cost=BigDecimal.ZERO,unit=BigDecimal.ZERO; String note="";
        Map<String,Object> report(){
            Map<String,Object> m=new LinkedHashMap<>();
            m.put("requests",requests);m.put("billing_units",units);m.put("unit_price_usd",unit);m.put("estimated_usd",cost);
            if(note!=null && !note.isEmpty())m.put("cost_note",note);
            return Collections.unmodifiableMap(m);
        }
    }
    private static final class Resource {
        final String kind;String id,name;final long start;long end=-1,bytes;boolean confirmed;long nextUnits=1;final Map<String,Charge> requests=new LinkedHashMap<>();
        Resource(String kind,long start){this.kind=kind;this.start=start;}
    }
    public CostLedger(String runId,String example,String region,Path path,BigDecimal cap,boolean live){this(runId,example,region,path,cap,live,System::nanoTime);}
    public CostLedger(String runId,String example,String region,Path path,BigDecimal cap,boolean live,LongSupplier clock){
        this.runId=runId;this.example=example;this.region=region;this.path=path;this.live=live;this.clock=clock;this.cap=cap==null?DEFAULT_CAP:cap;
        if(this.cap.signum()<0||this.cap.compareTo(HARD_CEILING)>0)throw new IllegalArgumentException("cost cap must be between $0 and $0.25");
        try{Files.createDirectories(path.toAbsolutePath().getParent());Files.createFile(path);}catch(java.io.IOException e){throw new IllegalStateException("cost ledger must be a new file",e);}
        write(Map.of("event","cost_header","schema","lmaws-cost-v2","run_id",runId,"example",example,"region",region,"live",live,"cap_usd",this.cap,"hard_ceiling_usd",HARD_CEILING,"price_table",PRICES,"price_metadata",priceMetadata()));
    }
    private static Map<String,Object> priceMetadata(){return Map.of("price_region","us-east-1","currency","USD","as_of","2026-10-25","free_tier_credits_applied",false,"month_minutes",43200,"estimate_only",true,"unknown_calls","conservative $5 per million attempts","sources",List.of("https://aws.amazon.com/s3/pricing/","https://aws.amazon.com/sqs/pricing/","https://aws.amazon.com/sns/pricing/","https://aws.amazon.com/dynamodb/pricing/","https://aws.amazon.com/systems-manager/pricing/","https://aws.amazon.com/secrets-manager/pricing/","https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/","https://aws.amazon.com/cloudwatch/pricing/"));}
    private static String service(String raw){String x=raw.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]","");if(x.contains("simplestorage")||x.endsWith("s3"))return "s3";if(x.contains("sqs"))return "sqs";if(x.contains("sns"))return "sns";if(x.contains("dynamodb"))return "dynamodb";if(x.contains("systemsmanager")||x.contains("ssm"))return "ssm";if(x.contains("cloudwatchlogs")||x.equals("logs"))return "logs";if(x.contains("secretsmanager"))return "secretsmanager";if(x.contains("costexplorer")||x.equals("ce"))return "costexplorer";if(x.contains("cloudwatch"))return "cloudwatch";if(x.contains("savingsplans")||x.contains("pricing")||x.contains("cloudformation"))return "free_metadata";if(x.contains("ec2")||x.contains("iam")||x.contains("sts")||x.contains("lambda")||x.contains("route53")||x.contains("ecs")||x.contains("cloudwatch"))return "free_metadata";return x;}
    private static BigDecimal unitPrice(String svc,String op){
        if(svc.equals("costexplorer"))return PRICES.get("costexplorer.primary_view_request");
        if(svc.equals("cloudwatch"))return op.equals("getmetricdata")?PRICES.get("cloudwatch.metric_requested"):op.equals("getmetricstatistics")?PRICES.get("cloudwatch.statistics_request"):BigDecimal.ZERO;
        if(svc.equals("s3")){if(Set.of("listbuckets","createbucket","deletebucket","deleteobject","deleteobjects").contains(op))return BigDecimal.ZERO;return PRICES.get(op.startsWith("get")||op.startsWith("head")?"s3.get_or_head_request":"s3.write_or_list_request");}
        if(svc.equals("sqs"))return PRICES.get("sqs.request_64kib");if(svc.equals("sns"))return PRICES.get("sns.request_64kib");
        if(svc.equals("dynamodb"))return op.equals("putitem")?PRICES.get("dynamodb.write_1kib"):BigDecimal.ZERO;
        if(Set.of("ssm","logs","free_metadata").contains(svc))return BigDecimal.ZERO;
        if(svc.equals("secretsmanager"))return PRICES.get("secretsmanager.api_request");return PRICES.get("conservative_unknown_api_request");
    }
    /** Package-visible price lookup for persistent provider ledgers. */
    static BigDecimal s3PriceForOperation(String operation){
        String op=(operation==null?"":operation).toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]","");
        return unitPrice("s3",op);
    }
    synchronized void s3BootstrapBudget(BigDecimal amount){requireBudget(amount,"creating and verifying an S3 bucket tag");}
    static Map<String,BigDecimal> s3PriceTable(){
        return Map.of("s3.write_or_list_request",PRICES.get("s3.write_or_list_request"),"s3.get_or_head_request",PRICES.get("s3.get_or_head_request"));
    }
    private BigDecimal reserved(){return resources.values().stream().filter(r->r.end<0).map(r->HEADROOM).reduce(BigDecimal.ZERO,BigDecimal::add).add(pending==null?BigDecimal.ZERO:HEADROOM);}
    private void requireBudget(BigDecimal extra,String action){if(cleanupDepth==0 && total().add(reserved()).add(extra).compareTo(cap)>0){refusals++;write(Map.of("event","cost_refused","action",action,"estimated_with_reserve_usd",total().add(reserved()).add(extra)));throw new BudgetExceeded("estimated cost cap exceeded before "+action+" (LMAWS_MAX_COST_USD)");}}
    public synchronized void request(String rawService,String operation){
        String svc=service(rawService),op=operation.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]","");
        long units=(svc.equals("dynamodb")&&op.equals("putitem")&&current!=null)?current.nextUnits:1;
        recordRequest(svc,operation,op,units);
    }
    /** GetMetricData bills metrics requested, not merely one unit per batched HTTP call. */
    public synchronized void metricRequest(String operation,long metricUnits){
        if(metricUnits<1||metricUnits>500)throw new IllegalArgumentException("metric billing units must be 1..500");
        String op=operation.toLowerCase(Locale.ROOT);
        if(!op.equals("getmetricdata")&&!op.equals("getmetricstatistics"))throw new IllegalArgumentException("unsupported metric operation");
        recordRequest("cloudwatch",operation,op,op.equals("getmetricstatistics")?1:metricUnits);
    }
    private void recordRequest(String svc,String operation,String op,long units){
        BigDecimal unit=unitPrice(svc,op),charge=unit.multiply(BigDecimal.valueOf(units));
        requireBudget(charge,"SDK request");
        if(live&&svc.equals("costexplorer")){
            long wait=500_000_000L-(System.nanoTime()-lastCeDispatch);
            if(wait>0)try{Thread.sleep(wait/1_000_000L,(int)(wait%1_000_000L));}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("spend request interrupted");}
            lastCeDispatch=System.nanoTime();
        }
        lastService=svc;lastOperation=operation;requestTotal=requestTotal.add(charge);String key=svc+"."+operation;
        String note=(svc.equals("cloudfront")&&op.equals("createinvalidation"))
            ?"First 1,000 CloudFront invalidation paths per month are free; additional paths cost $0.005 per path (1 nonexistent path per distribution, no wildcards)."
            :"";
        add(requests,key,units,unit,charge,note);Resource owner=current==null?pending:current;
        if(owner!=null)add(owner.requests,key,units,unit,charge,note);
        Map<String,Object> ev=new LinkedHashMap<>();
        ev.put("event","cost_request");ev.put("service",svc);ev.put("operation",operation);ev.put("billing_units",units);ev.put("unit_price_usd",unit);ev.put("estimated_usd",charge);
        if(!note.isEmpty())ev.put("cost_note",note);
        write(ev);
    }
    public synchronized long ceRequests(){return requests.entrySet().stream().filter(e->e.getKey().startsWith("costexplorer.")).mapToLong(e->e.getValue().requests).sum();}
    public synchronized long metricRequests(){return requests.entrySet().stream().filter(e->e.getKey().startsWith("cloudwatch.GetMetric")).mapToLong(e->e.getValue().requests).sum();}
    public synchronized long metricUnits(){return requests.entrySet().stream().filter(e->e.getKey().startsWith("cloudwatch.GetMetric")).mapToLong(e->e.getValue().units).sum();}

    private static void add(Map<String,Charge> target,String key,long units,BigDecimal unit,BigDecimal amount,String note){Charge c=target.computeIfAbsent(key,k->new Charge());c.requests++;c.units+=units;c.unit=unit;c.cost=c.cost.add(amount);if(note!=null&&!note.isEmpty())c.note=note;}
    public synchronized void reserveCreate(String kind){if(pending!=null)throw new IllegalStateException("previous creation attempt unresolved");requireBudget(HEADROOM.add(new BigDecimal("0.001")),"creating "+kind);pending=new Resource(kind,clock.getAsLong());current=null;write(Map.of("event","cost_reserve","kind",kind,"future_cleanup_usd",HEADROOM));}
    public synchronized void created(String kind,String id,String name){Resource r=pending==null?new Resource(kind,clock.getAsLong()):pending;r.id=id;r.name=name;r.confirmed=true;resources.put(kind+"\0"+id,r);pending=null;current=r;write(Map.of("event","cost_resource","state","created","kind",kind,"id",id,"name",name));}
    public synchronized String lastOperation(){return lastOperation;}
    public synchronized boolean creationWasTransmitted(String operation){return pending!=null && pending.requests.keySet().stream().anyMatch(k->k.endsWith("."+operation));}
    public synchronized void creationRejected(String kind,String name,String code,int status){
        Map<String,Object> entry=new LinkedHashMap<>();
        entry.put("kind",kind);entry.put("name",name);entry.put("error_code",code);entry.put("http_status",status);entry.put("confirmed_created",false);
        String lc=code==null?"":code.toLowerCase(Locale.ROOT);
        if(status==403 || lc.contains("accessdenied") || lc.contains("unauthorized")) {
            String svc=lastService.isEmpty()?kindToService(kind):lastService;
            String op=lastOperation.isEmpty()?kindToCreateOperation(kind):lastOperation;
            Map<String,String> patch=recordAccessDenied(svc,op,code,status,null);
            entry.put("access_denied_patch",patch);
        }
        failedCreates.add(Collections.unmodifiableMap(entry));
        pending=null;current=null;write(Map.of("event","cost_creation_rejected","kind",kind,"name",name,"http_status",status));
    }
    public synchronized Map<String,String> recordAccessDenied(String rawService,String operation,String errorCode,int httpStatus,String rawErrorMessage){
        String svc=(rawService==null||rawService.isBlank())?lastService:service(rawService);
        String op=(operation==null||operation.isBlank())?lastOperation:operation;
        Map<String,String> explained=PolicyAnalyzer.explainDenial(svc,op,rawErrorMessage);
        Map<String,String> patch=new LinkedHashMap<>();
        patch.put("service",explained.getOrDefault("service",svc));
        patch.put("operation",op==null?"":op);
        patch.put("error_code",errorCode==null||errorCode.isBlank()?"AccessDenied":errorCode);
        patch.put("http_status",String.valueOf(httpStatus));
        patch.put("action",explained.getOrDefault("action",""));
        patch.put("resource_arn_pattern",explained.getOrDefault("resource_arn_pattern",explained.getOrDefault("resource","*")));
        patch.put("condition_keys",explained.getOrDefault("condition_keys","none"));
        patch.put("denial_type",explained.getOrDefault("denial_type","identity_policy_missing_allow"));
        patch.put("failed_condition",explained.getOrDefault("failed_condition","none"));
        patch.put("minimal_builder_patch",explained.getOrDefault("minimal_builder_patch",explained.getOrDefault("builder_snippet","")));
        patch.put("statement_json",explained.getOrDefault("statement_json","{}"));
        Map<String,String> immutable=Collections.unmodifiableMap(patch);
        if(accessDeniedPatches.isEmpty() || !sameDenialPatch(accessDeniedPatches.get(accessDeniedPatches.size()-1),immutable)){
            accessDeniedPatches.add(immutable);
            Map<String,Object> ev=new LinkedHashMap<>(immutable);
            ev.put("event","cost_access_denied");
            write(ev);
        }
        return immutable;
    }
    private static boolean sameDenialPatch(Map<String,String> a,Map<String,String> b){
        return Objects.equals(a.get("action"),b.get("action"))
            && Objects.equals(a.get("resource_arn_pattern"),b.get("resource_arn_pattern"))
            && Objects.equals(a.get("condition_keys"),b.get("condition_keys"))
            && Objects.equals(a.get("minimal_builder_patch"),b.get("minimal_builder_patch"));
    }
    private static String kindToService(String kind){
        if(kind==null)return "aws";
        return switch(kind.toLowerCase(Locale.ROOT)){
            case "bucket"->"s3";case "queue"->"sqs";case "topic"->"sns";case "table"->"dynamodb";case "parameter"->"ssm";case "log_group"->"logs";case "instance"->"ec2";default->kind;
        };
    }
    private static String kindToCreateOperation(String kind){
        if(kind==null)return "Create";
        return switch(kind.toLowerCase(Locale.ROOT)){
            case "bucket"->"CreateBucket";case "queue"->"CreateQueue";case "topic"->"CreateTopic";case "table"->"CreateTable";case "parameter"->"PutParameter";case "log_group"->"CreateLogGroup";case "instance"->"RunInstances";default->"Create";
        };
    }
    public synchronized List<Map<String,String>> accessDeniedPatches(){return List.copyOf(accessDeniedPatches);}
    public synchronized void select(String kind,String id){current=resources.get(kind+"\0"+id);}
    public synchronized void deleted(String kind,String id){Resource r=resources.get(kind+"\0"+id);if(r==null)return;r.end=clock.getAsLong();write(Map.of("event","cost_resource","state","deleted","kind",kind,"id",id,"minutes_alive",minutes(r)));current=null;}
    public synchronized void put(String kind,String id,int bytes){put(kind,id,bytes,0);}
    public synchronized void put(String kind,String id,int bytes,int keyBytes){if(bytes<0||bytes>65536)throw new IllegalArgumentException("example payload must be at most 64 KiB");if(kind.equals("parameter")&&bytes>4096)throw new IllegalArgumentException("Standard parameter payload must be at most 4096 bytes");Resource r=resources.get(kind+"\0"+id);if(r==null)throw new IllegalStateException("resource is not cost-owned");requireBudget(new BigDecimal("0.00005"),"updating resource");current=r;r.nextUnits=kind.equals("table")?Math.max(1,(bytes+keyBytes+7+1023)/1024):1;if(kind.equals("bucket"))r.bytes+=bytes;else if(kind.equals("table"))r.bytes+=bytes+keyBytes+107;write(Map.of("event","cost_payload","kind",kind,"payload_bytes",bytes,"billing_units",r.nextUnits));}
    private BigDecimal minutes(Resource r){long end=r.end<0?clock.getAsLong():r.end;return BigDecimal.valueOf(Math.max(0,end-r.start)).divide(new BigDecimal("60000000000"),12,RoundingMode.HALF_UP);}
    private BigDecimal storage(Resource r){if(r.bytes==0)return BigDecimal.ZERO;String key=r.kind.equals("bucket")?"s3.storage_gb_month":"dynamodb.storage_gb_month";return PRICES.get(key).multiply(BigDecimal.valueOf(r.bytes)).multiply(minutes(r)).divide(GIB.multiply(MONTH_MINUTES),24,RoundingMode.HALF_UP);}
    public synchronized BigDecimal total(){return requestTotal.add(resources.values().stream().map(this::storage).reduce(BigDecimal.ZERO,BigDecimal::add));}
    private static Map<String,Object> charges(Map<String,Charge> data){Map<String,Object> out=new LinkedHashMap<>();data.forEach((k,v)->out.put(k,v.report()));return out;}
    public synchronized Map<String,Object> report(int leftovers){List<Map<String,Object>> rr=new ArrayList<>();for(Resource r:resources.values()){Map<String,Object> row=new LinkedHashMap<>();row.put("kind",r.kind);row.put("id",r.id);row.put("name",r.name);row.put("minutes_alive",minutes(r));row.put("stored_bytes_upper_bound",r.bytes);row.put("requests",charges(r.requests));row.put("storage_unit_price_usd_gb_month",r.bytes==0?BigDecimal.ZERO:PRICES.get(r.kind.equals("bucket")?"s3.storage_gb_month":"dynamodb.storage_gb_month"));BigDecimal req=r.requests.values().stream().map(v->v.cost).reduce(BigDecimal.ZERO,BigDecimal::add);row.put("request_cost_usd",req);row.put("storage_cost_usd",storage(r));row.put("cost_subtotal_usd",req.add(storage(r)));rr.add(row);}Map<String,Object> out=new LinkedHashMap<>();out.put("schema","lmaws-cost-v2");out.put("run_id",runId);out.put("example",example);out.put("region",region);out.put("live",live);out.put("cap_usd",cap);out.put("hard_ceiling_usd",HARD_CEILING);out.put("total_estimated_usd",total());out.put("reserved_future_usd",reserved());out.put("price_table",PRICES);out.put("price_metadata",priceMetadata());out.put("resources",rr);out.put("rejected_creations",failedCreates);out.put("access_denied_count",accessDeniedPatches.size());out.put("access_denied_patches",new ArrayList<>(accessDeniedPatches));if(!accessDeniedPatches.isEmpty())out.put("access_denied_patch",accessDeniedPatches.get(accessDeniedPatches.size()-1));out.put("service_requests",charges(requests));out.put("cap_refusals",refusals);out.put("leftover_count",leftovers);return out;}
    synchronized void webSnapshot(java.math.BigDecimal total,Object prices,String status) {
        write(Map.of("event","cost_web_snapshot","total_estimated_usd",total,"sdk_estimated_usd",this.total(),"price_table",prices,"web_status",status));
    }
    synchronized void serverlessSnapshot(java.math.BigDecimal total,Object prices,String status){write(Map.of("event","cost_serverless_snapshot","total_estimated_usd",total,"sdk_estimated_usd",this.total(),"price_table",prices,"serverless_status",status));}
    public synchronized String displayCost(){if(total().signum()==0)return "$0.00";return "$"+total().setScale(8,RoundingMode.CEILING).toPlainString();}
    public synchronized AutoCloseable cleanupScope(){cleanupDepth++;return ()->{synchronized(this){cleanupDepth--;}};}
    public void link(Path target){writeTo(target,Map.of("event","cost_link","cost_ledger",path.toString(),"cap_usd",cap,"price_table",PRICES));}
    private void write(Map<String,?> value){writeTo(path,value);}
    private static void writeTo(Path target,Map<String,?> value){try(FileChannel c=FileChannel.open(target,StandardOpenOption.WRITE,StandardOpenOption.APPEND)){ByteBuffer b=StandardCharsets.UTF_8.encode(Jsons.encodeRaw(value)+"\n");while(b.hasRemaining())c.write(b);c.force(true);}catch(java.io.IOException e){throw new IllegalStateException("cannot append cost ledger",e);}}
    public Path path(){return path;}public Path ledgerPath(){return path;}public String runId(){return runId;}public String example(){return example;}public String region(){return region;}public boolean live(){return live;}public boolean isLive(){return live;}public BigDecimal cap(){return cap;}
}
