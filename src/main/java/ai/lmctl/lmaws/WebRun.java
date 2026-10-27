package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.nio.file.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.acm.AcmClient;

/** Durable private state for individually scripted web-stack steps. No implicit deletion on success. */
final class WebRun implements AutoCloseable {
    final AwsBackend backend; final CostLedger cost; final String run,domain; final Path path;
    final LinkedHashMap<String,String> state=new LinkedHashMap<>();
    private final FileChannel channel; private final FileLock lock;
    private WebStackAws provider; private boolean recordedCost;
    WebRun(AwsBackend backend,CostLedger cost,String run,String domain,String file) {
        WebStack.requireRun(run);
        if(domain==null||!WebStack.isDomainName(domain))throw new IllegalArgumentException("invalid domain");
        this.backend=backend;this.cost=cost;this.run=run;this.domain=domain;this.path=Path.of(file).toAbsolutePath().normalize();
        if(java.util.stream.StreamSupport.stream(path.getParent().spliterator(),false).noneMatch(part->part.toString().equals(".lmweblab-local"))&&!backend.isDemo())throw new IllegalArgumentException("live web state must be in .lmweblab-local");
        try {
            Path ancestor=path.getRoot();boolean privatePart=false;
            for(Path part:path){ancestor=ancestor.resolve(part);privatePart|=part.toString().equals(".lmweblab-local");if(privatePart&&Files.isSymbolicLink(ancestor))throw new IllegalArgumentException("private web state symlink refused");}
            Files.createDirectories(path.getParent());
            if(Files.isSymbolicLink(path))throw new IllegalArgumentException("web state symlink refused");
            Path lockPath=path.resolveSibling(path.getFileName()+".lock");
            if(Files.isSymbolicLink(lockPath))throw new IllegalArgumentException("web lock symlink refused");
            channel=FileChannel.open(lockPath,StandardOpenOption.CREATE,StandardOpenOption.WRITE);lock=channel.tryLock();
            if(lock==null)throw new IllegalStateException("web run already active");
            if(Files.exists(path)) {
                if(Files.size(path)>262144)throw new IllegalArgumentException("web state too large");
                Object parsed=Json.parse(Files.readString(path));if(!(parsed instanceof Map<?,?> map))throw new IllegalArgumentException("invalid web state");
                for(var e:map.entrySet())state.put((String)e.getKey(),(String)e.getValue());
                if(!run.equals(state.get("run_id"))||!domain.equals(state.get("domain"))||!String.valueOf(backend.isDemo()).equals(state.get("demo")))throw new IllegalArgumentException("web state run/domain/mode mismatch");
            } else {
                state.put("run_id",run);state.put("domain",domain);state.put("demo",String.valueOf(backend.isDemo()));state.put("started_at",Instant.now().toString());state.put("cost_cap",cost.cap().toPlainString());state.put("request_cost_prior","0");state.put("price_table",Jsons.encodeRaw(Map.of("spot_bid_ceiling_usd_hour","0.0052","public_ipv4_usd_hour","0.005","gp3_gb_month","0.08","root_gib","8","as_of","2026-10-26","region","us-east-1","http_request_bound_usd","0.000001","http_transfer_bound_usd_gb","0.09")));
                state.put("bucket","lmaws-site-"+run);state.put("site","lmaws-site-"+run+"."+domain);state.put("app","lmaws-app-"+run+"."+domain);persist();
            }
            if(!state.containsKey("owner_proof")){state.put("owner_proof",UUID.randomUUID().toString().replace("-",""));persist();}
        } catch(java.io.IOException e){throw new IllegalStateException("cannot lock/read private web state",e);}
    }
    static List<Map<String,String>> find(AwsBackend backend,String run,String domain) {
        WebStack.requireRun(run);
        if(domain==null||!WebStack.isDomainName(domain))throw new IllegalArgumentException("invalid web domain");
        if(backend.isDemo())return List.of();
        try(var adapter=new WebStackAws(backend.webBuilder(Route53Client.builder()).region(software.amazon.awssdk.regions.Region.AWS_GLOBAL).build(),backend.webBuilder(CloudFrontClient.builder()).region(software.amazon.awssdk.regions.Region.AWS_GLOBAL).build(),backend.webBuilder(AcmClient.builder()).build(),backend.webBuilder(S3Client.builder()).build(),backend.ec2Client(),run,domain)) {
            List<Map<String,String>> result=new ArrayList<>(adapter.recoverOwned());result.addAll(new WebCompute(backend).inventory(run));return result;
        }
    }
    private WebStackAws aws() {
        if(provider==null)provider=new WebStackAws(backend.webBuilder(Route53Client.builder()).region(software.amazon.awssdk.regions.Region.AWS_GLOBAL).build(),backend.webBuilder(CloudFrontClient.builder()).region(software.amazon.awssdk.regions.Region.AWS_GLOBAL).build(),backend.webBuilder(AcmClient.builder()).build(),backend.webBuilder(S3Client.builder()).build(),backend.ec2Client(),run,domain,val("owner_proof"));
        return provider;
    }
    private void guard(){if(!backend.isDemo()&&(!"lmaws".equals(AwsBackend.activeProfile())||!AwsBackend.isLiveEnabled()||!"us-east-1".equals(cost.region())))throw new IllegalStateException("web mutations require live AWS_PROFILE=lmaws in us-east-1");}
    private void persist(){try{Path temp=Files.createTempFile(path.getParent(),".web-state-",".tmp");try{try{Files.setPosixFilePermissions(temp,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){}Files.writeString(temp,Jsons.encodeRaw(state));try(FileChannel f=FileChannel.open(temp,StandardOpenOption.WRITE)){f.force(true);}Files.move(temp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(temp);}}catch(java.io.IOException e){throw new IllegalStateException("cannot save private web state",e);}}
    private String val(String k){String v=state.get(k);if(v==null||v.isEmpty())throw new IllegalStateException("web step prerequisite missing: "+k);return v;}
    @SuppressWarnings("unchecked") synchronized Map<String,String> step(String op,String json) {
        guard();if(!Set.of("bucket","distribution","lambda_distribution","certificate","dns_site","compute","dns_app","dns_weighted","https","invalidate","record_http","reserve_http","cache").contains(op))throw new IllegalArgumentException("unknown web step");
        Object parsed=Json.parse(json);if(!(parsed instanceof Map<?,?> raw))throw new IllegalArgumentException("web step arguments must be an object");
        Map<String,Object> args=(Map<String,Object>)raw;
        if("down".equals(state.get("status")))throw new IllegalStateException("run is torn down; choose a new run id");
        // Weighted records are intentionally repeatable: each call may shift
        // the split (90/10 -> 50/50 -> 0/100) within the same run.
        if(!Set.of("record_http","reserve_http","dns_weighted").contains(op)&&"done".equals(state.get("step_"+op)))return summary();
        if(estimate().add(Set.of("record_http","reserve_http","cache").contains(op)?java.math.BigDecimal.ZERO:new java.math.BigDecimal(state.getOrDefault("http_reserved","0"))).compareTo(new java.math.BigDecimal(state.getOrDefault("cost_cap","0.10")))>=0)throw new CostLedger.BudgetExceeded("web run cost cap reached before step");
        state.put("intent",op);persist();long start=System.nanoTime();
        try{if(backend.isDemo()) demoStep(op,args);else liveStep(op,args);}
        catch(RuntimeException failure){
            if(failure instanceof software.amazon.awssdk.awscore.exception.AwsServiceException service&&service.awsErrorDetails()!=null){state.put("provider_error_detail",service.awsErrorDetails().errorMessage());state.put("provider_error_code",service.awsErrorDetails().errorCode());persist();}
            try{down();}catch(RuntimeException cleanup){failure.addSuppressed(cleanup);}throw failure;}
        state.put("step_"+op,"done");state.put("seconds_"+op,String.valueOf((System.nanoTime()-start)/1e9));state.put("status","up");state.remove("intent");persist();return summary();
    }
    private String arg(Map<String,Object> a,String k,String fallback){return a.containsKey(k)?String.valueOf(a.get(k)):fallback;}
    private long integerArg(Map<String,Object> values,String key) {
        Object value=values.getOrDefault(key,0);
        if(value instanceof Number number){double d=number.doubleValue();if(!Double.isFinite(d)||d!=Math.rint(d)||d<0||d>104857600)throw new IllegalArgumentException("invalid bounded integer argument");return (long)d;}
        return Long.parseLong(String.valueOf(value));
    }
    private void demoStep(String op,Map<String,Object>a) {
        switch(op){
            case "bucket"->state.put("bucket_created","true");
            case "distribution"->{val("bucket_created");state.put("oac","fixture-oac");state.put("distribution","fixture-distribution");state.put("cf_domain","dfixture.cloudfront.net");}
            case "lambda_distribution"->{val("cert");String fn=arg(a,"function_name","");if(!fn.startsWith("lmaws_"+run+"_"))throw new SecurityException("Lambda name outside this run");backend.requireLambdaUrlOwned(fn,arg(a,"lambda_url",""),run);if("true".equals(arg(a,"mixed","false")))val("bucket_created");state.put("distribution","fixture-lambda-distribution");state.put("distribution_arn","arn:aws:cloudfront::000000000000:distribution/fixture-lambda-distribution");state.put("cf_domain","dfixture.cloudfront.net");state.put("lambda_distribution","true");}
            case "certificate"->{state.put("cert","fixture-cert");state.put("certificate_status","ISSUED");}
            case "cache"->{val("distribution");long ttl=integerArg(a,"default_ttl"),max=integerArg(a,"max_ttl");if(ttl>300||max<ttl||max>3600)throw new IllegalArgumentException("cache TTL bounds");state.put("cache_default_ttl",Long.toString(ttl));state.put("cache_max_ttl",Long.toString(max));}
            case "dns_site"->{val("cert");state.put("site_record","true");state.put("zone","fixture-zone");}
            case "compute"->{WebStack.requireHttpCidr(arg(a,"cidr","203.0.113.10/32"));state.put("instance_id","i-fixture");state.put("security_group_id","sg-fixture");state.put("public_ip","203.0.113.20");}
            case "dns_app"->{val("instance_id");state.putIfAbsent("zone","fixture-zone");state.put("app_record","true");}
            case "dns_weighted"->{val("distribution");val("instance_id");state.put("weighted_name","lmaws-weighted-"+run+"."+domain);state.put("weighted_static_target","dfixture.cloudfront.net");state.put("weighted_dynamic_ip","203.0.113.20");state.put("weighted_static_weight",arg(a,"static_weight","90"));state.put("weighted_dynamic_weight",arg(a,"dynamic_weight","10"));state.put("weighted_record","true");}
            case "https"->{val("cert");state.put("https","true");}
            case "invalidate"->val("distribution");
            case "record_http", "reserve_http" -> { }
        }
    }
    private void liveStep(String op,Map<String,Object>a) {
        switch(op) {
            case "bucket"->{
                if(!state.containsKey("bucket_created")){aws().createBucket(val("bucket"));state.put("bucket_created","true");state.put("bucket_started_at",Instant.now().toString());persist();}
                Path site=Path.of(arg(a,"site_dir","shared/site"));
                for(String file:List.of("index.html","about.html","style.css","banner.png","404.html")){Path f=site.resolve(file);if(!Files.isRegularFile(f)||size(f)>262144)throw new IllegalArgumentException("missing or oversized static asset "+file);aws().upload(val("bucket"),file,f);state.put("site_bytes",String.valueOf(Long.parseLong(state.getOrDefault("site_bytes","0"))+size(f)));persist();}
            }
            case "distribution"->{
                if(!state.containsKey("oac")){state.put("oac",aws().createOac());persist();}
                if(!state.containsKey("distribution")){var d=aws().createDistribution(val("bucket"),val("site"),val("oac"),state.get("cert"));state.put("distribution",d.id());state.put("distribution_arn",d.arn());state.put("cf_domain",d.domainName());persist();}
                aws().bucketPolicy(val("bucket"),val("distribution_arn"));aws().waitDeployed(val("distribution"),Duration.ofMinutes(20));
            }
            case "lambda_distribution"->{
                String url=arg(a,"lambda_url",""); boolean mixed="true".equalsIgnoreCase(arg(a,"mixed","false"));
                String fn=arg(a,"function_name",""); if(fn.isBlank()||!fn.startsWith("lmaws-")&&!fn.startsWith("lmaws_"))throw new SecurityException("function_name must be the run-owned lmaws Lambda");
                if(!backend.isDemo())backend.requireLambdaUrlOwned(fn,url,run);
                if(mixed&&!state.containsKey("oac")){state.put("oac",aws().createOac());persist();}
                String alias=val("site"); String bucket=mixed?val("bucket"):""; String oac=mixed?val("oac"):""; String cert=state.get("cert");
                var d=aws().createLambdaDistribution(bucket,alias,url,oac,cert,mixed); state.put("distribution",d.id());state.put("distribution_arn",d.arn());state.put("cf_domain",d.domainName());state.put("lambda_distribution","true");persist();if(mixed)aws().bucketPolicy(val("bucket"),val("distribution_arn"));aws().waitDeployed(val("distribution"),Duration.ofMinutes(20));
            }
            case "certificate"->{
                if(!state.containsKey("zone")){state.put("zone",aws().zoneId(domain));persist();}
                if(!state.containsKey("cert")){state.put("cert",aws().requestCertificate(val("site")));persist();}
                long until=System.nanoTime()+Duration.ofMinutes(3).toNanos();
                while(!state.containsKey("validation_name")){
                    var cert=aws().certificate(val("cert"));
                    for(var option:cert.domainValidationOptions())if(option.resourceRecord()!=null){state.put("validation_name",option.resourceRecord().name());state.put("validation_value",option.resourceRecord().value());persist();break;}
                    if(!state.containsKey("validation_name")){if(System.nanoTime()>until)throw new IllegalStateException("ACM validation record timeout");sleep(3000);}
                }
                if(!state.containsKey("validation_record")){aws().recordCname(val("zone"),val("validation_name"),val("validation_value"),false,()->{state.put("validation_record","true");persist();});}
                aws().waitIssued(val("cert"),Duration.ofMinutes(15));state.put("certificate_status","ISSUED");
                if(state.containsKey("distribution"))aws().attachCertificate(val("distribution"),val("site"),val("cert"),false);
            }
            case "dns_site"->{aws().changeAlias(val("zone"),val("site"),val("cf_domain"),false,()->{state.put("site_record","true");persist();});}
            case "compute"->{
                String script=read(Path.of(arg(a,"user_data","shared/userdata/user_data.sh"))).replace("__RUN_ID__",run);
                if(estimate().add(new java.math.BigDecimal("0.003")).compareTo(new java.math.BigDecimal(state.getOrDefault("cost_cap","0.10")))>0)throw new CostLedger.BudgetExceeded("nano + public IPv4 + volume reservation exceeds run cap");
                state.putIfAbsent("compute_started_at",Instant.now().toString());persist();
                var result=new WebCompute(backend).create(run,arg(a,"vpc_id",""),arg(a,"subnet_id",""),arg(a,"ami",""),arg(a,"cidr",""),arg(a,"instance_type","t4g.nano"),8,script,Double.parseDouble(arg(a,"max_price","0.0042")),checkpoint->{state.putAll(checkpoint);persist();});
                state.putAll(result);persist();
            }
            case "dns_app"->{if(!state.containsKey("zone")){state.put("zone",aws().zoneId(domain));persist();}aws().recordA(val("zone"),val("app"),val("public_ip"),false,()->{state.put("app_record","true");persist();});}
            case "dns_weighted"->{
                String fqdn=arg(a,"name",state.getOrDefault("weighted_name","lmaws-weighted-"+run+"."+domain));
                String target=arg(a,"static_target",val("cf_domain")); String ip=arg(a,"dynamic_ip",val("public_ip"));
                if(!target.equals(val("cf_domain"))||!ip.equals(val("public_ip")))throw new SecurityException("weighted DNS targets must be this run's CloudFront and instance");
                long sw=integerArg(a,"static_weight"), dw=integerArg(a,"dynamic_weight");
                if(sw+dw!=100)throw new IllegalArgumentException("weighted DNS weights must sum to 100");
                if(!state.containsKey("zone")){state.put("zone",aws().zoneId(domain));persist();} String zone=arg(a,"zone",val("zone")); aws().weightedSetOwned(zone,fqdn,target,ip,sw,dw,false,state.containsKey("weighted_record"),()->{state.put("weighted_name",fqdn);state.put("weighted_static_target",target);state.put("weighted_dynamic_ip",ip);state.put("weighted_static_weight",String.valueOf(sw));state.put("weighted_dynamic_weight",String.valueOf(dw));state.put("weighted_record","true");persist();});
            }
            case "cache"->{long ttl=integerArg(a,"default_ttl"),max=integerArg(a,"max_ttl");if(ttl>300||max<ttl||max>3600)throw new IllegalArgumentException("cache TTL bounds");if(!backend.isDemo())aws().configureCache(val("distribution"),ttl,max);state.put("cache_default_ttl",Long.toString(ttl));state.put("cache_max_ttl",Long.toString(max));}
            case "https"->{aws().attachCertificate(val("distribution"),val("site"),val("cert"),true);state.put("https","true");}
            case "invalidate"->aws().invalidate(val("distribution"));
            case "reserve_http", "record_http"->{
                long requests=integerArg(a,"requests"),bytes=integerArg(a,"bytes");
                if(requests<0||requests>10000||bytes<0||bytes>104857600)throw new IllegalArgumentException("HTTP cost accounting bounds exceeded");
                var amount=java.math.BigDecimal.valueOf(requests).multiply(new java.math.BigDecimal("0.000001"))
                   .add(java.math.BigDecimal.valueOf(bytes).multiply(new java.math.BigDecimal("0.09")).divide(new java.math.BigDecimal("1073741824"),12,java.math.RoundingMode.CEILING));
                if(estimate().add(amount).compareTo(new java.math.BigDecimal(state.getOrDefault("cost_cap","0.10")))>0)throw new CostLedger.BudgetExceeded("HTTP estimate exceeds whole web-run cap");
                if(op.equals("reserve_http"))state.put("http_reserved",amount.toPlainString());
                else {
                    var reserved=new java.math.BigDecimal(state.getOrDefault("http_reserved","0"));
                    if(reserved.signum()>0&&amount.compareTo(reserved)>0)throw new CostLedger.BudgetExceeded("HTTP requests exceeded the admitted test reservation");
                    state.put("viewer_cost",new java.math.BigDecimal(state.getOrDefault("viewer_cost","0")).add(amount).toPlainString());state.remove("http_reserved");
                    state.put("viewer_requests",String.valueOf(Long.parseLong(state.getOrDefault("viewer_requests","0"))+requests));
                    state.put("viewer_bytes_bound",String.valueOf(Long.parseLong(state.getOrDefault("viewer_bytes_bound","0"))+bytes));
                }
            }
        }
    }
    private long size(Path f){try{return Files.size(f);}catch(java.io.IOException e){throw new IllegalArgumentException("asset read failed",e);}}
    private String read(Path f){if(size(f)>16384)throw new IllegalArgumentException("user data exceeds 16 KiB");try{return Files.readString(f);}catch(java.io.IOException e){throw new IllegalArgumentException("user data read failed",e);}}
    Map<String,String> summary(){Map<String,String> row=new LinkedHashMap<>();for(String k:List.of("run_id","status","demo","certificate_status","https"))row.put(k,state.getOrDefault(k,""));row.put("site_url",(state.containsKey("https")?"https://":"http://")+state.get("site"));row.put("cf_url","http://"+state.getOrDefault("cf_domain",""));row.put("app_url","http://"+state.get("app"));state.forEach((k,v)->{if(k.startsWith("seconds_"))row.put(k,v);});row.put("estimated_cost_usd",estimate().toPlainString());return row;}
    List<Map<String,String>> status(){return List.of(summary());}
    List<Map<String,String>> leftovers(){
        if(backend.isDemo())return "down".equals(state.get("status"))?List.of():List.of(Map.of("kind","fixture","run_id",run));
        List<Map<String,String>> rows=new ArrayList<>(aws().recoverOwned());rows.addAll(new WebCompute(backend).inventory(run));return rows;
    }
    private java.math.BigDecimal estimate(){
        if(backend.isDemo())return java.math.BigDecimal.ZERO;
        var total=new java.math.BigDecimal(state.getOrDefault("request_cost_prior","0")).add(recordedCost?java.math.BigDecimal.ZERO:cost.total());
        if(state.containsKey("compute_started_at")){
            Instant end=state.containsKey("compute_ended_at")?Instant.parse(state.get("compute_ended_at")):Instant.now();
            double seconds=Math.max(0,Duration.between(Instant.parse(state.get("compute_started_at")),end).toMillis()/1000.0);
            total=total.add(java.math.BigDecimal.valueOf(seconds).multiply(new java.math.BigDecimal(state.getOrDefault("max_price","0.0052")).add(new java.math.BigDecimal("0.005"))).divide(new java.math.BigDecimal("3600"),12,java.math.RoundingMode.CEILING));
            total=total.add(java.math.BigDecimal.valueOf(seconds).multiply(new java.math.BigDecimal("0.64")).divide(new java.math.BigDecimal("2592000"),12,java.math.RoundingMode.CEILING));
        }
        if(state.containsKey("bucket_started_at")) {
            Instant end=state.containsKey("bucket_ended_at")?Instant.parse(state.get("bucket_ended_at")):Instant.now();
            double seconds=Math.max(0,Duration.between(Instant.parse(state.get("bucket_started_at")),end).toMillis()/1000.0);
            total=total.add(java.math.BigDecimal.valueOf(seconds).multiply(new java.math.BigDecimal(state.getOrDefault("site_bytes","0"))).multiply(new java.math.BigDecimal("0.023")).divide(new java.math.BigDecimal("2783138807808000"),18,java.math.RoundingMode.CEILING));
        }
        total=total.add(new java.math.BigDecimal(state.getOrDefault("viewer_cost","0")));
        return total;
    }
    synchronized void emergencyDown() {
        if("down".equals(state.get("status")))return;
        boolean possibleWrite=state.containsKey("intent")||state.keySet().stream().anyMatch(k->k.startsWith("step_")||Set.of("bucket_created","distribution","oac","cert","instance_id","security_group_id","site_record","app_record","validation_record").contains(k));
        if(possibleWrite)down();
    }
    synchronized Map<String,String> down() {
        try(AutoCloseable scope=cost.cleanupScope()){return downInternal();}
        catch(RuntimeException e){throw e;}catch(Exception e){throw new IllegalStateException("web cleanup failed",e);}
    }
    private Map<String,String> downInternal() {
        guard();
        if(state.containsKey("http_reserved")){
            state.put("viewer_cost",new java.math.BigDecimal(state.getOrDefault("viewer_cost","0")).add(new java.math.BigDecimal(state.get("http_reserved"))).toPlainString());
            state.put("viewer_cost_basis","admitted upper bound for interrupted HTTP suite");state.remove("http_reserved");persist();
        }System.out.println("web teardown plan: own DNS records, tagged web compute, tagged distribution, OAC, bucket versions, certificate");
        if(!backend.isDemo()) {
            List<RuntimeException> errors=new ArrayList<>();
            // Discovery also covers writes whose successful response preceded a process failure.
            try{for(var item:aws().recoverOwned()) {
                if(!"true".equals(item.get("owned")))throw new IllegalStateException("same-name resource lacks this run tag; cleanup refused");
                switch(item.get("kind")) {
                    case "bucket" -> state.put("bucket_created","true");
                    case "distribution" -> {state.put("distribution",item.get("id"));state.put("distribution_arn",item.get("arn"));state.put("cf_domain",item.get("cf_domain"));}
                    case "oac" -> state.put("oac",item.get("id"));
                    case "certificate" -> state.put("cert",item.get("id"));
                    default -> { }
                }
            }
            }catch(RuntimeException recovery){errors.add(recovery);}
            try{for(var item:new WebCompute(backend).inventory(run)){
                if(item.get("kind").equals("instance")&&WebStack.resourceName(run,"app").equals(item.get("name")))state.put("instance_id",item.get("id"));
                if(item.get("kind").equals("security_group")&&WebStack.resourceName(run,"web-sg").equals(item.get("name")))state.put("security_group_id",item.get("id"));
            }
            }catch(RuntimeException recovery){errors.add(recovery);}
            persist();
            cleanup("app_record",()->aws().recordA(val("zone"),val("app"),val("public_ip"),true),errors);
            cleanup("weighted_record",()->aws().weightedSet(val("zone"),val("weighted_name"),val("weighted_static_target"),val("weighted_dynamic_ip"),Long.parseLong(val("weighted_static_weight")),Long.parseLong(val("weighted_dynamic_weight")),true,null),errors);
            cleanup("site_record",()->aws().changeAlias(val("zone"),val("site"),val("cf_domain"),true),errors);
            if(state.containsKey("security_group_id"))try{new WebCompute(backend).delete(run,state.getOrDefault("instance_id",""),val("security_group_id"),checkpoint->{state.putAll(checkpoint);persist();});state.remove("instance_id");state.remove("security_group_id");state.putIfAbsent("compute_ended_at",Instant.now().toString());persist();}catch(RuntimeException e){errors.add(e);}
            cleanup("distribution",()->{aws().disableDistribution(val("distribution"));aws().deleteDistribution(val("distribution"));},errors);
            cleanup("oac",()->aws().deleteOac(val("oac")),errors);
            cleanup("bucket_created",()->{aws().deleteBucket(val("bucket"));state.put("bucket_ended_at",Instant.now().toString());},errors);
            cleanup("cert",()->aws().deleteCertificate(val("cert")),errors);
            cleanup("validation_record",()->aws().recordCname(val("zone"),val("validation_name"),val("validation_value"),true),errors);
            if(errors.isEmpty()&&(!aws().recoverOwned().isEmpty()||!new WebCompute(backend).inventory(run).isEmpty()))errors.add(new IllegalStateException("independent web inventory still finds this run resources"));
            if(!errors.isEmpty()){state.put("status","cleanup_failed");state.put("cleanup_errors",Jsons.encodeRaw(errors.stream().map(x->x instanceof software.amazon.awssdk.awscore.exception.AwsServiceException aws&&aws.awsErrorDetails()!=null?aws.awsErrorDetails().errorCode()+": "+aws.awsErrorDetails().errorMessage():x.getClass().getSimpleName()+": "+x.getMessage()).toList()));persist();RuntimeException e=new IllegalStateException("web cleanup incomplete: "+errors.size()+" failures; inspect private state");errors.forEach(e::addSuppressed);throw e;}
        }
        state.put("status","down");state.put("finished_at",Instant.now().toString());persist();return Map.of("status","down","leftover_count","0","estimated_cost_usd",estimate().toPlainString());
    }
    private void cleanup(String key,Runnable action,List<RuntimeException> errors){if(state.containsKey(key))try{action.run();state.remove(key);persist();}catch(RuntimeException e){errors.add(e);}}
    static void sleep(long ms){try{Thread.sleep(ms);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("web wait interrupted",e);}}
    @Override public void close(){try{
        if(!recordedCost){
            var total=estimate();state.put("request_cost_prior",new java.math.BigDecimal(state.getOrDefault("request_cost_prior","0")).add(cost.total()).toPlainString());
            state.put("total_estimated_usd",total.toPlainString());persist();
            cost.webSnapshot(total,Json.parse(state.getOrDefault("price_table","{}")),state.getOrDefault("status","new"));recordedCost=true;
        }
        System.out.println("estimated cost: $"+estimate().setScale(8,java.math.RoundingMode.CEILING).toPlainString());
if(provider!=null)provider.close();lock.release();channel.close();}catch(java.io.IOException e){throw new IllegalStateException("web state unlock failed",e);}}
}
