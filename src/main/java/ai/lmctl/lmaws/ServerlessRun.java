package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.nio.file.*;
import java.nio.channels.*;
import java.time.Instant;
import java.util.*;

/** Durable ownership receipts for scenarios 03-06. No implicit teardown on close. */
final class ServerlessRun implements AutoCloseable {
    final AwsBackend backend; final CostLedger cost; final String run,domain; final Path path;
    final Map<String,String> state=new LinkedHashMap<>();
    private FileChannel channel; private FileLock lock; private boolean ready,accounted;
    ServerlessRun(AwsBackend backend,CostLedger cost,String run,String domain,String file) {
        WebStack.requireRun(run);if(run.length()>24)throw new IllegalArgumentException("serverless run must be 4..24 hex digits");
        if(domain==null||!WebStack.isDomainName(domain))throw new IllegalArgumentException("invalid domain");
        if(!backend.isDemo() && (!"lmaws".equals(AwsBackend.activeProfile()) || !AwsBackend.isLiveEnabled() || !"us-east-1".equals(backend.region())))
            throw new SecurityException("live serverless deployment requires AWS_PROFILE=lmaws, LMAWS_LIVE=1 and us-east-1");
        this.backend=backend;this.cost=cost;this.run=run;this.domain=domain;path=Path.of(file).toAbsolutePath().normalize();
        if(java.util.stream.StreamSupport.stream(path.spliterator(),false).noneMatch(p->p.toString().equals(".lmweblab-local")))throw new IllegalArgumentException("serverless state must be in .lmweblab-local");
        try {
            Path cursor=path.getRoot();boolean privatePart=false;
            for(Path part:path){cursor=cursor.resolve(part);privatePart|=part.toString().equals(".lmweblab-local");if(privatePart&&Files.isSymbolicLink(cursor))throw new IllegalArgumentException("private state symlink refused");}
            Files.createDirectories(path.getParent());Path lockPath=path.resolveSibling(path.getFileName()+".lock");
            if(Files.isSymbolicLink(lockPath))throw new IllegalArgumentException("state lock symlink refused");
            channel=FileChannel.open(lockPath,StandardOpenOption.CREATE,StandardOpenOption.WRITE);lock=channel.tryLock();if(lock==null)throw new IllegalStateException("serverless run already active");
            if(Files.exists(path)){
                if(Files.size(path)>262144)throw new IllegalArgumentException("state too large");
                var map=Json.object(Json.parse(Files.readString(path)));for(var entry:map.entrySet()){if(!(entry.getValue() instanceof String))throw new IllegalArgumentException("invalid state value");state.put(entry.getKey(),(String)entry.getValue());}
                if(!run.equals(state.get("run_id"))||!domain.equals(state.get("domain"))||!String.valueOf(backend.isDemo()).equals(state.get("demo")))throw new IllegalArgumentException("state run/domain/mode mismatch");
            }else{
                state.put("run_id",run);state.put("domain",domain);state.put("demo",String.valueOf(backend.isDemo()));state.put("status","new");state.put("started_at",Instant.now().toString());persist();
            }
            state.putIfAbsent("cost_cap",cost.cap().toPlainString());state.putIfAbsent("request_cost_prior","0");
            state.putIfAbsent("price_table",Jsons.encodeRaw(Map.of("lambda_gb_second","0.0000166667","lambda_request","0.0000002","http_request_bound","0.000001","transfer_gb","0.09","logs_gb","0.50","log_bytes_per_invoke_bound","16384","scheduled_invokes_bound","20","region","us-east-1")));
            ready=true;persist();
        }catch(Exception error){close();throw new IllegalStateException("cannot open private serverless state",error);}
    }
    void persist(){
        try{Path temp=Files.createTempFile(path.getParent(),".serverless-",".tmp");try{
            try{Files.setPosixFilePermissions(temp,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){}
            Files.writeString(temp,Jsons.encodeRaw(state));try(var file=FileChannel.open(temp,StandardOpenOption.WRITE)){file.force(true);}Files.move(temp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        }finally{Files.deleteIfExists(temp);}}catch(java.io.IOException e){throw new IllegalStateException("cannot persist serverless state",e);}
    }
    private String arg(Map<String,Object> args,String name,String fallback){Object value=args.get(name);return value==null?fallback:String.valueOf(value);}
    private int integer(Map<String,Object> args,String key,int fallback){Object v=args.get(key);if(v==null)return fallback;double n=v instanceof Number number?number.doubleValue():Double.parseDouble(v.toString());if(!Double.isFinite(n)||n!=Math.rint(n)||n<0||n>Integer.MAX_VALUE)throw new IllegalArgumentException("invalid integer "+key);return (int)n;}
    synchronized Map<String,String> step(String op,String json) {
        if(!Set.of("table","bucket","lambda","event","report","reserve_http","record_http","queues","worker").contains(op))throw new IllegalArgumentException("unknown serverless step");
        if("down".equals(state.get("status")))throw new IllegalStateException("run torn down; choose a new id");
        Map<String,Object> args=Json.object(Json.parse(json));String encoded=Jsons.encodeRaw(args);
        if(!Set.of("report","reserve_http","record_http","queues","worker").contains(op)&&"done".equals(state.get("step_"+op))){if(!encoded.equals(state.get("args_"+op)))throw new IllegalArgumentException("configuration changed; choose a new run");return summary();}
        enforceBudget(op,args);
        state.put("intent",op);state.put("intent_"+op,"true");state.put("args_"+op,encoded);persist();
        try {
            switch(op){
                case "table"->{
                    String name="lmaws_"+run+"_table";
                    if(!backend.isDemo()){if(backend.exists("table",name))throw new SecurityException("refusing existing table");backend.create("table",name,"",run);}
                    state.put("table",name);persist();
                    if(!backend.isDemo()){backend.awaitReady("table",name,run);backend.tableTtl(name,arg(args,"ttl_attribute","expires_at"),run);}
                }
                case "bucket"->{
                    String name="lmaws-"+run+"-report";
                    if(!backend.isDemo()){if(backend.exists("bucket",name))throw new SecurityException("refusing existing bucket");backend.create("bucket",name,"",run);}
                    state.put("bucket",name);persist();
                }
                case "lambda"->{
                    String name="lmaws_"+run+"_fn",role=arg(args,"role","lmaws_lambda_exec"),runtime=arg(args,"runtime","python3.12"),handler=arg(args,"handler","handler.handler");
                    String slug=arg(args,"slug",run); if(!slug.matches("[a-z0-9_-]{1,24}"))throw new IllegalArgumentException("invalid Lambda scenario slug");
                    String logGroup="lmaws_"+slug+"_logs_"+run;
                    int memory=integer(args,"memory_mb",128),timeout=integer(args,"timeout_s",10),ttl=integer(args,"ttl_seconds",3600);
                    if(memory>512||timeout>30||ttl<1||ttl>86400)throw new IllegalArgumentException("scenario memory/timeout/TTL caps exceeded");
                    Path sourcePath=Path.of(arg(args,"source_file",""));if(!Files.isRegularFile(sourcePath)||Files.size(sourcePath)>196608)throw new IllegalArgumentException("bounded source_file required");
                    String prefix="import os\n";
                    for(var e:Map.of("RUN_ID",run,"TABLE_NAME",state.getOrDefault("table",""),"BUCKET_NAME",state.getOrDefault("bucket",""),"TTL_SECONDS",String.valueOf(ttl)).entrySet())prefix+="os.environ["+Jsons.encodeRaw(e.getKey())+"]="+Jsons.encodeRaw(e.getValue())+"\n";
                    state.put("memory_mb",String.valueOf(memory));state.put("timeout_s",String.valueOf(timeout));
                    String source=prefix+ServerlessExtras.environment(this,args)+Files.readString(sourcePath);new LambdaFunction(name,role,runtime,handler,source,memory,timeout,run);
                    state.put("log_group",logGroup);persist();
                    String arn=backend.isDemo()?"arn:aws:lambda:local:000000000000:function:"+name:backend.createLambda(name,role,runtime,handler,source,memory,timeout,run,logGroup).get("arn");
                    state.put("lambda_name",name);state.put("lambda_name_receipt",name);state.put("log_group_receipt",logGroup);state.put("lambda_arn",arn);persist();
                    if(!backend.isDemo())backend.waitLambdaActive(arn,run,120);
                    String reason=arg(args,"url_reason","ephemeral scenario API with no secrets; bounded requests and explicit teardown");
                    state.put("lambda_url",backend.isDemo()?"https://"+name+".lambda-url.local/":backend.lambdaUrl(arn,reason));persist();
                }
                case "queues", "worker" -> {if(op.equals("worker")){state.put("worker_execution_bound",workerBound(args).toPlainString());persist();}ServerlessExtras.step(this,op,args);}
                case "event"->{
                    String function=state.get("lambda_arn");if(function==null)throw new IllegalStateException("Lambda prerequisite missing");String name="lmaws_"+run+"_rule",schedule=arg(args,"schedule","rate(1 minute)");new EventRule(name,schedule,run);
                    state.put("event_execution_bound",invokeBound(20).toPlainString());
                    if(!backend.isDemo())backend.putEventRule(name,schedule,run);state.put("rule",name);persist();if(!backend.isDemo())backend.putEventTarget(name,function,run);
                }
                case "report"->{
                    if(state.get("bucket")==null||state.get("table")==null)throw new IllegalStateException("report requires bucket and table");
                    state.putAll(backend.serverlessReport(state.get("bucket"),state.get("table"),run));persist();
                }
                case "reserve_http"->{
                    long requests=integer(args,"requests",0),bytes=integer(args,"bytes",0);if(requests>10000||bytes>104857600)throw new IllegalArgumentException("HTTP admission exceeds bounds");
                    var amount=httpBound(requests,bytes);state.put("http_reserved",amount.toPlainString());state.put("http_reserved_requests",Long.toString(requests));state.put("http_reserved_bytes",Long.toString(bytes));
                }
                case "record_http"->{
                    var admitted=new java.math.BigDecimal(state.getOrDefault("http_reserved","0"));var actual=httpBound(integer(args,"requests",0),integer(args,"bytes",0));
                    if(actual.compareTo(admitted)>0)throw new CostLedger.BudgetExceeded("HTTP usage exceeded admitted bound");state.put("http_actual",new java.math.BigDecimal(state.getOrDefault("http_actual","0")).add(actual).toPlainString());state.remove("http_reserved");
                }
            }
            state.put("step_"+op,"done");state.remove("intent");state.put("status","up");persist();return summary();
        }catch(Exception error){state.put("provider_error",privateError(error));persist();try{down();}catch(Exception cleanup){error.addSuppressed(cleanup);}if(error instanceof RuntimeException runtime)throw runtime;throw new IllegalStateException("serverless step failed",error);}
    }
    synchronized Map<String,String> summary(){var result=new LinkedHashMap<String,String>();for(String k:List.of("run_id","status","table","bucket","lambda_name","lambda_arn","lambda_url","log_group","rule","latest_json_body","latest_html_body","table_items","queue","dlq","worker_name","mapping"))result.put(k,state.getOrDefault(k,""));result.put("estimated_cost_usd",estimate().toPlainString());return result;}
    synchronized List<Map<String,String>> leftovers(){
        var rows=new ArrayList<Map<String,String>>();
        for(String kind:List.of("table","bucket","lambda_name","log_group","rule","queue","dlq","worker_name","worker_logs","mapping"))if(state.containsKey(kind))rows.add(Map.of("kind",kind,"name",state.get(kind),"run_id",run));
        return rows;
    }
    synchronized Map<String,String> down(){
        try(var ignored=cost.cleanupScope()){
            var errors=new ArrayList<RuntimeException>();
            ServerlessExtras.down(this,errors);
            var creationSettings=Json.object(Json.parse(state.getOrDefault("args_lambda","{}")));String receiptSlug=String.valueOf(creationSettings.getOrDefault("slug",run));
            boolean receiptConfig=receiptSlug.matches("[a-z0-9_-]{1,24}")&&"lmaws_lambda_exec".equals(String.valueOf(creationSettings.getOrDefault("role","lmaws_lambda_exec")));
            boolean explicitReceipt=state.containsKey("lambda_name_receipt")||state.containsKey("log_group_receipt");
            boolean recordedLambda="lmaws_".concat(run).concat("_fn").equals(state.get("lambda_name_receipt"))&&("lmaws_"+receiptSlug+"_logs_"+run).equals(state.get("log_group_receipt"));
            if(explicitReceipt&&(!receiptConfig||!recordedLambda))throw new SecurityException("creation receipt does not match this run");
            boolean completedLambda=receiptConfig&&(recordedLambda||"done".equals(state.get("step_lambda")));
            if(completedLambda&&state.containsKey("log_group")&&!("lmaws_"+receiptSlug+"_logs_"+run).equals(state.get("log_group")))throw new SecurityException("active log group differs from creation receipt");
            if(completedLambda&&!state.containsKey("lambda_name")&&state.containsKey("finished_at"))state.putIfAbsent("lambda_deleted_at",state.get("finished_at"));
            if(completedLambda&&!state.containsKey("log_group")&&state.containsKey("finished_at")){
                var settings=Json.object(Json.parse(state.getOrDefault("args_lambda","{}")));String slug=String.valueOf(settings.getOrDefault("slug",run));
                if(!slug.matches("[a-z0-9_-]{1,24}")||!"lmaws_lambda_exec".equals(String.valueOf(settings.getOrDefault("role","lmaws_lambda_exec"))))throw new SecurityException("invalid log creation receipt");
                state.put("log_group",state.getOrDefault("log_group_receipt","lmaws_"+slug+"_logs_"+run));persist();
            }
            cleanup("rule",()->{if(!backend.isDemo())backend.deleteEventRule(state.get("rule"),run);},errors);
            cleanup("lambda_name",()->{if(!backend.isDemo()){backend.deleteLambdaFunctionUrl(state.get("lambda_arn"),run);backend.deleteLambda(state.get("lambda_arn"),run);state.put("lambda_deleted_at",Instant.now().toString());persist();}state.remove("lambda_arn");state.remove("lambda_url");},errors);
            cleanup("log_group",()->{
                if(!backend.isDemo()&&completedLambda){Instant end=Instant.parse(state.getOrDefault("lambda_deleted_at",state.getOrDefault("finished_at",Instant.now().toString())));backend.reconcileRuntimeLogGroup(state.get("log_group"),run,Instant.parse(state.get("started_at")),end,true,stage->{state.put("log_reconciliation_stage",stage);if(stage.equals("run_tag_restored"))state.put("log_tag_repaired","true");state.put("log_reconciliation_at",Instant.now().toString());persist();});}
                else backend.deleteLambdaLogGroup(state.get("log_group"),run);
                state.remove("log_group");
            },errors);
            ServerlessExtras.cleanupLogs(this,errors);
            if(!state.containsKey("mapping"))cleanup("table",()->{if(!backend.isDemo()&&backend.exists("table",state.get("table"))){if(!backend.owned("table",state.get("table"),run))throw new SecurityException("table tag mismatch");backend.delete("table",state.get("table"));}},errors);
            cleanup("bucket",()->{if(!backend.isDemo()&&backend.exists("bucket",state.get("bucket"))){if(!backend.owned("bucket",state.get("bucket"),run))throw new SecurityException("bucket tag mismatch");backend.emptyServerlessBucket(state.get("bucket"),run);backend.delete("bucket",state.get("bucket"));}},errors);
            if(!errors.isEmpty()){state.put("status","cleanup_failed");state.put("cleanup_errors",Jsons.encodeRaw(errors.stream().map(this::privateError).toList()));persist();var error=new IllegalStateException("serverless cleanup incomplete");errors.forEach(error::addSuppressed);throw error;}
            state.put("status","down");state.put("finished_at",Instant.now().toString());persist();return summary();
        }catch(RuntimeException error){throw error;}catch(Exception error){throw new IllegalStateException("cleanup scope failed",error);}
    }
    private String privateError(Throwable error){
        if(error instanceof software.amazon.awssdk.awscore.exception.AwsServiceException aws&&aws.awsErrorDetails()!=null)return aws.awsErrorDetails().errorCode()+": "+aws.awsErrorDetails().errorMessage();
        return error.getClass().getSimpleName()+": "+error.getMessage();
    }
    private void cleanup(String key,Runnable action,List<RuntimeException> errors){if(state.containsKey(key))try{action.run();state.remove(key);persist();}catch(RuntimeException error){errors.add(error);}}
    private java.math.BigDecimal invokeBound(long requests){
        var gb=new java.math.BigDecimal(state.getOrDefault("memory_mb","128")).divide(new java.math.BigDecimal("1024"));
        return java.math.BigDecimal.valueOf(requests).multiply(gb.multiply(new java.math.BigDecimal(state.getOrDefault("timeout_s","10"))).multiply(new java.math.BigDecimal("0.0000166667")).add(new java.math.BigDecimal("0.0000002")).add(new java.math.BigDecimal("16384").multiply(new java.math.BigDecimal("0.50")).divide(new java.math.BigDecimal("1073741824"),16,java.math.RoundingMode.CEILING)));
    }
    private java.math.BigDecimal workerBound(Map<String,Object> args){
        int memory=integer(args,"memory_mb",128),timeout=integer(args,"timeout_s",10);
        if(memory<1||memory>512||timeout<1||timeout>30)throw new IllegalArgumentException("worker execution caps exceeded");
        var gb=new java.math.BigDecimal(memory).divide(new java.math.BigDecimal("1024"));
        // 100 admitted API messages, at most three deliveries each, plus queue/log requests.
        return new java.math.BigDecimal("300").multiply(gb.multiply(new java.math.BigDecimal(timeout)).multiply(new java.math.BigDecimal("0.0000166667")).add(new java.math.BigDecimal("0.0000002")).add(new java.math.BigDecimal("0.000008"))).add(new java.math.BigDecimal("0.00064"));
    }
    private java.math.BigDecimal httpBound(long requests,long bytes){return invokeBound(requests).add(java.math.BigDecimal.valueOf(requests).multiply(new java.math.BigDecimal("0.000001"))).add(java.math.BigDecimal.valueOf(bytes).multiply(new java.math.BigDecimal("0.09")).divide(new java.math.BigDecimal("1073741824"),16,java.math.RoundingMode.CEILING));}
    private java.math.BigDecimal estimate(){
        if(backend.isDemo())return java.math.BigDecimal.ZERO;
        return new java.math.BigDecimal(state.getOrDefault("request_cost_prior","0")).add(accounted?java.math.BigDecimal.ZERO:cost.total()).add(new java.math.BigDecimal(state.getOrDefault("http_actual","0"))).add(new java.math.BigDecimal(state.getOrDefault("http_reserved","0"))).add(new java.math.BigDecimal(state.getOrDefault("event_execution_bound","0"))).add(new java.math.BigDecimal(state.getOrDefault("worker_execution_bound","0")));
    }
    private void enforceBudget(String op,Map<String,Object> args){
        if(backend.isDemo())return;
        var projected=estimate();if(op.equals("reserve_http"))projected=projected.add(httpBound(integer(args,"requests",0),integer(args,"bytes",0)));
        if(op.equals("worker")&&!state.containsKey("worker_execution_bound"))projected=projected.add(workerBound(args));
        if(op.equals("event"))projected=projected.add(invokeBound(20));
        if(projected.compareTo(new java.math.BigDecimal(state.getOrDefault("cost_cap",cost.cap().toPlainString())))>0)throw new CostLedger.BudgetExceeded("serverless whole-run cap exceeded before "+op);
    }
    public void close(){try{
        if(ready&&!accounted){var total=estimate();state.put("request_cost_prior",new java.math.BigDecimal(state.getOrDefault("request_cost_prior","0")).add(cost.total()).toPlainString());state.put("total_estimated_usd",total.toPlainString());accounted=true;persist();cost.serverlessSnapshot(total,Json.parse(state.get("price_table")),state.getOrDefault("status","new"));}
        if(lock!=null&&lock.isValid())lock.release();if(channel!=null&&channel.isOpen())channel.close();
    }catch(java.io.IOException error){throw new IllegalStateException("cannot release serverless state",error);}}
}
