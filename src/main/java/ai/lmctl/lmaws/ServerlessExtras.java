package ai.lmctl.lmaws;

import java.nio.file.*;
import java.util.*;

/** Queue-worker additions use the same durable intent journal and ownership as serverless stacks. */
final class ServerlessExtras {
    private ServerlessExtras() {}
    static String environment(ServerlessRun run,Map<String,Object> args) {
        var env=new LinkedHashMap<String,String>();
        env.put("QUEUE_URL",run.state.getOrDefault("queue",""));env.put("DLQ_URL",run.state.getOrDefault("dlq",""));
        for(String key:List.of("MAX_UPLOAD_BYTES","UPLOAD_EXPIRY_SECONDS","CONTENT_TYPES")) {
            Object v=args.get(key.toLowerCase(Locale.ROOT));if(v!=null)env.put(key,String.valueOf(v));
        }
        if(args.containsKey("upload_bucket")) {
            String bucket=String.valueOf(args.get("upload_bucket"));
            if(!bucket.equals("lmaws-site-"+run.run))throw new SecurityException("upload bucket outside this run");
            if(!run.backend.isDemo()&&!run.backend.owned("bucket",bucket,run.run))throw new SecurityException("upload bucket tag mismatch");
            env.put("BUCKET_NAME",bucket);
        }
        String password=System.getenv("LMWEBLAB_DEMO_PASSWORD");
        if(password!=null&&!password.isEmpty()){if(password.length()>256)throw new IllegalArgumentException("demo password too long");env.put("LMWEBLAB_DEMO_PASSWORD",password);}
        String prefix="";
        for(var entry:env.entrySet())prefix+="os.environ["+Jsons.encodeRaw(entry.getKey())+"]="+Jsons.encodeRaw(entry.getValue())+"\n";
        return prefix;
    }
    static void step(ServerlessRun run,String op,Map<String,Object> args) throws java.io.IOException {
        var b=run.backend;var s=run.state;
        if(op.equals("queues")) {
            for(String key:List.of("dlq","queue")) {
                if(s.containsKey(key))continue;
                String name="lmaws_"+run.run+"_"+key;
                if(!b.isDemo()&&b.exists("queue",name))throw new SecurityException("refusing existing queue");
                // Intent records the exact prospective name before CreateQueue for recovery.
                s.put(key,name);run.persist();
                var created=b.create("queue",name,"",run.run);s.put(key,created.get("id"));run.persist();
            }
            b.setSqsRedrive(s.get("queue"),s.get("dlq"),run.run);
        } else {
            if(!s.containsKey("queue")||!s.containsKey("table"))throw new IllegalStateException("worker requires queues and table");
            String name="lmaws_"+run.run+"_worker",log="lmaws_s07_worker_logs_"+run.run;
            Path source=Path.of(String.valueOf(args.get("source_file")));
            String code=workerSource(run,source);
            String role=String.valueOf(args.getOrDefault("role","lmaws_lambda_exec"));
            String runtime=String.valueOf(args.getOrDefault("runtime","python3.12"));
            String handler=String.valueOf(args.getOrDefault("handler","worker.handler"));
            int memory=integer(args,"memory_mb",128,512),timeout=integer(args,"timeout_s",5,30);
            new LambdaFunction(name,role,runtime,handler,code,memory,timeout,run.run);
            s.put("worker_name",name);s.put("worker_logs",log);run.persist();
            String arn=b.isDemo()?"arn:aws:lambda:local:000000000000:function:"+name:b.createLambda(name,role,runtime,handler,code,memory,timeout,run.run,log).get("arn");
            s.put("worker_arn",arn);run.persist();if(!b.isDemo())b.waitLambdaActive(arn,run.run,120);
            var mapping=b.createEventSourceMapping(s.get("queue"),arn,1,run.run);
            s.put("mapping",mapping.status().get("id"));run.persist();
        }
    }
    static String workerSource(ServerlessRun run,Path source) throws java.io.IOException {
        if(!Files.isRegularFile(source)||Files.size(source)>196608)throw new IllegalArgumentException("bounded worker source required");
        return "import os\nos.environ['RUN_ID']="+Jsons.encodeRaw(run.run)+"\nos.environ['TABLE_NAME']="+Jsons.encodeRaw(run.state.get("table"))+"\n"+Files.readString(source);
    }
    private static int integer(Map<String,Object> args,String key,int fallback,int max) {
        Object raw=args.getOrDefault(key,fallback);double n=raw instanceof Number v?v.doubleValue():Double.parseDouble(raw.toString());
        if(!Double.isFinite(n)||n!=Math.rint(n)||n<1||n>max)throw new IllegalArgumentException("invalid worker "+key);return(int)n;
    }
    static void down(ServerlessRun run,List<RuntimeException> errors) {
        if(!run.backend.isDemo()&&run.state.containsKey("intent_worker")&&run.state.containsKey("worker_arn")&&!run.state.containsKey("mapping")) {
            try { for(var mapping:run.backend.findEventSourceMappings(run.run)){run.state.put("mapping",mapping.get("id"));run.persist();run.backend.deleteEventSourceMapping(mapping.get("id"),run.run);run.state.remove("mapping");run.persist();} }
            catch(RuntimeException e){errors.add(e);return;}
        }
        cleanup(run,"mapping",()->run.backend.deleteEventSourceMapping(run.state.get("mapping"),run.run),errors);
        // Keep dependent queues/functions if mapping removal fails.
        if(run.state.containsKey("mapping"))return;
        cleanup(run,"worker_name",()->{run.backend.deleteOwnedWorker(run.state.get("worker_name"),run.run);run.state.remove("worker_arn");},errors);
        cleanup(run,"worker_logs",()->run.backend.deleteLambdaLogGroup(run.state.get("worker_logs"),run.run),errors);
        for(String key:List.of("queue","dlq"))cleanup(run,key,()->{
            String id=run.state.get(key);
            if(run.backend.exists("queue",id)) {
                if(!run.backend.owned("queue",id,run.run))throw new SecurityException("queue tag mismatch");
                if(key.equals("queue"))run.backend.clearSqsRedrive(id,run.run);
                run.backend.delete("queue",id);
            }
        },errors);
    }
    private static void cleanup(ServerlessRun run,String key,Runnable action,List<RuntimeException> errors) {
        if(!run.state.containsKey(key))return;
        try{action.run();run.state.remove(key);run.persist();}catch(RuntimeException e){errors.add(e);}
    }
}
