package ai.lmctl.lmaws;
import java.nio.file.*;import java.math.BigDecimal;import java.util.*;
/** Offline persistence, invalid configuration and complete queue dependency teardown. */
public final class RemainingChecks {
 public static void main(String[] args)throws Exception {
  Path root=Files.createTempDirectory("remaining-checks-");Path dir=root.resolve(".lmweblab-local");Files.createDirectories(dir);
  Path source=root.resolve("api.py");Files.writeString(source,"def handler(event,context):return {}\n");
  var cost=new CostLedger("cafe07","remaining","us-east-1",dir.resolve("cost.jsonl"),new BigDecimal("0.05"),false);
  String config=Jsons.encodeRaw(Map.of("source_file",source.toString(),"handler","api.handler","memory_mb",128,"timeout_s",10));
  try(var backend=new AwsBackend("us-east-1",true,cost)) {
   Path state=dir.resolve("state.json");
   try(var run=new ServerlessRun(backend,cost,"cafe07","example.com",state.toString())) {
    String uploadEnv=ServerlessExtras.environment(run,io.lmctl.lmcode.Json.object(io.lmctl.lmcode.Json.parse("{\"max_upload_bytes\":1048576,\"upload_expiry_seconds\":10,\"content_types\":\"image/png\"}")));
    if(!uploadEnv.contains("MAX_UPLOAD_BYTES")||!uploadEnv.contains("1048576")||!uploadEnv.contains("UPLOAD_EXPIRY_SECONDS")||!uploadEnv.contains("10")||uploadEnv.contains("1048576.0")||uploadEnv.contains("10.0"))throw new AssertionError("numeric upload environment was not canonicalized: "+uploadEnv);
    refused(() -> ServerlessExtras.environment(run,Map.of("max_upload_bytes",1.5)));
    refused(() -> ServerlessExtras.environment(run,Map.of("upload_expiry_seconds",901.0)));
    run.step("table","{}");
    String code=ServerlessExtras.workerSource(run,source);
    if(!code.contains("os.environ['RUN_ID']=\"cafe07\"")||!code.contains("os.environ['TABLE_NAME']=\"lmaws_cafe07_table\""))throw new AssertionError("worker source lost its run/table environment");
    run.step("queues","{}");run.step("lambda",config);run.step("worker",config);
    var pendingErrors=new java.util.ArrayList<RuntimeException>();ServerlessExtras.cleanupLogs(run,pendingErrors);
    if(!run.state.containsKey("worker_logs")||!pendingErrors.isEmpty())throw new AssertionError("worker logs drained while functions remained active");
    if(run.leftovers().size()!=8)throw new AssertionError("expected table, queues, two functions/logs and mapping receipts: "+run.leftovers());
   }
   try(var run=new ServerlessRun(backend,cost,"cafe07","example.com",state.toString())) {
    if(!run.summary().get("mapping").contains("event-source-mapping"))throw new AssertionError("mapping was not durable");
    run.down();run.down();
    String receipt=run.state.get("worker_log_receipt");run.state.put("worker_log_receipt","lmaws_foreign_logs_cafe07");boolean refused=false;
    try{ServerlessExtras.cleanupLogs(run,new java.util.ArrayList<>());}catch(SecurityException expected){refused=true;}finally{run.state.put("worker_log_receipt",receipt);}
    if(!refused)throw new AssertionError("forged worker log receipt accepted");
    if(!run.leftovers().isEmpty())throw new AssertionError("queue cleanup incomplete");
   }
   try(var web=new WebRun(backend,cost,"cafe12","example.com",dir.resolve("web.json").toString())) {
    web.step("bucket","{}");web.step("distribution","{}");web.step("cache","{\"default_ttl\":30,\"max_ttl\":60}");web.down();
   }
  }finally{try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
  System.out.println("PASS durable queue/worker reopen, ordered teardown, repeat down and bounded static cache");
 }
 private static void refused(Runnable op){try{op.run();}catch(RuntimeException expected){return;}throw new AssertionError("invalid upload environment accepted");}
}
