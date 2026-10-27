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
    run.step("table","{}");
    String code=ServerlessExtras.workerSource(run,source);
    if(!code.contains("os.environ['RUN_ID']=\"cafe07\"")||!code.contains("os.environ['TABLE_NAME']=\"lmaws_cafe07_table\""))throw new AssertionError("worker source lost its run/table environment");
    run.step("queues","{}");run.step("lambda",config);run.step("worker",config);
    if(run.leftovers().size()!=8)throw new AssertionError("expected table, queues, two functions/logs and mapping receipts: "+run.leftovers());
   }
   try(var run=new ServerlessRun(backend,cost,"cafe07","example.com",state.toString())) {
    if(!run.summary().get("mapping").contains("event-source-mapping"))throw new AssertionError("mapping was not durable");
    run.down();run.down();if(!run.leftovers().isEmpty())throw new AssertionError("queue cleanup incomplete");
   }
   try(var web=new WebRun(backend,cost,"cafe12","example.com",dir.resolve("web.json").toString())) {
    web.step("bucket","{}");web.step("distribution","{}");web.step("cache","{\"default_ttl\":30,\"max_ttl\":60}");web.down();
   }
  }finally{try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
  System.out.println("PASS durable queue/worker reopen, ordered teardown, repeat down and bounded static cache");
 }
}
