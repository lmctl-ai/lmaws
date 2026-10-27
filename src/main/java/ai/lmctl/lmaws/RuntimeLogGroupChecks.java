package ai.lmctl.lmaws;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.*;

/** Verify receipt-scoped late-log reconciliation without AWS credentials. */
public final class RuntimeLogGroupChecks {
 public static void main(String[] args)throws Exception {
  String group="lmaws_s04_logs_cafe04";var tags=new AtomicReference<Map<String,String>>(Map.of());var created=new AtomicLong(System.currentTimeMillis());var present=new AtomicBoolean(true);var function=new AtomicBoolean(false);var writes=new ArrayList<String>();
  var server=HttpServer.create(new InetSocketAddress("127.0.0.1",Integer.parseInt(System.getenv("LMAWS_TEST_PORT"))),0);
  server.createContext("/",e->{String target=e.getRequestHeaders().getFirst("X-Amz-Target"),path=e.getRequestURI().getPath();e.getRequestBody().readAllBytes();String out="{}";int status=200;
   if(path.contains("/functions/")){if(function.get())out="{\"Configuration\":{\"FunctionName\":\"lmaws_cafe04_fn\"}}";else{status=404;out="{\"__type\":\"ResourceNotFoundException\",\"message\":\"absent\"}";e.getResponseHeaders().add("x-amzn-ErrorType","ResourceNotFoundException");}}
   else if(target.endsWith("DescribeLogGroups"))out="{\"logGroups\":"+(present.get()?"[{\"logGroupName\":\""+group+"\",\"creationTime\":"+created.get()+"}]":"[]")+"}";
   else if(target.endsWith("ListTagsLogGroup"))out="{\"tags\":"+Jsons.encodeRaw(tags.get())+"}";
   else if(target.endsWith("TagLogGroup")){writes.add("tag");tags.set(Map.of("lmaws_test","cafe04"));}
   else if(target.endsWith("DeleteLogGroup")){writes.add("delete");present.set(false);}
   byte[] data=out.getBytes(StandardCharsets.UTF_8);e.getResponseHeaders().add("Content-Type","application/json");e.sendResponseHeaders(status,data.length);e.getResponseBody().write(data);e.close();
  });server.start();
  try(var backend=new AwsBackend("us-east-1",false)){
   Instant start=Instant.now().minusSeconds(60),end=Instant.now();
   refused(()->backend.reconcileRuntimeLogGroup(group,"cafe04",start,end,false));if(!writes.isEmpty())throw new AssertionError("adopted without ledger");
   tags.set(Map.of("lmaws_test","foreign"));refused(()->backend.reconcileRuntimeLogGroup(group,"cafe04",start,end,true));if(!writes.isEmpty())throw new AssertionError("modified foreign group");
   tags.set(Map.of());created.set(start.minusSeconds(1).toEpochMilli());refused(()->backend.reconcileRuntimeLogGroup(group,"cafe04",start,end,true));if(!writes.isEmpty())throw new AssertionError("adopted pre-existing group");
   created.set(Instant.now().toEpochMilli());function.set(true);refused(()->backend.reconcileRuntimeLogGroup(group,"cafe04",start,end,true));if(!writes.isEmpty())throw new AssertionError("reconciled active function");
   function.set(false);backend.reconcileRuntimeLogGroup(group,"cafe04",start,end,true);if(!writes.equals(List.of("tag","delete")))throw new AssertionError("missing receipt-scoped repair/delete");
   backend.reconcileRuntimeLogGroup(group,"cafe04",start,end,true);if(writes.size()!=2)throw new AssertionError("idempotent reconciliation changed absent group");
   System.out.println("PASS late runtime log repair only with ledger, creation window and absent function; foreign and pre-existing groups refused");
  }finally{server.stop(0);}
 }
 static void refused(Runnable operation){try{operation.run();}catch(SecurityException expected){return;}throw new AssertionError("unsafe reconciliation accepted");}
}
