package ai.lmctl.lmaws;
import java.nio.file.*;
import java.math.BigDecimal;
import java.util.Comparator;

/** Whole-run HTTP/Lambda admission and process-boundary regression; no SDK dispatch. */
public final class ServerlessAccountingChecks {
 public static void main(String[] args)throws Exception {
  Path root=Files.createTempDirectory("serverless-accounting-");Path dir=root.resolve(".lmweblab-local");Files.createDirectories(dir);Path state=dir.resolve("state.json");
  try {
   var first=new CostLedger("cafe01","first","us-east-1",dir.resolve("first.jsonl"),new BigDecimal("0.05"),false);
   BigDecimal before;
   try(var backend=new AwsBackend("us-east-1",false,first);var run=new ServerlessRun(backend,first,"cafe01","example.com",state.toString())){
    first.request("s3","GetObject");run.step("reserve_http","{\"requests\":100,\"bytes\":1000}");before=new BigDecimal(run.summary().get("estimated_cost_usd"));
    if(before.compareTo(new BigDecimal("0.002"))<0)throw new AssertionError("Lambda compute/log bound missing");
   }
   var second=new CostLedger("cafe01","second","us-east-1",dir.resolve("second.jsonl"),new BigDecimal("0.05"),false);
   try(var backend=new AwsBackend("us-east-1",false,second);var run=new ServerlessRun(backend,second,"cafe01","example.com",state.toString())){
    second.request("s3","GetObject");var total=new BigDecimal(run.summary().get("estimated_cost_usd"));if(total.compareTo(before)<=0)throw new AssertionError("prior process cost lost");
    run.step("record_http","{\"requests\":100,\"bytes\":1000}");
    if(new BigDecimal(run.summary().get("estimated_cost_usd")).compareTo(total)!=0)throw new AssertionError("HTTP bound counted twice or dropped");
   }
   var third=new CostLedger("cafe01","third","us-east-1",dir.resolve("third.jsonl"),new BigDecimal("0.05"),false);
   try(var backend=new AwsBackend("us-east-1",false,third);var run=new ServerlessRun(backend,third,"cafe01","example.com",state.toString())){
    if(!new BigDecimal(run.state.get("request_cost_prior")).equals(first.total().add(second.total())))throw new AssertionError("cumulative request cost reset");
   }
   var tiny=new CostLedger("cafe02","tiny","us-east-1",dir.resolve("tiny.jsonl"),new BigDecimal("0.000001"),false);
   try(var backend=new AwsBackend("us-east-1",false,tiny);var run=new ServerlessRun(backend,tiny,"cafe02","example.com",dir.resolve("tiny-state.json").toString())){
    try{run.step("reserve_http","{\"requests\":1}");throw new AssertionError("compute bound bypassed cap");}catch(CostLedger.BudgetExceeded expected){}
   }
   System.out.println("PASS cumulative serverless costs, Lambda/log execution bound, HTTP settlement and cap refusal without SDK dispatch");
  }finally{try(var files=Files.walk(root)){for(Path p:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
 }
}
