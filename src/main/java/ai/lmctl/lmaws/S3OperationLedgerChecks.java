package ai.lmctl.lmaws;
import java.math.BigDecimal;import java.nio.file.*;import java.util.*;
/** Pure persistence/cap checks for the S3 operation ledger; no SDK or credentials. */
public final class S3OperationLedgerChecks {
  private static void ok(boolean value,String message){if(!value)throw new AssertionError(message);}
  public static void main(String[] args)throws Exception{
    if(args.length>0){try(S3OperationLedger child=S3OperationLedger.open("concurrent",Path.of(args[1]),new BigDecimal("0.00005"),"us-east-1")){for(int i=0;i<20;i++){try{child.recordAttempt("PutObject");}catch(CostLedger.BudgetExceeded expected){break;}}}return;}
    Path dir=Files.createTempDirectory("lmaws-s3-ledger-");
    try(S3OperationLedger first=S3OperationLedger.open("run01",dir,new BigDecimal("0.00001"),"us-east-1")){first.recordAttempt("PutObject");first.recordAttempt("HeadObject");first.bindBucket("lmaws-fixture-bucket","run01");}
    try(S3OperationLedger restarted=S3OperationLedger.open("run01",dir,new BigDecimal("0.00001"),"us-east-1")){Map<String,Object> s=restarted.summaryMap();ok(((Number)s.get("attempts")).longValue()==2,"restart must retain attempts");ok(((Map<?,?>)s.get("by_operation")).containsKey("PutObject"),"operation summary");try{restarted.recordAttempt("PutObject");throw new AssertionError("cap must persist across restart");}catch(CostLedger.BudgetExceeded expected){}}
    try{S3OperationLedger.open("run01",dir,new BigDecimal("0.00003"),"us-east-1");throw new AssertionError("cap increase accepted");}catch(IllegalArgumentException expected){}
    try{S3OperationLedger.open("../bad",dir);throw new AssertionError("unsafe run accepted");}catch(IllegalArgumentException expected){}
    try(S3OperationLedger summary=S3OperationLedger.open("empty",dir)){ok(((Number)summary.summaryMap().get("attempts")).longValue()==0,"empty summary must make no SDK calls");}
    Path torn=dir.resolve("torn-s3-operations.jsonl");Files.writeString(torn,"{\"event\":\"header\"}\n{\"event\":\"attempt\"}");try{S3OperationLedger.open("torn",dir);throw new AssertionError("torn ledger accepted");}catch(IllegalStateException expected){}
    try(S3OperationLedger bucket=S3OperationLedger.open("bucket",dir)){try{bucket.bindBucket("other-bucket","bucket");throw new AssertionError("foreign bucket bound");}catch(SecurityException expected){}}
    String emptySummary=S3OperationLedger.summary("nevercreated",dir);ok(emptySummary.contains("\"attempts\":0"),"pure summary of absent run");ok(!Files.exists(dir.resolve("nevercreated-s3-operations.jsonl")),"summary must not create a run");
    try(S3OperationLedger older=S3OperationLedger.open("lowered",dir)){older.recordAttempt("PutObject");try(S3OperationLedger lower=S3OperationLedger.open("lowered",dir,new BigDecimal("0.000005"),"us-east-1")){try{older.recordAttempt("HeadObject");throw new AssertionError("old handle ignored lower persisted cap");}catch(CostLedger.BudgetExceeded expected){}}}
    String javaExecutable=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").toLowerCase().contains("win")?"java.exe":"java").toString();
    Process one=new ProcessBuilder(javaExecutable,"-cp",System.getProperty("java.class.path"),S3OperationLedgerChecks.class.getName(),"child",dir.toString()).start();
    Process two=new ProcessBuilder(javaExecutable,"-cp",System.getProperty("java.class.path"),S3OperationLedgerChecks.class.getName(),"child",dir.toString()).start();
    ok(one.waitFor(30,java.util.concurrent.TimeUnit.SECONDS)&&two.waitFor(30,java.util.concurrent.TimeUnit.SECONDS),"concurrent children timed out");ok(one.exitValue()==0&&two.exitValue()==0,"concurrent ledger process failed");
    try(S3OperationLedger concurrent=S3OperationLedger.open("concurrent",dir,new BigDecimal("0.00005"),"us-east-1")){ok(((Number)concurrent.summaryMap().get("attempts")).longValue()==10,"concurrent processes overspent or duplicated the header");}
    System.out.println("PASS persistent S3 ledger restart, fsync journal, cap refusal, malformed/torn fail-closed, bucket guard and zero-SDK summary");
  }
}
