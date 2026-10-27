package ai.lmctl.lmaws;

import java.math.BigDecimal;
import java.nio.file.Files;

/** Offline contract checks for SQS/Lambda mapping and redrive lifecycle. */
public final class QueueWorkerChecks {
    public static void main(String[] args) throws Exception {
        var dir=Files.createTempDirectory("queue-worker-");
        var cost=new CostLedger("cafe07","queue_worker","us-east-1",dir.resolve("cost.jsonl"),new BigDecimal("0.05"),true);
        try(var backend=new AwsBackend("us-east-1",true,cost)) {
            var w=backend.createEventSourceMapping("lmaws_cafe07_source","arn:aws:lambda:local:000000000000:function:lmaws_cafe07_worker",10,"cafe07");
            if(!"Enabled".equals(w.status().get("state"))) throw new AssertionError("mapping state");
            var resumed=backend.resumeEventSourceMapping(w.status().get("id"),"cafe07");
            resumed.delete(); resumed.delete();
            backend.setSqsRedrive("lmaws_cafe07_source","lmaws_cafe07_dlq","cafe07");
            backend.clearSqsRedrive("lmaws_cafe07_source","cafe07");
            refused(()->backend.createEventSourceMapping("source","fn",0,"cafe07"));
            refused(()->backend.createEventSourceMapping("foreign","arn:aws:lambda:local:000000000000:function:lmaws_safe",1,"cafe07"));
            refused(()->backend.createEventSourceMapping("lmaws_safe","arn:aws:lambda:local:000000000000:function:foreign",1,"cafe07"));
            refused(()->backend.setSqsRedrive("same","same","cafe07"));
        }
        System.out.println("PASS offline SQS mapping, durable resume, idempotent delete and DLQ redrive guards");
    }
    private static void refused(Runnable r){try{r.run();}catch(RuntimeException ok){return;}throw new AssertionError("invalid input accepted");}
}
