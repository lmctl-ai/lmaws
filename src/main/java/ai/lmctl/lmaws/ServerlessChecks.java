package ai.lmctl.lmaws;

import java.math.BigDecimal;
import java.nio.file.*;

/** Persistence and failure-recovery checks that never construct live clients. */
public final class ServerlessChecks {
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("serverless-checks-");Path dir=root.resolve(".lmweblab-local");Files.createDirectories(dir);
        Path source=root.resolve("handler.py");Files.writeString(source,"def handler(event, context): return event\n");
        Path state=dir.resolve("state.json");var cost=new CostLedger("cafe03","serverless_checks","us-east-1",dir.resolve("cost.jsonl"),new BigDecimal("0.05"),true);
        String config=Jsons.encodeRaw(java.util.Map.of("source_file",source.toString(),"handler","handler.handler","memory_mb",128,"timeout_s",10));
        try(var backend=new AwsBackend("us-east-1",true,cost)){
            try(var run=new ServerlessRun(backend,cost,"cafe03","example.com",state.toString())){
                run.step("table","{}");run.step("bucket","{}");run.step("lambda",config);run.step("event","{}");
                var report=run.step("report","{}");if(!report.get("latest_json_body").contains("ok")||!"2".equals(report.get("table_items")))throw new AssertionError("report readback");
                run.step("reserve_http","{\"requests\":10,\"bytes\":1024}");run.step("record_http","{\"requests\":2,\"bytes\":100}");
                if(run.leftovers().size()!=5)throw new AssertionError("expected five simulated resource receipts including custom logs");
                String actualGroup=run.state.get("log_group");run.state.put("log_group","lmaws_foreign_logs_cafe03");refused(run::down);run.state.put("log_group",actualGroup);
            }
            try(var run=new ServerlessRun(backend,cost,"cafe03","example.com",state.toString())){
                if(!"up".equals(run.summary().get("status"))||run.leftovers().size()!=5)throw new AssertionError("close discarded up state");
                run.down();if(!run.leftovers().isEmpty())throw new AssertionError("cleanup receipts remain");run.down();
            }
            refused(()->new ServerlessRun(backend,cost,"dead04","example.com",state.toString()));
            refused(()->new ServerlessRun(backend,cost,"cafe03","different.example",state.toString()));
            Path failed=dir.resolve("failed.json");
            try(var run=new ServerlessRun(backend,cost,"cafe04","example.com",failed.toString())){
                run.step("table","{}");refused(()->run.step("lambda",Jsons.encodeRaw(java.util.Map.of("source_file",source.toString(),"role","other-role"))));
                if(!run.leftovers().isEmpty()||!"down".equals(run.summary().get("status")))throw new AssertionError("failed configuration skipped teardown");
            }
        }finally{try(var files=Files.walk(root)){for(Path file:files.sorted(java.util.Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}}
        System.out.println("PASS durable serverless demo reopen, exact ownership, idempotent down and failure cleanup");
    }
    private static void refused(Runnable op){try{op.run();}catch(RuntimeException expected){return;}throw new AssertionError("invalid operation accepted");}
}
