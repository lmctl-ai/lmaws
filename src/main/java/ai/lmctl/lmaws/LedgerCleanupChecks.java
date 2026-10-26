package ai.lmctl.lmaws;

import java.nio.file.*;
import java.time.*;
import java.util.*;

/** No account access: proof planning and a separately opt-in demo-only recovery. */
final class LedgerCleanupChecks {
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static Map<String,String> event(String event,String id,String run,String name,Instant time){var r=new LinkedHashMap<String,String>();r.put("event",event);r.put("kind","queue");r.put("id",id);r.put("name",name);r.put("run_id",run);r.put("action",event.equals("intent")?"create":"create");r.put("state","active");r.put("time",time.toString());return r;}
    private static Path ledger(Path directory,String run,String name,Instant created)throws Exception {Path p=directory.resolve("lmaws-"+run+".jsonl");Files.writeString(p,Jsons.encodeRaw(event("intent",name,run,name,created))+"\n"+Jsons.encodeRaw(event("created",name,run,name,created))+"\n");return p;}
    static void run() {
        try {
            Path dir=Files.createTempDirectory("lmaws-recovery-proof-").toRealPath();String run="rproof",name="lmaws_rproof_queue";Instant now=Instant.now(),old=now.minus(Duration.ofHours(72));Path file=ledger(dir,run,name,old);
            try(var locked=java.nio.channels.FileChannel.open(file,StandardOpenOption.READ,StandardOpenOption.WRITE);var held=locked.lock()) {
                check(LedgerCleanup.proofs(file,locked).size()==1,"exclusive owner reads proof through its locked channel");
            }
            Map<String,String> row=new LinkedHashMap<>(Map.of("kind","queue","name",name,"id",name,"created_at",old.toString(),"lmaws_test","true","run_id",run));
            var candidate=LedgerCleanup.plan(List.of(row),dir,"lmaws",24,now);check(candidate.size()==1&&candidate.get(0).row().get("eligible_for_delete").equals("true"),"valid proof was not eligible");
            // A link at the ledger directory or file is refused; trusted ancestors (macOS /var) are not checked.
            if(!System.getProperty("os.name","").toLowerCase(java.util.Locale.ROOT).contains("win")) {
                Path linkedDir=dir.resolveSibling(dir.getFileName()+"-link");Files.createSymbolicLink(linkedDir,dir);
                boolean dirRefused=false;try{LedgerCleanup.directoryProofs(linkedDir);}catch(IllegalStateException e){dirRefused=e.getMessage().contains("symlink");}
                check(dirRefused,"symlinked ledger directory was accepted");
                Path linkedFile=dir.resolve("lmaws-rlinked.jsonl");Files.createSymbolicLink(linkedFile,file);
                boolean fileRefused=false;try{LedgerCleanup.proofs(linkedFile);}catch(IllegalStateException e){fileRefused=e.getMessage().contains("symlink");}
                check(fileRefused,"symlinked ledger file was accepted");
                Files.delete(linkedFile);Files.delete(linkedDir);
            }
            for(var change:List.of(Map.of("lmaws_test","false"),Map.of("run_id","other"),Map.of("name","lmaws_rproof_other"))) {var bad=new LinkedHashMap<>(row);bad.putAll(change);check(!LedgerCleanup.plan(List.of(bad),dir,"lmaws",24,now).get(0).row().get("eligible_for_delete").equals("true"),"unowned candidate became eligible");}
            var young=new LinkedHashMap<>(row);young.put("created_at",now.toString());check(LedgerCleanup.plan(List.of(young),dir,"lmaws",24,now).isEmpty(),"young resource was swept");
            check(LedgerCleanup.plan(List.of(row),dir,"different",0,now).isEmpty(),"foreign prefix was adopted");
            try(RunLease active=RunLease.owner(file)){check(!LedgerCleanup.plan(List.of(row),dir,"lmaws",0,now).get(0).row().get("eligible_for_delete").equals("true"),"active run was swept");try{RunLease.recovery(file);throw new AssertionError("active run lock ignored");}catch(IllegalStateException expected){}}
            check(LedgerCleanup.plan(List.of(row),dir,"lmaws",0,now).get(0).row().get("eligible_for_delete").equals("true"),"released run remained locked");
            if (!System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")) {
                Path alias=dir.resolveSibling(dir.getFileName()+"-alias");
                try {
                    Files.createSymbolicLink(alias,dir);
                    check(LedgerCleanup.plan(List.of(row),dir,"lmaws",0,now).get(0).row().get("eligible_for_delete").equals("true"),"canonical temp directory accepted");
                    try { LedgerCleanup.plan(List.of(row),alias,"lmaws",0,now); throw new AssertionError("symlink ledger directory accepted"); }
                    catch (IllegalStateException expected) { check(expected.getMessage().contains("symlink ledger paths"),"symlink rejection reason"); }
                } catch (UnsupportedOperationException ignored) { }
                finally { Files.deleteIfExists(alias); }
            }
            Files.writeString(file,"{broken",StandardOpenOption.APPEND);try{LedgerCleanup.plan(List.of(row),dir,"lmaws",0,now);throw new AssertionError("torn proof accepted");}catch(RuntimeException expected){}
            Path noIntent=Files.createTempDirectory("lmaws-no-intent-").toRealPath();Files.writeString(noIntent.resolve("lmaws-unproven.jsonl"),Jsons.encodeRaw(event("created",name,run,name,old))+"\n");try{LedgerCleanup.plan(List.of(row),noIntent,"lmaws",0,now);throw new AssertionError("unconfirmed resource adopted");}catch(RuntimeException expected){}
        }catch(Exception e){throw new IllegalStateException(e);}
    }
    public static void main(String[] args)throws Exception {
        run();
        if(!"lmaws".equals(AwsBackend.activeProfile())||!"1".equals(System.getenv("LMAWS_LIVE")))throw new IllegalStateException("demo recovery check needs explicit test flags");
        Path dir=Files.createTempDirectory("lmaws-demo-recovery-").toRealPath();String run="rrecover",name="lmaws_rrecover_queue";
        // Explicit demo=true: no AWS client or credential provider is ever constructed.
        try(AwsBackend backend=new AwsBackend("us-east-1",true)) {
            backend.create("queue",name,"",run);ledger(dir,run,name,Instant.now().minusSeconds(1));
            var dry=LedgerCleanup.execute(backend,dir,"lmaws_rrecover",0,false);check(dry.size()==1&&dry.get(0).get("eligible_for_delete").equals("true"),"demo plan mismatch");check(backend.exists("queue",name),"dry-run mutated fixture");
            var result=LedgerCleanup.execute(backend,dir,"lmaws_rrecover",0,true);check(result.size()==1&&result.get(0).get("status").equals("deleted"),"demo cleanup failed");check(!backend.exists("queue",name),"demo object survived cleanup");check(LedgerCleanup.directoryProofs(dir).isEmpty(),"confirmed deletion not reflected in original ledger");
        }
        System.out.println("PASS recovery proofs, active-run leases, dry-run and demo deletion; no AWS calls");
    }
}
