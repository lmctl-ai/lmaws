package ai.lmctl.lmaws;

import java.nio.file.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import io.lmctl.lmcode.Json;

/** Account discovery is never adoption: deletion also requires original creation proof. */
final class LedgerCleanup {
    private static final Set<String> KINDS=Set.of("bucket","queue","topic","parameter","table","log_group");
    private static final int MAX_FILES=4096, MAX_RESOURCES=10000;
    record Owned(Path ledger,String kind,String id,String name,String run,Instant created) {}
    record Candidate(Map<String,String> row,Owned proof) {}
    private LedgerCleanup() {}

    static List<Map<String,String>> execute(AwsBackend backend,Path directory,String prefix,long hours,boolean apply) {
        if(prefix==null||prefix.isBlank()||prefix.length()>128||hours<0)throw new IllegalArgumentException("prefix and non-negative age are required");
        if(apply && (!"1".equals(System.getenv("LMAWS_LIVE"))||!"lmaws".equals(AwsBackend.activeProfile())))
            throw new IllegalStateException("delete mode requires LMAWS_LIVE=1 and AWS_PROFILE=lmaws");
        List<Map<String,String>> discovered;
        if(apply && !backend.isDemo()) {
            try(AwsBackend reader=backend.defaultReader()) {
                if(!backend.sameAccount(reader))throw new IllegalStateException("default and lmaws target different accounts; delete refused");
                discovered=reader.findPrefix(prefix);
            }
        } else discovered=backend.findPrefix(prefix);
        for(var row:discovered)if(!"ok".equals(row.getOrDefault("status","ok")))throw new IllegalStateException("account search incomplete; deletion refused");
        List<Candidate> plan=plan(discovered,directory,prefix,hours,Instant.now());
        List<Map<String,String>> out=new ArrayList<>();
        for(var candidate:plan)out.add(new LinkedHashMap<>(candidate.row));
        if(!apply)return out;
        // This is printed before the first mutation. Public serialization masks account identifiers.
        System.out.println("cleanup dry-run plan: "+Jsons.encode(out));
        for(int index=0;index<plan.size();index++) {
            Candidate candidate=plan.get(index);Map<String,String> row=out.get(index);
            if(!"true".equals(row.get("eligible_for_delete")))continue;
            Owned proof=candidate.proof;
            try(RunLease runLease=RunLease.recovery(proof.ledger); FileChannel channel=FileChannel.open(proof.ledger,StandardOpenOption.READ,StandardOpenOption.WRITE);
                FileLock lock=channel.tryLock()) {
                if(lock==null)throw new IllegalStateException("ledger is busy");
                // Re-read the proof after taking the lock; stale plans never authorize a delete.
                Owned current=proofs(proof.ledger).get(key(proof.kind,proof.id));
                if(current==null||!current.equals(proof))throw new IllegalStateException("ledger proof changed after planning");
                if(!proof.name.startsWith(prefix)||!backend.owned(proof.kind,proof.id,proof.run))throw new IllegalStateException("provider ownership changed after planning");
                append(channel,proof,"recovery_delete_intent","active");
                backend.delete(proof.kind,proof.id);
                long deadline=System.nanoTime()+Duration.ofSeconds(30).toNanos();
                while(backend.exists(proof.kind,proof.id)) {
                    if(System.nanoTime()>=deadline)throw new IllegalStateException("deletion is not yet confirmed");
                    try{Thread.sleep(250);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("cleanup interrupted");}
                }
                append(channel,proof,"deleted","deleted");
                row.put("status","deleted");row.put("provider_absent","true");
            } catch(Exception failure) {
                row.put("status","delete_failed");row.put("provider_absent","unknown");
                row.put("reason",failure.getClass().getSimpleName());
                // Preserve the row and the original ledger for explicit recovery; no false zero.
            }
        }
        return out;
    }

    static List<Candidate> plan(List<Map<String,String>> discovered,Path directory,String prefix,long hours,Instant now) {
        if(discovered.isEmpty())return List.of();
        Map<String,Owned> owned=directoryProofs(directory);
        List<Candidate> out=new ArrayList<>();
        for(var resource:discovered) {
            Map<String,String> row=new LinkedHashMap<>(resource);
            String kind=row.getOrDefault("kind",row.getOrDefault("resource_type",""));
            String name=row.getOrDefault("name","");String id=row.getOrDefault("id","");
            if(!name.startsWith(prefix))continue;
            Owned proof=owned.get(key(kind,id));
            Instant created=parseTime(row.get("created_at"));
            if(proof!=null && (created==null||created.isBefore(proof.created)))created=proof.created;
            if(created!=null && Duration.between(created,now).compareTo(Duration.ofHours(hours))<0)continue;
            String reason="";
            if(created==null)reason="creation age unavailable";
            else if(!KINDS.contains(kind))reason="resource type is read-only in this host";
            else if(proof==null)reason="no confirmed active creation in a run ledger";
            else if(RunLease.busy(proof.ledger))reason="run ledger is active";
            else if(!name.equals(proof.name))reason="ledger name mismatch";
            else if(!"true".equals(row.get("lmaws_test"))||!proof.run.equals(row.get("run_id")))reason="exact lmaws_test run tag mismatch";
            row.put("eligible_for_delete",Boolean.toString(reason.isEmpty()));
            row.put("status",created==null?"age_unknown":"dry_run");
            row.put("reason",reason.isEmpty()?"prefix, age, provider tag and active creation ledger match":reason);
            if(proof!=null)row.put("ledger",proof.ledger.toString());
            row.put("age_hours",created==null?"":Long.toString(Math.max(0,Duration.between(created,now).toHours())));
            out.add(new Candidate(row,proof));
            if(out.size()>MAX_RESOURCES)throw new IllegalStateException("cleanup plan exceeds resource limit");
        }
        return out;
    }

    static Map<String,Owned> directoryProofs(Path directory) {
        Map<String,Owned> out=new LinkedHashMap<>();
        if(directory==null||!Files.exists(directory))return out;
        rejectLinks(directory);
        try(var files=Files.list(directory)) {
            var paths=files.filter(p->p.getFileName().toString().startsWith("lmaws-")&&p.toString().endsWith(".jsonl")).limit(MAX_FILES+1).toList();
            if(paths.size()>MAX_FILES)throw new IllegalStateException("too many ledgers");
            for(Path path:paths) {
                for(var entry:proofs(path).entrySet()) {
                    Owned old=out.putIfAbsent(entry.getKey(),entry.getValue());
                    if(old!=null&&!old.equals(entry.getValue()))throw new IllegalStateException("ambiguous resource appears in multiple run ledgers");
                }
                if(out.size()>MAX_RESOURCES)throw new IllegalStateException("too many ledger resources");
            }
        }catch(java.io.IOException e){throw new IllegalStateException("cannot read ledger directory",e);}
        return out;
    }

    static Map<String,Owned> proofs(Path path) {
        rejectLinks(path);
        try {
            if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)>1024*1024)throw new IllegalStateException("ledger is not a bounded regular file");
            Map<String,Owned> result=new LinkedHashMap<>();Set<String> intents=new HashSet<>();
            for(String line:Files.readAllLines(path)) {
                if(line.isBlank())continue;
                Map<String,Object> row=Json.object(Json.parse(line));
                String event=text(row,"event");if(event.startsWith("cost_"))continue;
                String kind=text(row,"kind"),id=text(row,"id"),run=text(row,"run_id"),action=text(row,"action");
                if(!run.matches("[a-z0-9]{1,24}")||!KINDS.contains(kind))throw new IllegalStateException("invalid ledger ownership record");
                if(event.equals("intent")&&action.equals("create"))intents.add(kind+"\u0000"+id+"\u0000"+run);
                if(event.equals("created")) {
                    String name=text(row,"name");Instant when=parseTime(text(row,"time"));
                    String expected=kind.equals("bucket")?"lmaws-"+run+"-":"lmaws_"+run+"_";
                    if(when==null||!name.startsWith(expected)||!intents.contains(kind+"\u0000"+name+"\u0000"+run))throw new IllegalStateException("creation lacks original matching intent");
                    result.put(key(kind,id),new Owned(path.toAbsolutePath().normalize(),kind,id,name,run,when));
                }
                if(event.equals("deleted")||event.equals("not_created"))result.remove(key(kind,id));
            }
            return result;
        }catch(java.io.IOException e){throw new IllegalStateException("cannot read run ledger",e);}
    }
    private static String text(Map<String,Object> row,String name){Object value=row.get(name);return value instanceof String s?s:"";}
    private static Instant parseTime(String value){try{return value==null||value.isBlank()?null:Instant.parse(value);}catch(RuntimeException e){return null;}}
    private static String key(String kind,String id){return kind+"\u0000"+id;}
    private static void rejectLinks(Path path){Path absolute=path.toAbsolutePath().normalize(),p=absolute.getRoot();for(Path part:absolute){p=p.resolve(part);if(Files.isSymbolicLink(p))throw new IllegalStateException("symlink ledger paths are not accepted");}}

    private static void append(FileChannel channel,Owned proof,String event,String state)throws java.io.IOException {
        var row=new LinkedHashMap<String,String>();row.put("time",Instant.now().toString());row.put("event",event);row.put("kind",proof.kind);row.put("id",proof.id);row.put("name",proof.name);row.put("run_id",proof.run);row.put("state",state);row.put("action","delete");
        channel.position(channel.size());var bytes=java.nio.ByteBuffer.wrap((Jsons.encodeRaw(row)+"\n").getBytes(StandardCharsets.UTF_8));while(bytes.hasRemaining())channel.write(bytes);channel.force(true);
    }
}
