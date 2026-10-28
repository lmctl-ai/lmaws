package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Offline process-reopen and per-boot script regression checks. */
public final class ProvisionFlowChecks {
    @SuppressWarnings("unchecked") private static Map<String,Object> parse(String raw){return (Map<String,Object>)Json.parse(raw);}
    private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
    public static void main(String[] args) throws Exception {
        String id="flow-"+UUID.randomUUID().toString().substring(0,8);
        String cfg=Jsons.encodeRaw(Map.of("lmprov_id",id,"owner","test","purpose","offline","volume_gib",10));
        String volume;
        try(var backend=new AwsBackend("us-east-1",true)){
            var api=new Ec2Provision(backend);var made=parse(api.run(cfg));
            check(Boolean.TRUE.equals(made.get("ok")),"demo create");volume=(String)made.get("volume_id");
            var stop=parse(api.stop(id));check("stopped".equals(stop.get("state")),"stop confirmation");
        }
        try(var backend=new AwsBackend("us-east-1",true)){
            var api=new Ec2Provision(backend);check("stopped".equals(parse(api.describe(id)).get("state")),"state survived executor restart");
            check(Boolean.TRUE.equals(parse(api.dryRun(id,"start")).get("dry_run")),"start dry-run");
            check("stopped".equals(parse(api.describe(id)).get("state")),"dry-run changed state");
            var start=parse(api.start(id));check(volume.equals(start.get("volume_id")),"same root volume");
            check(parse(api.console(id)).get("output").toString().contains("boot=2"),"second boot");
            api.terminate(id);var verified=parse(api.verify(id));check(Boolean.TRUE.equals(verified.get("cleanup_complete")),"demo cleanup");
            var repeated=parse(api.run(cfg));check("terminated".equals(repeated.get("state")),"terminated id was recreated");
            var changed=parse(api.run(Jsons.encodeRaw(Map.of("lmprov_id",id,"volume_gib",20))));
            check(!Boolean.TRUE.equals(changed.get("ok")),"immutable config bypass");
            var cap=parse(api.run(Jsons.encodeRaw(Map.of("lmprov_id",id+"-cap","cap_usd",0))));check(!Boolean.TRUE.equals(cap.get("ok")),"zero cap admitted launch");
        }
        if(!System.getProperty("os.name","").toLowerCase(Locale.ROOT).contains("win")){
            Path dir=Files.createTempDirectory("lmprov-boot-");
            try{
                String script=Ec2Provision.bootScript(id).replace("/var/lib/lmprov",dir.resolve("state").toString()).replace("/dev/console",dir.resolve("console").toString());
                Path file=dir.resolve("boot.sh");Files.writeString(file,script);
                for(int n=1;n<=2;n++){
                    Process p=new ProcessBuilder("sh",file.toString()).redirectErrorStream(true).start();
                    check(p.waitFor(10,java.util.concurrent.TimeUnit.SECONDS)&&p.exitValue()==0,"boot script execution");
                    check(Files.readString(dir.resolve("console")).contains("LMPROV boot="+n+" id="+id),"boot counter console proof");
                }
                check(Files.readAllLines(dir.resolve("state/boots")).size()==2,"boots must append");
            }finally{try(var walk=Files.walk(dir)){for(Path file:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}}
        }else System.out.println("SKIP shell boot-counter execution on Windows; host demo boot proof is verified");
        System.out.println("PASS provisioning durable demo lifecycle, reattach, unchanged volume, boot script twice, cap and terminal-id idempotence");
    }
}
