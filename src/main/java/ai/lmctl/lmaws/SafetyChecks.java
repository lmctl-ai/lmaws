package ai.lmctl.lmaws;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Small dependency-free regression checks for the destructive-operation guard. */
public final class SafetyChecks {
    private SafetyChecks() {}

    public static void run() throws Exception {
        Path dir = Files.createTempDirectory("lmaws-safety-").toRealPath();
        AwsBackend backend = new AwsBackend("us-east-1", true);
        Sandbox box = new Sandbox(backend, "check01", dir);
        Map<String, String> resource = box.create("parameter", "sample", "secret-value");
        check(resource.get("name").startsWith("lmaws_check01_"), "resource prefix");
        box.put(resource, "description", "safe");
        check(box.remaining() == 1, "ledger count");
        boolean foreignRejected = false;
        try { box.put(Map.of("kind", "parameter", "id", "demo-parameters"), "x", "y"); }
        catch (IllegalArgumentException expected) { foreignRejected = true; }
        check(foreignRejected, "foreign resource rejected");
        box.cleanup();
        check(box.remaining() == 0, "cleanup");
        boolean closedRejected = false;
        box.close();
        try { box.create("parameter", "again", "x"); }
        catch (IllegalStateException expected) { closedRejected = true; }
        check(closedRejected, "closed sandbox rejected");
        check(Sandbox.leftovers(dir, 0).isEmpty(), "no leftovers");
        boolean duplicateRejected = false;
        try { new Sandbox(backend, "check01", dir.resolve("duplicate.jsonl")); new Sandbox(backend, "check01", dir.resolve("duplicate.jsonl")); }
        catch (IllegalStateException expected) { duplicateRejected = true; }
        check(duplicateRejected, "duplicate ledger rejected");
        boolean invalidRejected = false;
        try { new Sandbox(backend, "check02", dir.resolve("invalid.jsonl")).create("parameter", "lmaws_check02_../escape", "x"); }
        catch (IllegalArgumentException expected) { invalidRejected = true; }
        check(invalidRejected, "invalid prefixed name rejected");
        for(String kind:java.util.List.of("bucket","queue","topic","parameter","table","log_group")) {
            Path own=Files.createTempDirectory("lmaws-demo-"+kind+"-").toRealPath();
            try(Sandbox cycle=new Sandbox(backend,"cycle01",own)) {
                Map<String,String> made=cycle.create(kind,"fixture","secret-not-returned");
                check(!made.containsValue("secret-not-returned"),"payload excluded");
                cycle.put(made,kind.equals("log_group")?"retention_days":"fixture","7");
                check(cycle.remaining()==1,"owned cycle active");
                cycle.cleanup();
                check(cycle.remaining()==0,"owned cycle cleaned");
            }
            check(Sandbox.leftovers(own,0).isEmpty(),"cycle has no leftovers");
        }
        try(Sandbox namespaces=new Sandbox(backend,"names01",Files.createTempDirectory("lmaws-namespaces-").toRealPath())) {
            namespaces.create("queue","shared","x");
            namespaces.create("parameter","shared","x");
            check(namespaces.remaining()==2,"service namespaces are independent");
        }
        check(Jsons.mask("arn:aws:sns:us-east-1:123456789012:demo").contains("************"),"account masked");
        try(CloudHost host=new CloudHost()) {
            var registry=host.registry();
            boolean invalidUtf8=false;
            try{registry.resolve("method Cloud.region(string) -> Cloud").callback.call(host.context(64L*1024*1024),io.lmctl.lmcode.Value.object("Cloud",new Object()),new io.lmctl.lmcode.Value[]{io.lmctl.lmcode.Value.ofString(new io.lmctl.lmcode.VmString(new byte[]{(byte)0xff}))});}
            catch(io.lmctl.lmcode.VmException expected){invalidUtf8=expected.getMessage().contains("UTF-8");}
            check(invalidUtf8,"invalid UTF-8 rejected before network access");
        }
        backend.close();
        System.out.println("PASS sandbox guards and six offline lifecycle checks");
    }

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError("safety check failed: " + label);
    }
}
