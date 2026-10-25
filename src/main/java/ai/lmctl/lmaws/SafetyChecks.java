package ai.lmctl.lmaws;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Small dependency-free regression checks for the destructive-operation guard. */
public final class SafetyChecks {
    private SafetyChecks() {}

    public static void run() throws Exception {
        Path dir = Files.createTempDirectory("lmaws-safety-");
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
        backend.close();
    }

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError("safety check failed: " + label);
    }
}
