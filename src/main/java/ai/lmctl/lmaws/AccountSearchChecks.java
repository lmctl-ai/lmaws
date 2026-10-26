package ai.lmctl.lmaws;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Focused offline checks for the account-prefix search contract. */
public final class AccountSearchChecks {
    private AccountSearchChecks() {}

    public static void run() {
        Path dir;
        try { dir = Files.createTempDirectory("lmaws-prefix-check-"); }
        catch (Exception e) { throw new IllegalStateException(e); }
        try (AwsBackend backend = new AwsBackend("us-east-1", true)) {
            List<Map<String, String>> rows = backend.findPrefix("lmaws");
            if (rows.size() < 3) throw new AssertionError("demo prefix search returned too few rows");
            if (rows.stream().noneMatch(r -> r.get("name").startsWith("lmaws_"))) throw new AssertionError("underscore prefix missing");
            if (rows.stream().noneMatch(r -> r.get("name").startsWith("lmaws-"))) throw new AssertionError("hyphen prefix missing");
            if (rows.stream().noneMatch(r -> r.get("name").equals("lmawsOther"))) throw new AssertionError("arbitrary prefix missing");
            if (rows.stream().anyMatch(r -> !r.containsKey("service") || !r.containsKey("resource_type") || !r.containsKey("id") || !r.containsKey("region")))
                throw new AssertionError("typed search fields missing");
            if (rows.stream().anyMatch(r -> !r.containsKey("tags") || !r.containsKey("lmaws_test") || !r.containsKey("run_id")))
                throw new AssertionError("tag metadata fields missing");
            if (!backend.findPrefix("no-such-prefix").isEmpty()) throw new AssertionError("foreign prefix matched");
        } finally {
            try { Files.deleteIfExists(dir); } catch (Exception ignored) { }
        }
    }

    public static void main(String[] args) { run(); System.out.println("PASS account-prefix search checks"); }
}
