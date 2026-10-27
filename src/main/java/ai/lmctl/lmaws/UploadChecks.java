package ai.lmctl.lmaws;

import java.math.BigDecimal;
import java.nio.file.Files;

/** Synthetic presigned-upload and conditional-write checks; never contacts AWS. */
public final class UploadChecks {
    public static void main(String[] args) throws Exception {
        var dir = Files.createTempDirectory("lmaws-upload-check-");
        var ledger = new CostLedger("cafe10", "upload_checks", "us-east-1", dir.resolve("cost.jsonl"), new BigDecimal("0.05"), false);
        try (var backend = new AwsBackend("us-east-1", true, ledger)) {
            var good = backend.s3PresignPut("lmaws-cafe10-gallery", "uploads/demo.png", 512, "image/png", 300, "cafe10");
            require("true".equals(good.get("signed")) && "512".equals(good.get("content_length")), "signed length/type");
            refused(() -> backend.s3PresignPut("lmaws-cafe10-gallery", "uploads/demo.png", 1, "text/plain", 300, "cafe10"));
            refused(() -> backend.s3PresignPut("lmaws-cafe10-gallery", "uploads/demo.png", 1, "image/png", 901, "cafe10"));
            refused(() -> backend.s3PresignPut("foreign-cafe10", "uploads/demo.png", 1, "image/png", 300, "cafe10"));
            var conditional = backend.tableItemConditional("lmaws_cafe10_gallery", "first", "payload", "attribute_not_exists(pk)", "cafe10");
            require("attribute_not_exists(pk)".equals(conditional.get("condition")), "condition expression");
            refused(() -> backend.tableItemConditional("lmaws_cafe10_gallery", "first", "payload", "attribute_not_exists(secret)", "cafe10"));
        } finally {
            try (var files = Files.walk(dir)) { for (var p : files.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(p); }
        }
        System.out.println("PASS synthetic presign headers, TTL/size/content guards, ownership and conditional-write lint");
    }
    private static void require(boolean ok, String msg) { if (!ok) throw new AssertionError(msg); }
    private static void refused(Runnable op) { try { op.run(); } catch (RuntimeException expected) { return; } throw new AssertionError("invalid operation accepted"); }
}
