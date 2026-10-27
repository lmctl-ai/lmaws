package ai.lmctl.lmaws;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** Focused offline regression checks for the S3 account-boundary policy shape. */
public final class PolicySimulationChecks {
    private static final String OWN = "000000000000";
    private static final String FOREIGN = "111111111111";
    private static final Set<String> ROW_FIELDS = Set.of(
        "probe_id", "action", "resource", "context", "decision", "expected",
        "passed", "matched_statements", "missing_context", "status", "detail", "count");

    private PolicySimulationChecks() {}

    public static void run() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Sid":"UploadToAccountBuckets","Effect":"Allow",
               "Action":["s3:PutObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],
               "Resource":"arn:aws:s3:::*/*",
               "Condition":{"StringEquals":{"s3:ResourceAccount":"000000000000"}}},
              {"Sid":"DenyS3DeletionAndBucketWrites","Effect":"Deny",
               "Action":["s3:Delete*","s3:CreateBucket","s3:PutBucket*","s3:PutObjectAcl"],
               "Resource":"*"},
              {"Sid":"DenyUploadsToOtherAccounts","Effect":"Deny",
               "Action":["s3:PutObject","s3:AbortMultipartUpload"],
               "Resource":"arn:aws:s3:::*/*",
               "Condition":{"StringNotEquals":{"s3:ResourceAccount":"000000000000"}}}
            ]}
            """;
        Map<String, String> own = Map.of("s3:ResourceAccount", OWN);
        Map<String, String> foreign = Map.of("s3:ResourceAccount", FOREIGN);
        List<PolicySimulator.Probe> probes = List.of(
            new PolicySimulator.Probe("own_put", "s3:PutObject", "arn:aws:s3:::lmaws-fixture/object", own, "allowed"),
            new PolicySimulator.Probe("foreign_put", "s3:PutObject", "arn:aws:s3:::lmaws-fixture/object", foreign, "explicitDeny"),
            new PolicySimulator.Probe("own_abort", "s3:AbortMultipartUpload", "arn:aws:s3:::lmaws-fixture/object", own, "allowed"),
            new PolicySimulator.Probe("foreign_abort", "s3:AbortMultipartUpload", "arn:aws:s3:::lmaws-fixture/object", foreign, "explicitDeny"),
            new PolicySimulator.Probe("delete", "s3:DeleteObject", "arn:aws:s3:::lmaws-fixture/object", own, "explicitDeny"),
            new PolicySimulator.Probe("acl", "s3:PutObjectAcl", "arn:aws:s3:::lmaws-fixture/object", own, "explicitDeny"),
            new PolicySimulator.Probe("create_bucket", "s3:CreateBucket", "arn:aws:s3:::lmaws-fixture", own, "explicitDeny"));
        List<Map<String, String>> rows = PolicySimulator.evaluateOffline(policy, probes);
        check(rows.size() == probes.size(), "probe count");
        for (int i = 0; i < rows.size(); i++) {
            Map<String, String> row = rows.get(i);
            check(row.keySet().equals(ROW_FIELDS), "stable result fields for " + probes.get(i).id());
            check("true".equals(row.get("passed")), "decision for " + probes.get(i).id() + ": " + row);
            String expectedSid = switch (probes.get(i).id()) {
                case "own_put", "own_abort" -> "UploadToAccountBuckets";
                case "foreign_put", "foreign_abort" -> "DenyUploadsToOtherAccounts";
                default -> "DenyS3DeletionAndBucketWrites";
            };
            check(expectedSid.equals(row.get("matched_statements")), "matched Sid for " + probes.get(i).id());
        }
    }

    private static void check(boolean ok, String message) {
        if (!ok) throw new IllegalStateException("PolicySimulationChecks failed: " + message);
    }

    public static void main(String[] args) {
        run();
        System.out.println("PASS S3 account-boundary offline policy simulation checks");
    }
}
