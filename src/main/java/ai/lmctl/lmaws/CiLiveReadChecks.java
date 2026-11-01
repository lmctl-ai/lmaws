package ai.lmctl.lmaws;

import java.util.List;

/**
 * The CI read opt-in (LMAWS_CI_LIVE_READ=1), driven by scripts/test-ci-live-read.py against a loopback fake endpoint
 * (it sets CI, the opt-in, AWS_PROFILE and LMAWS_ENDPOINT per case). Prints one line: OK ..., REFUSED: ... or ALLOWED ...
 *   construct  build a live backend
 *   reads      identity, a bucket check and a table check (the cert-aws-checks.lms set)
 *   write      create a bucket (a mutation)
 *   list       the bucket inventory (a read outside the opt-in's set)
 *   iam        IAM role access
 * Offline unit part (no environment needed): main with no argument checks the allowlist itself.
 */
public final class CiLiveReadChecks {
    private CiLiveReadChecks() {}

    public static void main(String[] args) {
        if (args.length == 0) { allowlist(); return; }
        String mode = args[0];
        try (AwsBackend b = new AwsBackend("us-east-1", false)) {
            switch (mode) {
                case "construct" -> System.out.println("OK constructed ciLiveRead=" + b.ciLiveRead());
                case "reads" -> {
                    List<?> id = b.inventory("identity");
                    boolean bucket = b.exists("bucket", "lmaws-ci-read-check");
                    boolean table = b.exists("table", "lmaws-ci-read-check");
                    System.out.println("OK reads identity=" + id.size() + " bucket=" + bucket + " table=" + table);
                }
                case "write" -> { b.create("bucket", "lmaws-ci-read-write", "", "r00000000x0000000000"); System.out.println("ALLOWED write"); }
                case "list" -> { b.inventory("buckets"); System.out.println("ALLOWED list"); }
                case "iam" -> { b.iamRoleGet("lmaws_ci_read_check"); System.out.println("ALLOWED iam"); }
                default -> throw new IllegalArgumentException("unknown mode " + mode);
            }
        } catch (RuntimeException e) {
            Throwable t = e; while (t.getCause() != null && !(t instanceof SecurityException)) t = t.getCause();
            System.out.println("REFUSED: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private static void allowlist() {
        check(AwsBackend.ciReadAllowed("Sts", "GetCallerIdentity"), "sts GetCallerIdentity allowed");
        check(AwsBackend.ciReadAllowed("S3", "HeadBucket"), "s3 HeadBucket allowed");
        check(AwsBackend.ciReadAllowed("DynamoDb", "DescribeTable"), "dynamodb DescribeTable allowed");
        for (String[] bad : new String[][] {{"S3", "PutObject"}, {"S3", "CreateBucket"}, {"S3", "ListBuckets"}, {"S3", "GetObject"},
                {"DynamoDb", "PutItem"}, {"DynamoDb", "Scan"}, {"Iam", "GetRole"}, {"Iam", "PassRole"}, {"Sts", "AssumeRole"},
                {"CostExplorer", "GetCostAndUsage"}, {"Ec2", "DescribeInstances"}, {"SecretsManager", "GetSecretValue"}, {null, "HeadBucket"}, {"S3", null}})
            check(!AwsBackend.ciReadAllowed(bad[0], bad[1]), bad[0] + " " + bad[1] + " refused");
        check(AwsBackend.ciLiveReadRequested(java.util.Map.of("LMAWS_CI_LIVE_READ", "1")), "opt-in 1 honoured");
        for (String v : new String[] {"true", "yes", "0", ""}) check(!AwsBackend.ciLiveReadRequested(java.util.Map.of("LMAWS_CI_LIVE_READ", v)), "opt-in '" + v + "' ignored");
        check(!AwsBackend.ciLiveReadRequested(java.util.Map.of()), "no opt-in");
        System.out.println("PASS CiLiveReadChecks allowlist");
    }
    private static void check(boolean ok, String what) { if (!ok) throw new AssertionError(what); }
}
