package ai.lmctl.lmaws;

import java.util.List;

/**
 * CI live reads (LMAWS_OIDC_ALLOWED_ROLE), driven by scripts/test-ci-live-read.py against a loopback fake endpoint
 * (it sets CI, the allowlist, the credentials and LMAWS_ENDPOINT or AWS_ENDPOINT_URL per case). Prints one line: OK ..., REFUSED: ... or ALLOWED ...
 *   construct  build a live backend
 *   reads      identity, a bucket check and a table check (the cert-aws-checks.lms set)
 *   write      create a bucket (a mutation)
 *   list       the bucket inventory (a read outside the opt-in's set)
 *   iam        IAM role access
 *   exists KIND NAME [KIND NAME ...]   identity, then resource_exists for each (a real read-only check)
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
                case "exists" -> {
                    StringBuilder out = new StringBuilder("OK caller=" + b.inventory("identity").get(0).get("name"));
                    for (int i = 1; i + 1 < args.length; i += 2) out.append(' ').append(args[i]).append(':').append(args[i + 1]).append('=').append(b.exists(args[i], args[i + 1]));
                    System.out.println(out);
                }
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
        var env = java.util.Map.of("LMAWS_OIDC_ALLOWED_ROLE", "arn:aws:iam::111122223333:role/ci-cert, arn:aws:iam::111122223333:role/path/other");
        var allowed = AwsBackend.ciAllowedRoles(env);
        check(allowed.equals(List.of("111122223333:ci-cert", "111122223333:other")), "allowlist parsed " + allowed);
        check(AwsBackend.ciAllowedRoles(java.util.Map.of()).isEmpty(), "no allowlist");
        check(AwsBackend.ciAllowedRoles(java.util.Map.of("LMAWS_OIDC_ALLOWED_ROLE", " ")).isEmpty(), "blank allowlist");
        for (String bad : new String[] {"ci-cert", "arn:aws:iam::111122223333:user/ci-cert", "arn:aws:iam::1111:role/x", "*", "arn:aws:iam::111122223333:role/ci-cert,"})
            try { AwsBackend.ciAllowedRoles(java.util.Map.of("LMAWS_OIDC_ALLOWED_ROLE", bad)); throw new AssertionError("accepted " + bad); } catch (IllegalStateException expected) { }
        check(AwsBackend.ciRoleAllowed("arn:aws:sts::111122223333:assumed-role/ci-cert/run-1", allowed), "assumed-role session of an allowed role");
        check(AwsBackend.ciRoleAllowed("arn:aws:iam::111122223333:role/ci-cert", allowed), "role ARN of an allowed role");
        check(AwsBackend.ciRoleAllowed("arn:aws:sts::111122223333:assumed-role/other/s", allowed), "role with a path, by name");
        for (String bad : new String[] {"arn:aws:sts::444455556666:assumed-role/ci-cert/run-1", "arn:aws:sts::111122223333:assumed-role/ci-cert-2/x",
                "arn:aws:iam::111122223333:user/ci-cert", "arn:aws:sts::111122223333:federated-user/ci-cert", "", null, "arn:aws:sts::111122223333:assumed-role/ci-cert"})
            check(!AwsBackend.ciRoleAllowed(bad, allowed), "caller refused: " + bad);
        System.out.println("PASS CiLiveReadChecks allowlist");
    }
    private static void check(boolean ok, String what) { if (!ok) throw new AssertionError(what); }
}
