package ai.lmctl.lmaws;

import java.nio.file.Files;
import java.nio.file.Path;

public final class IamPolicyChecks {
    private IamPolicyChecks() {}

    public static void run() throws Exception {
        checkAllFourGuardCombinations();
        checkPolicyNamePrefix();
        checkLinterAcceptsValidPolicies();
        checkLinterRefusesForbiddenAndUnscopedPolicies();
        checkLambdaPassRoleAndScopedReads();
        checkPassRolePolicyContext();
        checkStatementLevelDiffAndDecoding();
        checkDemoBackendLifecycleAndRotation();
        System.out.println("PASS IAM managed policy lint, diff, 4-way profile/mutation guard and version rotation checks");
    }

    private static void checkAllFourGuardCombinations() {
        // Combination 1: admin profile + regular resource mutation -> MUST be refused
        expectThrows(
            IllegalStateException.class,
            "reserved exclusively for lmaws_ IAM policy grants",
            () -> IamPolicies.checkMutationGuard(false, "admin", true, true, true, null)
        );
        expectThrows(
            IllegalStateException.class,
            "reserved exclusively for lmaws_ IAM policy grants",
            () -> IamPolicies.checkMutationGuard(false, "admin", false, false, false, null)
        );

        // Combination 2: lmaws profile + regular resource mutation (with LMAWS_LIVE=1) -> MUST be allowed
        IamPolicies.checkMutationGuard(false, "lmaws", true, false, false, null);
        // Regular mutation with default profile or LMAWS_LIVE=0 -> refused
        expectThrows(
            IllegalStateException.class,
            "AWS_PROFILE=lmaws",
            () -> IamPolicies.checkMutationGuard(false, "default", true, false, false, null)
        );
        expectThrows(
            IllegalStateException.class,
            "LMAWS_LIVE=1",
            () -> IamPolicies.checkMutationGuard(false, "lmaws", false, false, false, null)
        );

        // Combination 3: lmaws profile (or missing grant/apply/prefix) + IAM policy write -> MUST be refused
        expectThrows(
            IllegalStateException.class,
            "AWS_PROFILE=admin",
            () -> IamPolicies.checkMutationGuard(true, "lmaws", true, true, true, "lmaws_session")
        );
        expectThrows(
            IllegalStateException.class,
            "AWS_PROFILE=admin",
            () -> IamPolicies.checkMutationGuard(true, "default", true, true, true, "lmaws_session")
        );
        expectThrows(
            IllegalStateException.class,
            "LMAWS_ADMIN_GRANT=1",
            () -> IamPolicies.checkMutationGuard(true, "admin", true, false, true, "lmaws_session")
        );
        expectThrows(
            IllegalStateException.class,
            "--apply",
            () -> IamPolicies.checkMutationGuard(true, "admin", true, true, false, "lmaws_session")
        );
        expectThrows(
            IllegalStateException.class,
            "LMAWS_LIVE=1",
            () -> IamPolicies.checkMutationGuard(true, "admin", false, true, true, "lmaws_session")
        );
        expectThrows(
            IllegalArgumentException.class,
            "lmaws_",
            () -> IamPolicies.checkMutationGuard(true, "admin", true, true, true, "admin_policy")
        );

        // Combination 4: admin profile + LMAWS_ADMIN_GRANT=1 + --apply + LMAWS_LIVE=1 + lmaws_ prefix -> MUST be allowed
        IamPolicies.checkMutationGuard(true, "admin", true, true, true, "lmaws_session");
    }

    private static void checkPolicyNamePrefix() {
        IamPolicies.requireValidPolicyName("lmaws_session");
        IamPolicies.requireValidPolicyName("lmaws_test-policy_1");
        for (String invalid : new String[]{"", "session", "lmaws-hyphen", "LMAWS_upper", "admin_policy", "lmaws_bad/slash"}) {
            expectThrows(
                IllegalArgumentException.class,
                "lmaws_",
                () -> IamPolicies.requireValidPolicyName(invalid)
            );
        }
    }

    private static void checkLinterAcceptsValidPolicies() throws Exception {
        IamPolicies.LintResult template = IamPolicies.lint(IamPolicies.sanitizedTemplatePolicyJson());
        require(template.valid(), "Sanitized template policy must pass lint: " + template.findings());
        require(template.compactLength() > 1000 && template.compactLength() <= IamPolicies.MANAGED_POLICY_LIMIT,
            "Unexpected template compact length: " + template.compactLength());
        require(template.statementCount() == 8, "Expected 8 statements in template policy");
        require(template.allowReadStatements() == 2, "Expected 2 read statements in template policy");
        require(template.allowScopedStatements() == 3, "Expected 3 scoped write statements in template policy");
        require(template.denyStatements() == 3, "Expected 3 deny statements in template policy");

        Path snapshot = Path.of(System.getProperty("user.home"), ".aws", "session-tools", "tasks", "iam-snapshots", "lmaws-managed-policy.json");
        if (Files.isRegularFile(snapshot)) {
            String raw = Files.readString(snapshot);
            IamPolicies.LintResult res = IamPolicies.lint(raw);
            require(res.valid(), "Real lmaws-managed-policy.json must pass lint: " + res.findings());
            require(
                res.compactLength() > IamPolicies.INLINE_SESSION_POLICY_LIMIT
                    && res.compactLength() <= IamPolicies.MANAGED_POLICY_LIMIT,
                "Expected compact length in (2048, 6144], got " + res.compactLength());
            require(res.statementCount() >= 20, "Expected >= 20 statements, got " + res.statementCount());
            require(res.allowReadStatements() >= 2, "Expected >= 2 allow_read statements, got " + res.allowReadStatements());
            require(res.allowScopedStatements() >= 13, "Expected >= 13 allow_scoped statements, got " + res.allowScopedStatements());
            require(res.denyStatements() >= 5, "Expected >= 5 deny statements, got " + res.denyStatements());
            require(
                IamPolicies.lint(res.compactDocument()).compactDocument().equals(res.compactDocument()),
                "Normalized compact JSON must round-trip deterministically");
        }
    }

    private static void checkLinterRefusesForbiddenAndUnscopedPolicies() {
        // 1. Invalid JSON
        require(!IamPolicies.lint("{not json").valid(), "Invalid JSON must fail lint");

        // 2. Wrong Version
        require(!IamPolicies.lint("""
            {"Version":"2008-10-17","Statement":[{"Sid":"R","Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}
            """).valid(), "Wrong Version must fail lint");

        // 3. Compact length > 6144
        StringBuilder huge = new StringBuilder("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Named\",\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":[");
        for (int i = 0; i < 180; i++) {
            if (i > 0) huge.append(',');
            huge.append("\"arn:aws:s3:::lmaws-bucket-number-").append(10000 + i).append("/*\"");
        }
        huge.append("]}]}");
        IamPolicies.LintResult hugeRes = IamPolicies.lint(huge.toString());
        require(!hugeRes.valid() && hugeRes.compactLength() > IamPolicies.MANAGED_POLICY_LIMIT,
            "Policy > 6144 compact chars must fail lint");

        // 4. Forbidden actions
        String[] forbiddenActions = {
            "iam:*",
            "iam:CreatePolicyVersion",
            "sts:AssumeRole",
            "sts:AssumeRoleWithWebIdentity",
            "organizations:*",
            "account:*",
            "kms:*",
            "secretsmanager:*",
            "*",
            "*:*"
        };
        for (String action : forbiddenActions) {
            String doc = """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Sid": "BadAction",
                      "Effect": "Allow",
                      "Action": "%s",
                      "Resource": "arn:aws:s3:::lmaws-*"
                    }
                  ]
                }
                """.formatted(action);
            IamPolicies.LintResult res = IamPolicies.lint(doc);
            require(!res.valid(), "Forbidden action '" + action + "' must be refused by lint");
        }

        // 5. Resource: "*" with a write action
        IamPolicies.LintResult starWrite = IamPolicies.lint("""
            {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Sid": "StarWrite",
                  "Effect": "Allow",
                  "Action": ["s3:ListAllMyBuckets", "s3:PutObject"],
                  "Resource": "*"
                }
              ]
            }
            """);
        require(!starWrite.valid(), "Resource '*' with write action must be refused by lint");

        // 6. Unscoped write action (resource not starting with lmaws- / lmaws_ and no lmaws_test tag condition)
        IamPolicies.LintResult unscopedWrite = IamPolicies.lint("""
            {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Sid": "UnscopedWrite",
                  "Effect": "Allow",
                  "Action": "s3:PutObject",
                  "Resource": "arn:aws:s3:::production-customer-bucket/*"
                }
              ]
            }
            """);
        require(!unscopedWrite.valid(), "Unscoped write action must be refused by lint");
    }

    private static void checkLambdaPassRoleAndScopedReads() {
        String passRole = """
            {"Version":"2012-10-17","Statement":[{"Sid":"LambdaPassRole","Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::*:role/lmaws_*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}]}
            """;
        require(IamPolicies.lint(passRole).valid(), "the exact Lambda PassRole exception must pass");
        String[] rejected = {
            passRole.replace("lambda.amazonaws.com", "ec2.amazonaws.com"),
            passRole.replace(",\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"lambda.amazonaws.com\"}}", ""),
            passRole.replace("arn:aws:iam::*:role/lmaws_*", "arn:aws:iam::*:role/*"),
            passRole.replace("\"Action\":\"iam:PassRole\"", "\"Action\":[\"iam:PassRole\",\"iam:GetRole\"]"),
            passRole.replace("\"StringEquals\":{\"iam:PassedToService\":\"lambda.amazonaws.com\"}", "\"StringEquals\":{\"iam:PassedToService\":[\"lambda.amazonaws.com\"]}"),
            passRole.replace("\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"lambda.amazonaws.com\"}}", "\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"lambda.amazonaws.com\"},\"StringLike\":{\"aws:PrincipalArn\":\"*\"}}")
        };
        for (String doc : rejected) require(!IamPolicies.lint(doc).valid(), "unsafe PassRole variant must fail: " + doc);

        String reads = """
            {"Version":"2012-10-17","Statement":[
              {"Sid":"Events","Effect":"Allow","Action":"events:ListRules","Resource":"*"},
              {"Sid":"Lambda","Effect":"Allow","Action":"lambda:ListFunctions","Resource":"*"},
              {"Sid":"Acm","Effect":"Allow","Action":["acm:ListCertificates","acm:DescribeCertificate"],"Resource":"*"},
              {"Sid":"Route","Effect":"Allow","Action":"route53:GetChange","Resource":"*"},
              {"Sid":"RoleRead","Effect":"Allow","Action":["iam:GetRole","iam:ListAttachedRolePolicies"],"Resource":"arn:aws:iam::*:role/lmaws_*"},
              {"Sid":"PolicyRead","Effect":"Allow","Action":"iam:GetPolicy","Resource":"arn:aws:iam::*:policy/lmaws_*"}
            ]}
            """;
        require(IamPolicies.lint(reads).valid(), "scoped safe inventory reads must pass");
        String[] badReads = {
            reads.replace("arn:aws:iam::*:role/lmaws_*", "*"),
            reads.replace("arn:aws:iam::*:policy/lmaws_*", "arn:aws:iam::*:policy/other_*"),
            reads.replace("iam:GetPolicy", "iam:PutRolePolicy")
        };
        require(IamPolicies.lint("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:GetRole\",\"iam:ListAttachedRolePolicies\",\"iam:GetPolicy\"],\"Resource\":[\"arn:aws:iam::123456789012:role/lmaws_*\",\"arn:aws:iam::*:policy/lmaws_*\"]}]}").valid(), "scoped mixed role/policy reads with concrete account pass");
        for (String doc : badReads) require(!IamPolicies.lint(doc).valid(), "unsafe scoped IAM read must fail");
    }

    private static void checkPassRolePolicyContext() {
        String passRole = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::*:role/lmaws_*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}]}
            """;
        IamPolicies.requirePassRolePolicyContext("lmaws_session", passRole);
        expectThrows(IllegalArgumentException.class, "only in the lmaws_session policy",
            () -> IamPolicies.requirePassRolePolicyContext("lmaws_lambda_policy", passRole));
        expectThrows(IllegalArgumentException.class, "only in the lmaws_session policy",
            () -> IamPolicies.requirePassRolePolicyContext("lmaws_lambda_exec", passRole));
        IamPolicies.requirePassRolePolicyContext("lmaws_lambda_policy", "{\"Statement\":[{\"Action\":\"lambda:InvokeFunction\"}]}");
        IamPolicies.requirePassRolePolicyContext("lmaws_lambda_policy", "{\"Statement\":[{\"Action\":[\"s3:GetObject\",\"lambda:InvokeFunction\"]}]}");
    }

    private static void checkStatementLevelDiffAndDecoding() {
        IamPolicies.DiffResult diff = IamPolicies.diff(
            IamPolicies.sanitizedBaselinePolicyJson(),
            IamPolicies.sanitizedTemplatePolicyJson()
        );
        require(diff.changed(), "Diff between baseline and template must be marked changed");
        require(diff.addedCount() == 5, "Expected 5 added statements, got " + diff.addedCount());
        require(diff.modifiedCount() == 1, "Expected 1 modified statement (Reads), got " + diff.modifiedCount());
        require(diff.unchangedCount() == 2, "Expected 2 unchanged statements, got " + diff.unchangedCount());
        require(diff.removedCount() == 0, "Expected 0 removed statements, got " + diff.removedCount());

        String encoded = "%7B%22Version%22%3A%222012-10-17%22%7D";
        require("{\"Version\":\"2012-10-17\"}".equals(IamPolicies.decodeAwsDocument(encoded)),
            "URL-encoded policy document must decode cleanly");
    }

    private static void checkDemoBackendLifecycleAndRotation() {
        java.io.PrintStream oldOut = System.out;
        System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
        try (AwsBackend backend = new AwsBackend("us-east-1", true)) {
            var got = backend.iamPolicyGet("lmaws_session");
            require("true".equals(got.get("exists")), "Demo lmaws_session must exist");
            require("v1".equals(got.get("default_version_id")), "Demo lmaws_session must start at v1");

            var dryPut = backend.iamPolicyPut("lmaws_session", IamPolicies.sanitizedTemplatePolicyJson(), false);
            require("false".equals(dryPut.get("applied")), "Dry-run put must have applied=false");
            require("dry_run".equals(dryPut.get("action")), "Dry-run put must have action=dry_run");
            require("5".equals(dryPut.get("added_count")), "Dry-run put must report 5 added statements");

            var dryDeleteUnattached = backend.iamPolicyDelete("lmaws_session", false);
            require("false".equals(dryDeleteUnattached.get("applied")), "Dry-run delete must have applied=false");

            expectThrows(
                IllegalStateException.class,
                "attached to 1 entity/entities",
                () -> backend.iamPolicyDelete("lmaws_attached_demo", false)
            );
        } finally {
            System.setOut(oldOut);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException("IamPolicyChecks failed: " + message);
        }
    }

    private static void expectThrows(Class<? extends Throwable> expectedType, String expectedSubstring, Runnable action) {
        try {
            action.run();
        } catch (Throwable ex) {
            if (!expectedType.isInstance(ex)) {
                throw new IllegalStateException("Expected " + expectedType.getSimpleName() + " but got " + ex, ex);
            }
            String msg = ex.getMessage() == null ? "" : ex.getMessage();
            if (expectedSubstring != null && !msg.contains(expectedSubstring)) {
                throw new IllegalStateException(
                    "Expected message containing '" + expectedSubstring + "' but got '" + msg + "'", ex);
            }
            return;
        }
        throw new IllegalStateException("Expected " + expectedType.getSimpleName() + " to be thrown, but call succeeded");
    }
}
