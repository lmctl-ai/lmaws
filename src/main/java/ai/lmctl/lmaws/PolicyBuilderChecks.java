package ai.lmctl.lmaws;

import com.sun.net.httpserver.HttpServer;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Self-test suite for PolicyCatalog, PolicyBuilder, PolicyAnalyzer, and PolicySimulator.
 */
public final class PolicyBuilderChecks {
    private PolicyBuilderChecks() {}

    public static void run() {
        checkCatalogAndTypos();
        checkSessionPolicyEquivalenceAndBlocks();
        checkFitInlineAndSplitManaged();
        checkExplainMatrixDenialLedgerAndImport();
        checkSimulatorOfflineAndLoopbackSdk();
        System.out.println("PASS policy builder, action catalog, inline/managed compaction, denial/ledger analysis and IAM simulator checks");
    }

    private static void checkCatalogAndTypos() {
        List<String> ec2Desc = PolicyCatalog.expandPattern("ec2:Describe*");
        require(ec2Desc.size() >= 15 && ec2Desc.contains("ec2:DescribeInstances"), "ec2:Describe* expands");
        require("list".equals(PolicyCatalog.classify("ec2:Describe*")), "ec2:Describe* classified as list");
        require("read".equals(PolicyCatalog.classify("ssm:GetParameter")), "ssm:GetParameter classified as read");
        require("write".equals(PolicyCatalog.classify("ec2:RunInstances")), "ec2:RunInstances classified as write");
        require("tagging".equals(PolicyCatalog.classify("ec2:CreateTags")), "ec2:CreateTags classified as tagging");
        require("permissions_management".equals(PolicyCatalog.classify("s3:PutBucketPolicy")), "s3:PutBucketPolicy classified as permissions_management");

        expectTypo("s3:PutObjekt", "s3:PutObject");
        expectTypo("ec2:RunInstance", "ec2:RunInstances");
        expectTypo("sqs:CreateQueues", "sqs:CreateQueue");
        expectTypo("s33:PutObject", "s3");
    }

    private static void expectTypo(String badAction, String expectedHint) {
        try {
            PolicyCatalog.validatePattern(badAction);
            throw new AssertionError("Expected typo rejection for " + badAction);
        } catch (IllegalArgumentException ex) {
            require(ex.getMessage().contains(expectedHint),
                "Typo error for '" + badAction + "' should suggest '" + expectedHint + "', got: " + ex.getMessage());
        }
    }

    private static void checkSessionPolicyEquivalenceAndBlocks() {
        PolicyBuilder session = new PolicyBuilder("lmaws_session")
            .lmawsSessionPolicy("lmaws", "lmaws_test", "example.com", "us-east-1", "t4g.nano,t3.nano", 8);
        String builtPretty = session.json();
        String builtCompact = session.compactJson();
        IamPolicies.LintResult lint = IamPolicies.lint(builtPretty);
        require(lint.valid(), "Built lmaws_session policy must pass lint: " + lint.findings());
        require(lint.statementCount() == 25, "Built lmaws_session must have 25 statements, got " + lint.statementCount());

        String baseline = new PolicyBuilder("lmaws_session")
            .lmawsSessionPolicy("lmaws", "lmaws_test", "example.com", "us-east-1", "t4g.nano,t3.nano", 8)
            .json();
        IamPolicies.DiffResult diff = IamPolicies.diff(baseline, builtPretty);
        require(!diff.changed() && diff.unchangedCount() == 25,
            "Built lmaws_session must match 25/25: " + diff.summary() + "\n" + diff.formattedLines());
        require(builtCompact.equals(IamPolicies.compactJson(PolicyAnalyzer.parseDoc(baseline))),
            "Built lmaws_session compact JSON must match baseline byte-for-byte");

        // Test pass_role_to_service helper + lint rule
        PolicyBuilder passRoleValid = new PolicyBuilder("lmaws_session")
            .passRoleToService("lmaws", "lambda.amazonaws.com");
        require(IamPolicies.lint(passRoleValid.json()).valid(),
            "pass_role_to_service('lmaws', 'lambda.amazonaws.com') must pass lint");
        IamPolicies.requirePassRolePolicyContext("lmaws_session", passRoleValid.json());

        PolicyBuilder passRoleEc2 = new PolicyBuilder("lmaws_session")
            .passRoleToService("lmaws", "ec2.amazonaws.com");
        IamPolicies.LintResult ec2PassRoleLint = IamPolicies.lint(passRoleEc2.json());
        require(!ec2PassRoleLint.valid() && ec2PassRoleLint.findings().toString().contains("PASS_ROLE_LAMBDA_ONLY"),
            "pass_role_to_service to ec2.amazonaws.com must be rejected by PASS_ROLE_LAMBDA_ONLY");

        // If the local snapshot file exists, extract its domain dynamically and verify 100% byte-for-byte equivalence
        Path v7Snapshot = Path.of(System.getProperty("user.home", ""),
            ".aws", "session-tools", "tasks", "iam-snapshots", "lmaws-managed-policy.v7.json");
        Path localSnapshot = Files.isRegularFile(v7Snapshot)
            ? v7Snapshot
            : Path.of(System.getProperty("user.home", ""),
                ".aws", "session-tools", "tasks", "iam-snapshots", "lmaws-managed-policy.json");
        // Opt-in only: --self-test must not depend on the operator's private ~/.aws files (they drift independently).
        if ("1".equals(System.getenv("LMAWS_CHECK_LOCAL_POLICY_SNAPSHOT")) && Files.isRegularFile(localSnapshot)) {
            try {
                String rawSnapshot = Files.readString(localSnapshot, StandardCharsets.UTF_8);
                var m = java.util.regex.Pattern.compile("lmaws-\\*\\.([a-z0-9.-]+)\"").matcher(rawSnapshot);
                String snapshotDomain = m.find() ? m.group(1) : "example.com";
                PolicyBuilder fromBuilder = new PolicyBuilder("lmaws_session")
                    .lmawsSessionPolicy("lmaws", "lmaws_test", snapshotDomain, "us-east-1", "t4g.nano,t3.nano", 8);
                IamPolicies.DiffResult snapDiff = IamPolicies.diff(rawSnapshot, fromBuilder.json());
                require(!snapDiff.changed() && snapDiff.unchangedCount() == 25,
                    "Built policy must match local snapshot 25/25: " + snapDiff.summary());
                require(fromBuilder.compactJson().equals(IamPolicies.compactJson(PolicyAnalyzer.parseDoc(rawSnapshot))),
                    "Built policy compact JSON must match local snapshot byte-for-byte");
                require(fromBuilder.json().trim().equals(rawSnapshot.trim()),
                    "Built policy pretty JSON must match local snapshot byte-for-byte");
            } catch (java.io.IOException ex) {
                throw new IllegalStateException("Failed reading local snapshot", ex);
            }
        }

        // Test composable sandbox blocks and intent helpers
        PolicyBuilder composed = new PolicyBuilder("lmaws_composed")
            .s3BucketSandbox("lmaws")
            .queueSandbox("lmaws")
            .topicSandbox("lmaws")
            .tableSandbox("lmaws")
            .parameterSandbox("lmaws")
            .logGroupSandbox("lmaws")
            .billingViewer()
            .ciBucketDeployer("lmaws-site-assets", "EDEMO123")
            .cidrOnly("Ingress32Only", "/32")
            .mfaRequired("MfaDeletes", "ec2:TerminateInstances,s3:DeleteBucket", "*")
            .timeWindow("BreakGlass", "2026-10-26T00:00:00Z", "2026-10-27T00:00:00Z")
            .sourceIp("CorpNet", "198.51.100.0/24")
            .denyDeleteUnlessTagged("ProtectUntagged", "s3:DeleteBucket,sqs:DeleteQueue", "*", "lmaws_test")
            .regionLock("OnlyUsEast1", "us-east-1", "sts:GetCallerIdentity,cloudfront:*,route53:*");
        require(composed.statements().size() >= 15, "Composed policy statements");
        require(composed.compactJson().contains("\"aws:MultiFactorAuthPresent\":\"false\""), "mfa_required condition");
        require(composed.compactJson().contains("\"NotIpAddress\":{\"aws:SourceIp\":\"198.51.100.0/24\"}"), "source_ip condition");
    }

    private static void checkFitInlineAndSplitManaged() {
        PolicyBuilder verbose = new PolicyBuilder("lmaws_verbose")
            .allow("Read1", "sts:GetCallerIdentity", "*")
            .allow("Read2", "s3:ListAllMyBuckets", "*")
            .allow("Read3", "sqs:ListQueues", "*")
            .allow("Read4", "sns:ListTopics", "*")
            .allow("Read5", "dynamodb:ListTables", "*")
            .allow("S3Write1", "s3:CreateBucket,s3:DeleteBucket,s3:PutObject,s3:GetObject,s3:DeleteObject", "arn:aws:s3:::lmaws-*")
            .allow("S3Write2", "s3:CreateBucket,s3:DeleteBucket,s3:PutObject,s3:GetObject,s3:DeleteObject", "arn:aws:s3:::lmaws-*/*")
            .regionLock("OnlyUsEast1", "us-east-1", "sts:GetCallerIdentity,cloudfront:*,route53:*");
        Map<String, String> fit = verbose.fitInline();
        require("true".equals(fit.get("fits_inline")), "fitInline fits within 2048: " + fit.get("summary"));
        require(Integer.parseInt(fit.get("saved_bytes")) > 100, "fitInline saved > 100 bytes");
        require(Integer.parseInt(fit.get("merged_statements")) < Integer.parseInt(fit.get("original_statements")),
            "fitInline merged compatible statements");

        PolicyBuilder session = new PolicyBuilder("lmaws_session")
            .lmawsSessionPolicy("lmaws", "lmaws_test", "example.com", "us-east-1", "t4g.nano,t3.nano", 8);
        List<Map<String, String>> parts = session.splitManaged();
        require(parts.size() >= 2, "splitManaged produces multiple balanced parts for 20-statement policy");
        for (Map<String, String> part : parts) {
            require("true".equals(part.get("fits_managed")), "Every split part fits <= 6144: " + part);
            require(Integer.parseInt(part.get("deny_count")) >= 1, "Every split part retains global Deny guardrails");
        }
        require(Integer.parseInt(parts.get(0).get("deny_count")) >= 4, "EC2 split part retains all 4 EC2+global Deny guardrails");
    }

    private static void checkExplainMatrixDenialLedgerAndImport() {
        PolicyBuilder session = new PolicyBuilder("lmaws_session")
            .lmawsSessionPolicy("lmaws", "lmaws_test", "lmnature.com", "us-east-1", "t4g.nano,t3.nano", 8);
        List<Map<String, String>> explained = session.explain();
        require(explained.size() == 26, "explain returns 25 statements + 1 POLICY_POSTURE summary");
        Map<String, String> posture = explained.get(explained.size() - 1);
        require("POLICY_POSTURE".equals(posture.get("sid")), "last row is POLICY_POSTURE");
        require(posture.get("plain_english").contains("region_lock=true"), "posture detects region_lock");

        List<Map<String, String>> matrix = session.matrix();
        require(matrix.size() >= 10, "matrix returns service x action_class x scope cells");

        // Statement-level size report + lint-valid compaction suggestions
        List<Map<String, String>> sizeRows = session.sizeReport();
        long stmtSizeCount = sizeRows.stream().filter(r -> "statement_size".equals(r.get("kind"))).count();
        long compSuggestionCount = sizeRows.stream().filter(r -> "compaction_suggestion".equals(r.get("kind"))).count();
        require(stmtSizeCount == 25, "sizeReport must return 25 statement_size rows, got " + stmtSizeCount);
        require(compSuggestionCount >= 3, "sizeReport must return >= 3 compaction suggestions, got " + compSuggestionCount);
        for (Map<String, String> r : sizeRows) {
            if ("compaction_suggestion".equals(r.get("kind"))) {
                require("true".equals(r.get("lint_valid")), "Compaction suggestion must be lint_valid=true: " + r);
                require(Integer.parseInt(r.get("saved_bytes")) > 0, "Compaction suggestion must save > 0 bytes: " + r);
            }
        }
        Map<String, String> sizeSummary = sizeRows.get(sizeRows.size() - 1);
        require("size_summary".equals(sizeSummary.get("kind")), "Last sizeReport row is size_summary");
        require("6032".equals(sizeSummary.get("compact_bytes")),
            "lmaws_session v7 (lmnature.com) must be 6032 compact bytes, got " + sizeSummary.get("compact_bytes"));

        // IAM cheat sheet for lmaws
        List<Map<String, String>> cheatRows = session.cheatSheet();
        require(cheatRows.size() == 6, "cheatSheet returns 6 capability rows");
        int totalCheatStmts = 0;
        for (Map<String, String> cr : cheatRows) {
            totalCheatStmts += Integer.parseInt(cr.get("statement_count"));
            require(!cr.get("statements").isBlank() && !cr.get("why_scoped").isBlank()
                    && !cr.get("missing_failure").isBlank() && !cr.get("minimal_builder_patch").isBlank(),
                "Cheat sheet row must populate all fields: " + cr);
        }
        require(totalCheatStmts == 25, "Cheat sheet rows must cover all 25 statements, got " + totalCheatStmts);

        Map<String, String> denial1 = PolicyAnalyzer.explainDenial(
            "User: arn:aws:sts::123456789012:federated-user/awsspot-local-lmaws is not authorized to perform: "
                + "ec2:RunInstances on resource: arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456 "
                + "with an explicit deny in an identity-based policy");
        require(!denial1.toString().contains("123456789012") && !denial1.toString().contains("i-0abc123def456"),
            "explainDenial redacts 12-digit account IDs and concrete instance IDs");
        require("ec2:RunInstances".equals(denial1.get("action")), "explainDenial extracts action");
        require("arn:aws:ec2:*:*:instance/*".equals(denial1.get("resource_arn_pattern")),
            "explainDenial generalizes resource_arn_pattern");
        require(denial1.get("condition_keys").contains("ec2:InstanceType"), "explainDenial includes condition_keys");
        require(denial1.get("minimal_builder_patch").contains("spot_nano_sandbox"), "explainDenial suggests spot_nano_sandbox");

        Map<String, String> denial2 = PolicyAnalyzer.explainDenial(
            "User: arn:aws:sts::123456789012:federated-user/awsspot-local-lmaws is not authorized to perform: "
                + "s3:PutObject on resource: arn:aws:s3:::lmaws-r9999-demo/file.txt "
                + "because no identity-based policy allows the s3:PutObject action");
        require("s3:PutObject".equals(denial2.get("action")), "explainDenial extracts s3:PutObject");
        require("arn:aws:s3:::lmaws-*/*".equals(denial2.get("resource_arn_pattern"))
                && !denial2.toString().contains("r9999"),
            "explainDenial generalizes s3 object ARN pattern without run ID");
        require(denial2.get("builder_snippet").contains("allow_cond"), "explainDenial suggests scoped allow_cond");

        Map<String, String> denial3 = PolicyAnalyzer.explainDenial(
            "User: arn:aws:sts::123456789012:federated-user/awsspot-local-lmaws is not authorized to perform: "
                + "iam:PassRole on resource: arn:aws:iam::123456789012:role/lmaws_r123_exec "
                + "because no session policy allows the iam:PassRole action");
        require("iam:PassRole".equals(denial3.get("action")), "explainDenial extracts iam:PassRole");
        require("arn:aws:iam::*:role/lmaws_*".equals(denial3.get("resource_arn_pattern")),
            "explainDenial generalizes IAM role ARN");
        require(denial3.get("condition_keys").contains("iam:PassedToService"),
            "explainDenial includes iam:PassedToService condition key");
        require(denial3.get("minimal_builder_patch").contains("pass_role_to_service"),
            "explainDenial suggests pass_role_to_service");

        try {
            Path tempLedger = Files.createTempFile("lmaws-ledger-check-", ".jsonl");
            try {
                Files.writeString(tempLedger, String.join("\n",
                    "{\"event\":\"cost_header\",\"run_id\":\"rdemo\",\"live\":false}",
                    "{\"event\":\"cost_request\",\"service\":\"s3\",\"operation\":\"CreateBucket\"}",
                    "{\"event\":\"cost_request\",\"service\":\"s3\",\"operation\":\"PutBucketTagging\"}",
                    "{\"event\":\"cost_request\",\"service\":\"s3\",\"operation\":\"PutObject\"}",
                    "{\"event\":\"cost_resource\",\"state\":\"created\",\"kind\":\"bucket\",\"id\":\"lmaws-demo\",\"name\":\"lmaws-demo\"}",
                    "{\"event\":\"cost_request\",\"service\":\"sqs\",\"operation\":\"CreateQueue\"}",
                    "{\"event\":\"cost_resource\",\"state\":\"created\",\"kind\":\"queue\",\"id\":\"lmaws_demo\",\"name\":\"lmaws_demo\"}"
                ) + "\n", StandardCharsets.UTF_8);
                Map<String, String> fromLedger = PolicyAnalyzer.fromLedger(tempLedger.toString());
                require("4".equals(fromLedger.get("observed_call_count")), "fromLedger counts 4 SDK calls");
                require(fromLedger.get("actions").contains("s3:CreateBucket") && fromLedger.get("actions").contains("sqs:CreateQueue"),
                    "fromLedger maps SDK calls to IAM actions");
                require(IamPolicies.lint(fromLedger.get("policy_json")).valid(), "fromLedger policy passes lint");
            } finally {
                Files.deleteIfExists(tempLedger);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("fromLedger check failed", ex);
        }

        Map<String, String> imported = PolicyAnalyzer.importJson(session.json());
        require("25".equals(imported.get("statement_count")), "importJson parses all 25 statements");
        require(imported.get("builder_program").contains(".require_tag_on_create("), "importJson recognizes require_tag_on_create");
        require(imported.get("builder_program").contains(".only_tagged("), "importJson recognizes only_tagged");
        require(imported.get("builder_program").contains(".pass_role_to_service("), "importJson recognizes pass_role_to_service");
    }

    private static void checkSimulatorOfflineAndLoopbackSdk() {
        PolicyBuilder session = new PolicyBuilder("lmaws_session")
            .lmawsSessionPolicy("lmaws", "lmaws_test", "example.com", "us-east-1", "t4g.nano,t3.nano", 8);
        List<Map<String, String>> offline = PolicySimulator.evaluateOffline(session.json(), PolicySimulator.defaultProbes());
        require(offline.size() == 8, "8 default probes evaluated offline");
        for (Map<String, String> row : offline) {
            require("true".equals(row.get("passed")), "Default probe must pass against lmaws_session: " + row);
        }

        // Verify Scenario 07 Lambda event-source-mapping probes offline
        String esmProbes = String.join(";",
            "lambda:CreateEventSourceMapping|*|aws:RequestedRegion=us-east-1,lambda:FunctionArn=arn:aws:lambda:us-east-1:000000000000:function:lmaws_s07_worker_r1,aws:RequestTag/lmaws_test=r1,aws:TagKeys=lmaws_test|allowed",
            "lambda:CreateEventSourceMapping|*|aws:RequestedRegion=us-east-1,lambda:FunctionArn=arn:aws:lambda:us-east-1:000000000000:function:prod_worker,aws:RequestTag/lmaws_test=r1,aws:TagKeys=lmaws_test|implicitDeny",
            "lambda:CreateEventSourceMapping|*|aws:RequestedRegion=us-east-1,lambda:FunctionArn=arn:aws:lambda:us-east-1:000000000000:function:lmaws_s07_worker_r1|implicitDeny",
            "lambda:TagResource|arn:aws:lambda:us-east-1:000000000000:event-source-mapping:00000000-0000-0000-0000-000000000001|aws:RequestedRegion=us-east-1,aws:RequestTag/lmaws_test=r1,aws:TagKeys=lmaws_test|allowed",
            "lambda:GetEventSourceMapping|arn:aws:lambda:us-east-1:000000000000:event-source-mapping:00000000-0000-0000-0000-000000000001|aws:RequestedRegion=us-east-1,aws:ResourceTag/lmaws_test=r1|allowed",
            "lambda:DeleteEventSourceMapping|arn:aws:lambda:us-east-1:000000000000:event-source-mapping:00000000-0000-0000-0000-000000000001|aws:RequestedRegion=us-east-1,aws:ResourceTag/lmaws_test=r1|allowed",
            "lambda:DeleteEventSourceMapping|arn:aws:lambda:us-east-1:000000000000:event-source-mapping:00000000-0000-0000-0000-000000000001|aws:RequestedRegion=us-east-1|implicitDeny",
            "lambda:ListTags|arn:aws:lambda:us-east-1:000000000000:event-source-mapping:00000000-0000-0000-0000-000000000001|aws:RequestedRegion=us-east-1,aws:ResourceTag/lmaws_test=r1|allowed",
            "lambda:ListEventSourceMappings|*|aws:RequestedRegion=us-east-1|allowed"
        );
        List<Map<String, String>> esmEval = PolicySimulator.evaluateOffline(session.json(), PolicySimulator.parseProbes(esmProbes));
        require(esmEval.size() == 9, "9 ESM probes evaluated offline");
        for (Map<String, String> row : esmEval) {
            require("true".equals(row.get("passed")), "ESM probe must match expected decision: " + row);
        }

        // Test simulate_run_instances across all 6 sub-resources
        List<Map<String, String>> launchAllowed = session.simulateRunInstances(
            "t4g.nano", 8, "lmaws_test", "r1", "us-east-1", "allowed");
        require(launchAllowed.size() == 6, "simulateRunInstances expands into 6 sub-resource probes");
        for (Map<String, String> row : launchAllowed) {
            require("true".equals(row.get("passed")) && "true".equals(row.get("launch_passed")),
                "All 6 sub-resources must pass for tagged t4g.nano <=8GiB launch: " + row);
        }

        List<Map<String, String>> launchLarge = session.simulateRunInstances(
            "t4g.large", 8, "lmaws_test", "r1", "us-east-1", "explicitDeny");
        require("explicitDeny".equals(launchLarge.get(0).get("decision"))
                && "true".equals(launchLarge.get(0).get("launch_passed")),
            "t4g.large launch is explicitly denied on instance by NanoOnly: " + launchLarge.get(0));

        List<Map<String, String>> launchBigDisk = session.simulateRunInstances(
            "t4g.nano", 20, "lmaws_test", "r1", "us-east-1", "explicitDeny");
        require("explicitDeny".equals(launchBigDisk.get(1).get("decision"))
                && "true".equals(launchBigDisk.get(1).get("launch_passed")),
            "20GiB volume launch is explicitly denied on volume by SmallDisks: " + launchBigDisk.get(1));

        List<Map<String, String>> launchUntagged = session.simulateRunInstances(
            "t4g.nano", 8, "", "", "us-east-1", "implicitDeny");
        require("implicitDeny".equals(launchUntagged.get(0).get("decision"))
                && "true".equals(launchUntagged.get(0).get("launch_passed")),
            "Untagged launch is implicitly denied on instance/volume by RunTagged: " + launchUntagged.get(0));

        // Verify a policy missing network-interface/* in RunRefs is caught by simulateRunInstances
        String missingEniJson = session.json().replace("\"arn:aws:ec2:*:*:network-interface/*\",", "");
        List<Map<String, String>> missingEniRes = PolicySimulator.simulateRunInstances(
            missingEniJson, "t4g.nano", 8, "lmaws_test", "r1", "us-east-1", "allowed");
        require("false".equals(missingEniRes.get(0).get("launch_passed"))
                && missingEniRes.get(0).get("failed_sub_resources").contains("network-interface"),
            "simulateRunInstances must catch missing network-interface/* sub-resource: " + missingEniRes);

        // Loopback HTTP fake test for AWS SDK IamClient.simulateCustomPolicy and simulatePrincipalPolicy
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String xml;
                if (body.contains("Action=SimulateCustomPolicy")) {
                    String decision = body.contains("t4g.large") ? "explicitDeny" : "allowed";
                    xml = "<SimulateCustomPolicyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">"
                        + "<SimulateCustomPolicyResult><EvaluationResults><member>"
                        + "<EvalActionName>ec2:RunInstances</EvalActionName>"
                        + "<EvalResourceName>arn:aws:ec2:us-east-1:000000000000:instance/i-demo</EvalResourceName>"
                        + "<EvalDecision>" + decision + "</EvalDecision>"
                        + "<MatchedStatements><member><SourcePolicyId>PolicyInputList.1</SourcePolicyId></member></MatchedStatements>"
                        + "</member></EvaluationResults></SimulateCustomPolicyResult>"
                        + "<ResponseMetadata><RequestId>req-sim-1</RequestId></ResponseMetadata>"
                        + "</SimulateCustomPolicyResponse>";
                } else if (body.contains("Action=SimulatePrincipalPolicy")) {
                    xml = "<SimulatePrincipalPolicyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">"
                        + "<SimulatePrincipalPolicyResult><EvaluationResults><member>"
                        + "<EvalActionName>sts:GetCallerIdentity</EvalActionName>"
                        + "<EvalResourceName>*</EvalResourceName>"
                        + "<EvalDecision>allowed</EvalDecision>"
                        + "</member></EvaluationResults></SimulatePrincipalPolicyResult>"
                        + "<ResponseMetadata><RequestId>req-sim-2</RequestId></ResponseMetadata>"
                        + "</SimulatePrincipalPolicyResponse>";
                } else {
                    xml = "<ErrorResponse><Error><Code>InvalidAction</Code></Error></ErrorResponse>";
                }
                byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/xml");
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
            Path tempDir = Files.createTempDirectory("lmaws-sim-check-").toRealPath();
            try (IamClient iam = IamClient.builder()
                    .region(Region.AWS_GLOBAL)
                    .endpointOverride(URI.create("http://127.0.0.1:" + server.getAddress().getPort()))
                    .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                    .httpClient(UrlConnectionHttpClient.builder().build())
                    .build()) {
                CostLedger ledger = new CostLedger("simtest", "simtest", "us-east-1",
                    tempDir.resolve("sim.jsonl"), CostLedger.DEFAULT_CAP, false);
                String probes = "ec2:RunInstances|arn:aws:ec2:us-east-1:000000000000:instance/i-demo|ec2:InstanceType=t4g.nano|allowed;"
                    + "ec2:RunInstances|arn:aws:ec2:us-east-1:000000000000:instance/i-demo|ec2:InstanceType=t4g.large|explicitDeny";
                List<Map<String, String>> customRes = PolicySimulator.simulateCustom(
                    iam, ledger, false, false, "admin", session.json(), probes);
                require(customRes.size() == 2 && "allowed".equals(customRes.get(0).get("decision"))
                    && "explicitDeny".equals(customRes.get(1).get("decision")),
                    "Loopback SimulateCustomPolicy returned expected decisions: " + customRes);

                List<Map<String, String>> principalRes = PolicySimulator.simulatePrincipal(
                    iam, ledger, false, false, "admin",
                    "arn:aws:iam::000000000000:policy/lmaws_session", session.json(),
                    "sts:GetCallerIdentity|*|aws:RequestedRegion=us-east-1|allowed");
                require(principalRes.size() == 1 && "allowed".equals(principalRes.get(0).get("decision")),
                    "Loopback SimulatePrincipalPolicy returned allowed");

                // Verify live profile guard rejects non-admin when liveWithoutFakeEndpoint=true
                try {
                    PolicySimulator.simulateCustom(iam, ledger, false, true, "default", session.json(), probes);
                    throw new AssertionError("Expected non-admin profile refusal for live SimulateCustomPolicy");
                } catch (IllegalStateException expected) {
                    require(expected.getMessage().contains("AWS_PROFILE=admin"), "Admin profile required message");
                }
            } finally {
                server.stop(0);
                try (var s = Files.walk(tempDir)) {
                    s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                        try { Files.deleteIfExists(p); } catch (Exception ignored) {}
                    });
                }
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Simulator loopback check failed", ex);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException("PolicyBuilderChecks failed: " + message);
        }
    }
}
