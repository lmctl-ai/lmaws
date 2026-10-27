package ai.lmctl.lmaws;

import com.sun.net.httpserver.HttpServer;
import io.lmctl.lmcode.Json;

import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Self-test suite for {@link FleetRoles} and {@link IamPolicies#lintInstanceRole(String)}:
 * offline synthetic operations-needs model, instance-role lint mode vs unweakened session lint,
 * 5-way human-admin guard, ID masking, and loopback fake HTTP server verification of
 * sequential 1-by-1 instance profile replacement (ops-node-1 -> verify -> ops-node-2 -> verify)
 * and one-command rollback.
 */
public final class FleetRoleChecks {
    private FleetRoleChecks() {}

    public static void run() throws Exception {
        checkInstanceRoleLintAndUnweakenedSessionLint();
        checkOfflinePlanAndMasking();
        checkHumanAdminGuards();
        checkLoopbackApplyAndRollback();
        System.out.println("PASS fleet operational instance roles: synthetic ops model, instance-role lint, 5-way human-admin guard, sequential node1->node2 swap and rollback");
    }

    private static void checkInstanceRoleLintAndUnweakenedSessionLint() {
        String node1Json = FleetRoles.buildNode1Policy().json();
        String node2Json = FleetRoles.buildNode2Policy().json();
        String boundaryJson = FleetRoles.buildBoundaryPolicy().json();

        IamPolicies.LintResult node1Lint = IamPolicies.lintInstanceRole(node1Json);
        IamPolicies.LintResult node2Lint = IamPolicies.lintInstanceRole(node2Json);
        IamPolicies.LintResult boundaryLint = IamPolicies.lintInstanceRole(boundaryJson);

        require(node1Lint.valid(), "example-ops-role-1 must pass lintInstanceRole: " + node1Lint.findings());
        require(node2Lint.valid(), "example-ops-role-2 must pass lintInstanceRole: " + node2Lint.findings());
        require(boundaryLint.valid(), "example-ops-boundary must pass lintInstanceRole: " + boundaryLint.findings());

        // Session lint (for lmaws_session) MUST remain unweakened and reject instance-role documents
        require(!IamPolicies.lint(node1Json).valid(), "Standard session lint must reject node1 instance role policy");
        require(!IamPolicies.lint(node2Json).valid(), "Standard session lint must reject node2 instance role policy");

        // Admin wildcard policy MUST fail both linters
        String adminDoc = """
            {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Sid": "ExampleLegacyWideFromInstances",
                  "Effect": "Allow",
                  "Action": "*",
                  "Resource": "*"
                }
              ]
            }
            """;
        IamPolicies.LintResult adminInstanceLint = IamPolicies.lintInstanceRole(adminDoc);
        require(!adminInstanceLint.valid()
                && adminInstanceLint.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_NO_ADMIN),
            "Admin wildcard must be rejected by INSTANCE_ROLE_NO_ADMIN_WILDCARD: " + adminInstanceLint.findings());

        // Privilege escalation / forbidden fleet actions must be rejected by lintInstanceRole
        String[] forbiddenActions = {
            "iam:CreateRole",
            "iam:PassRole",
            "organizations:CloseAccount",
            "account:PutContactInformation",
            "kms:PutKeyPolicy",
            "ec2:TerminateInstances",
            "ec2:DeleteVolume",
            "ec2:ReleaseAddress",
            "ec2:ReplaceIamInstanceProfileAssociation",
            "ec2:RunInstances",
            "ec2:StartInstances",
            "cloudtrail:StopLogging",
            "config:StopConfigurationRecorder",
            "secretsmanager:PutSecretValue",
            "secretsmanager:DeleteSecret"
        };
        for (String badAction : forbiddenActions) {
            String doc = node1Json.replace("\"sts:GetCallerIdentity\"", "\"" + badAction + "\"");
            IamPolicies.LintResult res = IamPolicies.lintInstanceRole(doc);
            require(!res.valid() && res.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_FORBIDDEN_ESCALATION),
                "Forbidden action '" + badAction + "' must fail lintInstanceRole with INSTANCE_ROLE_FORBIDDEN_ESCALATION: " + res.findings());
        }

        // Unscoped StopInstances must be rejected with INSTANCE_ROLE_SELF_STOP_SCOPED
        String unscopedStop = node1Json.replace("\"aws:ResourceTag/Project\"", "\"aws:ResourceTag/Other\"");
        IamPolicies.LintResult unscopedStopRes = IamPolicies.lintInstanceRole(unscopedStop);
        require(!unscopedStopRes.valid()
                && unscopedStopRes.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_SELF_STOP_SCOPED),
            "StopInstances without Project tag must fail with INSTANCE_ROLE_SELF_STOP_SCOPED");

        // sts:AssumeRole on an admin role must be rejected
        String badAssume = node1Json.replace("role/" + FleetRoles.DEPLOY_ROLE_NAME, "role/admin-all");
        IamPolicies.LintResult badAssumeRes = IamPolicies.lintInstanceRole(badAssume);
        require(!badAssumeRes.valid()
                && badAssumeRes.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_WEBSITE_ASSUME_SCOPED),
            "sts:AssumeRole on admin role must fail with INSTANCE_ROLE_WEBSITE_ASSUME_SCOPED");

        // S3 access on a wildcard bucket must be rejected
        String badS3 = node1Json.replace("arn:aws:s3:::" + FleetRoles.ASSET_BUCKET_NAME + "/*", "arn:aws:s3:::*/*");
        IamPolicies.LintResult badS3Res = IamPolicies.lintInstanceRole(badS3);
        require(!badS3Res.valid()
                && badS3Res.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_WWW_S3_SCOPED),
            "S3 write on wildcard bucket must fail with INSTANCE_ROLE_WWW_S3_SCOPED");

        // CodeCommit without companion DenyCodeCommitDelete must be rejected
        String noCcDeny = node1Json.replace("\"codecommit:DeleteBranch\"", "\"codecommit:GitPull\"");
        IamPolicies.LintResult noCcDenyRes = IamPolicies.lintInstanceRole(noCcDeny);
        require(!noCcDenyRes.valid()
                && noCcDenyRes.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_CODECOMMIT_NO_DELETE),
            "CodeCommit without DeleteBranch deny must fail with INSTANCE_ROLE_CODECOMMIT_NO_DELETE");

        // Cognito without unconditional companion DenyCognitoDestructive must be rejected
        String noCogDeny = node2Json.replace("\"cognito-idp:ForgetDevice\"", "\"cognito-idp:ListUsers\"");
        IamPolicies.LintResult noCogDenyRes = IamPolicies.lintInstanceRole(noCogDeny);
        require(!noCogDenyRes.valid()
                && noCogDenyRes.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_COGNITO_NO_DELETE),
            "Cognito without ForgetDevice deny must fail with INSTANCE_ROLE_COGNITO_NO_DELETE");

        // kms:Decrypt without kms:ViaService=secretsmanager.us-east-1.amazonaws.com must be rejected
        String unscopedKms = node1Json.replace("secretsmanager.us-east-1.amazonaws.com", "ec2.us-east-1.amazonaws.com");
        IamPolicies.LintResult unscopedKmsRes = IamPolicies.lintInstanceRole(unscopedKms);
        require(!unscopedKmsRes.valid()
                && unscopedKmsRes.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_FORBIDDEN_ESCALATION),
            "kms:Decrypt without kms:ViaService=secretsmanager.us-east-1.amazonaws.com must fail with INSTANCE_ROLE_FORBIDDEN_ESCALATION");

        // Missing ec2:SourceInstanceArn origin guard must be rejected
        String noOriginGuard = node1Json.replace("\"ec2:SourceInstanceArn\"", "\"aws:TagKeys\"");
        IamPolicies.LintResult noOriginRes = IamPolicies.lintInstanceRole(noOriginGuard);
        require(!noOriginRes.valid()
                && noOriginRes.findings().toString().contains(IamPolicies.RULE_INSTANCE_ROLE_ORIGIN_GUARD),
            "Policy without ec2:SourceInstanceArn origin guard must fail with INSTANCE_ROLE_ORIGIN_AND_REGION_GUARD");
    }

    private static void checkOfflinePlanAndMasking() {
        String masked = FleetRoles.maskFleetIds(
            "account 123456789012 instance i-0abcdef1234567890 vol-0123456789abcdef0 eipalloc-0123456789abcdef0 iip-assoc-0123456789abcdef0");
        require(!masked.contains("123456789012")
                && !masked.contains("i-0abcdef")
                && !masked.contains("vol-012345")
                && !masked.contains("eipalloc-012345")
                && !masked.contains("iip-assoc-012345"),
            "maskFleetIds must redact account, instance, volume, EIP, and association IDs: " + masked);

        List<Map<String, String>> ops = FleetRoles.opsNeedsTable();
        require(ops.size() == 9, "Expected 9 synthetic operations-needs rows, got " + ops.size());

        try (AwsBackend demo = new AwsBackend("us-east-1", true)) {
            Map<String, String> plan = demo.fleetRolesPlan();
            require("dry_run_plan".equals(plan.get("mode")) && "false".equals(plan.get("applied")),
                "Default plan must be dry_run_plan with applied=false");
            require("true".equals(plan.get("node1_lint_valid"))
                    && "true".equals(plan.get("node2_lint_valid"))
                    && "true".equals(plan.get("boundary_lint_valid")),
                "All 3 generated documents in plan must pass lintInstanceRole");
            String fullPlanJson = Jsons.encode(plan);
            require(!fullPlanJson.matches(".*\\bi-[0-9a-f]{8,17}\\b.*"),
                "Plan output must not contain unmasked EC2 instance IDs");
        }
    }

    private static void checkHumanAdminGuards() {
        // 1. Missing --apply
        expectThrows("requires --apply", () ->
            FleetRoles.checkAdminHumanApplyGuard("admin", true, true, false, true));
        // 2. Missing --i-am-the-admin-human
        expectThrows("--i-am-the-admin-human", () ->
            FleetRoles.checkAdminHumanApplyGuard("admin", true, true, true, false));
        // 3. Missing LMAWS_LIVE=1
        expectThrows("LMAWS_LIVE=1", () ->
            FleetRoles.checkAdminHumanApplyGuard("admin", false, true, true, true));
        // 4. Wrong profile (default, lmaws, lmaws-ec2)
        for (String badProfile : List.of("default", "lmaws", "lmaws-ec2")) {
            expectThrows("AWS_PROFILE=admin", () ->
                FleetRoles.checkAdminHumanApplyGuard(badProfile, true, true, true, true));
        }
        // 5. Missing LMAWS_ADMIN_GRANT=1
        expectThrows("LMAWS_ADMIN_GRANT=1", () ->
            FleetRoles.checkAdminHumanApplyGuard("admin", true, false, true, true));

        // 6. All 5 present -> passes
        FleetRoles.checkAdminHumanApplyGuard("admin", true, true, true, true);
    }

    @SuppressWarnings("unchecked")
    private static void checkLoopbackApplyAndRollback() throws Exception {
        List<String> callOrder = new ArrayList<>();
        Map<String, String> assocProfileByInst = new LinkedHashMap<>();
        assocProfileByInst.put("i-01111111111111111", FleetRoles.CURRENT_ADMIN_ROLE);
        assocProfileByInst.put("i-02222222222222222", FleetRoles.CURRENT_ADMIN_ROLE);
        Map<String, String> instByAssoc = new LinkedHashMap<>();
        instByAssoc.put("iip-assoc-01111111111111111", "i-01111111111111111");
        instByAssoc.put("iip-assoc-02222222222222222", "i-02222222222222222");
        Map<String, String> createdRoleBoundaries = new LinkedHashMap<>();
        Map<String, String> inlineRolePolicies = new LinkedHashMap<>();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, String> form = parseForm(raw);
            String action = form.getOrDefault("Action", "");
            int status = 200;
            String xml;
            switch (action) {
                case "GetCallerIdentity" -> {
                    callOrder.add("sts:GetCallerIdentity");
                    xml = "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                        + "<GetCallerIdentityResult><Account>123456789012</Account>"
                        + "<Arn>arn:aws:iam::123456789012:user/admin</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>";
                }
                case "GetPolicy" -> {
                    status = 404;
                    xml = "<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>Policy not found</Message></Error></ErrorResponse>";
                }
                case "CreatePolicy" -> {
                    String pName = form.getOrDefault("PolicyName", "");
                    callOrder.add("iam:CreatePolicy:" + pName);
                    xml = "<CreatePolicyResponse><CreatePolicyResult><Policy>"
                        + "<PolicyName>" + pName + "</PolicyName>"
                        + "<Arn>arn:aws:iam::123456789012:policy/" + pName + "</Arn>"
                        + "<DefaultVersionId>v1</DefaultVersionId>"
                        + "</Policy></CreatePolicyResult></CreatePolicyResponse>";
                }
                case "GetRole" -> {
                    status = 404;
                    xml = "<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>Role not found</Message></Error></ErrorResponse>";
                }
                case "CreateRole" -> {
                    String rName = form.getOrDefault("RoleName", "");
                    String boundary = form.getOrDefault("PermissionsBoundary", "");
                    createdRoleBoundaries.put(rName, boundary);
                    callOrder.add("iam:CreateRole:" + rName);
                    xml = "<CreateRoleResponse><CreateRoleResult><Role>"
                        + "<RoleName>" + rName + "</RoleName>"
                        + "<Arn>arn:aws:iam::123456789012:role/" + rName + "</Arn>"
                        + "</Role></CreateRoleResult></CreateRoleResponse>";
                }
                case "PutRolePolicy" -> {
                    String rName = form.getOrDefault("RoleName", "");
                    inlineRolePolicies.put(rName, form.getOrDefault("PolicyDocument", ""));
                    callOrder.add("iam:PutRolePolicy:" + rName);
                    xml = "<PutRolePolicyResponse><ResponseMetadata><RequestId>req</RequestId></ResponseMetadata></PutRolePolicyResponse>";
                }
                case "GetInstanceProfile" -> {
                    status = 404;
                    xml = "<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>Profile not found</Message></Error></ErrorResponse>";
                }
                case "CreateInstanceProfile" -> {
                    String ipName = form.getOrDefault("InstanceProfileName", "");
                    callOrder.add("iam:CreateInstanceProfile:" + ipName);
                    xml = "<CreateInstanceProfileResponse><CreateInstanceProfileResult><InstanceProfile>"
                        + "<InstanceProfileName>" + ipName + "</InstanceProfileName>"
                        + "<Arn>arn:aws:iam::123456789012:instance-profile/" + ipName + "</Arn>"
                        + "</InstanceProfile></CreateInstanceProfileResult></CreateInstanceProfileResponse>";
                }
                case "AddRoleToInstanceProfile" -> {
                    String ipName = form.getOrDefault("InstanceProfileName", "");
                    callOrder.add("iam:AddRoleToInstanceProfile:" + ipName);
                    xml = "<AddRoleToInstanceProfileResponse><ResponseMetadata><RequestId>req</RequestId></ResponseMetadata></AddRoleToInstanceProfileResponse>";
                }
                case "DescribeInstances" -> {
                    callOrder.add("ec2:DescribeInstances");
                    String p1 = assocProfileByInst.get("i-01111111111111111");
                    String p2 = assocProfileByInst.get("i-02222222222222222");
                    xml = "<DescribeInstancesResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><reservationSet><item><instancesSet>"
                        + "<item><instanceId>i-01111111111111111</instanceId><instanceState><name>running</name></instanceState>"
                        + "<instanceType>t4g.xlarge</instanceType>"
                        + "<iamInstanceProfile><arn>arn:aws:iam::123456789012:instance-profile/" + p1 + "</arn></iamInstanceProfile>"
                        + "<tagSet><item><key>Project</key><value>" + FleetRoles.PROJECT_TAG + "</value></item><item><key>Name</key><value>" + FleetRoles.INSTANCE_1 + "</value></item><item><key>Role</key><value>" + FleetRoles.ROLE_TAG_1 + "</value></item></tagSet></item>"
                        + "<item><instanceId>i-02222222222222222</instanceId><instanceState><name>running</name></instanceState>"
                        + "<instanceType>t4g.xlarge</instanceType>"
                        + "<iamInstanceProfile><arn>arn:aws:iam::123456789012:instance-profile/" + p2 + "</arn></iamInstanceProfile>"
                        + "<tagSet><item><key>Project</key><value>" + FleetRoles.PROJECT_TAG + "</value></item><item><key>Name</key><value>" + FleetRoles.INSTANCE_2 + "</value></item><item><key>Role</key><value>" + FleetRoles.ROLE_TAG_2 + "</value></item></tagSet></item>"
                        + "</instancesSet></item></reservationSet></DescribeInstancesResponse>";
                }
                case "DescribeIamInstanceProfileAssociations" -> {
                    String filterInst = form.getOrDefault("Filter.1.Value.1", "");
                    String assocIdFilter = form.getOrDefault("AssociationId.1", "");
                    String instId = !filterInst.isEmpty() ? filterInst : instByAssoc.getOrDefault(assocIdFilter, "i-01111111111111111");
                    String assocId = "i-02222222222222222".equals(instId)
                        ? "iip-assoc-02222222222222222" : "iip-assoc-01111111111111111";
                    String prof = assocProfileByInst.getOrDefault(instId, FleetRoles.CURRENT_ADMIN_ROLE);
                    if (!assocIdFilter.isEmpty()) {
                        callOrder.add("ec2:VerifyAssociation:" + ("i-02222222222222222".equals(instId) ? FleetRoles.INSTANCE_2 : FleetRoles.INSTANCE_1) + ":" + prof);
                    }
                    xml = "<DescribeIamInstanceProfileAssociationsResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\">"
                        + "<iamInstanceProfileAssociationSet><item>"
                        + "<associationId>" + assocId + "</associationId>"
                        + "<instanceId>" + instId + "</instanceId>"
                        + "<state>associated</state>"
                        + "<iamInstanceProfile><arn>arn:aws:iam::123456789012:instance-profile/" + prof + "</arn></iamInstanceProfile>"
                        + "</item></iamInstanceProfileAssociationSet></DescribeIamInstanceProfileAssociationsResponse>";
                }
                case "ReplaceIamInstanceProfileAssociation" -> {
                    String assocId = form.getOrDefault("AssociationId", "");
                    String newProf = form.getOrDefault("IamInstanceProfile.Name", "");
                    String instId = instByAssoc.getOrDefault(assocId, "");
                    assocProfileByInst.put(instId, newProf);
                    String instName = "i-02222222222222222".equals(instId) ? FleetRoles.INSTANCE_2 : FleetRoles.INSTANCE_1;
                    callOrder.add("ec2:ReplaceAssociation:" + instName + "->" + newProf);
                    xml = "<ReplaceIamInstanceProfileAssociationResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\">"
                        + "<iamInstanceProfileAssociation>"
                        + "<associationId>" + assocId + "</associationId>"
                        + "<instanceId>" + instId + "</instanceId>"
                        + "<state>associated</state>"
                        + "<iamInstanceProfile><arn>arn:aws:iam::123456789012:instance-profile/" + newProf + "</arn></iamInstanceProfile>"
                        + "</iamInstanceProfileAssociation></ReplaceIamInstanceProfileAssociationResponse>";
                }
                case "DescribeInstanceStatus" -> {
                    String instId = form.getOrDefault("InstanceId.1", "");
                    String instName = "i-02222222222222222".equals(instId) ? FleetRoles.INSTANCE_2 : FleetRoles.INSTANCE_1;
                    callOrder.add("ec2:VerifyStatus:" + instName);
                    xml = "<DescribeInstanceStatusResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\">"
                        + "<instanceStatusSet><item><instanceId>" + instId + "</instanceId>"
                        + "<instanceState><name>running</name></instanceState></item></instanceStatusSet></DescribeInstanceStatusResponse>";
                }
                default -> {
                    status = 400;
                    xml = "<ErrorResponse><Error><Code>UnsupportedOperation</Code><Message>" + URLEncoder.encode(action, StandardCharsets.UTF_8) + "</Message></Error></ErrorResponse>";
                }
            }
            byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/xml");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        String prevProfile = System.getProperty("lmaws.profile");
        String prevLive = System.getProperty("lmaws.live");
        String prevApply = System.getProperty("lmaws.apply");
        try (AwsBackend backend = new AwsBackend("us-east-1", true, null, "admin")) {
            Field demoField = AwsBackend.class.getDeclaredField("demo");
            demoField.setAccessible(true);
            demoField.set(backend, false);
            Field epField = AwsBackend.class.getDeclaredField("endpoint");
            epField.setAccessible(true);
            epField.set(backend, URI.create("http://127.0.0.1:" + server.getAddress().getPort()));

            System.setProperty("lmaws.profile", "admin");
            System.setProperty("lmaws.live", "true");
            System.setProperty("lmaws.apply", "true");

            if (!"1".equals(System.getenv("LMAWS_ADMIN_GRANT"))) {
                expectThrows("LMAWS_ADMIN_GRANT=1", () -> FleetRoles.apply(backend, true, true));
                require(callOrder.isEmpty(), "Guard failure must not contact endpoint");
            }

            Map<String, String> applied = applyWithTestGrant(backend);
            require("applied".equals(applied.get("mode")) && "true".equals(applied.get("applied")),
                "Loopback apply must succeed");
            require(("arn:aws:iam::123456789012:policy/" + FleetRoles.BOUNDARY_NAME).equals(createdRoleBoundaries.get(FleetRoles.ROLE_NODE_1))
                    && ("arn:aws:iam::123456789012:policy/" + FleetRoles.BOUNDARY_NAME).equals(createdRoleBoundaries.get(FleetRoles.ROLE_NODE_2)),
                "Both roles must be created with the mandatory permissions boundary");
            require(inlineRolePolicies.containsKey(FleetRoles.ROLE_NODE_1) && inlineRolePolicies.containsKey(FleetRoles.ROLE_NODE_2),
                "Both roles must receive their least-privilege inline policies");

            // Verify strict sequential order: ops-node-1 replaced and verified BEFORE ops-node-2 is replaced!
            int idxReplace1 = callOrder.indexOf("ec2:ReplaceAssociation:" + FleetRoles.INSTANCE_1 + "->" + FleetRoles.ROLE_NODE_1);
            int idxVerifyAssoc1 = callOrder.indexOf("ec2:VerifyAssociation:" + FleetRoles.INSTANCE_1 + ":" + FleetRoles.ROLE_NODE_1);
            int idxVerifyStatus1 = callOrder.indexOf("ec2:VerifyStatus:" + FleetRoles.INSTANCE_1);
            int idxReplace2 = callOrder.indexOf("ec2:ReplaceAssociation:" + FleetRoles.INSTANCE_2 + "->" + FleetRoles.ROLE_NODE_2);
            int idxVerifyAssoc2 = callOrder.indexOf("ec2:VerifyAssociation:" + FleetRoles.INSTANCE_2 + ":" + FleetRoles.ROLE_NODE_2);
            int idxVerifyStatus2 = callOrder.indexOf("ec2:VerifyStatus:" + FleetRoles.INSTANCE_2);
            require(idxReplace1 >= 0 && idxVerifyAssoc1 > idxReplace1 && idxVerifyStatus1 > idxVerifyAssoc1
                    && idxReplace2 > idxVerifyStatus1 && idxVerifyAssoc2 > idxReplace2 && idxVerifyStatus2 > idxVerifyAssoc2,
                "ops-node-1 must be replaced and read-only verified before ops-node-2 is replaced; actual callOrder=" + callOrder);

            // Now test one-command rollback (restores ops-node-2 then ops-node-1 back to example-legacy-wide-role)
            callOrder.clear();
            String receiptJson = applied.get("rollback_receipt_json");
            Map<String, String> dryRollback = FleetRoles.rollback(backend, receiptJson, false, false);
            require("false".equals(dryRollback.get("applied")) && callOrder.isEmpty(),
                "Dry-run rollback must not make AWS calls");

            Map<String, String> rolledBack = rollbackWithTestGrant(backend, receiptJson);
            require("true".equals(rolledBack.get("applied")) && "2".equals(rolledBack.get("restored_count")),
                "Rollback must restore both instance associations");
            int rb2 = callOrder.indexOf("ec2:ReplaceAssociation:" + FleetRoles.INSTANCE_2 + "->" + FleetRoles.CURRENT_ADMIN_ROLE);
            int rb1 = callOrder.indexOf("ec2:ReplaceAssociation:" + FleetRoles.INSTANCE_1 + "->" + FleetRoles.CURRENT_ADMIN_ROLE);
            require(rb2 >= 0 && rb1 > rb2,
                "Rollback must restore ops-node-2 first and then ops-node-1; actual callOrder=" + callOrder);
            require(FleetRoles.CURRENT_ADMIN_ROLE.equals(assocProfileByInst.get("i-01111111111111111"))
                    && FleetRoles.CURRENT_ADMIN_ROLE.equals(assocProfileByInst.get("i-02222222222222222")),
                "Both instances must be restored to legacy profile after rollback");
        } finally {
            restoreProp("lmaws.profile", prevProfile);
            restoreProp("lmaws.live", prevLive);
            restoreProp("lmaws.apply", prevApply);
            server.stop(0);
        }
    }

    private static Map<String, String> applyWithTestGrant(AwsBackend backend) throws Exception {
        String prev = System.getProperty("lmaws.adminGrantTest");
        try {
            System.setProperty("lmaws.adminGrantTest", "true");
            return FleetRoles.apply(backend, true, true);
        } finally {
            restoreProp("lmaws.adminGrantTest", prev);
        }
    }

    private static Map<String, String> rollbackWithTestGrant(AwsBackend backend, String receiptJson) {
        String prev = System.getProperty("lmaws.adminGrantTest");
        try {
            System.setProperty("lmaws.adminGrantTest", "true");
            return FleetRoles.rollback(backend, receiptJson, true, true);
        } finally {
            restoreProp("lmaws.adminGrantTest", prev);
        }
    }

    private static void restoreProp(String key, String value) {
        if (value == null) System.clearProperty(key);
        else System.setProperty(key, value);
    }

    private static Map<String, String> parseForm(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) return out;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                out.put(k, v);
            }
        }
        return out;
    }

    private static void expectThrows(String expectedSubstring, Runnable action) {
        try {
            action.run();
        } catch (RuntimeException ex) {
            String msg = ex.getMessage() == null ? "" : ex.getMessage();
            if (msg.contains(expectedSubstring)) return;
            throw new AssertionError("Expected error containing '" + expectedSubstring + "', got: " + msg, ex);
        }
        throw new AssertionError("Expected exception containing '" + expectedSubstring + "', but call succeeded");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
