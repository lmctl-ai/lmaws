package ai.lmctl.lmaws;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/** Self-tests for the closed set of non-mutating publish grant verification probes. */
public final class PublishGrantProbeChecks {
    private PublishGrantProbeChecks() {}

    private static final String FAKE_ACCOUNT = "123456789012";

    public static void run() throws Exception {
        // 1. Closed probe catalog and refusal of unknown kinds.
        List<Map<String, String>> kinds = PublishGrantProbes.describeKinds();
        check(kinds.size() == 10, "expected 10 safe probe kinds");
        for (String badKind : List.of("", "s3_put_unconditional", "s3_delete_existing", "iam_attach_policy", "exec")) {
            boolean refused = false;
            try {
                PublishGrantProbes.requireAllowedKind(badKind);
            } catch (IllegalArgumentException expected) {
                refused = true;
            }
            check(refused, "unknown probe kind must be refused: " + badKind);
        }

        // 2. Profile guard: admin and mutating profiles must be refused before any SDK call.
        String prevProfile = System.getProperty("lmaws.profile");
        try {
            for (String forbidden : List.of("admin", "lmaws", "lmaws-ec2")) {
                System.setProperty("lmaws.profile", forbidden);
                AwsBackend badBackend = new AwsBackend("us-east-1", true, null, forbidden);
                boolean refused = false;
                try {
                    PublishGrantProbes.runSingle(badBackend, "identity_sanity", "", "");
                } catch (SecurityException expected) {
                    refused = true;
                } finally {
                    badBackend.close();
                }
                check(refused, "profile must be refused: " + forbidden);
            }

            // 3. Demo mode checks with default profile.
            System.setProperty("lmaws.profile", "default");
            try (AwsBackend demo = new AwsBackend("us-east-1", true, null, "default")) {
                String batchSpec = Jsons.encodeRaw(List.of(
                    Map.of("id", "id1", "kind", "identity_sanity", "target", "", "extra", ""),
                    Map.of("id", "own1", "kind", "bucket_owner_sanity", "target", "synthetic-site-bucket", "extra", ""),
                    Map.of("id", "meta1", "kind", "bucket_metadata_sanity", "target", "synthetic-site-bucket", "extra", ""),
                    Map.of("id", "put1", "kind", "s3_put_if_match_wrong_etag", "target", "synthetic-site-bucket/dataset/*", "extra", ""),
                    Map.of("id", "del1", "kind", "s3_delete_nonexistent", "target", "synthetic-site-bucket/dataset/*", "extra", "cafe01"),
                    Map.of("id", "acl1", "kind", "s3_put_acl_nonexistent", "target", "synthetic-site-bucket/dataset/*", "extra", "cafe01"),
                    Map.of("id", "sec1", "kind", "secrets_get_nonexistent", "target", "__perm_check_nonexistent_cafe01", "extra", ""),
                    Map.of("id", "ssm1", "kind", "ssm_get_nonexistent", "target", "/__perm_check_nonexistent_cafe01", "extra", ""),
                    Map.of("id", "cfneg", "kind", "cloudfront_invalidate_nonexistent_dist", "target", "E00000NONEXIST", "extra", "cafe01"),
                    Map.of("id", "cfopt", "kind", "cloudfront_invalidate_opt_in", "target", "E1SYNTHETIC123", "extra", "opt_in:cafe01")
                ));
                List<Map<String, String>> demoRows = PublishGrantProbes.runBatch(demo, batchSpec);
                check(demoRows.size() == 10, "all 10 demo probes executed");
                for (Map<String, String> row : demoRows) {
                    check("PASS".equals(row.get("status")) && "true".equals(row.get("passed")),
                        "demo probe must pass: " + row.get("probe_id"));
                }

                // Guardrails on target patterns in safe probes.
                checkRefused(() -> PublishGrantProbes.runSingle(demo, "secrets_get_nonexistent", "real-production-secret", ""));
                checkRefused(() -> PublishGrantProbes.runSingle(demo, "ssm_get_nonexistent", "/real/production/param", ""));
                checkRefused(() -> PublishGrantProbes.runSingle(demo, "cloudfront_invalidate_nonexistent_dist", "E1REALDIST1234", "cafe01"));
                checkRefused(() -> PublishGrantProbes.runSingle(demo, "cloudfront_invalidate_opt_in", "E1SYNTHETIC123", "cafe01"));
            }

            // 4. Loopback fake transport tests: happy path, wrongly-granted 403 PutObject, and 204 DeleteObject immediate stop.
            runLoopbackTransportChecks();
        } finally {
            if (prevProfile == null) System.clearProperty("lmaws.profile");
            else System.setProperty("lmaws.profile", prevProfile);
        }
        System.out.println("PASS publish grant probes: closed probe catalog, default-only guard, conditional If-Match wire proof, 403 denial detection, and immediate stop on non-403 DeleteObject");
    }

    private static void checkRefused(Runnable action) {
        boolean refused = false;
        try {
            action.run();
        } catch (RuntimeException expected) {
            refused = true;
        }
        check(refused, "unsafe probe argument should be refused");
    }

    private static final class ProbeFakeState {
        String mode = "happy";
        final List<String> calls = new ArrayList<>();
        String lastIfMatch = "";
    }

    private static void runLoopbackTransportChecks() throws Exception {
        ProbeFakeState state = new ProbeFakeState();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(null);
        server.createContext("/", ex -> handleFake(ex, state));
        server.start();
        String endpoint = "http://127.0.0.1:" + server.getAddress().getPort();
        try {
            System.setProperty("lmaws.profile", "default");
            try (AwsBackend liveFake = newBackendWithEndpoint(endpoint)) {
                // Case A: Happy path — PutObject with wrong If-Match returns 412 PreconditionFailed (PASS),
                // negative probes return 403 AccessDenied (PASS), opt-in CloudFront returns 201+200 (PASS).
                state.mode = "happy";
                state.calls.clear();
                Map<String, String> putOk = PublishGrantProbes.runSingle(
                    liveFake, "s3_put_if_match_wrong_etag", "synthetic-bucket/dataset/*", "");
                check("PASS".equals(putOk.get("status")) && "412".equals(putOk.get("http_status")),
                    "412 PreconditionFailed must be PASS: " + putOk);
                check("\"00000000000000000000000000000000\"".equals(state.lastIfMatch),
                    "PutObject must send quoted wrong If-Match header on the wire; got " + state.lastIfMatch);

                // Verify alternate wrong ETag selection when existing object has all-zero ETag.
                state.mode = "zero_etag";
                Map<String, String> putAlt = PublishGrantProbes.runSingle(
                    liveFake, "s3_put_if_match_wrong_etag", "synthetic-bucket/dataset/*", "");
                check("PASS".equals(putAlt.get("status")) && "\"ffffffffffffffffffffffffffffffff\"".equals(state.lastIfMatch),
                    "all-zero object ETag must select alternate wrong If-Match ETag; got " + state.lastIfMatch);

                // Case B: Wrongly-granted policy where S3 PutObject returns 403 AccessDenied -> must FAIL.
                state.mode = "put_denied_403";
                Map<String, String> putDenied = PublishGrantProbes.runSingle(
                    liveFake, "s3_put_if_match_wrong_etag", "synthetic-bucket/dataset/*", "");
                check("FAIL".equals(putDenied.get("status"))
                        && "false".equals(putDenied.get("passed"))
                        && "403".equals(putDenied.get("http_status")),
                    "403 AccessDenied on PutObject must be FAIL: " + putDenied);

                // Case C: Negative probes when properly denied (403) vs wrongly allowed (ResourceNotFound/ParameterNotFound/204).
                state.mode = "happy";
                check("PASS".equals(PublishGrantProbes.runSingle(
                    liveFake, "s3_delete_nonexistent", "synthetic-bucket/dataset/*", "cafe01").get("status")),
                    "403 on DeleteObject must PASS");
                check("PASS".equals(PublishGrantProbes.runSingle(
                    liveFake, "s3_put_acl_nonexistent", "synthetic-bucket/dataset/*", "cafe01").get("status")),
                    "403 on PutObjectAcl must PASS");
                check("PASS".equals(PublishGrantProbes.runSingle(
                    liveFake, "secrets_get_nonexistent", "__perm_check_nonexistent_cafe01", "").get("status")),
                    "AccessDeniedException on GetSecretValue must PASS");
                check("PASS".equals(PublishGrantProbes.runSingle(
                    liveFake, "ssm_get_nonexistent", "/__perm_check_nonexistent_cafe01", "").get("status")),
                    "AccessDeniedException on GetParameter must PASS");
                check("PASS".equals(PublishGrantProbes.runSingle(
                    liveFake, "cloudfront_invalidate_nonexistent_dist", "E00000NONEXIST", "cafe01").get("status")),
                    "403 on nonexistent CloudFront distribution must PASS");
                Map<String, String> cfOptOk = PublishGrantProbes.runSingle(
                    liveFake, "cloudfront_invalidate_opt_in", "E1SYNTHETIC123", "opt_in:cafe01");
                check("PASS".equals(cfOptOk.get("status"))
                        && "****NV01".equals(cfOptOk.get("invalidation_id"))
                        && "201/200".equals(cfOptOk.get("http_status"))
                        && "/__perm_check/cafe01-e1synthetic123".equals(cfOptOk.get("invalidation_path")),
                    "opt-in CloudFront invalidation must PASS with masked invalidation_id and unique path: " + cfOptOk);

                // Wrongly-granted negative probes (e.g. ResourceNotFoundException / ParameterNotFound / NoSuchDistribution) must FAIL.
                state.mode = "negative_not_found";
                check("FAIL".equals(PublishGrantProbes.runSingle(
                    liveFake, "secrets_get_nonexistent", "__perm_check_nonexistent_cafe01", "").get("status")),
                    "ResourceNotFoundException on GetSecretValue means explicit deny is missing -> FAIL");
                check("FAIL".equals(PublishGrantProbes.runSingle(
                    liveFake, "ssm_get_nonexistent", "/__perm_check_nonexistent_cafe01", "").get("status")),
                    "ParameterNotFound on GetParameter means explicit deny is missing -> FAIL");
                check("FAIL".equals(PublishGrantProbes.runSingle(
                    liveFake, "cloudfront_invalidate_nonexistent_dist", "E00000NONEXIST", "cafe01").get("status")),
                    "404 NoSuchDistribution on CreateInvalidation means wildcard CloudFront allow -> FAIL");

                // Case D: CRITICAL safety check — if DeleteObject returns 204 instead of 403, mark FAIL and stop batch immediately!
                state.mode = "delete_allowed_204";
                state.calls.clear();
                String batchWithBadDelete = Jsons.encodeRaw(List.of(
                    Map.of("id", "del_first", "kind", "s3_delete_nonexistent", "target", "synthetic-bucket/dataset/*", "extra", "cafe01"),
                    Map.of("id", "acl_second", "kind", "s3_put_acl_nonexistent", "target", "synthetic-bucket/dataset/*", "extra", "cafe01")
                ));
                List<Map<String, String>> abortedBatch = PublishGrantProbes.runBatch(liveFake, batchWithBadDelete);
                check(abortedBatch.size() == 1, "batch must stop immediately after non-403 DeleteObject; got " + abortedBatch.size());
                check("FAIL".equals(abortedBatch.get(0).get("status"))
                        && "true".equals(abortedBatch.get(0).get("stop_immediately")),
                    "non-403 DeleteObject must set stop_immediately=true: " + abortedBatch.get(0));
            }
        } finally {
            server.stop(0);
        }
    }

    private static AwsBackend newBackendWithEndpoint(String endpoint) throws Exception {
        AwsBackend b = new AwsBackend("us-east-1", true, null, "default");
        Field demoField = AwsBackend.class.getDeclaredField("demo");
        demoField.setAccessible(true);
        demoField.set(b, false);
        Field epField = AwsBackend.class.getDeclaredField("endpoint");
        epField.setAccessible(true);
        epField.set(b, java.net.URI.create(endpoint));
        return b;
    }

    private static void handleFake(HttpExchange ex, ProbeFakeState state) throws IOException {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        String query = ex.getRequestURI().getRawQuery() == null ? "" : ex.getRequestURI().getRawQuery();
        String target = ex.getRequestHeaders().getFirst("X-Amz-Target");
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        synchronized (state) {
            state.calls.add(method + " " + path + (query.isEmpty() ? "" : "?" + query));
        }

        // STS GetCallerIdentity
        if ("POST".equals(method) && body.contains("Action=GetCallerIdentity")) {
            sendXml(ex, 200, "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                + "<GetCallerIdentityResult><Account>" + FAKE_ACCOUNT + "</Account>"
                + "<Arn>arn:aws:sts::" + FAKE_ACCOUNT + ":federated-user/awsspot-local-default</Arn>"
                + "<UserId>AIDASYNTHETIC:default</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>");
            return;
        }

        // Secrets Manager & SSM JSON protocol
        if (target != null && target.contains("secretsmanager")) {
            if ("negative_not_found".equals(state.mode)) {
                sendJson(ex, 400, "{\"__type\":\"ResourceNotFoundException\",\"Message\":\"Secret not found\"}");
            } else {
                sendJson(ex, 400, "{\"__type\":\"AccessDeniedException\",\"Message\":\"User is not authorized to perform: secretsmanager:GetSecretValue with an explicit deny\"}");
            }
            return;
        }
        if (target != null && target.contains("AmazonSSM")) {
            if ("negative_not_found".equals(state.mode)) {
                sendJson(ex, 400, "{\"__type\":\"ParameterNotFound\",\"Message\":\"Parameter not found\"}");
            } else {
                sendJson(ex, 400, "{\"__type\":\"AccessDeniedException\",\"Message\":\"User is not authorized to perform: ssm:GetParameter with an explicit deny\"}");
            }
            return;
        }

        // CloudFront REST XML
        if (path.contains("/2020-05-31/distribution/")) {
            if (path.contains("E00000NONEXIST")) {
                if ("negative_not_found".equals(state.mode)) {
                    sendXml(ex, 404, "<ErrorResponse xmlns=\"http://cloudfront.amazonaws.com/doc/2020-05-31/\"><Error><Type>Sender</Type><Code>NoSuchDistribution</Code><Message>The specified distribution does not exist.</Message></Error></ErrorResponse>");
                } else {
                    sendXml(ex, 403, "<ErrorResponse xmlns=\"http://cloudfront.amazonaws.com/doc/2020-05-31/\"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User is not authorized to perform: cloudfront:CreateInvalidation</Message></Error></ErrorResponse>");
                }
                return;
            }
            if ("POST".equals(method) && path.endsWith("/invalidation")) {
                sendXml(ex, 201, "<Invalidation xmlns=\"http://cloudfront.amazonaws.com/doc/2020-05-31/\"><Id>ISYNTHETICINV01</Id><Status>InProgress</Status><CreateTime>2026-10-27T12:00:00Z</CreateTime><InvalidationBatch><Paths><Quantity>1</Quantity><Items><Path>/__perm_check/cafe01</Path></Items></Paths><CallerReference>perm-check-cafe01</CallerReference></InvalidationBatch></Invalidation>");
                return;
            }
            if ("GET".equals(method) && path.contains("/invalidation/")) {
                sendXml(ex, 200, "<Invalidation xmlns=\"http://cloudfront.amazonaws.com/doc/2020-05-31/\"><Id>ISYNTHETICINV01</Id><Status>Completed</Status><CreateTime>2026-10-27T12:00:00Z</CreateTime><InvalidationBatch><Paths><Quantity>1</Quantity><Items><Path>/__perm_check/cafe01</Path></Items></Paths><CallerReference>perm-check-cafe01</CallerReference></InvalidationBatch></Invalidation>");
                return;
            }
        }

        // S3 ListObjectsV2
        if ("GET".equals(method) && query.contains("list-type=2")) {
            sendXml(ex, 200, "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                + "<Name>synthetic-bucket</Name><Prefix>dataset/</Prefix><KeyCount>1</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated>"
                + "<Contents><Key>dataset/existing.json</Key><Size>42</Size><ETag>\"abcdef0123456789abcdef0123456789\"</ETag></Contents>"
                + "</ListBucketResult>");
            return;
        }

        // S3 HeadObject
        if ("HEAD".equals(method)) {
            String etag = "zero_etag".equals(state.mode)
                ? "\"00000000000000000000000000000000\""
                : "\"abcdef0123456789abcdef0123456789\"";
            ex.getResponseHeaders().set("ETag", etag);
            ex.getResponseHeaders().set("Content-Length", "42");
            ex.sendResponseHeaders(200, -1);
            ex.close();
            return;
        }

        // S3 PutObject / PutObjectAcl
        if ("PUT".equals(method)) {
            if (query.contains("acl")) {
                sendXml(ex, 403, "<Error><Code>AccessDenied</Code><Message>Explicit deny in session policy</Message></Error>");
                return;
            }
            synchronized (state) {
                state.lastIfMatch = ex.getRequestHeaders().getFirst("If-Match");
            }
            if ("put_denied_403".equals(state.mode)) {
                sendXml(ex, 403, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>");
                return;
            }
            sendXml(ex, 412, "<Error><Code>PreconditionFailed</Code><Message>At least one of the pre-conditions you specified did not hold</Message></Error>");
            return;
        }

        // S3 DeleteObject
        if ("DELETE".equals(method)) {
            if ("delete_allowed_204".equals(state.mode)) {
                ex.sendResponseHeaders(204, -1);
                ex.close();
                return;
            }
            sendXml(ex, 403, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>");
            return;
        }

        sendXml(ex, 500, "<Error><Code>InternalError</Code><Message>Unhandled fake route</Message></Error>");
    }

    private static void sendXml(HttpExchange ex, int status, String xml) throws IOException {
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/xml");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void sendJson(HttpExchange ex, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/x-amz-json-1.1");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void check(boolean ok, String label) {
        if (!ok) throw new AssertionError("PublishGrantProbeChecks failed: " + label);
    }
}
