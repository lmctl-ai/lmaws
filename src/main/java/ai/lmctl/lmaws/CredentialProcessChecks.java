package ai.lmctl.lmaws;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Self-tests for {@link CredentialProcess}: federation spec, source-profile guard,
 * ambient credential isolation, 0600 file + in-memory cache with 5-minute expiry margin,
 * loopback STS GetCallerIdentity/GetFederationToken, error redaction, and session_doctor.
 */
public final class CredentialProcessChecks {
    private CredentialProcessChecks() {}

    public static void run() throws Exception {
        checkFederationSpecs();
        checkPolicyFilesAndPaths();
        checkSourceProfileAndIsolationGuards();
        checkCachePermissionsAndExpiry();
        checkLoopbackStsAndErrorRedaction();
        checkDemoSessionDoctor();
        System.out.println(
            "PASS credential-process modes, isolated source profile loading, 0600 cache expiry, fake STS and redaction checks");
    }

    private static void checkFederationSpecs() {
        CredentialProcess.FederationSpec def = CredentialProcess.buildFederationSpec("default", 3600, null, "{\"Statement\":[]}");
        require("awsspot-local-default".equals(def.federatedUserName()), "Unexpected default federated user name");
        require(def.durationSeconds() == 3600, "Unexpected default duration");
        require(def.policyArns().equals(List.of(CredentialProcess.READ_ONLY_POLICY_ARN)), "Unexpected default policyArns");
        require(def.inlinePolicy() != null && def.inlinePolicy().contains("Statement"),
            "Default mode must include supplied inline policy");
        require(def.inlinePolicy().length() + CredentialProcess.READ_ONLY_POLICY_ARN.length() <= 2048,
            "Default session policy must fit within 2048 characters");

        for (String mode : List.of("lmaws", "lmaws-ec2", "lmaws-web")) {
            CredentialProcess.FederationSpec spec = CredentialProcess.buildFederationSpec(mode, 3600, "111122223333", null);
            require(("awsspot-local-" + mode).equals(spec.federatedUserName()), "Unexpected federated user for " + mode);
            require(
                spec.policyArns().equals(List.of("arn:aws:iam::111122223333:policy/lmaws_session")),
                "Managed mode must resolve arn:aws:iam::<account>:policy/lmaws_session");
            require(spec.inlinePolicy() == null, "Managed mode must not set an inline policy");
        }

        expectThrows(IllegalArgumentException.class, () -> CredentialProcess.buildFederationSpec("admin", 3600, "111122223333", null));
        expectThrows(IllegalArgumentException.class, () -> CredentialProcess.buildFederationSpec("unknown", 3600, "111122223333", null));
        expectThrows(IllegalArgumentException.class, () -> CredentialProcess.buildFederationSpec("lmaws", 600, "111122223333", null));
        expectThrows(IllegalArgumentException.class, () -> CredentialProcess.buildFederationSpec("lmaws", 200000, "111122223333", null));
        expectThrows(IllegalArgumentException.class, () -> CredentialProcess.buildFederationSpec("lmaws", 3600, "not-an-account", null));
    }

    private static void checkPolicyFilesAndPaths() throws Exception {
        Path file = Files.createTempFile("lmaws-policy-contract-", ".json");
        try {
            String prefix = "{\"Statement\":[],\"Pad\":\"";
            String suffix = "\"}";
            int padding = 2048 - CredentialProcess.READ_ONLY_POLICY_ARN.length() - prefix.length() - suffix.length();
            Files.writeString(file, prefix + "x".repeat(padding) + suffix);
            require(CredentialProcess.readInlinePolicy(file).length()
                + CredentialProcess.READ_ONLY_POLICY_ARN.length() == 2048, "inclusive STS size boundary");
            Files.writeString(file, prefix + "x".repeat(padding + 1) + suffix);
            expectThrows(IllegalArgumentException.class, () -> CredentialProcess.readInlinePolicy(file));
            Files.writeString(file, "{ \"Statement\" : [], \"Sid\" : \"café\\u007f\" }");
            require(CredentialProcess.readInlinePolicy(file).equals(
                "{\"Statement\":[],\"Sid\":\"caf\\u00e9\\u007f\"}"), "Python ASCII compact policy semantics");
            Path home = Path.of(System.getProperty("user.home", "."));
            require(CredentialProcess.policyPath("~/policy.json").equals(home.resolve("policy.json")), "Unix home expansion");
            require(CredentialProcess.policyPath("~\\policy.json").equals(home.resolve("policy.json")), "Windows home expansion");
            require(CredentialProcess.policyPath("relative policy.json").equals(Path.of("relative policy.json")), "relative path with spaces");
        } finally { Files.deleteIfExists(file); }
    }

    private static void checkSourceProfileAndIsolationGuards() throws Exception {
        for (String badProfile : List.of("", "admin", "prod-ADMIN", "admin-helper")) {
            expectThrows(IllegalArgumentException.class, () -> CredentialProcess.requireSourceProfile(badProfile));
        }
        CredentialProcess.requireSourceProfile("agent-issuer");

        Path tempAws = Files.createTempDirectory("lmaws-cred-isolation-");
        try {
            // 1. Missing credentials/config files -> refused even if ambient system properties are set
            String oldAk = System.getProperty("aws.accessKeyId");
            String oldSk = System.getProperty("aws.secretAccessKey");
            try {
                System.setProperty("aws.accessKeyId", "AMBIENT_KEY_MUST_BE_IGNORED");
                System.setProperty("aws.secretAccessKey", "AMBIENT_SECRET_MUST_BE_IGNORED");
                expectThrows(
                    IllegalStateException.class,
                    () -> CredentialProcess.loadIsolatedSourceCredentials("agent-issuer", tempAws));

                // 2. Credentials file has [default] and [lmaws], but no [agent-issuer] -> refused
                Files.writeString(
                    tempAws.resolve("credentials"),
                    "[default]\naws_access_key_id = AKIA_DEFAULT\naws_secret_access_key = SECRET_DEFAULT\n",
                    StandardCharsets.UTF_8);
                expectThrows(
                    IllegalStateException.class,
                    () -> CredentialProcess.loadIsolatedSourceCredentials("agent-issuer", tempAws));

                // 3. [agent-issuer] has role_arn / credential_process / web_identity_token_file / aws_session_token -> refused
                for (String forbiddenLine : List.of(
                        "aws_session_token = SESSION_TOK",
                        "role_arn = arn:aws:iam::111122223333:role/Admin",
                        "credential_process = /bin/true",
                        "web_identity_token_file = /tmp/token",
                        "credential_source = Environment",
                        "sso_start_url = https://example.awsapps.com/start")) {
                    Files.writeString(
                        tempAws.resolve("credentials"),
                        "[agent-issuer]\naws_access_key_id = AKIA_ADMIN_TEST\naws_secret_access_key = SECRET_ADMIN_TEST\n"
                            + forbiddenLine + "\n",
                        StandardCharsets.UTF_8);
                    expectThrows(
                        IllegalStateException.class,
                        () -> CredentialProcess.loadIsolatedSourceCredentials("agent-issuer", tempAws));
                }

                // 4. Valid static [agent-issuer] credentials -> resolves exact static keys from file, ignoring ambient properties
                Files.writeString(
                    tempAws.resolve("credentials"),
                    "[agent-issuer]\naws_access_key_id = AKIA_STATIC_ADMIN_OK\naws_secret_access_key = SECRET_STATIC_ADMIN_OK\n",
                    StandardCharsets.UTF_8);
                var provider = CredentialProcess.loadIsolatedSourceCredentials("agent-issuer", tempAws);
                var resolved = provider.resolveCredentials();
                require("AKIA_STATIC_ADMIN_OK".equals(resolved.accessKeyId()), "Must resolve static source access key from file");
                require("SECRET_STATIC_ADMIN_OK".equals(resolved.secretAccessKey()), "Must resolve static source secret key from file");
            } finally {
                if (oldAk == null) System.clearProperty("aws.accessKeyId");
                else System.setProperty("aws.accessKeyId", oldAk);
                if (oldSk == null) System.clearProperty("aws.secretAccessKey");
                else System.setProperty("aws.secretAccessKey", oldSk);
            }
        } finally {
            deleteRecursively(tempAws);
        }
    }

    private static void checkCachePermissionsAndExpiry() throws Exception {
        Path cacheDir = Files.createTempDirectory("lmaws-cred-cache-");
        try {
            CredentialProcess.clearMemoryCache();
            Instant base = Instant.parse("2026-10-26T20:00:00Z");
            Instant exp = base.plusSeconds(3600); // 21:00:00Z
            CredentialProcess.TokenResult token = new CredentialProcess.TokenResult(
                "ASIA_TEST_KEY", "SECRET_TEST_VAL", "TOKEN_TEST_VAL", exp);
            Path cacheFile = CredentialProcess.cacheFilePath(
                cacheDir, "lmaws", 3600, URI.create("http://127.0.0.1:9999"), cacheDir);

            CredentialProcess.writeCachedToken(cacheFile, token);
            require(Files.isRegularFile(cacheFile), "Cache file must exist");
            require(CredentialProcess.hasStrictOwnerOnlyPermissions(cacheFile), "Cache file must have 0600 owner-only permissions");

            // Valid 10 minutes before expiry (margin is 5 minutes)
            var hit = CredentialProcess.readCachedToken(cacheFile, exp.minusSeconds(600));
            require(hit.isPresent() && "ASIA_TEST_KEY".equals(hit.get().accessKeyId()), "Cache must hit when >5m before expiry");

            // Within 5 minutes (299s before expiry) -> cache miss
            var miss = CredentialProcess.readCachedToken(cacheFile, exp.minusSeconds(299));
            require(miss.isEmpty(), "Cache must miss when <=5m before expiry");

            // If POSIX permissions are widened to 0644, cache file must be rejected and deleted
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(cacheFile, PosixFilePermissions.fromString("rw-r--r--"));
                var insecure = CredentialProcess.readCachedToken(cacheFile, exp.minusSeconds(600));
                require(insecure.isEmpty(), "Insecure 0644 cache file must be rejected");
                require(!Files.exists(cacheFile), "Insecure cache file must be deleted");
            }
        } finally {
            CredentialProcess.clearMemoryCache();
            deleteRecursively(cacheDir);
        }
    }

    private static void checkLoopbackStsAndErrorRedaction() throws Exception {
        Path tempDir = Files.createTempDirectory("lmaws-sts-fake-");
        Path awsDir = tempDir.resolve(".aws");
        Path cacheDir = tempDir.resolve("cache");
        Files.createDirectories(awsDir);
        Path policyFile = awsDir.resolve("session-tools/tasks/iam-snapshots/local-default-session.json");
        Files.createDirectories(policyFile.getParent());
        Files.writeString(policyFile, "{\"Statement\":[{\"Sid\":\"FromPolicyFile\",\"Effect\":\"Deny\",\"Action\":\"secretsmanager:GetSecretValue\",\"Resource\":\"*\"}]}");
        Files.writeString(
            awsDir.resolve("credentials"),
            "[agent-issuer]\naws_access_key_id = AKIA_FAKE_ADMIN\naws_secret_access_key = SECRET_FAKE_ADMIN\n",
            StandardCharsets.UTF_8);

        AtomicInteger identityCalls = new AtomicInteger();
        AtomicInteger federationCalls = new AtomicInteger();
        AtomicBoolean failSts = new AtomicBoolean(false);
        List<Map<String, String>> capturedFederationParams = new ArrayList<>();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
            String body = new String(bodyBytes, StandardCharsets.UTF_8);
            Map<String, String> form = parseForm(body);
            String action = form.getOrDefault("Action", "");
            if (failSts.get()) {
                byte[] err = ("<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>"
                    + "<Message>TOP_SECRET_UPSTREAM_SENTINEL_123456789012</Message></Error></ErrorResponse>")
                    .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/xml");
                exchange.sendResponseHeaders(403, err.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(err);
                }
                return;
            }
            if ("GetCallerIdentity".equals(action)) {
                identityCalls.incrementAndGet();
                byte[] xml = ("<GetCallerIdentityResponse><GetCallerIdentityResult>"
                    + "<Account>111122223333</Account>"
                    + "<Arn>arn:aws:iam::111122223333:user/admin</Arn>"
                    + "<UserId>AIDAFAKEADMIN</UserId>"
                    + "</GetCallerIdentityResult></GetCallerIdentityResponse>")
                    .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/xml");
                exchange.sendResponseHeaders(200, xml.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(xml);
                }
                return;
            }
            if ("GetFederationToken".equals(action)) {
                int n = federationCalls.incrementAndGet();
                synchronized (capturedFederationParams) {
                    capturedFederationParams.add(form);
                }
                byte[] xml = ("<GetFederationTokenResponse><GetFederationTokenResult>"
                    + "<Credentials>"
                    + "<AccessKeyId>ASIAFAKEKEY" + n + "</AccessKeyId>"
                    + "<SecretAccessKey>FAKESECRET" + n + "</SecretAccessKey>"
                    + "<SessionToken>FAKETOKEN" + n + "</SessionToken>"
                    + "<Expiration>2026-10-26T22:00:00Z</Expiration>"
                    + "</Credentials>"
                    + "</GetFederationTokenResult></GetFederationTokenResponse>")
                    .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/xml");
                exchange.sendResponseHeaders(200, xml.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(xml);
                }
                return;
            }
            exchange.sendResponseHeaders(400, -1);
        });
        server.start();
        URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort());

        try {
            CredentialProcess.clearMemoryCache();
            Clock clockValid = Clock.fixed(Instant.parse("2026-10-26T21:10:00Z"), ZoneOffset.UTC);
            Clock clockNearExpiry = Clock.fixed(Instant.parse("2026-10-26T21:56:00Z"), ZoneOffset.UTC);

            // 1. Issue 'default' mode token (no GetCallerIdentity needed, inline policy + ReadOnlyAccess)
            var defToken = CredentialProcess.issueOrGetCached(
                "default", 3600, "agent-issuer", awsDir, cacheDir, endpoint, true, clockValid);
            require("ASIAFAKEKEY1".equals(defToken.accessKeyId()), "Unexpected default token key");
            require(identityCalls.get() == 0, "default mode should not need GetCallerIdentity");
            require(federationCalls.get() == 1, "Expected 1 GetFederationToken call");
            Map<String, String> defReq = capturedFederationParams.get(0);
            require("awsspot-local-default".equals(defReq.get("Name")), "Unexpected federated Name for default");
            require(CredentialProcess.READ_ONLY_POLICY_ARN.equals(defReq.get("PolicyArns.member.1.arn")),
                "Unexpected PolicyArns for default");
            require(defReq.getOrDefault("Policy", "").contains("FromPolicyFile"),
                "Expected inline file policy for default");

            // 2. Issue 'lmaws' mode token (resolves account via GetCallerIdentity -> arn:aws:iam::111122223333:policy/lmaws_session)
            var lmawsToken1 = CredentialProcess.issueOrGetCached(
                "lmaws", 3600, "agent-issuer", awsDir, cacheDir, endpoint, true, clockValid);
            require("ASIAFAKEKEY2".equals(lmawsToken1.accessKeyId()), "Unexpected lmaws token key");
            require(identityCalls.get() == 1, "lmaws mode must call GetCallerIdentity once");
            require(federationCalls.get() == 2, "Expected 2nd GetFederationToken call");
            Map<String, String> lmawsReq = capturedFederationParams.get(1);
            require("awsspot-local-lmaws".equals(lmawsReq.get("Name")), "Unexpected federated Name for lmaws");
            require("arn:aws:iam::111122223333:policy/lmaws_session".equals(lmawsReq.get("PolicyArns.member.1.arn")),
                "Unexpected PolicyArns for lmaws: " + lmawsReq);
            require(!lmawsReq.containsKey("Policy"), "lmaws mode must not send an inline Policy");

            // 3. Repeated call within validity window hits cache (in-memory and disk) -> 0 new STS calls
            CredentialProcess.clearMemoryCache(); // Force disk cache read
            var lmawsTokenCached = CredentialProcess.issueOrGetCached(
                "lmaws", 3600, "agent-issuer", awsDir, cacheDir, endpoint, true, clockValid);
            require("ASIAFAKEKEY2".equals(lmawsTokenCached.accessKeyId()), "Must return cached token");
            require(identityCalls.get() == 1 && federationCalls.get() == 2, "Cache hit must make 0 STS calls");

            // 4. Call at 4 minutes before expiry (< 5m margin) refreshes from STS
            var lmawsTokenRefreshed = CredentialProcess.issueOrGetCached(
                "lmaws", 3600, "agent-issuer", awsDir, cacheDir, endpoint, true, clockNearExpiry);
            require("ASIAFAKEKEY3".equals(lmawsTokenRefreshed.accessKeyId()), "Near-expiry token must refresh");
            require(federationCalls.get() == 3, "Expected 3rd GetFederationToken call on refresh");

            // 5. Error redaction: STS failure or invalid argument prints ONLY generic message to stderr and nothing to stdout
            failSts.set(true);
            PrintStream origOut = System.out;
            PrintStream origErr = System.err;
            ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
            ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
            try {
                System.setOut(new PrintStream(outBuf, true, StandardCharsets.UTF_8));
                System.setErr(new PrintStream(errBuf, true, StandardCharsets.UTF_8));
                int code = CredentialProcess.runCli(new String[]{"--credential-process", "invalid-mode"});
                require(code == 1, "Invalid mode must exit with code 1");
                require(outBuf.toString(StandardCharsets.UTF_8).isEmpty(), "Failed credential-process must print nothing to stdout");
                String errText = errBuf.toString(StandardCharsets.UTF_8).trim();
                require(CredentialProcess.GENERIC_ERROR.equals(errText), "Unexpected stderr on failure: " + errText);
                require(!errText.contains("TOP_SECRET"), "Stderr must never leak upstream details");
            } finally {
                System.setOut(origOut);
                System.setErr(origErr);
            }
        } finally {
            server.stop(0);
            CredentialProcess.clearMemoryCache();
            deleteRecursively(tempDir);
        }
    }

    private static void checkDemoSessionDoctor() {
        List<Map<String, String>> rows = CredentialProcess.demoSessionDoctorRows();
        require(rows.size() == 12, "Expected 12 rows (4 profiles + 8 probes) in demo session doctor");
        long profileCount = rows.stream().filter(r -> "profile".equals(r.get("kind"))).count();
        long probeCount = rows.stream().filter(r -> "probe".equals(r.get("kind"))).count();
        require(profileCount == 4 && probeCount == 8, "Expected 4 profile rows and 8 probe rows");
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> out = new LinkedHashMap<>();
        if (body == null || body.isBlank()) return out;
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                out.put(k, v);
            }
        }
        return out;
    }

    private static void deleteRecursively(Path root) {
        if (root == null || !Files.exists(root)) return;
        try (var stream = Files.walk(root)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {}
            });
        } catch (Exception ignored) {}
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException("CredentialProcessChecks failed: " + message);
        }
    }

    private static void expectThrows(Class<? extends Throwable> expected, Runnable action) {
        try {
            action.run();
        } catch (Throwable t) {
            if (expected.isInstance(t)) return;
            throw new IllegalStateException("Expected " + expected.getSimpleName() + ", got " + t, t);
        }
        throw new IllegalStateException("Expected " + expected.getSimpleName() + " to be thrown, but succeeded");
    }
}
