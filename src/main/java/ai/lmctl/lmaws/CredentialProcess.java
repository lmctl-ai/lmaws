package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.LinkOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.profiles.Profile;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.InstanceType;
import software.amazon.awssdk.services.ec2.model.ResourceType;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ec2.model.TagSpecification;
import software.amazon.awssdk.services.ssm.model.SsmException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.services.sts.model.GetFederationTokenRequest;
import software.amazon.awssdk.services.sts.model.GetFederationTokenResponse;
import software.amazon.awssdk.services.sts.model.PolicyDescriptorType;

/**
 * Native credential_process implementation (`lmaws --credential-process <mode>`) and
 * read-only session doctor (`cloud.session_doctor()`).
 *
 * <p>Second documented exception to the profile guard: {@code lmaws --credential-process <mode>}
 * reads ONLY the selected static source profile from the shared credentials/config files to call
 * {@code sts:GetCallerIdentity} and {@code sts:GetFederationToken} in {@code us-east-1}. It creates
 * no AWS resources, changes no IAM permissions, ignores all ambient credentials (environment
 * variables, system properties, web identity, container, and instance metadata), caches tokens in
 * memory and in a {@code 0600} file under the user cache directory until 5 minutes before expiry,
 * and never prints secrets anywhere except the {@code credential_process} JSON on stdout.
 */
public final class CredentialProcess {
    public static final String GENERIC_ERROR =
        "AWS scoped profile unavailable; check the isolated source profile and session policy; agents never use admin.";
    public static final String DEFAULT_SOURCE_PROFILE = "agent-issuer";
    public static final String READ_ONLY_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess";
    public static final int INLINE_SESSION_LIMIT = 2048;
    public static final int MAX_SESSION_POLICY_ARNS = 10;
    public static final int DEFAULT_DURATION_SECONDS = 3600;
    public static final Duration EXPIRY_SAFETY_MARGIN = Duration.ofMinutes(5);

    private static final java.util.regex.Pattern EXTRA_POLICY_NAME_PATTERN =
        java.util.regex.Pattern.compile("^(?:lmaws|lmctl)_[a-z0-9_-]{1,64}$");
    private static final java.util.regex.Pattern EXTRA_POLICY_ARN_PATTERN =
        java.util.regex.Pattern.compile("^arn:aws:iam::([0-9]{12}):policy/((?:lmaws|lmctl)_[a-z0-9_-]{1,64})$");

    public static final Set<String> SUPPORTED_MODES = Set.of("default", "lmaws", "lmaws-ec2", "lmaws-web");
    public static final Map<String, String> MANAGED_POLICY_BY_MODE = Map.of(
        "lmaws", "lmaws_session",
        "lmaws-ec2", "lmaws_session",
        "lmaws-web", "lmaws_session"
    );

    public static final String ADMIN_SOURCE_ERROR =
        "Admin source profiles are refused: agents never use admin. Only a human may set LMAWS_ALLOW_ADMIN_SOURCE=1.";

    private static final Set<String> FORBIDDEN_SOURCE_PROFILE_PROPERTIES = Set.of(
        "aws_session_token",
        "aws_security_token",
        "role_arn",
        "source_profile",
        "credential_source",
        "credential_process",
        "web_identity_token_file",
        "sso_start_url",
        "sso_account_id",
        "sso_role_name",
        "sso_session",
        "external_id"
    );

    private static final Set<PosixFilePermission> GROUP_OR_OTHER_PERMS = EnumSet.of(
        PosixFilePermission.GROUP_READ,
        PosixFilePermission.GROUP_WRITE,
        PosixFilePermission.GROUP_EXECUTE,
        PosixFilePermission.OTHERS_READ,
        PosixFilePermission.OTHERS_WRITE,
        PosixFilePermission.OTHERS_EXECUTE
    );

    private static final ConcurrentHashMap<String, TokenResult> MEMORY_CACHE = new ConcurrentHashMap<>();

    private CredentialProcess() {}

    public record FederationSpec(
        String mode,
        String federatedUserName,
        int durationSeconds,
        List<String> policyArns,
        String inlinePolicy
    ) {}

    public record TokenResult(
        String accessKeyId,
        String secretAccessKey,
        String sessionToken,
        Instant expiration
    ) {
        public TokenResult {
            if (accessKeyId == null || accessKeyId.isBlank()
                    || secretAccessKey == null || secretAccessKey.isBlank()
                    || sessionToken == null || sessionToken.isBlank()
                    || expiration == null) {
                throw new IllegalArgumentException("incomplete STS credentials");
            }
        }

        public String expirationIso() {
            return expiration.truncatedTo(ChronoUnit.SECONDS).toString();
        }

        public String toCredentialProcessJson() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("Version", 1);
            out.put("AccessKeyId", accessKeyId);
            out.put("SecretAccessKey", secretAccessKey);
            out.put("SessionToken", sessionToken);
            out.put("Expiration", expirationIso());
            return IamPolicies.compactJson(out);
        }
    }

    public record CacheMetadata(
        String mode,
        boolean cached,
        String expirationIso,
        long ttlSeconds
    ) {}

    public static void clearMemoryCache() {
        MEMORY_CACHE.clear();
    }

    /** Explicit names only; no credentials provider chain or implicit admin source. */
    public static void requireSourceProfile(String sourceProfile) {
        if (sourceProfile == null || !sourceProfile.matches("[A-Za-z0-9_.@+-]{1,128}")) {
            throw new IllegalArgumentException("invalid source profile name");
        }
        if (sourceProfile.toLowerCase(Locale.ROOT).contains("admin")
                && !"1".equals(System.getenv("LMAWS_ALLOW_ADMIN_SOURCE"))) {
            throw new AdminSourceRefused();
        }
    }

    private static final class AdminSourceRefused extends IllegalArgumentException {}

    static String configuredSourceProfile() {
        return System.getenv().getOrDefault("LMAWS_CREDENTIAL_SOURCE_PROFILE", DEFAULT_SOURCE_PROFILE);
    }

    static Path policyPath(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("policy path is required");
        if (value.equals("~")) return Path.of(System.getProperty("user.home", "."));
        if (value.startsWith("~/") || value.startsWith("~\\")) {
            return Path.of(System.getProperty("user.home", ".")).resolve(value.substring(2));
        }
        return Path.of(value);
    }

    static Path defaultPolicyPath(Path awsDir) {
        String env = System.getenv("LMAWS_DEFAULT_SESSION_POLICY");
        return env == null || env.isBlank()
            ? awsDir.resolve("session-tools").resolve("tasks").resolve("iam-snapshots")
                .resolve("local-default-session.json") : policyPath(env);
    }

    /** Match Python json.dumps(..., separators=(",", ":")), including ensure_ascii. */
    static String readInlinePolicy(Path path) {
        return readInlinePolicy(path, List.of());
    }

    static String readInlinePolicy(Path path, List<String> extraPolicies) {
        try {
            if (Files.size(path) > 1024 * 1024) throw new IllegalArgumentException("policy file is too large");
            Object parsed = Json.parse(Files.readString(path, StandardCharsets.UTF_8));
            if (!(parsed instanceof Map<?, ?> doc) || !doc.containsKey("Statement")) {
                throw new IllegalArgumentException("expected a policy document");
            }
            String compact = IamPolicies.compactJson(parsed);
            StringBuilder ascii = new StringBuilder();
            for (char c : compact.toCharArray()) {
                if (c >= 127) ascii.append(String.format(Locale.ROOT, "\\u%04x", (int)c));
                else ascii.append(c);
            }
            String result = ascii.toString();
            int length = result.length() + READ_ONLY_POLICY_ARN.length();
            if (extraPolicies != null) {
                for (String extra : extraPolicies) {
                    length += resolvedExtraPolicyArnLength(extra);
                }
            }
            if (length > INLINE_SESSION_LIMIT) {
                throw new PolicyLimitExceeded(length);
            }
            return result;
        } catch (IOException e) {
            throw new IllegalArgumentException("session policy file unavailable");
        }
    }

    public static String validateExtraPolicyEntry(String rawEntry) {
        if (rawEntry == null) {
            throw new IllegalArgumentException("extra policy entry is required");
        }
        String entry = rawEntry.trim();
        if (entry.isEmpty()
                || entry.toLowerCase(Locale.ROOT).contains("admin")
                || entry.contains("*")) {
            throw new IllegalArgumentException("invalid or forbidden extra policy entry");
        }
        if (EXTRA_POLICY_NAME_PATTERN.matcher(entry).matches()
                || EXTRA_POLICY_ARN_PATTERN.matcher(entry).matches()) {
            return entry;
        }
        throw new IllegalArgumentException(
            "extra policy must be an lmaws_/lmctl_ policy name or full customer-managed IAM policy ARN");
    }

    static int resolvedExtraPolicyArnLength(String rawEntry) {
        String entry = validateExtraPolicyEntry(rawEntry);
        if (entry.startsWith("arn:aws:iam::")) {
            return entry.length();
        }
        return "arn:aws:iam::000000000000:policy/".length() + entry.length();
    }

    static String resolveExtraPolicyArn(String rawEntry, String accountId) {
        String entry = validateExtraPolicyEntry(rawEntry);
        var matcher = EXTRA_POLICY_ARN_PATTERN.matcher(entry);
        if (matcher.matches()) {
            if (accountId != null && !accountId.isBlank() && !accountId.equals(matcher.group(1))) {
                throw new IllegalArgumentException("extra policy ARN account mismatch");
            }
            return entry;
        }
        if (accountId == null || !accountId.matches("^[0-9]{12}$")) {
            throw new IllegalArgumentException("valid 12-digit AWS account ID required for extra managed policy ARN");
        }
        return "arn:aws:iam::" + accountId + ":policy/" + entry;
    }

    @SuppressWarnings("unchecked")
    public static List<String> parseExtraPolicySpecs(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        String trimmed = raw.trim();
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        if (trimmed.startsWith("[")) {
            Object parsed = Json.parse(trimmed);
            if (!(parsed instanceof List<?> list)) {
                throw new IllegalArgumentException("extra policy JSON must be an array");
            }
            for (Object item : list) {
                if (!(item instanceof String s)) {
                    throw new IllegalArgumentException("extra policy JSON entries must be strings");
                }
                out.add(validateExtraPolicyEntry(s));
            }
        } else {
            for (String line : trimmed.split("\\r?\\n")) {
                int hash = line.indexOf('#');
                String cleanLine = (hash >= 0 ? line.substring(0, hash) : line).trim();
                if (cleanLine.isEmpty()) continue;
                for (String token : cleanLine.split(",")) {
                    String t = token.trim();
                    if (!t.isEmpty()) {
                        out.add(validateExtraPolicyEntry(t));
                    }
                }
            }
        }
        if (out.size() > MAX_SESSION_POLICY_ARNS - 1) {
            throw new IllegalArgumentException("STS allows at most 10 PolicyArns (ReadOnlyAccess + up to 9 extra)");
        }
        return List.copyOf(out);
    }

    static List<String> configuredExtraPolicies(Path awsDir, Path policyFile, String cliExtraPolicyArns) {
        if (cliExtraPolicyArns != null) {
            return parseExtraPolicySpecs(cliExtraPolicyArns);
        }
        String env = System.getenv("LMAWS_DEFAULT_EXTRA_POLICY_ARNS");
        if (env != null && !env.isBlank()) {
            return parseExtraPolicySpecs(env);
        }
        String envFile = System.getenv("LMAWS_DEFAULT_EXTRA_POLICY_ARNS_FILE");
        if (envFile != null && !envFile.isBlank()) {
            Path p = policyPath(envFile);
            try {
                if (Files.size(p) > 64 * 1024) throw new IllegalArgumentException("extra policy file is too large");
                return parseExtraPolicySpecs(Files.readString(p, StandardCharsets.UTF_8));
            } catch (IOException e) {
                throw new IllegalArgumentException("extra policy file unavailable");
            }
        }
        Path dir = (policyFile != null && policyFile.getParent() != null)
            ? policyFile.getParent()
            : (awsDir == null ? null : awsDir.resolve("session-tools").resolve("tasks").resolve("iam-snapshots"));
        if (dir != null) {
            Path sibling = dir.resolve("local-default-extra-policy-arns.txt");
            if (Files.isRegularFile(sibling)) {
                try {
                    if (Files.size(sibling) > 64 * 1024) throw new IllegalArgumentException("extra policy file is too large");
                    return parseExtraPolicySpecs(Files.readString(sibling, StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new IllegalArgumentException("extra policy file unavailable");
                }
            }
        }
        return List.of();
    }

    private static final class PolicyLimitExceeded extends IllegalArgumentException {
        PolicyLimitExceeded(int length) {
            super("Session policy plus ReadOnlyAccess ARN is " + length + " characters; STS limit is 2048. Refusing issuance.");
        }
    }

    /**
     * Build the STS GetFederationToken specification for the given mode.
     *
     * <ul>
     *   <li>{@code default}: {@code ReadOnlyAccess} managed policy (+ optional extra customer-managed
     *       {@code PolicyArns}) + the supplied real inline session policy (verified {@code <= 2048}
     *       combined characters).
     *   <li>{@code lmaws}, {@code lmaws-ec2}, {@code lmaws-web}: {@code arn:aws:iam::<account>:policy/lmaws_session},
     *       no inline policy.
     * </ul>
     */
    public static FederationSpec buildFederationSpec(String mode, int durationSeconds, String accountId, String inlinePolicy) {
        return buildFederationSpec(mode, durationSeconds, accountId, inlinePolicy, List.of());
    }

    public static FederationSpec buildFederationSpec(
            String mode,
            int durationSeconds,
            String accountId,
            String inlinePolicy,
            List<String> extraPolicySpecs) {
        if (mode == null || !SUPPORTED_MODES.contains(mode)) {
            throw new IllegalArgumentException("expected default, lmaws, lmaws-ec2 or lmaws-web");
        }
        if (durationSeconds != DEFAULT_DURATION_SECONDS) {
            throw new IllegalArgumentException("durationSeconds must be 3600 to match the scoped session helper");
        }
        String federatedName = "awsspot-local-" + mode;
        String managedName = MANAGED_POLICY_BY_MODE.get(mode);
        if (managedName != null) {
            if (extraPolicySpecs != null && !extraPolicySpecs.isEmpty()) {
                throw new IllegalArgumentException("extra policy ARNs are only supported in default mode");
            }
            if (accountId == null || !accountId.matches("^[0-9]{12}$")) {
                throw new IllegalArgumentException("valid 12-digit AWS account ID required for managed policy ARN");
            }
            String arn = "arn:aws:iam::" + accountId + ":policy/" + managedName;
            return new FederationSpec(mode, federatedName, durationSeconds, List.of(arn), null);
        }
        if (inlinePolicy == null) throw new IllegalArgumentException("default mode requires a policy file");
        List<String> policyArns = new ArrayList<>();
        policyArns.add(READ_ONLY_POLICY_ARN);
        if (extraPolicySpecs != null && !extraPolicySpecs.isEmpty()) {
            List<String> normalized = parseExtraPolicySpecs(String.join(",", extraPolicySpecs));
            for (String raw : normalized) {
                String arn = resolveExtraPolicyArn(raw, accountId);
                if (!policyArns.contains(arn)) {
                    policyArns.add(arn);
                }
            }
        }
        if (policyArns.size() > MAX_SESSION_POLICY_ARNS) {
            throw new IllegalArgumentException("STS allows at most 10 PolicyArns");
        }
        int combinedLen = inlinePolicy.length() + policyArns.stream().mapToInt(String::length).sum();
        if (combinedLen > INLINE_SESSION_LIMIT) {
            throw new PolicyLimitExceeded(combinedLen);
        }
        return new FederationSpec(
            mode,
            federatedName,
            durationSeconds,
            List.copyOf(policyArns),
            inlinePolicy
        );
    }

    /**
     * Resolve selected static source credentials strictly from the shared credentials/config files.
     * Never reads environment variables, system properties, web identity tokens, container
     * credentials, or EC2 instance metadata, and refuses assumed roles or recursive credential_process.
     */
    public static StaticCredentialsProvider loadIsolatedSourceCredentials(String sourceProfile, Path awsDir) {
        requireSourceProfile(sourceProfile);
        if (awsDir == null) {
            throw new IllegalStateException("AWS configuration directory is required");
        }
        Path credentialsPath = awsDir.resolve("credentials");
        Path configPath = awsDir.resolve("config");
        ProfileFile.Aggregator aggregator = ProfileFile.aggregator();
        boolean anyFile = false;
        if (Files.isRegularFile(credentialsPath)) {
            aggregator.addFile(
                ProfileFile.builder()
                    .content(credentialsPath)
                    .type(ProfileFile.Type.CREDENTIALS)
                    .build());
            anyFile = true;
        }
        if (Files.isRegularFile(configPath)) {
            aggregator.addFile(
                ProfileFile.builder()
                    .content(configPath)
                    .type(ProfileFile.Type.CONFIGURATION)
                    .build());
            anyFile = true;
        }
        if (!anyFile) {
            throw new IllegalStateException("shared AWS credentials/config files not found");
        }
        ProfileFile profileFile = aggregator.build();
        Profile source = profileFile.profile(sourceProfile)
            .orElseThrow(() -> new IllegalStateException("selected source profile not found in shared credentials"));

        Map<String, String> props = source.properties();
        for (String propName : props.keySet()) {
            String lower = propName.toLowerCase(Locale.ROOT);
            if (FORBIDDEN_SOURCE_PROFILE_PROPERTIES.contains(lower)) {
                throw new IllegalStateException("source profile must use static IAM user credentials only");
            }
        }
        String accessKeyId = source.property("aws_access_key_id").orElse("").trim();
        String secretAccessKey = source.property("aws_secret_access_key").orElse("").trim();
        if (accessKeyId.isEmpty() || secretAccessKey.isEmpty()) {
            throw new IllegalStateException("source profile is missing static access key credentials");
        }
        return StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKeyId, secretAccessKey));
    }

    public static boolean isCacheUsable(Instant expiration, Instant now) {
        if (expiration == null || now == null) return false;
        return now.plus(EXPIRY_SAFETY_MARGIN).isBefore(expiration);
    }

    public static Path defaultAwsDir() {
        String testOverride = System.getenv("LMAWS_TEST_AWS_DIR");
        String endpoint = System.getenv("LMAWS_ENDPOINT");
        if (testOverride != null && !testOverride.isBlank() && endpoint != null && !endpoint.isBlank()) {
            return Path.of(testOverride.trim());
        }
        return Path.of(System.getProperty("user.home", "."), ".aws");
    }

    public static Path defaultCacheDir() {
        String prop = System.getProperty("lmaws.credentialCacheDir");
        if (prop != null && !prop.isBlank()) {
            return Path.of(prop.trim());
        }
        String envOverride = System.getenv("LMAWS_CREDENTIAL_CACHE_DIR");
        if (envOverride != null && !envOverride.isBlank()) {
            return Path.of(envOverride.trim());
        }
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String home = System.getProperty("user.home", ".");
        if (os.contains("win")) {
            String localAppData = System.getenv("LOCALAPPDATA");
            if (localAppData != null && !localAppData.isBlank()) {
                return Path.of(localAppData, "lmaws", "credential-process");
            }
            return Path.of(home, "AppData", "Local", "lmaws", "credential-process");
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return Path.of(home, "Library", "Caches", "lmaws", "credential-process");
        }
        String xdgCache = System.getenv("XDG_CACHE_HOME");
        if (xdgCache != null && !xdgCache.isBlank()) {
            return Path.of(xdgCache.trim(), "lmaws", "credential-process");
        }
        return Path.of(home, ".cache", "lmaws", "credential-process");
    }

    private static String issuanceScope(String mode, String source, StaticCredentialsProvider provider, String inline) {
        return issuanceScope(mode, source, provider, inline, List.of());
    }

    private static String issuanceScope(
            String mode,
            String source,
            StaticCredentialsProvider provider,
            String inline,
            List<String> extraPolicies) {
        var credentials = provider.resolveCredentials();
        String base = source + "\n" + credentials.accessKeyId() + "\n"
            + credentials.secretAccessKey() + "\n" + (inline == null ? "managed:lmaws_session" : inline);
        if (extraPolicies != null && !extraPolicies.isEmpty()) {
            base = base + "\nextra:" + String.join(",", extraPolicies);
        }
        return mode + "-v2-" + shortSha256(base);
    }

    private static String cacheKey(String mode, int durationSeconds, URI endpoint, Path awsDir, Path cacheDir) {
        String ep = endpoint == null ? "aws" : endpoint.toString();
        String dir = awsDir == null ? "" : awsDir.toAbsolutePath().normalize().toString();
        String cdir = cacheDir == null ? "" : cacheDir.toAbsolutePath().normalize().toString();
        return mode + ":" + durationSeconds + ":" + ep + ":" + dir + ":" + cdir;
    }

    public static Path cacheFilePath(Path cacheDir, String mode, int durationSeconds, URI endpoint, Path awsDir) {
        String scope = (endpoint == null ? "aws" : endpoint.toString()) + "|"
            + (awsDir == null ? "" : awsDir.toAbsolutePath().normalize().toString());
        String digest = shortSha256(scope);
        return cacheDir.resolve("session-" + mode + "-" + durationSeconds + "-" + digest + ".json");
    }

    private static String shortSha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 8);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static boolean supportsPosix(Path path) {
        try {
            return path.getFileSystem().supportedFileAttributeViews().contains("posix");
        } catch (Exception e) {
            return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
        }
    }

    private static void enforceOwnerOnlyDir(Path dir) throws IOException {
        if (Files.isSymbolicLink(dir)) throw new IOException("credential cache directory must not be a symbolic link");
        boolean created = !Files.exists(dir, LinkOption.NOFOLLOW_LINKS);
        if (created && supportsPosix(dir.toAbsolutePath().getParent() == null ? dir : dir.toAbsolutePath().getParent())) {
            Path parent = dir.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            try { Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))); }
            catch (FileAlreadyExistsException raced) { created = false; }
        } else if (created) {
            Files.createDirectories(dir);
        }
        if (supportsPosix(dir)) {
            // Tighten to 0700 (only the owner can; a directory of another user fails here and the cache is not used).
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS);
            for (PosixFilePermission p : GROUP_OR_OTHER_PERMS) if (perms.contains(p)) {
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
                break;
            }
        } else {
            File f = dir.toFile();
            f.setReadable(false, false);
            f.setReadable(true, true);
            f.setWritable(false, false);
            f.setWritable(true, true);
            f.setExecutable(false, false);
            f.setExecutable(true, true);
        }
    }

    public static void enforceOwnerOnlyFile(Path file) throws IOException {
        if (supportsPosix(file)) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } else {
            File f = file.toFile();
            f.setReadable(false, false);
            f.setReadable(true, true);
            f.setWritable(false, false);
            f.setWritable(true, true);
            f.setExecutable(false, false);
        }
    }

    public static boolean hasStrictOwnerOnlyPermissions(Path file) {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) return false;
        if (supportsPosix(file)) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
                for (PosixFilePermission p : GROUP_OR_OTHER_PERMS) {
                    if (perms.contains(p)) return false;
                }
                return perms.contains(PosixFilePermission.OWNER_READ);
            } catch (IOException e) {
                return false;
            }
        }
        return Files.isReadable(file);
    }

    @SuppressWarnings("unchecked")
    public static Optional<TokenResult> readCachedToken(Path cacheFile, Instant now) {
        if (!Files.isRegularFile(cacheFile, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        if (!hasStrictOwnerOnlyPermissions(cacheFile)) {
            try {
                Files.deleteIfExists(cacheFile);
            } catch (IOException ignored) {}
            return Optional.empty();
        }
        try {
            String raw = Files.readString(cacheFile, StandardCharsets.UTF_8);
            Object parsed = Json.parse(raw);
            if (!(parsed instanceof Map<?, ?> map)) return Optional.empty();
            Map<String, Object> m = (Map<String, Object>) map;
            String ak = String.valueOf(m.getOrDefault("AccessKeyId", ""));
            String sk = String.valueOf(m.getOrDefault("SecretAccessKey", ""));
            String st = String.valueOf(m.getOrDefault("SessionToken", ""));
            String expStr = String.valueOf(m.getOrDefault("Expiration", ""));
            if (ak.isBlank() || sk.isBlank() || st.isBlank() || expStr.isBlank()) {
                return Optional.empty();
            }
            Instant exp = Instant.parse(expStr);
            if (!isCacheUsable(exp, now)) {
                return Optional.empty();
            }
            return Optional.of(new TokenResult(ak, sk, st, exp));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public static void writeCachedToken(Path cacheFile, TokenResult token) throws IOException {
        Path parent = cacheFile.getParent();
        if (parent != null) {
            enforceOwnerOnlyDir(parent);
        }
        Path tmp = cacheFile.resolveSibling(cacheFile.getFileName().toString() + ".tmp-" + ProcessHandle.current().pid() + "-" + System.nanoTime());
        try {
            // Create the temp file owner-only before any secret is written (no world-readable window).
            if (supportsPosix(parent == null ? tmp.toAbsolutePath().getParent() : parent)) Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            else Files.createFile(tmp);
            enforceOwnerOnlyFile(tmp);
            Files.writeString(tmp, token.toCredentialProcessJson() + "\n", StandardCharsets.UTF_8, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(tmp, cacheFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, cacheFile, StandardCopyOption.REPLACE_EXISTING);
            }
            enforceOwnerOnlyFile(cacheFile);
        } finally {
            try {
                Files.deleteIfExists(tmp);
            } catch (IOException ignored) {}
        }
    }

    /**
     * Read ONLY non-secret cache metadata (expiration timestamp and remaining TTL) for {@code session_doctor}.
     * Never returns {@code AccessKeyId}, {@code SecretAccessKey}, or {@code SessionToken}.
     */
    @SuppressWarnings("unchecked")
    public static CacheMetadata inspectCacheMetadata(
            String mode,
            int durationSeconds,
            URI endpoint,
            Path awsDir,
            Path cacheDir,
            Instant now) {
        if (mode == null || !SUPPORTED_MODES.contains(mode)) {
            return new CacheMetadata(String.valueOf(mode), false, "not_cached", 0L);
        }
        String scope;
        try {
            String source = configuredSourceProfile();
            requireSourceProfile(source);
            Path policyFile = defaultPolicyPath(awsDir);
            List<String> extras = "default".equals(mode)
                ? configuredExtraPolicies(awsDir, policyFile, null)
                : List.of();
            scope = issuanceScope(mode, source, loadIsolatedSourceCredentials(source, awsDir),
                "default".equals(mode) ? readInlinePolicy(policyFile, extras) : null, extras);
        } catch (Exception ignored) {
            return new CacheMetadata(mode, false, "not_cached", 0L);
        }
        String key = cacheKey(scope, durationSeconds, endpoint, awsDir, cacheDir);
        TokenResult mem = MEMORY_CACHE.get(key);
        if (mem != null && isCacheUsable(mem.expiration(), now)) {
            long ttl = Math.max(0L, Duration.between(now, mem.expiration()).getSeconds());
            return new CacheMetadata(mode, true, mem.expirationIso(), ttl);
        }
        Path file = cacheFilePath(cacheDir, scope, durationSeconds, endpoint, awsDir);
        if (!Files.isRegularFile(file) || !hasStrictOwnerOnlyPermissions(file)) {
            return new CacheMetadata(mode, false, "not_cached", 0L);
        }
        try {
            Object parsed = Json.parse(Files.readString(file, StandardCharsets.UTF_8));
            if (!(parsed instanceof Map<?, ?> rawMap)) {
                return new CacheMetadata(mode, false, "not_cached", 0L);
            }
            Map<String, Object> m = (Map<String, Object>) rawMap;
            String expStr = String.valueOf(m.getOrDefault("Expiration", ""));
            if (expStr.isBlank()) {
                return new CacheMetadata(mode, false, "not_cached", 0L);
            }
            Instant exp = Instant.parse(expStr);
            if (!isCacheUsable(exp, now)) {
                return new CacheMetadata(mode, false, "expired", 0L);
            }
            long ttl = Math.max(0L, Duration.between(now, exp).getSeconds());
            return new CacheMetadata(mode, true, exp.truncatedTo(ChronoUnit.SECONDS).toString(), ttl);
        } catch (Exception e) {
            return new CacheMetadata(mode, false, "not_cached", 0L);
        }
    }

    public static TokenResult issueOrGetCached(String mode, int durationSeconds, String sourceProfile,
            Path awsDir, Path cacheDir, URI endpointOverride, boolean useCache, Clock clock) {
        return issueOrGetCached(mode, durationSeconds, sourceProfile, awsDir, cacheDir,
            endpointOverride, useCache, clock, defaultPolicyPath(awsDir));
    }

    public static TokenResult issueOrGetCached(
            String mode,
            int durationSeconds,
            String sourceProfile,
            Path awsDir,
            Path cacheDir,
            URI endpointOverride,
            boolean useCache,
            Clock clock, Path policyFile) {
        return issueOrGetCached(
            mode,
            durationSeconds,
            sourceProfile,
            awsDir,
            cacheDir,
            endpointOverride,
            useCache,
            clock,
            policyFile,
            "default".equals(mode) ? configuredExtraPolicies(awsDir, policyFile, null) : List.of()
        );
    }

    public static TokenResult issueOrGetCached(
            String mode,
            int durationSeconds,
            String sourceProfile,
            Path awsDir,
            Path cacheDir,
            URI endpointOverride,
            boolean useCache,
            Clock clock,
            Path policyFile,
            List<String> extraPolicySpecs) {
        if (mode == null || !SUPPORTED_MODES.contains(mode)) {
            throw new IllegalArgumentException("expected default, lmaws, lmaws-ec2 or lmaws-web");
        }
        if (durationSeconds != DEFAULT_DURATION_SECONDS) {
            throw new IllegalArgumentException("durationSeconds must be 3600 to match the scoped session helper");
        }
        requireSourceProfile(sourceProfile);
        List<String> extras = extraPolicySpecs == null || extraPolicySpecs.isEmpty()
            ? List.of()
            : parseExtraPolicySpecs(String.join(",", extraPolicySpecs));
        if (!"default".equals(mode) && !extras.isEmpty()) {
            throw new IllegalArgumentException("extra policy ARNs are only supported in default mode");
        }
        String inlinePolicy = "default".equals(mode) ? readInlinePolicy(policyFile, extras) : null;
        // Validate the explicitly selected file credentials BEFORE consulting either cache.
        StaticCredentialsProvider sourceCredentials = loadIsolatedSourceCredentials(sourceProfile, awsDir);
        String scope = issuanceScope(mode, sourceProfile, sourceCredentials, inlinePolicy, extras);
        Instant now = clock.instant();
        String key = cacheKey(scope, durationSeconds, endpointOverride, awsDir, cacheDir);

        if (useCache) {
            TokenResult memHit = MEMORY_CACHE.get(key);
            if (memHit != null && isCacheUsable(memHit.expiration(), now)) {
                return memHit;
            }
            if (cacheDir != null) {
                Path cacheFile = cacheFilePath(cacheDir, scope, durationSeconds, endpointOverride, awsDir);
                Optional<TokenResult> diskHit = readCachedToken(cacheFile, now);
                if (diskHit.isPresent()) {
                    MEMORY_CACHE.put(key, diskHit.get());
                    return diskHit.get();
                }
            }
        }

        StsClientBuilder builder = StsClient.builder()
            .region(Region.US_EAST_1)
            .credentialsProvider(sourceCredentials)
            .httpClient(UrlConnectionHttpClient.create())
            .endpointProvider(software.amazon.awssdk.services.sts.endpoints.StsEndpointProvider.defaultProvider())
            .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(45)));
        if (endpointOverride != null) {
            builder.endpointOverride(endpointOverride);
        } else {
            builder.endpointOverride(URI.create("https://sts.us-east-1.amazonaws.com"));
        }

        TokenResult fresh;
        try (StsClient sts = builder.build()) {
            String accountId = null;
            if (MANAGED_POLICY_BY_MODE.containsKey(mode) || !extras.isEmpty()) {
                accountId = sts.getCallerIdentity().account();
                if (accountId == null || !accountId.matches("^[0-9]{12}$")) {
                    throw new IllegalStateException("STS identity lookup failed");
                }
            }
            FederationSpec spec = buildFederationSpec(mode, durationSeconds, accountId, inlinePolicy, extras);
            GetFederationTokenRequest.Builder req = GetFederationTokenRequest.builder()
                .name(spec.federatedUserName())
                .durationSeconds(spec.durationSeconds())
                .policyArns(spec.policyArns().stream()
                    .map(arn -> PolicyDescriptorType.builder().arn(arn).build())
                    .toList());
            if (spec.inlinePolicy() != null) {
                req.policy(spec.inlinePolicy());
            }
            GetFederationTokenResponse resp = sts.getFederationToken(req.build());
            Credentials creds = resp.credentials();
            if (creds == null) {
                throw new IllegalStateException("missing STS credentials");
            }
            fresh = new TokenResult(
                creds.accessKeyId(),
                creds.secretAccessKey(),
                creds.sessionToken(),
                creds.expiration()
            );
        }

        if (useCache) {
            MEMORY_CACHE.put(key, fresh);
            if (cacheDir != null) {
                Path cacheFile = cacheFilePath(cacheDir, scope, durationSeconds, endpointOverride, awsDir);
                try {
                    writeCachedToken(cacheFile, fresh);
                } catch (IOException e) {
                    throw new IllegalStateException("cannot persist credential cache", e);
                }
            }
        }
        return fresh;
    }

    static URI checkedLoopbackEndpoint(String raw) {
        if (raw == null || raw.isBlank()) return null;
        URI u = URI.create(raw.trim());
        String h = u.getHost();
        if (!"http".equalsIgnoreCase(u.getScheme())
                || u.getUserInfo() != null
                || u.getQuery() != null
                || u.getFragment() != null
                || (u.getPath() != null && !u.getPath().isEmpty() && !"/".equals(u.getPath()))
                || !("127.0.0.1".equals(h) || "::1".equals(h) || "[::1]".equals(h))) {
            throw new IllegalArgumentException("LMAWS_ENDPOINT must be http://127.0.0.1 or http://[::1]");
        }
        return u;
    }

    /**
     * Entrypoint for {@code lmaws --credential-process <mode>}.
     * Prints ONLY the credential_process JSON to stdout on success, or {@link #GENERIC_ERROR}
     * to stderr on any error (exiting with status 1).
     */
    public static int runCli(String[] args) {
        try {
            String mode = null;
            int durationSeconds = DEFAULT_DURATION_SECONDS;
            String sourceProfile = configuredSourceProfile();
            Path awsDir = defaultAwsDir();
            Path policyFile = defaultPolicyPath(awsDir);
            String cliExtraPolicyArns = null;
            boolean useCache = !"0".equals(System.getenv("LMAWS_CREDENTIAL_PROCESS_CACHE"));

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if ("--credential-process".equals(arg)) {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("missing mode");
                    }
                    mode = args[++i];
                } else if ("--duration".equals(arg)) {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("missing duration");
                    }
                    durationSeconds = Integer.parseInt(args[++i]);
                } else if ("--source-profile".equals(arg)) {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("missing source profile");
                    }
                    sourceProfile = args[++i];
                } else if ("--policy-file".equals(arg)) {
                    if (i + 1 >= args.length) throw new IllegalArgumentException("missing policy file");
                    policyFile = policyPath(args[++i]);
                } else if ("--extra-policy-arns".equals(arg)) {
                    if (i + 1 >= args.length) throw new IllegalArgumentException("missing extra policy ARNs");
                    cliExtraPolicyArns = args[++i];
                } else if ("--no-cache".equals(arg)) {
                    useCache = false;
                } else {
                    throw new IllegalArgumentException("unexpected argument");
                }
            }
            if (mode == null) {
                throw new IllegalArgumentException("one profile mode is required");
            }
            if (!"default".equals(mode) && cliExtraPolicyArns != null && !cliExtraPolicyArns.isBlank()) {
                throw new IllegalArgumentException("extra policy ARNs are only supported in default mode");
            }
            List<String> extras = "default".equals(mode)
                ? configuredExtraPolicies(awsDir, policyFile, cliExtraPolicyArns)
                : List.of();
            URI endpoint = checkedLoopbackEndpoint(System.getenv("LMAWS_ENDPOINT"));
            TokenResult token = issueOrGetCached(
                mode,
                durationSeconds,
                sourceProfile,
                awsDir,
                defaultCacheDir(),
                endpoint,
                useCache,
                Clock.systemUTC(),
                policyFile,
                extras
            );
            System.out.println(token.toCredentialProcessJson());
            return 0;
        } catch (AdminSourceRefused refused) {
            System.err.println(ADMIN_SOURCE_ERROR);
            return 1;
        } catch (PolicyLimitExceeded refused) {
            System.err.println(refused.getMessage());
            return 1;
        } catch (Throwable ignored) {
            // Never relay upstream exception details, account IDs, or secret material.
            System.err.println(GENERIC_ERROR);
            return 1;
        }
    }

    /**
     * Read-only session doctor (`cloud.session_doctor()`): reports profile session mappings,
     * cache expiry/TTL, caller identity, and dry-run/read-only permission & guardrail probes without
     * creating any AWS resources or exposing any secrets.
     */
    public static List<Map<String, String>> sessionDoctor(AwsBackend backend) {
        if (backend.isDemo()) {
            return demoSessionDoctorRows();
        }
        List<Map<String, String>> rows = new ArrayList<>();
        Path awsDir = defaultAwsDir();
        Path cacheDir = defaultCacheDir();
        URI endpoint = checkedLoopbackEndpoint(System.getenv("LMAWS_ENDPOINT"));
        Instant now = Instant.now();

        Map<String, Profile> configuredProfiles = new LinkedHashMap<>();
        Path configPath = awsDir.resolve("config");
        if (Files.isRegularFile(configPath)) {
            try {
                ProfileFile pf = ProfileFile.builder()
                    .content(configPath)
                    .type(ProfileFile.Type.CONFIGURATION)
                    .build();
                configuredProfiles.putAll(pf.profiles());
            } catch (Exception ignored) {}
        }

        for (String mode : List.of("default", "lmaws", "lmaws-ec2", "lmaws-web")) {
            Profile p = configuredProfiles.get(mode);
            String credProc = p == null ? "" : p.property("credential_process").orElse("").trim();
            String helper;
            if (credProc.contains("lmaws") && credProc.contains("--credential-process")) {
                helper = "lmaws --credential-process " + mode;
            } else if (credProc.contains("aws-profile-session.py")) {
                helper = "aws-profile-session.py " + mode;
            } else if (!credProc.isEmpty()) {
                helper = "custom_credential_process";
            } else {
                helper = "unconfigured";
            }
            String sessionType = "default".equals(mode)
                ? "federated_readonly"
                : "federated_managed_lmaws_session";
            String policyScope = "default".equals(mode)
                ? "ReadOnlyAccess + policy-file session policy"
                : "arn:aws:iam::************:policy/lmaws_session";
            CacheMetadata meta = inspectCacheMetadata(
                mode, DEFAULT_DURATION_SECONDS, endpoint, awsDir, cacheDir, now);
            String status = !credProc.isEmpty() || meta.cached() ? "configured" : "unconfigured";
            rows.add(doctorRow(
                "profile",
                "profile:" + mode,
                mode,
                sessionType,
                helper,
                meta.expirationIso(),
                String.valueOf(meta.ttlSeconds()),
                "config_and_cache",
                status,
                "federated_user=awsspot-local-" + mode + "; policy=" + policyScope
            ));
        }

        String active = AwsBackend.activeProfile();
        String activeSessionType = "default".equals(active)
            ? "federated_readonly"
            : MANAGED_POLICY_BY_MODE.containsKey(active) ? "federated_managed_lmaws_session" : "custom_profile";

        // Probe 1: sts:GetCallerIdentity
        rows.add(runReadProbe(
            "sts:GetCallerIdentity",
            active,
            activeSessionType,
            false,
            () -> {
                var id = backend.stsClientForDoctor().getCallerIdentity();
                return Jsons.mask(String.valueOf(id.arn()));
            }
        ));

        // Probe 2: s3:ListAllMyBuckets
        rows.add(runReadProbe(
            "s3:ListAllMyBuckets",
            active,
            activeSessionType,
            false,
            () -> "buckets=" + backend.s3ClientForDoctor().listBuckets().buckets().size()
        ));

        // Probe 3: sqs:ListQueues
        rows.add(runReadProbe(
            "sqs:ListQueues",
            active,
            activeSessionType,
            false,
            () -> "queues=" + backend.sqsClientForDoctor().listQueues().queueUrls().size()
        ));

        // Probe 4: dynamodb:ListTables
        rows.add(runReadProbe(
            "dynamodb:ListTables",
            active,
            activeSessionType,
            false,
            () -> "tables=" + backend.ddbClientForDoctor().listTables().tableNames().size()
        ));

        // Probe 5: ssm:GetParameter(/aws/service/...)
        String[] resolvedAmi = new String[]{"ami-0123456789abcdef0"};
        rows.add(runReadProbe(
            "ssm:GetParameter(/aws/service/...)",
            active,
            activeSessionType,
            "default".equals(active),
            () -> {
                var param = backend.ssmClientForDoctor().getParameter(
                    r -> r.name("/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-arm64"));
                String val = param.parameter().value();
                if (val != null && val.startsWith("ami-")) {
                    resolvedAmi[0] = val.trim();
                }
                return "parameter=" + param.parameter().name();
            }
        ));

        // Probe 6: ec2:CreateSecurityGroup (tagged lmaws_test, DryRun=true)
        rows.add(runEc2DryRunProbe(
            "ec2:CreateSecurityGroup(tagged lmaws_test)",
            active,
            activeSessionType,
            false,
            () -> backend.ec2ClientForDoctor().createSecurityGroup(r -> r
                .dryRun(true)
                .groupName("lmaws_doctor_probe")
                .description("lmaws session_doctor dry-run probe")
                .tagSpecifications(TagSpecification.builder()
                    .resourceType(ResourceType.SECURITY_GROUP)
                    .tags(Tag.builder().key("lmaws_test").value("doctor").build())
                    .build()))
        ));

        // Probe 7: ec2:CreateSecurityGroup (untagged guardrail, DryRun=true)
        rows.add(runEc2DryRunProbe(
            "ec2:CreateSecurityGroup(untagged guardrail)",
            active,
            activeSessionType,
            true,
            () -> backend.ec2ClientForDoctor().createSecurityGroup(r -> r
                .dryRun(true)
                .groupName("lmaws_doctor_untagged")
                .description("lmaws session_doctor untagged guardrail probe"))
        ));

        // Probe 8: ec2:RunInstances (t4g.large guardrail, DryRun=true)
        rows.add(runEc2DryRunProbe(
            "ec2:RunInstances(t4g.large guardrail)",
            active,
            activeSessionType,
            true,
            () -> backend.ec2ClientForDoctor().runInstances(r -> r
                .dryRun(true)
                .imageId(resolvedAmi[0])
                .instanceType(InstanceType.T4_G_LARGE)
                .minCount(1)
                .maxCount(1)
                .tagSpecifications(
                    TagSpecification.builder()
                        .resourceType(ResourceType.INSTANCE)
                        .tags(Tag.builder().key("lmaws_test").value("doctor").build())
                        .build(),
                    TagSpecification.builder()
                        .resourceType(ResourceType.VOLUME)
                        .tags(Tag.builder().key("lmaws_test").value("doctor").build())
                        .build()))
        ));

        return rows;
    }

    private static Map<String, String> runReadProbe(
            String probeName,
            String activeProfile,
            String sessionType,
            boolean expectGuardrailDeny,
            Supplier<String> call) {
        try {
            String detail = call.get();
            return doctorRow(
                "probe",
                probeName,
                activeProfile,
                sessionType,
                "sdk_read",
                "-",
                "0",
                "read_probe",
                "allowed",
                Jsons.mask(detail)
            );
        } catch (SsmException e) {
            String code = e.awsErrorDetails() == null ? "SsmException" : e.awsErrorDetails().errorCode();
            String status = expectGuardrailDeny && "AccessDeniedException".equals(code)
                ? "denied_by_guardrail"
                : "denied";
            return doctorRow(
                "probe",
                probeName,
                activeProfile,
                sessionType,
                "sdk_read",
                "-",
                "0",
                "read_probe",
                status,
                "AWS " + code
            );
        } catch (Exception e) {
            return doctorRow(
                "probe",
                probeName,
                activeProfile,
                sessionType,
                "sdk_read",
                "-",
                "0",
                "read_probe",
                expectGuardrailDeny ? "denied_by_guardrail" : "denied",
                Main.safeError(e)
            );
        }
    }

    private static Map<String, String> runEc2DryRunProbe(
            String probeName,
            String activeProfile,
            String sessionType,
            boolean expectGuardrailDeny,
            Runnable call) {
        try {
            call.run();
            return doctorRow(
                "probe",
                probeName,
                activeProfile,
                sessionType,
                "ec2_dry_run",
                "-",
                "0",
                "ec2_dry_run",
                expectGuardrailDeny ? "unexpected_allow" : "allowed",
                "DryRunOperation"
            );
        } catch (Ec2Exception e) {
            String code = e.awsErrorDetails() == null ? "" : String.valueOf(e.awsErrorDetails().errorCode());
            // In AWS EC2, DryRunOperation (HTTP 412) means IAM allowed the action and all DryRun checks succeeded.
            if ("DryRunOperation".equals(code)) {
                return doctorRow(
                    "probe",
                    probeName,
                    activeProfile,
                    sessionType,
                    "ec2_dry_run",
                    "-",
                    "0",
                    "ec2_dry_run",
                    expectGuardrailDeny ? "unexpected_allow" : "allowed",
                    "AWS " + code + " (IAM authorized)"
                );
            }
            String status = expectGuardrailDeny ? "denied_by_guardrail" : "denied";
            return doctorRow(
                "probe",
                probeName,
                activeProfile,
                sessionType,
                "ec2_dry_run",
                "-",
                "0",
                "ec2_dry_run",
                status,
                "AWS " + (code.isEmpty() ? "UnauthorizedOperation" : code)
            );
        } catch (Exception e) {
            return doctorRow(
                "probe",
                probeName,
                activeProfile,
                sessionType,
                "ec2_dry_run",
                "-",
                "0",
                "ec2_dry_run",
                expectGuardrailDeny ? "denied_by_guardrail" : "denied",
                Main.safeError(e)
            );
        }
    }

    public static List<Map<String, String>> demoSessionDoctorRows() {
        List<Map<String, String>> rows = new ArrayList<>();
        rows.add(doctorRow(
            "profile",
            "profile:default",
            "default",
            "federated_readonly",
            "lmaws --credential-process default",
            "2026-10-26T22:00:00Z",
            "3120",
            "config_and_cache",
            "configured",
            "federated_user=awsspot-local-default; policy=ReadOnlyAccess + policy-file session policy"
        ));
        rows.add(doctorRow(
            "profile",
            "profile:lmaws",
            "lmaws",
            "federated_managed_lmaws_session",
            "lmaws --credential-process lmaws",
            "2026-10-26T22:00:00Z",
            "3120",
            "config_and_cache",
            "configured",
            "federated_user=awsspot-local-lmaws; policy=arn:aws:iam::************:policy/lmaws_session"
        ));
        rows.add(doctorRow(
            "profile",
            "profile:lmaws-ec2",
            "lmaws-ec2",
            "federated_managed_lmaws_session",
            "lmaws --credential-process lmaws-ec2",
            "2026-10-26T22:00:00Z",
            "3120",
            "config_and_cache",
            "configured",
            "federated_user=awsspot-local-lmaws-ec2; policy=arn:aws:iam::************:policy/lmaws_session"
        ));
        rows.add(doctorRow(
            "profile",
            "profile:lmaws-web",
            "lmaws-web",
            "federated_managed_lmaws_session",
            "lmaws --credential-process lmaws-web",
            "not_cached",
            "0",
            "config_and_cache",
            "configured",
            "federated_user=awsspot-local-lmaws-web; policy=arn:aws:iam::************:policy/lmaws_session"
        ));
        rows.add(doctorRow(
            "probe",
            "sts:GetCallerIdentity",
            "lmaws",
            "federated_managed_lmaws_session",
            "sdk_read",
            "-",
            "0",
            "read_probe",
            "allowed",
            "arn:aws:sts::************:federated-user/awsspot-local-lmaws"
        ));
        rows.add(doctorRow(
            "probe",
            "s3:ListAllMyBuckets",
            "lmaws",
            "federated_managed_lmaws_session",
            "sdk_read",
            "-",
            "0",
            "read_probe",
            "allowed",
            "buckets=3"
        ));
        rows.add(doctorRow(
            "probe",
            "sqs:ListQueues",
            "lmaws",
            "federated_managed_lmaws_session",
            "sdk_read",
            "-",
            "0",
            "read_probe",
            "allowed",
            "queues=2"
        ));
        rows.add(doctorRow(
            "probe",
            "dynamodb:ListTables",
            "lmaws",
            "federated_managed_lmaws_session",
            "sdk_read",
            "-",
            "0",
            "read_probe",
            "allowed",
            "tables=3"
        ));
        rows.add(doctorRow(
            "probe",
            "ssm:GetParameter(/aws/service/...)",
            "lmaws",
            "federated_managed_lmaws_session",
            "sdk_read",
            "-",
            "0",
            "read_probe",
            "allowed",
            "parameter=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-arm64"
        ));
        rows.add(doctorRow(
            "probe",
            "ec2:CreateSecurityGroup(tagged lmaws_test)",
            "lmaws",
            "federated_managed_lmaws_session",
            "ec2_dry_run",
            "-",
            "0",
            "ec2_dry_run",
            "allowed",
            "AWS DryRunOperation (IAM authorized)"
        ));
        rows.add(doctorRow(
            "probe",
            "ec2:CreateSecurityGroup(untagged guardrail)",
            "lmaws",
            "federated_managed_lmaws_session",
            "ec2_dry_run",
            "-",
            "0",
            "ec2_dry_run",
            "denied_by_guardrail",
            "AWS UnauthorizedOperation"
        ));
        rows.add(doctorRow(
            "probe",
            "ec2:RunInstances(t4g.large guardrail)",
            "lmaws",
            "federated_managed_lmaws_session",
            "ec2_dry_run",
            "-",
            "0",
            "ec2_dry_run",
            "denied_by_guardrail",
            "AWS UnauthorizedOperation"
        ));
        return rows;
    }

    private static Map<String, String> doctorRow(
            String kind,
            String name,
            String profile,
            String sessionType,
            String helper,
            String expiry,
            String ttlSeconds,
            String method,
            String status,
            String detail) {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("kind", kind);
        row.put("name", name);
        row.put("profile", profile);
        row.put("session_type", sessionType);
        row.put("helper", helper);
        row.put("expiry", expiry);
        row.put("ttl_seconds", ttlSeconds);
        row.put("method", method);
        row.put("status", status);
        row.put("detail", detail);
        return row;
    }
}
