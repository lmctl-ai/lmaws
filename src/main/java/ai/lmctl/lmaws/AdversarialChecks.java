package ai.lmctl.lmaws;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;

/** Adversarial self-tests of the input guards that protect mutating calls and cached credentials. */
final class AdversarialChecks {
    private AdversarialChecks() {}
    private static void check(boolean ok, String label) { if (!ok) throw new AssertionError("adversarial check failed: " + label); }
    private static boolean refused(Runnable r) { try { r.run(); return false; } catch (RuntimeException e) { return true; } }

    static void run() throws Exception {
        // One routable IPv4 /32 only.
        for (String bad : new String[]{"999.1.1.1/32", "256.0.0.1/32", "0.0.0.0/32", "255.255.255.255/32", "1.2.3.4/24", "1.2.3.4/32 ", " 1.2.3.4/32", "01.2.3.4/32", "1.2.3/32", "::1/128", "1.2.3.4/32\n", "1.2.3.4"})
            check(refused(() -> WebStack.requireHttpCidr(bad)), "cidr refused: " + bad);
        for (String good : new String[]{"203.0.113.10/32", "8.8.8.8/32", "100.64.1.255/32"}) WebStack.requireHttpCidr(good);
        // Domains: DNS labels without leading/trailing hyphens, no empty labels, lowercase, at least two labels.
        for (String bad : new String[]{"com", "a.-b.com", "-a.com", "a-.com", "a..b", "A.COM", "a.b.", ".a.b", "a b.com", "a.b/c", "x".repeat(64) + ".com"})
            check(!WebStack.isDomainName(bad), "domain refused: " + bad);
        for (String good : new String[]{"example.com", "lmaws.example.test", "a-b.c-d.org", "x".repeat(63) + ".com"}) check(WebStack.isDomainName(good), "domain accepted: " + good);
        // IAM role specifications: Lambda-only trust, lmaws_boundary, allow-listed managed policies, lmaws_ names.
        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"}}]}";
        String spec = "{\"trust_policy\":%s,\"permissions_boundary\":\"arn:aws:iam::${aws:PrincipalAccount}:policy/lmaws_boundary\",\"managed_policies\":%s,\"inline_policies\":{}}";
        IamRoles.parseSpec(spec.formatted(trust, "[]"));
        for (String badTrust : new String[]{
                trust.replace("lambda.amazonaws.com", "*"), trust.replace("lambda.amazonaws.com", "ec2.amazonaws.com"),
                trust.replace("\"sts:AssumeRole\"", "[\"sts:AssumeRole\",\"iam:PassRole\"]"),
                trust.replace("\"Principal\"", "\"Condition\":{},\"Principal\""), trust.replace("{\"Service\":\"lambda.amazonaws.com\"}", "{\"AWS\":\"*\"}"),
                trust.replace("\"Allow\"", "\"Deny\""), trust.replace("]}", ",{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"AWS\":\"*\"}}]}")})
            check(refused(() -> IamRoles.parseSpec(spec.formatted(badTrust, "[]"))), "trust refused: " + badTrust);
        for (String badManaged : new String[]{"[\"arn:aws:iam::aws:policy/AdministratorAccess\"]", "[\"arn:aws:iam::123456789012:policy/admin_lambda_x\"]", "[\"arn:aws:iam::123456789012:policy/lmaws_lambda_x/../../AdministratorAccess\"]"})
            check(refused(() -> IamRoles.parseSpec(spec.formatted(trust, badManaged))), "managed refused: " + badManaged);
        check(refused(() -> IamRoles.parseSpec(spec.formatted(trust, "[]").replace("lmaws_boundary", "AdministratorAccess"))), "boundary refused");
        for (String badName : new String[]{"admin", "lmaws_", "lmaws_X", "lmaws_a/b", "lmaws_a\n", "LMAWS_a", "lmaws_" + "a".repeat(65)})
            check(refused(() -> IamRoles.requireName(badName)), "role name refused: " + badName);
        // Credential cache: private on creation, refuses shared directories and symlinked files.
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Path base = Files.createTempDirectory("lmaws-adv-cache-");
            try {
                var token = new CredentialProcess.TokenResult("ASIAFAKEFAKEFAKEFAKE", "secret-not-printed", "token-not-printed", Instant.now().plusSeconds(3600));
                Path fresh = base.resolve("fresh").resolve("session.json");
                CredentialProcess.writeCachedToken(fresh, token);
                check(PosixFilePermissions.toString(Files.getPosixFilePermissions(fresh)).equals("rw-------"), "cache file is 0600");
                check(PosixFilePermissions.toString(Files.getPosixFilePermissions(fresh.getParent())).equals("rwx------"), "cache dir is 0700");
                check(CredentialProcess.readCachedToken(fresh, Instant.now()).isPresent(), "private cache is reused");
                Path shared = Files.createDirectory(base.resolve("shared"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")));
                CredentialProcess.writeCachedToken(shared.resolve("session.json"), token);
                check(PosixFilePermissions.toString(Files.getPosixFilePermissions(shared)).equals("rwx------"), "an existing own directory is tightened to 0700 before use");
                Path linkedDir = base.resolve("linked-dir"); Files.createSymbolicLink(linkedDir, shared);
                boolean linkRefused = false;
                try { CredentialProcess.writeCachedToken(linkedDir.resolve("session.json"), token); } catch (java.io.IOException e) { linkRefused = true; }
                check(linkRefused, "a symlinked cache directory is refused");
                Path link = fresh.resolveSibling("linked.json"); Files.createSymbolicLink(link, fresh);
                check(CredentialProcess.readCachedToken(link, Instant.now()).isEmpty(), "a symlinked cache file is never read");
                check(Files.exists(fresh), "refusing a link does not delete its target");
            } finally {
                try (var walk = Files.walk(base)) { walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> { try { Files.deleteIfExists(p); } catch (java.io.IOException ignored) {} }); }
            }
        }
        System.out.println("PASS adversarial guards: CIDR, domains, IAM trust/boundary/managed/names, credential cache permissions and links");
    }
}
