package ai.lmctl.lmaws;

/** Fast, credential-free regression checks for web-stack ownership guards. */
public final class WebStackChecks {
    private WebStackChecks() {}
    public static void main(String[] args) { run(); System.out.println("web stack safety checks: ok"); }
    public static void run() {
        var fake = new WebStack.FakeProvider();
        var r = fake.put("s3", "bucket", WebStack.resourceName("a1b2c3d4", "site"), "a1b2c3d4", java.util.Map.of());
        if (!r.ownedBy("a1b2c3d4") || fake.list("s3", "bucket", "lmaws-").size() != 1) throw new AssertionError("web fake ownership");
        boolean denied = false;
        try { fake.delete(r, "deadbeef"); } catch (SecurityException expected) { denied = true; }
        if (!denied) throw new AssertionError("foreign run deletion was accepted");
        fake.delete(r, "a1b2c3d4");
        if (fake.size() != 0) throw new AssertionError("web fake teardown");
        WebStack.requireRecordName("lmaws-site-a1b2c3d4.example.com", "example.com");
        WebStack.requireAliasTarget("d1234567890.cloudfront.net");
        WebStack.requireHttpCidr("192.0.2.1/32");
        WebStack.requireNano("t4g.nano", 8);
        expect(() -> WebStack.requireHttpCidr("0.0.0.0/0"));
        expect(() -> WebStack.requireNano("m7g.large", 8));
        expect(() -> WebStack.requireRecordName("production.example.com", "example.com"));
    }
    private static void expect(Runnable action) {
        try { action.run(); } catch (RuntimeException expected) { return; }
        throw new AssertionError("unsafe web-stack input accepted");
    }
}
