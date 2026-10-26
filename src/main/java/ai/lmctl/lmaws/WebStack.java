package ai.lmctl.lmaws;

import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Shared safety and state model for the lmweblab web-stack recipes.
 *
 * Provider adapters use this class before issuing an SDK request.  Keeping the
 * checks here makes the live adapter and the loopback fake obey exactly the
 * same ownership rules.  This class deliberately contains no AWS SDK types so
 * the fake transport can be used in the local gate.
 */
public final class WebStack {
    private static final Pattern RUN = Pattern.compile("[0-9a-f]{4,32}");
    private static final Pattern NAME = Pattern.compile("lmaws-[a-z0-9-]{1,48}");
    private static final Pattern DOMAIN = Pattern.compile("lmaws-[a-z0-9-]+\\.[A-Za-z0-9.-]+\\.?$");
    private WebStack() {}

    public record Resource(String service, String type, String name, String id,
                           String region, Map<String,String> tags, Instant created) {
        public Resource {
            tags = tags == null ? Map.of() : Map.copyOf(tags);
        }
        public boolean ownedBy(String runId) {
            return runId != null && runId.equals(tags.get("lmaws_test"));
        }
    }

    /** Provider-neutral operations implemented by the AWS adapter and fake. */
    public interface Provider extends AutoCloseable {
        Resource put(String service, String type, String name, String runId, Map<String,String> tags);
        Optional<Resource> get(String service, String type, String id);
        List<Resource> list(String service, String type, String prefix);
        void delete(Resource resource, String runId);
        default void close() {}
    }

    public static String resourceName(String runId, String role) {
        requireRun(runId); Objects.requireNonNull(role, "role");
        String suffix = role.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9-]", "-");
        String value = "lmaws-" + suffix + "-" + runId;
        if (!NAME.matcher(value).matches()) throw new IllegalArgumentException("invalid lmaws resource name");
        return value;
    }

    public static void requireRun(String runId) {
        if (runId == null || !RUN.matcher(runId).matches())
            throw new IllegalArgumentException("run id must be 4-32 lowercase hexadecimal characters");
    }

    public static void requireOwned(Resource resource, String runId) {
        Objects.requireNonNull(resource, "resource"); requireRun(runId);
        if (!resource.name().startsWith("lmaws-")) throw new SecurityException("resource is outside lmaws- namespace");
        if (!resource.ownedBy(runId)) throw new SecurityException("resource is not tagged for this run");
    }

    public static void requireRecordName(String fqdn, String domain) {
        Objects.requireNonNull(fqdn, "record name"); Objects.requireNonNull(domain, "domain");
        String n = fqdn.endsWith(".") ? fqdn.substring(0, fqdn.length()-1) : fqdn;
        String d = domain.endsWith(".") ? domain.substring(0, domain.length()-1) : domain;
        if (!n.endsWith("." + d) || !n.startsWith("lmaws-") || !DOMAIN.matcher(n).matches())
            throw new SecurityException("Route 53 record must be lmaws-*.domain");
        if (n.contains("..") || n.length() > 253) throw new IllegalArgumentException("invalid DNS name");
    }

    public static void requireAliasTarget(String target) {
        if (target == null || !target.matches("[A-Za-z0-9][A-Za-z0-9.-]{2,252}\\.cloudfront\\.net\\.?"))
            throw new IllegalArgumentException("alias target must be a CloudFront hostname");
    }

    public static void requireHttpCidr(String cidr) {
        if (cidr == null || !cidr.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/32"))
            throw new SecurityException("web ingress requires one IPv4 /32");
        String ip = cidr.substring(0, cidr.length()-3);
        for (String octet : ip.split("\\.")) if (Integer.parseInt(octet) > 255)
            throw new IllegalArgumentException("invalid IPv4 address");
    }

    public static void requireNano(String instanceType, int volumeGiB) {
        if (!Set.of("t3.nano", "t4g.nano").contains(instanceType))
            throw new SecurityException("web stack permits only t3.nano or t4g.nano");
        if (volumeGiB < 1 || volumeGiB > 8) throw new SecurityException("web stack volume must be 1..8 GiB");
    }

    /** In-memory provider used by fake-transport tests and offline examples. */
    public static final class FakeProvider implements Provider {
        private final Map<String,Resource> resources = new ConcurrentHashMap<>();
        @Override public Resource put(String service, String type, String name, String runId, Map<String,String> tags) {
            requireRun(runId); if (!name.startsWith("lmaws-")) throw new SecurityException("outside lmaws namespace");
            Map<String,String> owned = new LinkedHashMap<>(tags == null ? Map.of() : tags); owned.put("lmaws_test", runId);
            Resource r = new Resource(service, type, name, service + ":" + name, "us-east-1", owned, Instant.now());
            if (resources.putIfAbsent(r.id(), r) != null) throw new IllegalStateException("resource already exists");
            return r;
        }
        @Override public Optional<Resource> get(String service, String type, String id) {
            return Optional.ofNullable(resources.get(id)).filter(r -> r.service().equals(service) && r.type().equals(type));
        }
        @Override public List<Resource> list(String service, String type, String prefix) {
            if (prefix == null || prefix.isBlank()) throw new IllegalArgumentException("prefix required");
            return resources.values().stream().filter(r -> r.service().equals(service) && r.type().equals(type) && r.name().startsWith(prefix)).toList();
        }
        @Override public void delete(Resource resource, String runId) {
            requireOwned(resource, runId);
            if (!resources.remove(resource.id(), resource)) throw new NoSuchElementException("resource is absent");
        }
        public int size() { return resources.size(); }
    }
}
