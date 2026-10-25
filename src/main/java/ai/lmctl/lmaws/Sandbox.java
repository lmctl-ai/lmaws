package ai.lmctl.lmaws;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/** Owns the resources created by one run and makes teardown retryable. */
public final class Sandbox implements AutoCloseable {
    private static final Pattern RUN = Pattern.compile("[a-z0-9]{1,24}");
    private static final Pattern SUFFIX = Pattern.compile("[a-z0-9][a-z0-9_-]{0,48}");
    private final AwsBackend backend;
    private final String runId;
    private final Path ledger;
    private final Map<String, Entry> resources = new LinkedHashMap<>();
    private boolean closed;

    public Sandbox(AwsBackend backend, String runId, Path ledger) {
        this.backend = Objects.requireNonNull(backend, "backend");
        if (runId == null || !RUN.matcher(runId).matches())
            throw new IllegalArgumentException("runId must be 1-24 lowercase letters or digits");
        this.runId = runId;
        this.ledger = openLedger(Objects.requireNonNull(ledger, "ledger"), runId);
    }

    public synchronized Map<String, String> create(String kind, String name, String value) {
        ensureOpen();
        String k = requireKind(kind);
        String n = resourceName(k, name);
        append(record("intent", k, n, "pending", "create"));
        try {
            Map<String, String> raw = backend.create(k, n, value, runId);
            String id = raw == null ? null : raw.get("id");
            if (id == null || id.isBlank()) throw new IllegalStateException("create returned no resource id");
            Entry e = new Entry(k, id, n);
            resources.put(key(k, id), e);
            append(createdRecord(k, id, n));
            backend.awaitReady(k,id,runId);
            if (!backend.owned(k, id, runId)) throw new IllegalStateException("created resource ownership was not verified");
            return new LinkedHashMap<>(raw);
        } catch (RuntimeException ex) {
            append(record("failure", k, n, "pending", "create:" + safeError(ex)));
            throw ex;
        }
    }

    public synchronized void put(Map<String, String> resource, String key, String value) {
        ensureOpen();
        Entry e = entry(resource);
        if (key == null || key.isBlank()) throw new IllegalArgumentException("key is required");
        append(record("intent", e.kind, e.id, "active", "update:" + key));
        try {
            backend.update(e.kind, e.id, key, value);
            append(record("updated", e.kind, e.id, "active", "update:" + key));
        } catch (RuntimeException ex) {
            append(record("failure", e.kind, e.id, "active", "update:" + safeError(ex)));
            throw ex;
        }
    }

    public synchronized int remaining() { return resources.size(); }

    public synchronized void cleanup() {
        if (closed) return;
        RuntimeException first = null;
        List<Entry> copy = new ArrayList<>(resources.values());
        java.util.Collections.reverse(copy);
        for (Entry e : copy) {
            try {
                if (!backend.owned(e.kind, e.id, runId)) throw new IllegalStateException("ownership check failed");
                append(record("intent", e.kind, e.id, "active", "delete"));
                backend.delete(e.kind, e.id);
                append(record("deleted", e.kind, e.id, "deleted", "delete"));
                resources.remove(key(e.kind, e.id));
            } catch (RuntimeException ex) {
                append(record("failure", e.kind, e.id, "active", "delete:" + safeError(ex)));
                if (first == null) first = ex;
            }
        }
        if (first != null) throw first;
    }

    @Override public synchronized void close() { cleanup(); closed = true; }

    /** Returns old pending/active ledger records; this method never deletes anything. */
    public static List<Map<String, String>> leftovers(Path directory, long olderHours) {
        if (olderHours < 0) throw new IllegalArgumentException("olderHours must be non-negative");
        List<Map<String, String>> out = new ArrayList<>();
        if (directory == null || !Files.isDirectory(directory)) return out;
        Instant cutoff = Instant.now().minus(olderHours, ChronoUnit.HOURS);
        try (var files = Files.list(directory)) {
            files.filter(p -> p.getFileName().toString().startsWith("lmaws-") && p.getFileName().toString().endsWith(".jsonl"))
                    .forEach(p -> scan(p, cutoff, out));
        } catch (IOException e) { throw new IllegalStateException("cannot scan ledger directory", e); }
        return out;
    }

    private Entry entry(Map<String, String> resource) {
        if (resource == null) throw new IllegalArgumentException("resource is required");
        String kind = resource.get("kind"), id = resource.get("id");
        Entry e = resources.get(key(kind, id));
        if (e == null) throw new IllegalArgumentException("resource is not owned by this sandbox");
        if (!backend.owned(e.kind, e.id, runId)) throw new IllegalArgumentException("resource ownership was not verified");
        return e;
    }

    private void ensureOpen() { if (closed) throw new IllegalStateException("sandbox is closed"); }
    private static String requireKind(String k) { if (k == null || !List.of("bucket","queue","topic","parameter","table","log_group").contains(k)) throw new IllegalArgumentException("unsupported write kind: " + k); return k; }
    private String resourceName(String kind, String name) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("name is required");
        String prefix = kind.equals("bucket") ? "lmaws-" + runId + "-" : "lmaws_" + runId + "_";
        String suffix = name.startsWith(prefix) ? name.substring(prefix.length()) : name;
        if (!SUFFIX.matcher(suffix).matches()) throw new IllegalArgumentException("name suffix contains unsafe characters");
        String result = prefix + suffix;
        if (kind.equals("bucket")) {
            if (result.length() > 63 || !result.matches("[a-z0-9][a-z0-9.-]*[a-z0-9]")) throw new IllegalArgumentException("bucket name must be lowercase DNS-compatible and at most 63 characters");
        } else if (result.length() > 64 || result.chars().anyMatch(c -> c < 0x20 || c == 0x7f || c == '/' || c == '\\')) throw new IllegalArgumentException("resource name contains unsafe characters");
        return result;
    }
    private static String key(String kind, String id) { return String.valueOf(kind) + "\u0000" + String.valueOf(id); }
    private static Path openLedger(Path p, String run) {
        try {
            if (Files.isDirectory(p)) p = p.resolve("lmaws-" + run + "-" + System.nanoTime() + ".jsonl");
            Files.createDirectories(p.toAbsolutePath().getParent());
            Files.newByteChannel(p, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).close();
            return p;
        } catch (IOException e) { throw new IllegalStateException("ledger already exists or cannot be created", e); }
    }
    private void append(Map<String, String> row) {
        try (FileChannel channel = FileChannel.open(ledger, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            byte[] bytes = (Jsons.encode(row) + "\n").getBytes(StandardCharsets.UTF_8);
            java.nio.ByteBuffer buffer=java.nio.ByteBuffer.wrap(bytes);
            while(buffer.hasRemaining())channel.write(buffer);
            channel.force(true);
        }
        catch (IOException e) { throw new IllegalStateException("cannot append sandbox ledger", e); }
    }
    private Map<String, String> record(String event, String kind, String id, String state, String action) {
        return new LinkedHashMap<>(Map.of("time", Instant.now().toString(), "event", event, "kind", kind, "id", id, "run_id", runId, "state", state, "action", action));
    }
    private static String safeError(Throwable x) { return x.getClass().getSimpleName(); }
    private Map<String, String> createdRecord(String kind, String id, String name) { var r = record("created", kind, id, "active", "create"); r.put("name", name); return r; }
    private static void scan(Path p, Instant cutoff, List<Map<String, String>> out) {
        try {
            if (Files.getLastModifiedTime(p).toInstant().isAfter(cutoff)) return;
            if (Files.size(p) > 1024 * 1024) { out.add(Map.of("ledger", p.toString(), "record", "manual review: ledger exceeds 1 MiB")); return; }
            Map<String, Map<String, String>> latest = new LinkedHashMap<>();
            Map<String, String> aliases = new LinkedHashMap<>();
            for (String line : Files.readAllLines(p)) {
                if (!line.trim().endsWith("}")) { out.add(Map.of("ledger", p.toString(), "record", "manual review: torn ledger record")); continue; }
                Map<String, String> row;
                try { row = jsonRow(line); } catch (RuntimeException ex) { out.add(Map.of("ledger", p.toString(), "record", "manual review: malformed ledger record")); continue; }
                String kind = row.get("kind"), id = row.get("id");
                if (kind == null || id == null || row.get("state") == null) { out.add(Map.of("ledger", p.toString(), "record", "manual review: malformed ledger record")); continue; }
                latest.put(kind + "\u0000" + id, row);
                if ("created".equals(row.get("event")) && row.get("name") != null) {
                    aliases.put(kind + "\u0000" + row.get("name"), id);
                    latest.put(kind + "\u0000" + row.get("name"), row);
                }
                if ("deleted".equals(row.get("event"))) {
                    String name = row.get("name");
                    if (name == null) for (var a : aliases.entrySet()) if (a.getValue().equals(id)) { name = a.getKey().substring(kind.length() + 1); break; }
                    if (name != null) latest.put(kind + "\u0000" + name, row);
                }
            }
            latest.values().stream().filter(r -> "active".equals(r.get("state")) || "pending".equals(r.get("state")))
                    .distinct().forEach(r -> out.add(new LinkedHashMap<>(Map.of("ledger", p.toString(), "record", Jsons.encode(r)))));
        } catch (IOException e) { out.add(Map.of("ledger", p.toString(), "record", "manual review: unreadable ledger")); }
    }
    private static Map<String, String> jsonRow(String line) {
        Map<String, String> out = new LinkedHashMap<>();
        for (var e : io.lmctl.lmcode.Json.object(io.lmctl.lmcode.Json.parse(line)).entrySet()) {
            if (!(e.getValue() instanceof String)) throw new IllegalArgumentException("ledger value is not string");
            out.put(e.getKey(), (String)e.getValue());
        }
        return out;
    }
    private static final class Entry { final String kind, id, name; Entry(String k, String i, String n) { kind=k; id=i; name=n; } }
}
