package ai.lmctl.lmaws;

/** Independent, read-only exact-name checks; denied/unknown errors propagate. */
final class ResourceLookup {
    private ResourceLookup() {}
    static boolean exists(AwsBackend backend,String kind,String name) {
        if(name==null||name.isBlank())throw new IllegalArgumentException("resource name is required");
        if(kind.equals("topic"))return backend.inventory("topics").stream().anyMatch(row->name.equals(row.get("name")));
        return backend.exists(kind,name);
    }
}
