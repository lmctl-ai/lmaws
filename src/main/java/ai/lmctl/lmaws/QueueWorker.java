package ai.lmctl.lmaws;

import java.util.Map;

/** Run-owned SQS to Lambda event-source mapping. The host owns the mapping and DLQ wiring. */
final class QueueWorker {
    private final AwsBackend backend;
    private final String mappingArn;
    private final String runId;
    QueueWorker(AwsBackend backend, String mappingArn, String runId) {
        this.backend = backend; this.mappingArn = mappingArn; this.runId = runId;
    }
    String arn() { return mappingArn; }
    Map<String,String> status() { return backend.eventSourceMappingStatus(mappingArn, runId); }
    Map<String,String> delete() { return backend.deleteEventSourceMapping(mappingArn, runId); }
}
