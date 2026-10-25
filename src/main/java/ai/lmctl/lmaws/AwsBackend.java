package ai.lmctl.lmaws;

import java.net.InetAddress;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.Iterator;
import java.util.Spliterators;
import java.util.Spliterator;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.interceptor.SdkExecutionAttribute;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.DescribeAlarmsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.DescribeLogGroupsRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ListTablesRequest;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeVpcsRequest;
import software.amazon.awssdk.services.ec2.model.IpPermission;
import software.amazon.awssdk.services.ecs.EcsClient;
import software.amazon.awssdk.services.ecs.model.ListClustersRequest;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.ListRolesRequest;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.ListFunctionsRequest;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.route53.model.ListHostedZonesRequest;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketConfiguration;
import software.amazon.awssdk.services.s3.model.Tag;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsRequest;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.CreateTopicRequest;
import software.amazon.awssdk.services.sns.model.DeleteTopicRequest;
import software.amazon.awssdk.services.sns.model.ListTopicsRequest;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.DeleteParameterRequest;
import software.amazon.awssdk.services.ssm.model.PutParameterRequest;
import software.amazon.awssdk.services.ssm.model.DescribeParametersRequest;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.CreateQueueRequest;
import software.amazon.awssdk.services.sqs.model.DeleteQueueRequest;
import software.amazon.awssdk.services.sqs.model.ListQueuesRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.QueueDoesNotExistException;
import software.amazon.awssdk.services.sns.model.NotFoundException;
import software.amazon.awssdk.services.ssm.model.ParameterAlreadyExistsException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

/** Narrow, safe AWS facade used by the lmscript host. Values and credentials are never projected. */
public final class AwsBackend implements AutoCloseable {
    private static final Pattern KIND = Pattern.compile("[a-z_]+");
    private static final List<String> KINDS = List.of("identity", "buckets", "instances", "vpcs", "security_groups",
            "tables", "queues", "topics", "functions", "log_groups", "alarms", "zones", "secrets", "parameters",
            "clusters", "roles");
    private final String regionName;
    private final Region region;
    private final boolean demo;
    private final URI endpoint;
    private final CostLedger cost;
    private final Map<String, Map<String, String>> demoResources = new LinkedHashMap<>();
    private final Map<String, java.util.Set<String>> bucketObjects = new LinkedHashMap<>();
    private final List<AutoCloseable> clients = new ArrayList<>();
    private final ClientOverrideConfiguration config;

    private S3Client s3; private SqsClient sqs; private SnsClient sns; private SsmClient ssm; private DynamoDbClient ddb;
    private CloudWatchLogsClient logs; private CloudWatchClient cloudwatch; private Ec2Client ec2; private LambdaClient lambda;
    private Route53Client route53; private SecretsManagerClient secrets; private EcsClient ecs; private IamClient iam; private StsClient sts;

    public AwsBackend(String region, boolean demo) {
        this(region, demo, null);
    }

    public AwsBackend(String region, boolean demo, CostLedger cost) {
        String selected = region == null || region.isBlank()
                ? (demo ? "us-east-1" : Objects.requireNonNull(DefaultAwsRegionProviderChain.builder().build().getRegion(), "AWS region is not configured").id())
                : region;
        this.regionName = selected;
        this.region = Region.of(selected);
        this.demo = demo;
        this.cost = cost;
        ClientOverrideConfiguration.Builder configBuilder = ClientOverrideConfiguration.builder()
                .apiCallTimeout(Duration.ofSeconds(25)).apiCallAttemptTimeout(Duration.ofSeconds(10))
                .retryPolicy(RetryPolicy.builder().numRetries(2).build());
        if (cost != null) configBuilder.addExecutionInterceptor(new CostInterceptor(cost));
        this.config = configBuilder.build();
        String endpointText = System.getenv("LMAWS_ENDPOINT");
        this.endpoint = endpointText == null || endpointText.isBlank() ? null : checkedEndpoint(endpointText);
        if (!demo && endpoint == null && ciEnvironment())
            throw new IllegalStateException("live AWS credentials are disabled in CI; use a loopback fake endpoint");
        if (demo) seedDemo();
    }

    public String region() { return regionName; }
    public boolean isDemo() { return demo; }

    /** Strict, read-only provider absence check used after teardown. */
    public boolean exists(String kind, String id) {
        String k = createKind(kind);
        requireText(id, "id");
        if (demo) return demoResources.containsKey(demoKey(k, id));
        return switch (k) {
            case "bucket" -> {
                try { s3().headBucket(x -> x.bucket(id)); yield true; }
                catch (S3Exception e) { if (e.statusCode() == 404) yield false; throw e; }
            }
            case "queue" -> {
                try { sqs().getQueueUrl(x -> x.queueName(last(id))).queueUrl(); yield true; }
                catch (QueueDoesNotExistException e) { yield false; }
            }
            case "topic" -> {
                try { sns().getTopicAttributes(x -> x.topicArn(id)); yield true; }
                catch (NotFoundException e) { yield false; }
            }
            case "parameter" -> {
                var request = DescribeParametersRequest.builder().parameterFilters(
                        software.amazon.awssdk.services.ssm.model.ParameterStringFilter.builder()
                                .key("Name").option("Equals").values(id).build()).build();
                try { yield !ssm().describeParameters(request).parameters().isEmpty(); }
                catch (software.amazon.awssdk.services.ssm.model.InvalidFilterKeyException e) { throw e; }
            }
            case "table" -> {
                try { ddb().describeTable(x -> x.tableName(id)); yield true; }
                catch (software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException e) { yield false; }
            }
            case "log_group" -> {
                var pages = logs().describeLogGroupsPaginator(x -> x.logGroupNamePrefix(id));
                yield pages.stream().flatMap(p -> p.logGroups().stream()).anyMatch(g -> id.equals(g.logGroupName()));
            }
            default -> throw new IllegalArgumentException("unsupported resource kind: " + k);
        };
    }

    public List<Map<String, String>> inventory(String kind) {
        String k = normalizeKind(kind);
        if (demo) return demoInventory(k);
        return switch (k) {
            case "identity" -> List.of(identity());
            case "buckets" -> bounded(pages(s3().listBucketsPaginator()).flatMap(p -> p.buckets().stream()).map(b -> row("kind", "bucket", "id", b.name(), "name", b.name(), "region", b.bucketRegion() == null ? "" : b.bucketRegion())).map(x -> (Map<String, String>) x).limit(10001).toList());
            case "instances" -> bounded(pages(ec2().describeInstancesPaginator()).flatMap(p -> p.reservations().stream()).flatMap(r -> r.instances().stream()).map(i -> row("kind", "instance", "id", i.instanceId(), "name", i.instanceId(), "state", i.state() == null ? "" : i.state().nameAsString(), "type", i.instanceTypeAsString(), "tagged", Boolean.toString(!i.tags().isEmpty()))).limit(10001).toList());
            case "vpcs" -> bounded(pages(ec2().describeVpcsPaginator()).flatMap(p -> p.vpcs().stream()).map(v -> row("kind", "vpc", "id", v.vpcId(), "name", v.vpcId(), "cidr", v.cidrBlock(), "state", v.stateAsString(), "tagged", Boolean.toString(!v.tags().isEmpty()))).limit(10001).toList());
            case "security_groups" -> bounded(pages(ec2().describeSecurityGroupsPaginator()).flatMap(p -> p.securityGroups().stream()).map(g -> { boolean open = g.ipPermissions().stream().anyMatch(p -> p.ipRanges().stream().anyMatch(r -> "0.0.0.0/0".equals(r.cidrIp())) || p.ipv6Ranges().stream().anyMatch(r -> "::/0".equals(r.cidrIpv6()))); return row("kind", "security_group", "id", g.groupId(), "name", g.groupName(), "vpc", g.vpcId(), "public", Boolean.toString(open), "open_ports", openPorts(g.ipPermissions()), "tagged", Boolean.toString(!g.tags().isEmpty())); }).limit(10001).toList());
            case "tables" -> bounded(pages(ddb().listTablesPaginator()).flatMap(p -> p.tableNames().stream()).map(n -> row("kind", "table", "id", n, "name", n, "region", regionName)).limit(10001).toList());
            case "queues" -> bounded(pages(sqs().listQueuesPaginator()).flatMap(p -> p.queueUrls().stream()).map(u -> row("kind", "queue", "id", u, "name", last(u))).limit(10001).toList());
            case "topics" -> bounded(pages(sns().listTopicsPaginator()).flatMap(p -> p.topics().stream()).map(t -> row("kind", "topic", "id", t.topicArn(), "name", last(t.topicArn()))).limit(10001).toList());
            case "functions" -> bounded(pages(lambda().listFunctionsPaginator()).flatMap(p -> p.functions().stream()).map(f -> row("kind", "function", "id", f.functionArn(), "name", f.functionName(), "runtime", f.runtimeAsString())).limit(10001).toList());
            case "log_groups" -> bounded(pages(logs().describeLogGroupsPaginator()).flatMap(p -> p.logGroups().stream()).map(g -> row("kind", "log_group", "id", g.logGroupName(), "name", g.logGroupName(), "retention", String.valueOf(g.retentionInDays() == null ? 0 : g.retentionInDays()), "tagged", "unknown")).limit(10001).toList());
            case "alarms" -> bounded(pages(cloudwatch().describeAlarmsPaginator()).flatMap(p -> p.metricAlarms().stream()).map(a -> row("kind", "alarm", "id", a.alarmArn(), "name", a.alarmName(), "state", a.stateValueAsString())).limit(10001).toList());
            case "zones" -> bounded(pages(route53().listHostedZonesPaginator()).flatMap(p -> p.hostedZones().stream()).map(z -> row("kind", "zone", "id", z.id(), "name", z.name())).limit(10001).toList());
            case "secrets" -> bounded(pages(secrets().listSecretsPaginator()).flatMap(p -> p.secretList().stream()).map(s -> row("kind", "secret", "id", s.arn(), "name", s.name(), "last_changed", String.valueOf(s.lastChangedDate()), "value", "[redacted]")).limit(10001).toList());
            case "parameters" -> bounded(pages(ssm().describeParametersPaginator()).flatMap(p -> p.parameters().stream()).map(p -> row("kind", "parameter", "id", p.name(), "name", p.name(), "type", p.typeAsString(), "value", "[redacted]")).limit(10001).toList());
            case "clusters" -> bounded(pages(ecs().listClustersPaginator()).flatMap(p -> p.clusterArns().stream()).map(a -> row("kind", "cluster", "id", a, "name", last(a))).limit(10001).toList());
            case "roles" -> bounded(pages(iam().listRolesPaginator()).flatMap(p -> p.roles().stream()).map(r -> row("kind", "role", "id", r.arn(), "name", r.roleName(), "created", String.valueOf(r.createDate()))).limit(10001).toList());
            default -> throw new IllegalArgumentException("unsupported inventory kind: " + k);
        };
    }

    public Map<String, String> create(String kind, String name, String value, String runId) {
        String k = createKind(kind); String n = requireName(name); requireRunId(runId);
        requireWriteEnabled();
        if (demo) return demoCreate(k, n, value, runId);
        Map<String, String> out;
        switch (k) {
            case "bucket" -> { preflightBucket(n); CreateBucketRequest.Builder b = CreateBucketRequest.builder().bucket(n); if (!regionName.equals("us-east-1")) b.createBucketConfiguration(CreateBucketConfiguration.builder().locationConstraint(regionName).build()); s3().createBucket(b.build()); bucketObjects.put(n, new java.util.LinkedHashSet<>()); try { tagBucket(n, runId); } catch (RuntimeException e) { bucketObjects.remove(n); try { s3().deleteBucket(DeleteBucketRequest.builder().bucket(n).build()); } catch (RuntimeException ignored) { } throw e; } out = row("kind", k, "id", n, "name", n); }
            case "queue" -> { preflightQueue(n); String u = sqs().createQueue(CreateQueueRequest.builder().queueName(n).tags(Map.of("lmaws_test", runId)).build()).queueUrl(); out = row("kind", k, "id", u, "name", n); }
            case "topic" -> { preflightTopic(n); String a = sns().createTopic(CreateTopicRequest.builder().name(n).tags(software.amazon.awssdk.services.sns.model.Tag.builder().key("lmaws_test").value(runId).build()).build()).topicArn(); out = row("kind", k, "id", a, "name", n); }
            case "parameter" -> { ssm().putParameter(PutParameterRequest.builder().name(n).value(value == null ? "" : value).type("String").tier("Standard").overwrite(false).tags(software.amazon.awssdk.services.ssm.model.Tag.builder().key("lmaws_test").value(runId).build()).build()); out = row("kind", k, "id", n, "name", n); }
            case "table" -> { var created = ddb().createTable(x -> x.tableName(n).billingMode("PAY_PER_REQUEST").attributeDefinitions(a -> a.attributeName("pk").attributeType("S")).keySchema(a -> a.attributeName("pk").keyType("HASH")).tags(software.amazon.awssdk.services.dynamodb.model.Tag.builder().key("lmaws_test").value(runId).build())); String arn = created.tableDescription().tableArn(); out = row("kind", k, "id", n, "name", n, "arn", arn); }
            case "log_group" -> { logs().createLogGroup(x -> x.logGroupName(n).tags(Map.of("lmaws_test", runId))); out = row("kind", k, "id", n, "name", n); }
            default -> throw new IllegalArgumentException("unsupported create kind: " + k);
        }
        out.put("created", Instant.now().toString()); out.put("run_id", runId); return out;
    }

    public void update(String kind, String id, String key, String value) {
        String k = createKind(kind); requireText(id, "id");
        requireWriteEnabled();
        if (demo) { demoResources.computeIfPresent(demoKey(k, id), (x, old) -> { old.put("updated", "true"); return old; }); return; }
        switch (k) {
            case "bucket" -> { requireObjectKey(key); ensureNewObject(id, key); bucketObjects.computeIfAbsent(id, x -> new java.util.LinkedHashSet<>()).add(key); s3().putObject(PutObjectRequest.builder().bucket(id).key(key).build(), software.amazon.awssdk.core.sync.RequestBody.fromString(value == null ? "" : value)); }
            case "queue" -> sqs().sendMessage(SendMessageRequest.builder().queueUrl(id).messageBody(value == null ? "" : value).build());
            case "topic" -> sns().publish(PublishRequest.builder().topicArn(id).message(value == null ? "" : value).build());
            case "parameter" -> ssm().putParameter(PutParameterRequest.builder().name(id).value(value == null ? "" : value).type("String").tier("Standard").overwrite(true).build());
            case "table" -> ddb().putItem(x -> x.tableName(id).item(Map.of("pk", AttributeValue.builder().s(key).build(), "value", AttributeValue.builder().s(value == null ? "" : value).build())));
            case "log_group" -> { if (!"retention_days".equals(key)) throw new IllegalArgumentException("log_group supports retention_days only"); logs().putRetentionPolicy(x -> x.logGroupName(id).retentionInDays(Integer.parseInt(value))); }
            default -> throw new IllegalArgumentException("unsupported update kind: " + k);
        }
    }

    public void delete(String kind, String id) {
        String k = createKind(kind); requireText(id, "id");
        requireWriteEnabled();
        if (demo) { demoResources.remove(demoKey(k, id)); return; }
        switch (k) {
            case "bucket" -> { java.util.Set<String> keys = bucketObjects.getOrDefault(id, java.util.Set.of()); for (String key : keys) s3().deleteObject(DeleteObjectRequest.builder().bucket(id).key(key).build()); boolean remaining = pages(s3().listObjectsV2Paginator(x -> x.bucket(id))).flatMap(p -> p.contents().stream()).findAny().isPresent(); if (remaining) throw new IllegalStateException("bucket contains objects outside this run; refusing deletion"); s3().deleteBucket(DeleteBucketRequest.builder().bucket(id).build()); bucketObjects.remove(id); }
            case "queue" -> sqs().deleteQueue(DeleteQueueRequest.builder().queueUrl(id).build());
            case "topic" -> sns().deleteTopic(DeleteTopicRequest.builder().topicArn(id).build());
            case "parameter" -> ssm().deleteParameter(DeleteParameterRequest.builder().name(id).build());
            case "table" -> { ddb().deleteTable(x -> x.tableName(id)); waitTableGone(id); }
            case "log_group" -> logs().deleteLogGroup(x -> x.logGroupName(id));
            default -> throw new IllegalArgumentException("unsupported delete kind: " + k);
        }
    }

    public boolean owned(String kind, String id, String runId) {
        String k = createKind(kind); requireText(id, "id"); requireRunId(runId);
        if (demo) { Map<String, String> resource = demoResources.get(demoKey(k, id)); return resource != null && runId.equals(resource.get("run_id")); }
        String n = last(id);
        String prefix = "bucket".equals(k) ? "lmaws-" + runId + "-" : "lmaws_" + runId + "_";
        if (!n.startsWith(prefix)) return false;
        return switch (k) {
            case "bucket" -> hasTag(s3().getBucketTagging(x -> x.bucket(id)).tagSet(), runId);
            case "queue" -> runId.equals(sqs().listQueueTags(x -> x.queueUrl(id)).tags().get("lmaws_test"));
            case "topic" -> sns().listTagsForResource(x -> x.resourceArn(id)).tags().stream().anyMatch(t -> "lmaws_test".equals(t.key()) && runId.equals(t.value()));
            case "parameter" -> ssm().listTagsForResource(x -> x.resourceType("Parameter").resourceId(id)).tagList().stream().anyMatch(t -> "lmaws_test".equals(t.key()) && runId.equals(t.value()));
            case "table" -> { var d = ddb().describeTable(x -> x.tableName(id)).table(); yield d != null && d.tableArn() != null && ddb().listTagsOfResource(x -> x.resourceArn(d.tableArn())).tags().stream().anyMatch(t -> "lmaws_test".equals(t.key()) && runId.equals(t.value())); }
            case "log_group" -> runId.equals(logs().listTagsLogGroup(x -> x.logGroupName(id)).tags().get("lmaws_test"));
            default -> false;
        };
    }

    /** Waits for a newly-created resource to become describeable and to expose its exact run tag. */
    public void awaitReady(String kind, String id, String runId) {
        String k = createKind(kind); requireText(id, "id"); requireRunId(runId);
        if(demo) {if(!owned(k,id,runId))throw new IllegalStateException("demo resource ownership mismatch");return;}
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        RuntimeException last = null;
        while (System.nanoTime() < deadline) {
            try {
                if ("table".equals(k)) {
                    var table = ddb().describeTable(x -> x.tableName(id)).table();
                    if (table == null || !"ACTIVE".equals(table.tableStatusAsString())) { sleepReady(); continue; }
                }
                if (owned(k, id, runId)) return;
            } catch (RuntimeException e) { last = e; }
            sleepReady();
        }
        if (last != null) throw new IllegalStateException("resource did not become ready within 30 seconds", last);
        throw new IllegalStateException("resource did not become ready within 30 seconds");
    }

    @Override public void close() { for (AutoCloseable c : clients) try { c.close(); } catch (Exception ignored) { } }

    private StsClient sts() { return sts == null ? sts = register(base(StsClient.builder()).build()) : sts; }
    private S3Client s3() { if (s3 == null) { var b = S3Client.builder(); if (endpoint != null) b.forcePathStyle(true); s3 = register(base(b).build()); } return s3; }
    private SqsClient sqs() { return sqs == null ? sqs = register(base(SqsClient.builder()).build()) : sqs; }
    private SnsClient sns() { return sns == null ? sns = register(base(SnsClient.builder()).build()) : sns; }
    private SsmClient ssm() { return ssm == null ? ssm = register(base(SsmClient.builder()).build()) : ssm; }
    private DynamoDbClient ddb() { return ddb == null ? ddb = register(base(DynamoDbClient.builder()).build()) : ddb; }
    private CloudWatchLogsClient logs() { return logs == null ? logs = register(base(CloudWatchLogsClient.builder()).build()) : logs; }
    private CloudWatchClient cloudwatch() { return cloudwatch == null ? cloudwatch = register(base(CloudWatchClient.builder()).build()) : cloudwatch; }
    private Ec2Client ec2() { return ec2 == null ? ec2 = register(base(Ec2Client.builder()).build()) : ec2; }
    private LambdaClient lambda() { return lambda == null ? lambda = register(base(LambdaClient.builder()).build()) : lambda; }
    private Route53Client route53() { return route53 == null ? route53 = register(base(Route53Client.builder()).build()) : route53; }
    private SecretsManagerClient secrets() { return secrets == null ? secrets = register(base(SecretsManagerClient.builder()).build()) : secrets; }
    private EcsClient ecs() { return ecs == null ? ecs = register(base(EcsClient.builder()).build()) : ecs; }
    private IamClient iam() { return iam == null ? iam = register(base(IamClient.builder()).build()) : iam; }
    private <T extends software.amazon.awssdk.awscore.client.builder.AwsClientBuilder<?, ?>> T base(T b) { b.region(region).overrideConfiguration(config); ((software.amazon.awssdk.awscore.client.builder.AwsSyncClientBuilder<?, ?>) b).httpClientBuilder(UrlConnectionHttpClient.builder()); if (endpoint != null) b.endpointOverride(endpoint).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"))); else b.credentialsProvider(ProfileCredentialsProvider.builder().profileName(System.getenv().getOrDefault("AWS_PROFILE", "default")).build()); return b; }

    private static final class CostInterceptor implements ExecutionInterceptor {
        private final CostLedger ledger;
        CostInterceptor(CostLedger ledger) { this.ledger = ledger; }
        @Override public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes attributes) {
            String service = attributes.getOptionalAttribute(SdkExecutionAttribute.SERVICE_NAME).orElse("aws");
            String operation = attributes.getOptionalAttribute(SdkExecutionAttribute.OPERATION_NAME).orElse("request");
            ledger.request(service, operation);
        }
    }
    private <T extends AutoCloseable> T register(T c) { clients.add(c); return c; }

    private Map<String, String> identity() { var i = sts().getCallerIdentity(GetCallerIdentityRequest.builder().build()); return row("kind", "identity", "id", safeId(i.account()), "name", safeId(i.arn())); }
    private static String safeId(String s) { return s == null ? "" : s.replaceAll("\\d(?=\\d{4})", "*"); }
    private static String last(String s) { int i = s.lastIndexOf('/'); if (i < 0) i = s.lastIndexOf(':'); return i < 0 ? s : s.substring(i + 1); }
    private static String openPorts(List<IpPermission> permissions) { List<String> ports = new ArrayList<>(); for (var p : permissions) { boolean broad = p.ipRanges().stream().anyMatch(r -> "0.0.0.0/0".equals(r.cidrIp())) || p.ipv6Ranges().stream().anyMatch(r -> "::/0".equals(r.cidrIpv6())); if (!broad) continue; if (p.fromPort() == null || p.toPort() == null) ports.add("-1"); else if (p.fromPort().intValue() == p.toPort().intValue()) ports.add(Integer.toString(p.fromPort())); else ports.add(p.fromPort() + "-" + p.toPort()); } return String.join(",", ports); }
    private static Map<String, String> row(String... kv) { Map<String, String> m = new LinkedHashMap<>(); for (int i = 0; i + 1 < kv.length; i += 2) if (kv[i + 1] != null) m.put(kv[i], kv[i + 1]); return m; }
    private static <T> List<T> bounded(List<T> rows) { if (rows.size() > 10000) throw new IllegalStateException("inventory exceeds 10000 rows"); return rows; }
    private static <T> Stream<T> pages(Iterable<T> iterable) {
        final long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        Iterator<T> source = iterable.iterator();
        Iterator<T> bounded = new Iterator<>() {
            int count;
            public boolean hasNext() { if (System.nanoTime() > deadline) throw new IllegalStateException("inventory pagination exceeded 60 seconds"); return source.hasNext(); }
            public T next() { if (++count > 100) throw new IllegalStateException("inventory pagination exceeded 100 pages"); return source.next(); }
        };
        return StreamSupport.stream(Spliterators.spliteratorUnknownSize(bounded, Spliterator.ORDERED), false);
    }
    private static String normalizeKind(String k) { if (k == null) throw new IllegalArgumentException("kind is required"); String x = k.toLowerCase(Locale.ROOT); if (!KINDS.contains(x)) throw new IllegalArgumentException("unsupported inventory kind: " + x); return x; }
    private static String createKind(String k) { String x = Objects.requireNonNull(k, "kind").toLowerCase(Locale.ROOT); if (!List.of("bucket", "queue", "topic", "parameter", "table", "log_group").contains(x)) throw new IllegalArgumentException("unsupported write kind: " + x); return x; }
    private static String requireName(String x) { requireText(x, "name"); if (!x.matches("[a-z0-9][a-z0-9_.-]{0,62}")) throw new IllegalArgumentException("name contains unsupported characters"); return x; }
    private static void requireText(String x, String n) { if (x == null || x.isBlank()) throw new IllegalArgumentException(n + " is required"); }
    private static void requireRunId(String x) { if (x == null || !x.matches("[a-z0-9]{1,24}")) throw new IllegalArgumentException("runId contains unsupported characters"); }
    private static void requireObjectKey(String x) { requireText(x, "key"); if (x.length() > 1024 || x.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) throw new IllegalArgumentException("object key contains unsupported characters"); }
    private void ensureNewObject(String bucket, String key) {
        java.util.Set<String> tracked = bucketObjects.get(bucket);
        if (tracked == null) throw new IllegalStateException("bucket was not created in this run");
        if (tracked.contains(key)) return;
        try { s3().headObject(x -> x.bucket(bucket).key(key)); throw new IllegalStateException("refusing to overwrite object outside this run"); }
        catch (S3Exception e) { if (e.statusCode() != 404) throw e; }
    }
    private static void sleepReady() { try { Thread.sleep(250L); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("resource readiness wait interrupted", e); } }
    private void waitTableGone(String id) { long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos(); while (System.nanoTime() < deadline) { try { ddb().describeTable(x -> x.tableName(id)); } catch (software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException e) { return; } sleepReady(); } throw new IllegalStateException("table deletion did not complete within 30 seconds"); }
    private static URI checkedEndpoint(String x) { URI u = URI.create(x); String h = u.getHost(); if (!"http".equalsIgnoreCase(u.getScheme()) || u.getUserInfo() != null || u.getQuery() != null || u.getFragment() != null || (u.getPath() != null && !u.getPath().isEmpty() && !"/".equals(u.getPath())) || !("127.0.0.1".equals(h) || "::1".equals(h) || "[::1]".equals(h))) throw new IllegalArgumentException("LMAWS_ENDPOINT must be http://127.0.0.1 or http://[::1]"); return u; }

    private void requireWriteEnabled() { if (!demo && endpoint == null && !"1".equals(System.getenv("LMAWS_LIVE"))) throw new IllegalStateException("live writes require LMAWS_LIVE=1"); }
    private static boolean ciEnvironment() {
        String value = System.getenv("CI");
        return value != null && (value.equalsIgnoreCase("true") || value.equals("1") || value.equalsIgnoreCase("yes"));
    }
    private void preflightBucket(String name) { try { s3().headBucket(x -> x.bucket(name)); throw new IllegalStateException("bucket already exists: " + name); } catch (S3Exception e) { if (e.statusCode() != 404) throw e; } }
    private void preflightQueue(String name) { try { sqs().getQueueUrl(x -> x.queueName(name)); throw new IllegalStateException("queue already exists: " + name); } catch (QueueDoesNotExistException e) { } }
    private void preflightTopic(String name) { if (pages(sns().listTopicsPaginator(ListTopicsRequest.builder().build())).flatMap(p -> p.topics().stream()).anyMatch(topic -> name.equals(last(topic.topicArn())))) throw new IllegalStateException("topic already exists: " + name); }
    private static boolean hasTag(List<Tag> tags, String runId) { return tags.stream().anyMatch(t -> "lmaws_test".equals(t.key()) && runId.equals(t.value())); }

    private void seedDemo() {
        for (String k : KINDS) {
            String prefix = "demo-" + k + "-";
            for (int i = 1; i <= 3; i++) {
                String id = prefix + i;
                Map<String, String> r = row("kind", inventoryKind(k), "id", id, "name", id, "region", regionName, "tagged", i == 3 ? "false" : "true");
                if (k.equals("instances")) { r.put("state", i == 1 ? "running" : "stopped"); r.put("type", "t3.micro"); }
                if (k.equals("security_groups")) { r.put("public", i == 1 ? "true" : "false"); r.put("open_ports", i == 1 ? "22,443" : ""); }
                if (k.equals("tables")) r.put("billing", "on_demand");
                if (k.equals("secrets") || k.equals("parameters")) r.put("value", "[redacted]");
                demoResources.put(id, r);
            }
        }
    }
    private static String inventoryKind(String inventory) {
        return switch(inventory) {
            case "buckets" -> "bucket"; case "instances" -> "instance"; case "vpcs" -> "vpc";
            case "security_groups" -> "security_group"; case "tables" -> "table"; case "queues" -> "queue";
            case "topics" -> "topic"; case "functions" -> "function"; case "log_groups" -> "log_group";
            case "alarms" -> "alarm"; case "zones" -> "zone"; case "secrets" -> "secret";
            case "parameters" -> "parameter"; case "clusters" -> "cluster"; case "roles" -> "role";
            default -> inventory;
        };
    }
    private List<Map<String, String>> demoInventory(String k) { return demoResources.values().stream().filter(x -> inventoryKind(k).equals(x.get("kind"))).map(x -> (Map<String, String>) new LinkedHashMap<>(x)).toList(); }
    private Map<String, String> demoCreate(String k, String n, String value, String runId) { String id = n; String key = demoKey(k, id); if(demoResources.containsKey(key))throw new IllegalStateException("demo resource already exists"); Map<String, String> m = row("kind", k, "id", id, "name", n, "created", Instant.now().toString(), "run_id", runId); if (value != null) m.put("value_metadata", "stored"); demoResources.put(key, m); return new LinkedHashMap<>(m); }
    private static String demoKey(String kind, String id) { return kind + "\u0000" + id; }

    private void tagBucket(String id,String runId) {
        s3().putBucketTagging(x -> x.bucket(id).tagging(t -> t.tagSet(Tag.builder().key("lmaws_test").value(runId).build())));
    }
}
