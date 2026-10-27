package ai.lmctl.lmaws;

import java.net.InetAddress;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
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
import software.amazon.awssdk.services.cloudwatchlogs.model.LogGroup;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ListTablesRequest;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeTagsRequest;
import software.amazon.awssdk.services.ec2.model.Filter;
import software.amazon.awssdk.services.ec2.model.DescribeVpcsRequest;
import software.amazon.awssdk.services.ec2.model.IpPermission;
import software.amazon.awssdk.services.ecs.EcsClient;
import software.amazon.awssdk.services.ecs.model.ListClustersRequest;
import software.amazon.awssdk.services.ecs.model.DescribeClustersRequest;
import software.amazon.awssdk.services.ecs.model.ClusterField;
import software.amazon.awssdk.services.cloudformation.CloudFormationClient;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksRequest;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.CreatePolicyVersionResponse;
import software.amazon.awssdk.services.iam.model.GetPolicyResponse;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionResponse;
import software.amazon.awssdk.services.iam.model.ListRolesRequest;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.iam.model.Policy;
import software.amazon.awssdk.services.iam.model.PolicyVersion;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.ListFunctionsRequest;
import software.amazon.awssdk.services.lambda.model.CreateEventSourceMappingRequest;
import software.amazon.awssdk.services.lambda.model.FunctionResponseType;
import software.amazon.awssdk.services.lambda.model.ResourceNotFoundException;
import software.amazon.awssdk.services.eventbridge.EventBridgeClient;
import software.amazon.awssdk.core.SdkBytes;
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
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.model.NotificationConfiguration;
import software.amazon.awssdk.services.s3.model.LambdaFunctionConfiguration;
import software.amazon.awssdk.services.s3.model.Event;
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
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;
import software.amazon.awssdk.services.sqs.model.GetQueueAttributesRequest;
import software.amazon.awssdk.services.sns.model.NotFoundException;
import software.amazon.awssdk.services.ssm.model.ParameterAlreadyExistsException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

/** Narrow, safe AWS facade used by the lmscript host. Values and credentials are never projected. */
public final class AwsBackend implements AutoCloseable {
    private static final Pattern KIND = Pattern.compile("[a-z_]+");
    private static final List<String> KINDS = List.of("identity", "buckets", "instances", "vpcs", "security_groups",
            "tables", "queues", "topics", "functions", "log_groups", "alarms", "zones", "secrets", "parameters",
            "clusters", "stacks", "roles");
    private final String regionName;
    private final String profileName;
    private final Region region;
    private final boolean demo;
    private final URI endpoint;
    private final CostLedger cost;
    private final Map<String, Map<String, String>> demoResources = new LinkedHashMap<>();
    private final Map<String,String> mappingRuns = new LinkedHashMap<>();
    private final Map<String,S3Client> regionalBuckets=new LinkedHashMap<>();
    private final Map<String, java.util.Set<String>> bucketObjects = new LinkedHashMap<>();
    private final Map<String, DemoPolicyState> demoPolicies = new LinkedHashMap<>();
    private final Map<String,String> lambdaRuns = new LinkedHashMap<>();
    private final Map<String,String> eventRuns = new LinkedHashMap<>();
    private final List<AutoCloseable> clients = new ArrayList<>();
    private final ClientOverrideConfiguration config;
    private String cachedAccountId;

    private S3Client s3; private SqsClient sqs; private SnsClient sns; private SsmClient ssm; private DynamoDbClient ddb;
    private CloudWatchLogsClient logs; private CloudWatchClient cloudwatch; private Ec2Client ec2; private LambdaClient lambda;
    private EventBridgeClient events;
    private Route53Client route53; private SecretsManagerClient secrets; private EcsClient ecs; private IamClient iam; private StsClient sts; private CloudFormationClient cloudformation;

    public AwsBackend(String region, boolean demo) {
        this(region, demo, null);
    }

    public AwsBackend(String region, boolean demo, CostLedger cost) { this(region,demo,cost,activeProfile()); }

    private AwsBackend(String region,boolean demo,CostLedger cost,String profileName) {
        this.profileName=profileName;
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

    /** Read-only native prefix filters plus bounded client-side matching and exact tag metadata. */
    public List<Map<String, String>> findPrefix(String prefix) {
        requireText(prefix, "prefix");
        if (prefix.length() > 128) throw new IllegalArgumentException("prefix is too long");
        List<Map<String, String>> result = new ArrayList<>();
        for (String kind : KINDS) {
            // IAM is intentionally not queried by federated sessions.  Other
            // inventories are read-only and may be used by the default profile.
            if ("identity".equals(kind) || "roles".equals(kind)) continue;
            List<Map<String, String>> rows = switch (kind) {
                case "queues" -> demo ? inventory(kind) : prefixQueues(prefix);
                case "log_groups" -> demo ? inventory(kind) : prefixLogGroups(prefix);
                case "parameters" -> demo ? inventory(kind) : prefixParameters(prefix);
                case "instances" -> demo ? inventory(kind) : prefixEc2Tags(prefix);
                case "vpcs", "security_groups" -> demo ? inventory(kind) : List.of();
                case "clusters" -> demo ? inventory(kind) : prefixEcsClusters(prefix);
                case "stacks" -> demo ? List.of() : prefixStacks(prefix);
                case "buckets" -> demo ? inventory(kind) : prefixBuckets(prefix);
                case "topics" -> demo ? inventory(kind) : prefixTopics(prefix);
                case "functions" -> demo ? inventory(kind) : prefixFunctions(prefix);
                case "tables" -> demo ? inventory(kind) : prefixTables(prefix);
                default -> inventory(kind);
            };
            if(demo) {
                rows=new ArrayList<>(rows);
                if(kind.equals("queues"))checkedSearchAdd(rows,row("kind","queue","id","lmaws_demo_queue","name","lmaws_demo_queue","region",regionName,"created","2026-10-20T00:00:00Z","run_id","demo","tags","{\"lmaws_test\":\"demo\"}"));
                if(kind.equals("buckets"))checkedSearchAdd(rows,row("kind","bucket","id","lmaws-demo-bucket","name","lmaws-demo-bucket","region",regionName,"created","2026-10-20T00:00:00Z","run_id","demo","tags","{\"lmaws_test\":\"demo\"}"));
                if(kind.equals("topics"))checkedSearchAdd(rows,row("kind","topic","id","lmawsOther","name","lmawsOther","region",regionName,"created","2026-10-20T00:00:00Z","tags","{}"));
            }
            for (Map<String, String> source : rows) {
                String name = source.getOrDefault("name", "");
                if (!name.startsWith(prefix)) continue;
                Map<String, String> row = new LinkedHashMap<>();
                row.put("service", serviceFor(kind));
                row.put("resource_type", source.getOrDefault("kind", kind));
                row.put("kind", source.getOrDefault("kind", kind));
                row.put("name", name);
                row.put("id", source.getOrDefault("id", name));
                row.put("arn", source.getOrDefault("arn",source.getOrDefault("id","").startsWith("arn:")?source.get("id"):""));
                row.put("region", source.getOrDefault("region", regionName));
                row.put("created_at", source.getOrDefault("created", source.getOrDefault("created_at", "")));
                row.put("modified_at",source.getOrDefault("modified_at",""));
                row.put("age_basis",row.get("created_at").isBlank()?(row.get("modified_at").isBlank()?"unknown":"last_modified"):"created");
                row.put("age_hours", ageHours(row.get("created_at").isBlank()?row.get("modified_at"):row.get("created_at")));
                String tagJson=source.getOrDefault("tags","{}");
                boolean knownTags=source.containsKey("tags") || !source.getOrDefault("run_id","").isBlank();
                boolean hasTestTag=io.lmctl.lmcode.Json.object(io.lmctl.lmcode.Json.parse(tagJson)).containsKey("lmaws_test");
                String tagged=Boolean.toString(hasTestTag || !source.getOrDefault("run_id","").isBlank());
                row.put("tags_status",knownTags?"known":"unknown");
                row.put("tags", source.getOrDefault("tags", "{}"));
                row.put("lmaws_test", tagged);
                row.put("run_id", source.getOrDefault("run_id", ""));
                row.put("status", "ok");
                row.put("match_field",source.getOrDefault("match_field","name"));
                row.put("provider_state",source.getOrDefault("status",""));
                checkedSearchAdd(result,row);
                if (result.size() > 10000) throw new IllegalStateException("prefix search exceeds 10000 rows");
            }
        }
        return List.copyOf(result);
    }

    private List<Map<String, String>> prefixQueues(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : prefixPages(sqs().listQueuesPaginator(ListQueuesRequest.builder().queueNamePrefix(prefix).build()))) {
            for (String url : page.queueUrls()) {
                String name = last(url);
                if (!name.startsWith(prefix)) continue;
                Map<String, String> tags = sqs().listQueueTags(x -> x.queueUrl(url)).tags();
                var attrs=sqs().getQueueAttributes(x->x.queueUrl(url).attributeNames(software.amazon.awssdk.services.sqs.model.QueueAttributeName.CREATED_TIMESTAMP,software.amazon.awssdk.services.sqs.model.QueueAttributeName.QUEUE_ARN)).attributesAsStrings();
                checkedSearchAdd(rows,row("kind", "queue", "id", url, "name", name, "region", regionName,"created",attrs.containsKey("CreatedTimestamp")?Instant.ofEpochSecond(Long.parseLong(attrs.get("CreatedTimestamp"))).toString():"","arn",attrs.getOrDefault("QueueArn",""),
                        "tagged", Boolean.toString(tags.containsKey("lmaws_test")),
                        "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
            }
        }
        return bounded(rows);
    }

    private List<Map<String, String>> prefixLogGroups(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : prefixPages(logs().describeLogGroupsPaginator(DescribeLogGroupsRequest.builder().logGroupNamePrefix(prefix).build()))) {
            for (LogGroup group : page.logGroups()) {
                String name = group.logGroupName();
                if (name == null || !name.startsWith(prefix)) continue;
                Map<String, String> tags = logs().listTagsLogGroup(x -> x.logGroupName(name)).tags();
                checkedSearchAdd(rows,row("kind", "log_group", "id", name, "name", name, "region", regionName,
                        "created", group.creationTime() == null ? "" : Instant.ofEpochMilli(group.creationTime()).toString(),
                        "tagged", Boolean.toString(tags.containsKey("lmaws_test")),
                        "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
            }
        }
        return bounded(rows);
    }

    private List<Map<String, String>> prefixParameters(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        var filter = software.amazon.awssdk.services.ssm.model.ParameterStringFilter.builder()
                .key("Name").option("BeginsWith").values(prefix).build();
        for (var page : prefixPages(ssm().describeParametersPaginator(DescribeParametersRequest.builder().parameterFilters(filter).build()))) {
            for (var parameter : page.parameters()) {
                String name = parameter.name();
                if (name == null || !name.startsWith(prefix)) continue;
                Map<String, String> tags = new LinkedHashMap<>();
                try { for (var tag : ssm().listTagsForResource(x -> x.resourceType("Parameter").resourceId(name)).tagList()) tags.put(tag.key(), tag.value()); }
                catch (RuntimeException e) { throw new IllegalStateException("prefix search could not read SSM tags", e); }
                checkedSearchAdd(rows,row("kind", "parameter", "id", name, "name", name, "region", regionName,
                        "modified_at", parameter.lastModifiedDate() == null ? "" : parameter.lastModifiedDate().toString(),
                        "tagged", Boolean.toString(tags.containsKey("lmaws_test")),
                        "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
            }
        }
        return bounded(rows);
    }

    private List<Map<String,String>> prefixEc2Tags(String prefix) {
        Map<String,Map<String,String>> matched=new LinkedHashMap<>();
        var request=DescribeTagsRequest.builder().filters(Filter.builder().name("value").values(prefix+"*").build()).build();
        for(var page:prefixPages(ec2().describeTagsPaginator(request)))for(var tag:page.tags()) {
            if(!"Name".equals(tag.key())||tag.value()==null||!tag.value().startsWith(prefix)||matched.containsKey(tag.resourceId()))continue;
            Map<String,String> tags=new LinkedHashMap<>();
            var all=DescribeTagsRequest.builder().filters(Filter.builder().name("resource-id").values(tag.resourceId()).build()).build();
            for(var tagPage:prefixPages(ec2().describeTagsPaginator(all)))for(var item:tagPage.tags())tags.put(item.key(),item.value());
            String name=tags.getOrDefault("Name",tag.value());if(!name.startsWith(prefix))name=tag.value();
            String type=tag.resourceTypeAsString()==null?"ec2_resource":tag.resourceTypeAsString().replace('-','_');
            matched.put(tag.resourceId(),row("kind",type,"id",tag.resourceId(),"name",name,"region",regionName,"tags",safeSearchTags(tags),"run_id",tags.getOrDefault("lmaws_test",""),"match_field",tags.getOrDefault("Name","").equals(name)?"tag:Name":"tag:"+tag.key()));
            if(matched.size()>10000)throw new IllegalStateException("prefix search exceeds 10000 EC2 resources");
        }
        var groups=DescribeSecurityGroupsRequest.builder().filters(Filter.builder().name("group-name").values(prefix+"*").build()).build();
        for(var page:prefixPages(ec2().describeSecurityGroupsPaginator(groups)))for(var group:page.securityGroups()) {
            if(group.groupName()==null||!group.groupName().startsWith(prefix))continue;
            Map<String,String> tags=new LinkedHashMap<>();for(var tag:group.tags())tags.put(tag.key(),tag.value());
            matched.putIfAbsent(group.groupId(),row("kind","security_group","id",group.groupId(),"name",group.groupName(),"region",regionName,"tags",safeSearchTags(tags),"run_id",tags.getOrDefault("lmaws_test",""),"match_field","group_name"));
            if(matched.size()>10000)throw new IllegalStateException("prefix search exceeds 10000 EC2 resources");
        }
        return List.copyOf(matched.values());
    }

    private List<Map<String, String>> prefixEcsClusters(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : prefixPages(ecs().listClustersPaginator(ListClustersRequest.builder().build()))) {
            for (String arn : page.clusterArns()) {
                if(!last(arn).startsWith(prefix))continue;
                var described = ecs().describeClusters(DescribeClustersRequest.builder().clusters(arn).include(ClusterField.TAGS).build());
                if(!described.failures().isEmpty())throw new IllegalStateException("ECS cluster metadata unavailable; search incomplete");
                for (var cluster : described.clusters()) {
                    String name = cluster.clusterName();
                    Map<String, String> tags = new LinkedHashMap<>();
                    for (var tag : cluster.tags()) tags.put(tag.key(), tag.value());
                    boolean match = name != null && name.startsWith(prefix);
                    for (var tag : cluster.tags()) match |= tag.value() != null && tag.value().startsWith(prefix);
                    if (!match) continue;
                    checkedSearchAdd(rows,row("kind", "cluster", "id", cluster.clusterArn(), "name", name,
                            "region", regionName, "tagged", Boolean.toString(tags.containsKey("lmaws_test")),
                            "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
                }
            }
        }
        return bounded(rows);
    }

    private List<Map<String, String>> prefixBuckets(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : prefixPages(s3().listBucketsPaginator())) for (var bucket : page.buckets()) {
            if (bucket.name() == null || !bucket.name().startsWith(prefix)) continue;
            String bucketRegion=bucket.bucketRegion();
            if(bucketRegion==null||bucketRegion.isBlank()){String found=s3().getBucketLocation(x->x.bucket(bucket.name())).locationConstraintAsString();bucketRegion=found==null||found.isBlank()?"us-east-1":found.equals("EU")?"eu-west-1":found;}
            Map<String, String> tags = new LinkedHashMap<>();
            try { for (var tag : regionalBucket(bucketRegion).getBucketTagging(x -> x.bucket(bucket.name())).tagSet()) tags.put(tag.key(), tag.value()); }
            catch (S3Exception e) {String code=e.awsErrorDetails()==null?"":e.awsErrorDetails().errorCode();if("NoSuchBucket".equals(code))continue;if(!"NoSuchTagSet".equals(code))throw e;}
            checkedSearchAdd(rows,row("kind", "bucket", "id", bucket.name(), "name", bucket.name(), "region", bucketRegion,"arn","arn:aws:s3:::"+bucket.name(),
                    "created", bucket.creationDate() == null ? "" : bucket.creationDate().toString(),
                    "tagged", Boolean.toString(tags.containsKey("lmaws_test")), "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
        }
        return bounded(rows);
    }

    private List<Map<String, String>> prefixTopics(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : prefixPages(sns().listTopicsPaginator())) for (var topic : page.topics()) {
            String name = last(topic.topicArn()); if (!name.startsWith(prefix)) continue;
            Map<String, String> tags = new LinkedHashMap<>();
            for (var tag : sns().listTagsForResource(x -> x.resourceArn(topic.topicArn())).tags()) tags.put(tag.key(), tag.value());
            checkedSearchAdd(rows,row("kind", "topic", "id", topic.topicArn(), "name", name, "region", regionName,
                    "tagged", Boolean.toString(tags.containsKey("lmaws_test")), "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
        }
        return bounded(rows);
    }

    private List<Map<String, String>> prefixFunctions(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : prefixPages(lambda().listFunctionsPaginator())) for (var fn : page.functions()) {
            if (fn.functionName() == null || !fn.functionName().startsWith(prefix)) continue;
            Map<String, String> tags = new LinkedHashMap<>(lambda().listTags(x -> x.resource(fn.functionArn())).tags());
            checkedSearchAdd(rows,row("kind", "function", "id", fn.functionArn(), "name", fn.functionName(), "region", regionName,
                    "modified_at", normalizeModified(fn.lastModified()), "tagged", Boolean.toString(tags.containsKey("lmaws_test")),
                    "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
        }
        return bounded(rows);
    }
    List<Map<String,String>> serverlessInventory(String runId) {
        WebStack.requireRun(runId);
        if(demo)return List.of();
        List<Map<String,String>> rows=new ArrayList<>();
        for(var row:prefixFunctions("lmaws_"+runId+"_")){rows.add(row);if(runId.equals(row.get("run_id")))try{rows.add(lambdaUrlRecord(row.get("id"),runId));}catch(software.amazon.awssdk.services.lambda.model.ResourceNotFoundException ignored){}}
        rows.addAll(prefixQueues("lmaws_"+runId+"_"));
        for(var row:prefixTables("lmaws_"+runId+"_"))rows.add(row);
        for(var row:prefixLogGroups("lmaws_"))if(row.getOrDefault("name","").endsWith("_logs_"+runId))rows.add(row);
        for(var row:prefixBuckets("lmaws-"+runId+"-"))rows.add(row);
        String ruleName="lmaws_"+runId+"_rule"; try { var rule=events().describeRule(x->x.name(ruleName)); var tags=events().listTagsForResource(x->x.resourceARN(rule.arn())).tags();boolean owned=tags.stream().anyMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value())); rows.add(row("kind","event_rule","id",rule.arn(),"name",rule.name(),"region",regionName,"run_id",owned?runId:""));if(owned)for(var target:events().listTargetsByRule(x->x.rule(rule.name())).targets())rows.add(row("kind","event_target","id",target.id(),"name",rule.name(),"target",target.arn(),"region",regionName,"run_id",runId));} catch(software.amazon.awssdk.services.eventbridge.model.ResourceNotFoundException ignored) { }
        return List.copyOf(rows);
    }

    private List<Map<String, String>> prefixTables(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : prefixPages(ddb().listTablesPaginator())) for (String name : page.tableNames()) {
            if (!name.startsWith(prefix)) continue;
            var table = ddb().describeTable(x -> x.tableName(name)).table();
            Map<String, String> tags = new LinkedHashMap<>();
            if(table!=null&&table.tableArn()!=null){String token=null;int tagPages=0;do{if(++tagPages>100)throw new IllegalStateException("DynamoDB tag pagination exceeded limit");var tagResponse=ddb().listTagsOfResource(software.amazon.awssdk.services.dynamodb.model.ListTagsOfResourceRequest.builder().resourceArn(table.tableArn()).nextToken(token).build());for(var tag:tagResponse.tags())tags.put(tag.key(),tag.value());token=tagResponse.nextToken();}while(token!=null&&!token.isBlank());}
            checkedSearchAdd(rows,row("kind", "table", "id", name, "name", name, "region", regionName,
                    "created", table == null || table.creationDateTime() == null ? "" : table.creationDateTime().toString(),
                    "tagged", Boolean.toString(tags.containsKey("lmaws_test")), "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
        }
        return bounded(rows);
    }

    private List<Map<String, String>> prefixStacks(String prefix) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : prefixPages(cloudformation().describeStacksPaginator(DescribeStacksRequest.builder().build()))) {
            for (var stack : page.stacks()) {
                String name = stack.stackName();
                if (name == null || !name.startsWith(prefix)) continue;
                Map<String, String> tags = new LinkedHashMap<>();
                for (var tag : stack.tags()) tags.put(tag.key(), tag.value());
                checkedSearchAdd(rows,row("kind", "stack", "id", stack.stackId(), "name", name, "region", regionName,
                        "created", stack.creationTime() == null ? "" : stack.creationTime().toString(),
                        "status", stack.stackStatusAsString(), "tagged", Boolean.toString(tags.containsKey("lmaws_test")),
                        "tags", safeSearchTags(tags), "run_id", tags.getOrDefault("lmaws_test", "")));
            }
        }
        return bounded(rows);
    }

    private static String safeSearchTags(Map<String,String> tags){Map<String,String> safe=new LinkedHashMap<>();tags.forEach((key,value)->safe.put(key,key.toLowerCase(Locale.ROOT).matches(".*(password|passwd|secret|token|credential|api.?key|access.?key|private.?key).*")?"[redacted]":value));return Jsons.encode(safe);}
    private static <T> Iterable<T> prefixPages(Iterable<T> source){return ()->pages(source).iterator();}
    private static void checkedSearchAdd(List<Map<String,String>> rows,Map<String,String> row){if(rows.size()>=10000)throw new IllegalStateException("prefix search exceeds 10000 rows");rows.add(row);}
    private static String normalizeModified(String value){if(value==null)return "";try{return Instant.parse(value).toString();}catch(RuntimeException e){try{return java.time.OffsetDateTime.parse(value,java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ")).toInstant().toString();}catch(RuntimeException ignored){return value;}}}
    private static String serviceFor(String kind) {
        return switch (kind) {
            case "buckets" -> "s3"; case "instances", "vpcs", "security_groups" -> "ec2";
            case "tables" -> "dynamodb"; case "queues" -> "sqs"; case "topics" -> "sns";
            case "functions" -> "lambda"; case "log_groups" -> "logs"; case "alarms" -> "cloudwatch";
            case "zones" -> "route53"; case "secrets" -> "secretsmanager"; case "parameters" -> "ssm";
            case "clusters" -> "ecs"; case "stacks" -> "cloudformation"; default -> kind;
        };
    }

    private static String ageHours(String created) {
        if (created == null || created.isBlank()) return "";
        try { return String.format(Locale.ROOT, "%.3f", Math.max(0, Duration.between(Instant.parse(created), Instant.now()).toSeconds() / 3600.0)); }
        catch (RuntimeException ignored) { return ""; }
    }

    private static String maskIdentifier(String value) {
        if (value == null) return "";
        return value.replaceAll("(?<!\\d)\\d{12}(?!\\d)", "************");
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

    boolean fixtureEndpoint(){return endpoint!=null;}
    void emptyServerlessBucket(String bucket,String runId) {
        requireScenarioWrite();if(!owned("bucket",bucket,runId))throw new SecurityException("bucket ownership mismatch");
        for(var page:s3().listObjectsV2Paginator(x->x.bucket(bucket)))for(var object:page.contents())s3().deleteObject(x->x.bucket(bucket).key(object.key()));
    }
    Map<String,String> serverlessReport(String bucket,String table,String runId) {
        requireScenarioWrite();requireRunId(runId);requireName(bucket);requireName(table);
        if(demo)return row("bucket",bucket,"table",table,"latest_json_body","{\"ok\":true}","latest_html_body","<html>fixture</html>","table_items","2","run_id",runId);
        if(!owned("bucket",bucket,runId)||!owned("table",table,runId))throw new SecurityException("report resources are not owned by this run");
        var json=s3().getObjectAsBytes(software.amazon.awssdk.services.s3.model.GetObjectRequest.builder().bucket(bucket).key("latest.json").build()).asUtf8String();
        var html=s3().getObjectAsBytes(software.amazon.awssdk.services.s3.model.GetObjectRequest.builder().bucket(bucket).key("latest.html").build()).asUtf8String();
        long items=0;String token=null;do{var response=ddb().scan(software.amazon.awssdk.services.dynamodb.model.ScanRequest.builder().tableName(table).exclusiveStartKey(token==null?null:Map.of("pk",AttributeValue.builder().s(token).build())).select(software.amazon.awssdk.services.dynamodb.model.Select.COUNT).build());items+=response.count()==null?0:response.count();token=response.lastEvaluatedKey()==null?null:response.lastEvaluatedKey().getOrDefault("pk",AttributeValue.builder().s("").build()).s();}while(token!=null&&!token.isBlank());
        if(json.length()>65536||html.length()>65536)throw new IllegalStateException("report body exceeds bounded readback");
        return row("bucket",bucket,"table",table,"latest_json_body",json,"latest_html_body",html,"table_items",Long.toString(items),"run_id",runId);
    }
    private void requireScenarioWrite() {
        requireWriteEnabled();
        if(!demo && endpoint==null && (!"lmaws".equals(activeProfile()) || !"us-east-1".equals(regionName)))
            throw new SecurityException("scenario mutations require AWS_PROFILE=lmaws in us-east-1");
    }
    private void requireOwnedLambda(String arn,String runId) {
        requireRunId(runId);
        if(arn==null || !arn.matches("arn:aws:lambda:us-east-1:[0-9]{12}:function:lmaws[-_][A-Za-z0-9_-]{1,58}"))
            throw new SecurityException("Lambda ARN outside the scenario namespace");
        if(demo)return;
        var actual=lambda().getFunction(x->x.functionName(arn));
        if(actual.configuration()==null || !arn.equals(actual.configuration().functionArn()) || actual.tags()==null || !runId.equals(actual.tags().get("lmaws_test")))
            throw new SecurityException("Lambda provider ownership tag mismatch");
    }
    Map<String,String> lambdaUrlRecord(String arn,String runId) {
        requireScenarioWrite();requireOwnedLambda(arn,runId);var cfg=lambda().getFunctionUrlConfig(x->x.functionName(arn));return row("kind","function_url","id",arn,"url",cfg.functionUrl(),"auth",cfg.authTypeAsString(),"run_id",runId);
    }
    void deleteLambdaFunctionUrl(String arn,String runId) {
        requireScenarioWrite();if(demo)return;try{requireOwnedLambda(arn,runId);lambda().deleteFunctionUrlConfig(x->x.functionName(arn));}catch(software.amazon.awssdk.services.lambda.model.ResourceNotFoundException ignored){}
    }
    private String requireOwnedEvent(String name,String runId) {
        requireRunId(runId);requireName(name);
        if(!runId.equals(eventRuns.get(name))&&!name.startsWith("lmaws_"+runId+"_"))throw new SecurityException("EventBridge rule outside this run namespace");
        var rule=events().describeRule(x->x.name(name));String arn=rule.arn();
        if(arn==null || !arn.matches("arn:aws:events:us-east-1:[0-9]{12}:rule/lmaws[-_][A-Za-z0-9_-]+") || events().listTagsForResource(x->x.resourceARN(arn)).tags().stream().noneMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value())))
            throw new SecurityException("EventBridge provider ownership tag mismatch");
        return arn;
    }
    private static String eventPermissionId(String rule){return "lmaws-event-"+Integer.toUnsignedString(rule.hashCode(),16);}
    Map<String,String> createLambda(String name,String role,String runtime,String handler,String source,int memory,int timeout,String runId) {
        return createLambda(name,role,runtime,handler,source,memory,timeout,runId,"lmaws_"+name.substring("lmaws_".length())+"_logs_"+runId);
    }
    Map<String,String> createLambda(String name,String role,String runtime,String handler,String source,int memory,int timeout,String runId,String logGroup) {
        requireScenarioWrite();requireName(name);requireRunId(runId);
        requireLogGroupName(logGroup,runId);
        new LambdaFunction(name,role,runtime,handler,source,memory,timeout,runId);
        if(memory>512||timeout>30)throw new IllegalArgumentException("scenario Lambda caps: 512 MiB / 30 seconds");
        if(demo)return row("kind","lambda","id","arn:aws:lambda:local:000000000000:function:"+name,"name",name,"run_id",runId,"log_group",logGroup,"state","active");
        ensureLogGroup(logGroup,runId);
        String roleArn=role.startsWith("arn:")?role:"arn:aws:iam::"+sts().getCallerIdentity().account()+":role/"+role;
        byte[] zip=LambdaFunction.sourceZip(handler,source);
        var response=lambda().createFunction(x->x.functionName(name).role(roleArn).runtime(software.amazon.awssdk.services.lambda.model.Runtime.fromValue(runtime)).handler(handler).memorySize(memory).timeout(timeout).code(c->c.zipFile(SdkBytes.fromByteArray(zip))).loggingConfig(software.amazon.awssdk.services.lambda.model.LoggingConfig.builder().logFormat("JSON").logGroup(logGroup).build()).publish(true).tags(Map.of("lmaws_test",runId)));
        String arn=response.functionArn();lambdaRuns.put(arn,runId);
        return row("kind","lambda","id",arn,"name",name,"arn",arn,"run_id",runId,"log_group",logGroup,"state",response.stateAsString()==null?"Pending":response.stateAsString());
    }
    private void requireLogGroupName(String logGroup,String runId) {
        if(logGroup==null||!logGroup.matches("lmaws_[a-z0-9_-]{1,48}_logs_"+Pattern.quote(runId))) throw new SecurityException("Lambda log group must be lmaws_<slug>_logs_<run>");
    }
    private void ensureLogGroup(String logGroup,String runId) {
        try {
            var groups=logs().describeLogGroups(x->x.logGroupNamePrefix(logGroup)).logGroups();
            var existing=groups.stream().filter(g->logGroup.equals(g.logGroupName())).findFirst();
            if(existing.isPresent()) {
                var tags=logs().listTagsLogGroup(x->x.logGroupName(logGroup)).tags();
                if(!runId.equals(tags.get("lmaws_test"))) throw new SecurityException("Lambda log group exists without this run tag");
                return;
            }
            logs().createLogGroup(x->x.logGroupName(logGroup).tags(Map.of("lmaws_test",runId)));
        } catch (software.amazon.awssdk.services.cloudwatchlogs.model.ResourceAlreadyExistsException e) {
            var tags=logs().listTagsLogGroup(x->x.logGroupName(logGroup)).tags();
            if(!runId.equals(tags.get("lmaws_test"))) throw new SecurityException("Lambda log group race has foreign ownership");
        }
    }
    /** Repairs only an empty-tag group recreated by final Lambda log delivery after our acknowledged teardown. */
    void reconcileRuntimeLogGroup(String logGroup,String runId,Instant earliest,Instant latest,boolean creationReceipt){
        reconcileRuntimeLogGroup(logGroup,runId,earliest,latest,creationReceipt,stage->{});
    }
    void reconcileRuntimeLogGroup(String logGroup,String runId,Instant earliest,Instant latest,boolean creationReceipt,java.util.function.Consumer<String> checkpoint){
        requireScenarioWrite();requireLogGroupName(logGroup,runId);requireRunId(runId);
        if(demo)return;
        if(endpoint==null)try{long delay=latest==null?12000:Math.max(0,12000-java.time.Duration.between(latest,Instant.now()).toMillis());if(delay>0)Thread.sleep(delay);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException("log drain interrupted");}
        String fn="lmaws_"+runId+"_fn";
        try{lambda().getFunction(x->x.functionName(fn));throw new SecurityException("log drain requires an absent run function");}catch(software.amazon.awssdk.services.lambda.model.ResourceNotFoundException absent){}
        checkpoint.accept("function_absent_and_drain_complete");
        var groups=logs().describeLogGroups(x->x.logGroupNamePrefix(logGroup)).logGroups();
        var found=groups.stream().filter(g->logGroup.equals(g.logGroupName())).findFirst();if(found.isEmpty()){checkpoint.accept("already_absent");return;}
        Map<String,String> tags;
        try{tags=logs().listTagsLogGroup(x->x.logGroupName(logGroup)).tags();}catch(software.amazon.awssdk.services.cloudwatchlogs.model.ResourceNotFoundException absent){return;}
        if(!runId.equals(tags.get("lmaws_test"))){
            long created=found.get().creationTime()==null?0:found.get().creationTime();
            if(!creationReceipt||!tags.isEmpty()||earliest==null||latest==null||created<earliest.toEpochMilli()||created>latest.plusSeconds(900).toEpochMilli())throw new SecurityException("untagged log group lacks a matching creation/deletion receipt");
            checkpoint.accept("empty_tags_match_private_creation_receipt");
            logs().tagLogGroup(x->x.logGroupName(logGroup).tags(Map.of("lmaws_test",runId)));checkpoint.accept("run_tag_restored");
        }
        deleteLambdaLogGroup(logGroup,runId);checkpoint.accept("deleted");
    }
    void deleteLambdaLogGroup(String logGroup,String runId) {
        if(logGroup==null||logGroup.isBlank())return;
        requireLogGroupName(logGroup,runId);
        if(demo)return;
        Map<String,String> tags;try{tags=logs().listTagsLogGroup(x->x.logGroupName(logGroup)).tags();}catch(software.amazon.awssdk.services.cloudwatchlogs.model.ResourceNotFoundException absent){return;}
        if(!runId.equals(tags.get("lmaws_test"))) throw new SecurityException("refusing foreign Lambda log group");
        try{logs().deleteLogGroup(x->x.logGroupName(logGroup));}catch(software.amazon.awssdk.services.cloudwatchlogs.model.ResourceNotFoundException ignored){}
    }
    Map<String,String> waitLambdaActive(String arn,String runId,int seconds) {
        if(seconds<1||seconds>120)throw new IllegalArgumentException("Lambda Active wait must be 1..120 seconds");
        requireScenarioWrite();requireOwnedLambda(arn,runId);
        if(demo)return row("kind","lambda","state","Active","run_id",runId);
        long deadline=System.nanoTime()+Duration.ofSeconds(seconds).toNanos();
        while(System.nanoTime()<deadline) {
            var result=lambda().getFunctionConfiguration(r->r.functionName(arn));
            if("Active".equals(result.stateAsString()))return row("kind","lambda","state","Active","run_id",runId);
            if("Failed".equals(result.stateAsString()))throw new IllegalStateException("Lambda creation entered Failed state");
            long remaining=deadline-System.nanoTime();if(remaining<=0)break;
            try{Thread.sleep(Math.min(1000,Math.max(1,remaining/1000000)));}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("Lambda Active wait interrupted");}
        }
        throw new IllegalStateException("Lambda did not become Active within the bounded wait");
    }
    Map<String,String> invokeLambda(String arn,String payload) {
        requireScenarioWrite();
        if(payload==null||payload.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>262144)throw new IllegalArgumentException("Lambda payload exceeds 256 KiB");
        if(demo)return row("status","200","function_name",arn,"request_id","fake-invoke","payload",payload,"cold_start","false");
        String run=lambdaRuns.get(arn);if(run==null)throw new SecurityException("Lambda not created by this host");requireOwnedLambda(arn,run);
        var response=lambda().invoke(x->x.functionName(arn).payload(SdkBytes.fromUtf8String(payload)).invocationType("RequestResponse"));
        if(response.functionError()!=null)throw new IllegalStateException("Lambda invocation returned a function error");
        return row("status",Integer.toString(response.statusCode()),"function_name",arn,"request_id",response.executedVersion()==null?"":response.executedVersion(),"payload",response.payload()==null?"":response.payload().asUtf8String());
    }
    QueueWorker createEventSourceMapping(String queueUrl,String lambdaArn,int batchSize,String runId) {
        requireScenarioWrite(); requireRunId(runId);
        requireName(last(queueUrl));
        if(!demo&&!queueUrl.matches("https://sqs\\.us-east-1\\.amazonaws\\.com/[0-9]{12}/lmaws[_-][A-Za-z0-9_-]+"))throw new SecurityException("queue URL outside the scenario region and namespace");
        if(lambdaArn==null||!lambdaArn.matches("arn:aws:lambda:(?:us-east-1|local):[0-9]{12}:function:lmaws[_-][A-Za-z0-9_-]+"))throw new SecurityException("worker function ARN outside namespace");
        if(batchSize<1||batchSize>10) throw new IllegalArgumentException("SQS Lambda batch size must be 1..10 without a batching window");
        if(!demo) {
            if(!owned("queue",queueUrl,runId)) throw new SecurityException("SQS source queue ownership mismatch");
            requireOwnedLambda(lambdaArn,runId);
            String queueArn=sqs().getQueueAttributes(GetQueueAttributesRequest.builder().queueUrl(queueUrl).attributeNames(QueueAttributeName.QUEUE_ARN).build()).attributesAsStrings().get("QueueArn");
            if(queueArn==null||!queueArn.matches("arn:aws:sqs:us-east-1:[0-9]{12}:lmaws[_-][A-Za-z0-9_-]+")) throw new SecurityException("SQS source is outside the scenario namespace");
            var response=lambda().createEventSourceMapping(CreateEventSourceMappingRequest.builder().eventSourceArn(queueArn).functionName(lambdaArn).batchSize(batchSize).enabled(true).tags(Map.of("lmaws_test",runId)).functionResponseTypes(FunctionResponseType.REPORT_BATCH_ITEM_FAILURES).build());
            String arn=response.eventSourceMappingArn();
            mappingRuns.put(arn,runId);
            return new QueueWorker(this,arn,runId);
        }
        String arn="arn:aws:lambda:local:000000000000:event-source-mapping:lmaws-"+runId+"-"+Integer.toUnsignedString((queueUrl+lambdaArn).hashCode(),16);
        mappingRuns.put(arn,runId); return new QueueWorker(this,arn,runId);
    }
    /**
     * Compensating host guard for EsmTag: AWS Lambda has no CreateAction condition key for
     * event-source-mapping, so the lmaws host forbids standalone lambda:TagResource on
     * event-source-mapping ARNs and only tags mappings atomically inside CreateEventSourceMapping.
     */
    static void requireNoStandaloneEsmTag(String resourceArn) {
        if(resourceArn!=null&&resourceArn.contains(":event-source-mapping:")) {
            throw new SecurityException("refusing standalone lambda:TagResource on event-source-mapping ARN; mappings may only be tagged at creation inside CreateEventSourceMapping");
        }
    }
    Map<String,String> eventSourceMappingStatus(String arn,String runId) {
        requireRunId(runId); if(mappingRuns.containsKey(arn)&&!runId.equals(mappingRuns.get(arn))) throw new SecurityException("event source mapping ownership mismatch");
        if(demo)return row("kind","sqs_event_source_mapping","id",arn,"state","Enabled","run_id",runId);
        if(!arn.matches("arn:aws:lambda:us-east-1:[0-9]{12}:event-source-mapping:[A-Za-z0-9-]{8,128}")) throw new SecurityException("event source mapping ARN outside the scenario namespace");
        var m=lambda().getEventSourceMapping(x->x.uuid(arn.substring(arn.lastIndexOf(':')+1)));
        if(m.eventSourceMappingArn()==null||!arn.equals(m.eventSourceMappingArn())) throw new SecurityException("event source mapping identity mismatch");
        // Compensating guard for EsmTag/EsmOwn: verify runId tag on the mapping AND on the lmaws_* SQS queue AND on the lmaws_* Lambda function.
        var tags=lambda().listTags(x->x.resource(arn)).tags(); if(!runId.equals(tags.get("lmaws_test"))) throw new SecurityException("event source mapping ownership tag mismatch");
        if(m.eventSourceArn()==null||!m.eventSourceArn().matches("arn:aws:sqs:us-east-1:[0-9]{12}:lmaws[_-][A-Za-z0-9_-]+")) throw new SecurityException("event source queue outside scenario namespace");
        if(m.functionArn()==null||!m.functionArn().matches("arn:aws:lambda:us-east-1:[0-9]{12}:function:lmaws[-_][A-Za-z0-9_-]{1,58}")) throw new SecurityException("event source function outside scenario namespace");
        String queueUrl=sqs().getQueueUrl(x->x.queueName(last(m.eventSourceArn()))).queueUrl();
        if(!owned("queue",queueUrl,runId)) throw new SecurityException("event source queue ownership tag mismatch");
        requireOwnedLambda(m.functionArn(),runId);
        return row("kind","sqs_event_source_mapping","id",arn,"state",m.state(),"source",m.eventSourceArn(),"function",m.functionArn(),"run_id",runId);
    }
    QueueWorker resumeEventSourceMapping(String arn,String runId) { eventSourceMappingStatus(arn,runId); mappingRuns.put(arn,runId); return new QueueWorker(this,arn,runId); }
    void waitEventSourceMappingEnabled(String arn,String runId,int maxSeconds) {
        if(maxSeconds<1||maxSeconds>120)throw new IllegalArgumentException("event source mapping wait must be 1..120 seconds");
        if(demo)return;
        long deadline=System.nanoTime()+Duration.ofSeconds(maxSeconds).toNanos();
        for(;;){
            String state=eventSourceMappingStatus(arn,runId).getOrDefault("state","");
            if("Enabled".equalsIgnoreCase(state))return;
            if("Failed".equalsIgnoreCase(state)||"UpdateFailed".equalsIgnoreCase(state))throw new IllegalStateException("SQS Lambda event source mapping entered "+state);
            if(System.nanoTime()>=deadline)throw new IllegalStateException("SQS Lambda event source mapping did not become Enabled within "+maxSeconds+" seconds");
            sleepReady();
        }
    }
    List<Map<String,String>> findEventSourceMappings(String runId) {
        requireRunId(runId); List<Map<String,String>> out=new ArrayList<>();
        if(demo){ for(String arn:mappingRuns.keySet()) if(runId.equals(mappingRuns.get(arn))) out.add(row("kind","sqs_event_source_mapping","id",arn,"run_id",runId)); return out; }
        int seen=0; for(var page:lambda().listEventSourceMappingsPaginator(x->x.functionName("lmaws_"+runId+"_worker"))) for(var m:page.eventSourceMappings()) {
            if(++seen>1000) throw new IllegalStateException("event source mapping inventory exceeded 1000 items");
            String arn=m.eventSourceMappingArn(); if(arn==null||!arn.matches("arn:aws:lambda:us-east-1:[0-9]{12}:event-source-mapping:[A-Za-z0-9-]{8,128}")) continue;
            var tags=lambda().listTags(x->x.resource(arn)).tags();
            boolean owned=runId.equals(tags.get("lmaws_test"));
            out.add(row("kind","sqs_event_source_mapping","id",arn,"state",m.state(),"source",m.eventSourceArn()==null?"":m.eventSourceArn(),"function",m.functionArn()==null?"":m.functionArn(),"owned",Boolean.toString(owned),"run_id",owned?runId:""));
        }
        return out;
    }
    Map<String,String> deleteEventSourceMapping(String arn,String runId) {
        requireScenarioWrite(); requireRunId(runId); try { eventSourceMappingStatus(arn,runId); } catch(ResourceNotFoundException absent) { mappingRuns.remove(arn); return row("kind","sqs_event_source_mapping","id",arn,"state","deleted","run_id",runId); }
        if(!demo) {
            String uuid=arn.substring(arn.lastIndexOf(':')+1);
            String state=eventSourceMappingStatus(arn,runId).getOrDefault("state","");
            if(!"Deleting".equalsIgnoreCase(state))try { lambda().deleteEventSourceMapping(x->x.uuid(uuid)); } catch(ResourceNotFoundException ignored) { mappingRuns.remove(arn); return row("kind","sqs_event_source_mapping","id",arn,"state","deleted","run_id",runId); }
            long deadline=System.nanoTime()+Duration.ofSeconds(120).toNanos();
            while(System.nanoTime()<deadline) { try { lambda().getEventSourceMapping(x->x.uuid(arn.substring(arn.lastIndexOf(':')+1))); sleepReady(); } catch(ResourceNotFoundException gone) { mappingRuns.remove(arn); return row("kind","sqs_event_source_mapping","id",arn,"state","deleted","run_id",runId); } }
            throw new IllegalStateException("SQS Lambda event source mapping did not disappear within 120 seconds");
        }
        mappingRuns.remove(arn); return row("kind","sqs_event_source_mapping","id",arn,"state","deleted","run_id",runId);
    }
    Map<String,String> setSqsRedrive(String sourceUrl,String dlqUrl,String runId) {
        requireScenarioWrite(); requireRunId(runId); requireName(last(sourceUrl));requireName(last(dlqUrl)); if(sourceUrl.equals(dlqUrl)) throw new IllegalArgumentException("DLQ must differ from source queue");
        if(!demo) {
            if(!owned("queue",sourceUrl,runId)||!owned("queue",dlqUrl,runId)) throw new SecurityException("SQS redrive queue ownership mismatch");
            String arn=sqs().getQueueAttributes(GetQueueAttributesRequest.builder().queueUrl(dlqUrl).attributeNames(QueueAttributeName.QUEUE_ARN).build()).attributesAsStrings().get("QueueArn");
            String policy=Jsons.encode(Map.of("deadLetterTargetArn",arn,"maxReceiveCount","3"));
            sqs().setQueueAttributes(x->x.queueUrl(sourceUrl).attributes(Map.of(QueueAttributeName.REDRIVE_POLICY,policy)));
        }
        return row("kind","sqs_redrive","source",sourceUrl,"dlq",dlqUrl,"max_receive_count","3","run_id",runId,"state","active");
    }
    Map<String,String> clearSqsRedrive(String sourceUrl,String runId) {
        requireScenarioWrite(); requireRunId(runId); requireName(last(sourceUrl)); if(!demo) { if(!owned("queue",sourceUrl,runId)) throw new SecurityException("SQS source queue ownership mismatch"); sqs().setQueueAttributes(x->x.queueUrl(sourceUrl).attributes(Map.of(QueueAttributeName.REDRIVE_POLICY,"{}"))); }
        return row("kind","sqs_redrive","source",sourceUrl,"state","cleared","run_id",runId);
    }
    String lambdaUrl(String arn,String reason) {
        requireScenarioWrite();
        if(reason==null||reason.isBlank()||reason.length()>256)throw new IllegalArgumentException("public Function URL auth NONE requires a bounded explicit reason");
        if(demo)return "https://"+last(arn)+".lambda-url.local/";
        String run=lambdaRuns.get(arn);if(run==null)throw new SecurityException("Lambda not created by this host");requireOwnedLambda(arn,run);
        var config=lambda().createFunctionUrlConfig(x->x.functionName(arn).authType("NONE"));
        lambda().addPermission(x->x.functionName(arn).statementId("lmaws-url").action("lambda:InvokeFunctionUrl").principal("*").functionUrlAuthType("NONE"));
        lambda().addPermission(x->x.functionName(arn).statementId("lmaws-invoke-url").action("lambda:InvokeFunction").principal("*").invokedViaFunctionUrl(true));
        return config.functionUrl();
    }
    void requireLambdaUrlOwned(String functionName,String expectedUrl,String runId) {
        requireRunId(runId);requireName(functionName);
        if(expectedUrl==null||expectedUrl.isBlank())throw new IllegalArgumentException("Lambda URL required");
        if(demo){if(!expectedUrl.matches("https://"+java.util.regex.Pattern.quote(functionName)+"\\.lambda-url\\.local/?"))throw new SecurityException("fixture Lambda URL mismatch");return;}
        var fn=lambda().getFunction(x->x.functionName(functionName));
        if(fn.configuration()==null)throw new SecurityException("missing Lambda configuration");requireOwnedLambda(fn.configuration().functionArn(),runId);
        var cfg=lambda().getFunctionUrlConfig(x->x.functionName(functionName));
        if(!"NONE".equals(cfg.authTypeAsString())||!expectedUrl.equals(cfg.functionUrl()))throw new SecurityException("Lambda URL does not match owned NONE-auth configuration");
    }
    Map<String,String> putEventRule(String name,String schedule,String runId) {
        requireScenarioWrite();requireName(name);requireRunId(runId);new EventRule(name,schedule,runId);
        if(demo)return row("kind","event_rule","name",name,"id","arn:aws:events:local:rule/"+name,"run_id",runId,"state","active");
        try{events().describeRule(x->x.name(name));throw new SecurityException("refusing existing EventBridge rule");}catch(software.amazon.awssdk.services.eventbridge.model.ResourceNotFoundException absent){}
        var out=events().putRule(x->x.name(name).scheduleExpression(schedule).state("ENABLED").tags(software.amazon.awssdk.services.eventbridge.model.Tag.builder().key("lmaws_test").value(runId).build()));eventRuns.put(name,runId);
        return row("kind","event_rule","name",name,"id",out.ruleArn(),"arn",out.ruleArn(),"run_id",runId,"state","active");
    }
    Map<String,String> putEventTarget(String rule,String lambdaArn,String runId) {
        requireScenarioWrite();requireRunId(runId);
        if(demo)return row("kind","event_target","rule",rule,"target",lambdaArn,"state","active");
        String ruleArn=requireOwnedEvent(rule,runId);requireOwnedLambda(lambdaArn,runId);
        lambda().addPermission(x->x.functionName(lambdaArn).statementId(eventPermissionId(rule)).action("lambda:InvokeFunction").principal("events.amazonaws.com").sourceArn(ruleArn).sourceAccount(lambdaArn.split(":")[4]));
        var response=events().putTargets(x->x.rule(rule).targets(software.amazon.awssdk.services.eventbridge.model.Target.builder().id("lmaws-target").arn(lambdaArn).build()));
        if(response.failedEntryCount()!=null&&response.failedEntryCount()>0)throw new IllegalStateException("EventBridge target rejected");
        return row("kind","event_target","rule",rule,"target",lambdaArn,"state","active");
    }
    Map<String,String> deleteEventRule(String name,String runId) {
        requireScenarioWrite();
        if(!demo){requireOwnedEvent(name,runId);var result=events().removeTargets(x->x.rule(name).ids("lmaws-target"));if(result.failedEntryCount()!=null&&result.failedEntryCount()>0)throw new IllegalStateException("EventBridge target removal rejected");events().deleteRule(x->x.name(name));eventRuns.remove(name);}
        return row("kind","event_rule","name",name,"state","deleted","run_id",runId);
    }
    void deleteOwnedWorker(String name,String runId) {
        requireScenarioWrite();requireName(name);requireRunId(runId);
        if(!name.equals("lmaws_"+runId+"_worker"))throw new SecurityException("worker name outside run");
        if(demo)return;
        try{var found=lambda().getFunction(x->x.functionName(name));String arn=found.configuration().functionArn();requireOwnedLambda(arn,runId);deleteLambda(arn,runId);}
        catch(ResourceNotFoundException absent){}
    }
    Map<String,String> deleteLambda(String arn,String runId) {
        requireScenarioWrite();if(!demo){try{requireOwnedLambda(arn,runId);lambda().deleteFunction(x->x.functionName(arn));}catch(software.amazon.awssdk.services.lambda.model.ResourceNotFoundException absent){}lambdaRuns.remove(arn);}
        return row("kind","lambda","id",arn,"state","deleted","run_id",runId);
    }
    Map<String,String> tableTtl(String table,String attribute,String runId) {
        requireScenarioWrite();requireName(table);requireRunId(runId);
        if(attribute==null||!attribute.matches("[A-Za-z0-9_-]{1,255}"))throw new IllegalArgumentException("invalid TTL attribute");
        if(!demo){if(!owned("table",table,runId))throw new SecurityException("table ownership mismatch");ddb().updateTimeToLive(x->x.tableName(table).timeToLiveSpecification(t->t.attributeName(attribute).enabled(true)));}
        return row("kind","dynamodb_ttl","table",table,"attribute",attribute,"enabled","true");
    }
    Map<String,String> tableItem(String table,String key,String value,String runId) {
        requireScenarioWrite();requireName(table);requireRunId(runId);
        if(key==null||key.isBlank()||key.length()>1024||value==null||value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>65536)throw new IllegalArgumentException("bounded item key/value required");
        if(!demo){if(!owned("table",table,runId))throw new SecurityException("table ownership mismatch");ddb().putItem(x->x.tableName(table).item(Map.of("pk",AttributeValue.builder().s(key).build(),"value",AttributeValue.builder().s(value).build())));}
        return row("kind","dynamodb_item","table",table,"pk",key,"value",value);
    }
    Map<String,String> s3Notification(String bucket,String lambdaArn,String eventName,String runId) {
        requireScenarioWrite();requireName(bucket);requireRunId(runId);
        if(eventName==null||!eventName.matches("s3:ObjectCreated:(Put|Post|Copy|CompleteMultipartUpload|\\*)"))throw new IllegalArgumentException("unsupported notification event");
        if(!demo){
            if(!owned("bucket",bucket,runId))throw new SecurityException("bucket ownership mismatch");requireOwnedLambda(lambdaArn,runId);
            var prior=s3().getBucketNotificationConfiguration(x->x.bucket(bucket));
            if(!prior.lambdaFunctionConfigurations().isEmpty()||!prior.topicConfigurations().isEmpty()||!prior.queueConfigurations().isEmpty()||prior.eventBridgeConfiguration()!=null)throw new SecurityException("refusing to replace existing bucket notifications");
            lambda().addPermission(x->x.functionName(lambdaArn).statementId("lmaws-s3-"+Integer.toUnsignedString(bucket.hashCode(),16)).action("lambda:InvokeFunction").principal("s3.amazonaws.com").sourceArn("arn:aws:s3:::"+bucket).sourceAccount(lambdaArn.split(":")[4]));
            s3().putBucketNotificationConfiguration(x->x.bucket(bucket).notificationConfiguration(NotificationConfiguration.builder().lambdaFunctionConfigurations(LambdaFunctionConfiguration.builder().id("lmaws-"+runId).lambdaFunctionArn(lambdaArn).events(Event.fromValue(eventName)).build()).build()));
        }
        return row("kind","s3_notification","bucket",bucket,"lambda_arn",lambdaArn,"event",eventName,"state","active");
    }

    /** Issue a bounded SigV4 PUT URL for an object in a run-owned bucket. */
    Map<String,String> s3PresignPut(String bucket,String key,long size,String contentType,int expiry,String runId) {
        requireScenarioWrite(); requireRunId(runId); requireName(bucket); requireObjectKey(key);
        if (!bucket.matches("lmaws-[a-z0-9-]{1,48}")) throw new IllegalArgumentException("presigned upload bucket must use lmaws- prefix");
        if (size < 1 || size > 10L * 1024L * 1024L) throw new IllegalArgumentException("presigned upload size must be 1..10485760 bytes");
        if (expiry < 1 || expiry > 900) throw new IllegalArgumentException("presigned upload expiry must be 1..900 seconds");
        if (contentType == null || !contentType.matches("image/(?:png|jpeg|webp|gif)")) throw new IllegalArgumentException("content type must be a supported image type");
        if (demo) return row("kind","s3_presigned_put","bucket",bucket,"key",key,"url","https://"+bucket+".s3.local/"+key,"expires_in",Integer.toString(expiry),"content_length",Long.toString(size),"content_type",contentType,"run_id",runId,"signed","true");
        if (!owned("bucket",bucket,runId)) throw new SecurityException("bucket ownership mismatch");
        var request = software.amazon.awssdk.services.s3.model.PutObjectRequest.builder().bucket(bucket).key(key).contentLength(size).contentType(contentType).build();
        var signerBuilder = S3Presigner.builder().region(region);
        if (endpoint != null) signerBuilder.endpointOverride(endpoint).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")));
        else signerBuilder.credentialsProvider(ProfileCredentialsProvider.builder().profileName(profileName).build());
        try (S3Presigner signer = register(signerBuilder.build())) {
            PresignedPutObjectRequest signed = signer.presignPutObject(x -> x.signatureDuration(Duration.ofSeconds(expiry)).putObjectRequest(request));
            return row("kind","s3_presigned_put","bucket",bucket,"key",key,"url",signed.url().toString(),"expires_in",Integer.toString(expiry),"content_length",Long.toString(size),"content_type",contentType,"run_id",runId,"signed","true");
        }
    }

    Map<String,String> tableItemConditional(String table,String key,String value,String condition,String runId) {
        requireScenarioWrite(); requireName(table); requireRunId(runId);
        if (condition == null || !(condition.equals("attribute_not_exists(pk)") || condition.equals("attribute_exists(pk)"))) throw new IllegalArgumentException("condition must be attribute_exists(pk) or attribute_not_exists(pk)");
        if (key == null || key.isBlank() || key.length() > 1024 || value == null || value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 65536) throw new IllegalArgumentException("bounded item key/value required");
        if (!demo) { if (!owned("table",table,runId)) throw new SecurityException("table ownership mismatch"); ddb().putItem(x -> x.tableName(table).item(Map.of("pk",AttributeValue.builder().s(key).build(),"value",AttributeValue.builder().s(value).build())).conditionExpression(condition)); }
        return row("kind","dynamodb_item_conditional","table",table,"pk",key,"condition",condition,"value",value,"run_id",runId);
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
        if ("bucket".equals(k)) {
            // Web stacks use the exact lmaws-site-<run> bucket; upload-only
            // stacks retain the legacy lmaws-<run>-<suffix> shape. Both still
            // require the authoritative lmaws_test tag below.
            if (!n.equals("lmaws-site-" + runId) && !n.startsWith("lmaws-" + runId + "-")) return false;
        } else if (!n.startsWith("lmaws_" + runId + "_")) return false;
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

    AwsBackend defaultReader(){return new AwsBackend(regionName,demo,cost,"default");}
    boolean sameAccount(AwsBackend other){if(demo||endpoint!=null)return true;String left=sts().getCallerIdentity().account(),right=other.sts().getCallerIdentity().account();return left!=null&&left.matches("[0-9]{12}")&&left.equals(right);}
    @Override public void close() { for (AutoCloseable c : clients) try { c.close(); } catch (Exception ignored) { } }

    private StsClient sts() { return sts == null ? sts = register(base(StsClient.builder()).build()) : sts; }
    private S3Client s3() { if (s3 == null) { var b = S3Client.builder(); if (endpoint != null) b.forcePathStyle(true); s3 = register(base(b).build()); } return s3; }
    private S3Client regionalBucket(String selected){if(endpoint!=null||selected.equals(regionName))return s3();return regionalBuckets.computeIfAbsent(selected,r->register(base(S3Client.builder()).region(Region.of(r)).build()));}
    private SqsClient sqs() { return sqs == null ? sqs = register(base(SqsClient.builder()).build()) : sqs; }
    private SnsClient sns() { return sns == null ? sns = register(base(SnsClient.builder()).build()) : sns; }
    private SsmClient ssm() { return ssm == null ? ssm = register(base(SsmClient.builder()).build()) : ssm; }
    private DynamoDbClient ddb() { return ddb == null ? ddb = register(base(DynamoDbClient.builder()).build()) : ddb; }
    private CloudWatchLogsClient logs() { return logs == null ? logs = register(base(CloudWatchLogsClient.builder()).build()) : logs; }
    private CloudWatchClient cloudwatch() { return cloudwatch == null ? cloudwatch = register(base(CloudWatchClient.builder()).build()) : cloudwatch; }
    private Ec2Client ec2() { return ec2 == null ? ec2 = register(base(Ec2Client.builder()).build()) : ec2; }
    private LambdaClient lambda() { return lambda == null ? lambda = register(base(LambdaClient.builder()).build()) : lambda; }
    private EventBridgeClient events() { return events == null ? events = register(base(EventBridgeClient.builder()).build()) : events; }
    private Route53Client route53() { return route53 == null ? route53 = register(base(Route53Client.builder()).build()) : route53; }
    private SecretsManagerClient secrets() { return secrets == null ? secrets = register(base(SecretsManagerClient.builder()).build()) : secrets; }
    private EcsClient ecs() { return ecs == null ? ecs = register(base(EcsClient.builder()).build()) : ecs; }
    private IamClient iam() {
        if (iam == null) {
            var b = base(IamClient.builder());
            if (endpoint == null) b.region(Region.AWS_GLOBAL);
            iam = register(b.build());
        }
        return iam;
    }
    private CloudFormationClient cloudformation() { return cloudformation == null ? cloudformation = register(base(CloudFormationClient.builder()).build()) : cloudformation; }
    private <T extends software.amazon.awssdk.awscore.client.builder.AwsClientBuilder<?, ?>> T base(T b) { b.region(region).overrideConfiguration(config); ((software.amazon.awssdk.awscore.client.builder.AwsSyncClientBuilder<?, ?>) b).httpClientBuilder(UrlConnectionHttpClient.builder()); if (endpoint != null) b.endpointOverride(endpoint).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"))); else b.credentialsProvider(ProfileCredentialsProvider.builder().profileName(profileName).build()); return b; }

    <B extends software.amazon.awssdk.awscore.client.builder.AwsClientBuilder<?, ?>> B webBuilder(B builder) { return base(builder); }
    private static final class CostInterceptor implements ExecutionInterceptor {
        private final CostLedger ledger;
        CostInterceptor(CostLedger ledger) { this.ledger = ledger; }
        @Override public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes attributes) {
            String service = attributes.getOptionalAttribute(SdkExecutionAttribute.SERVICE_NAME).orElse("aws");
            String operation = attributes.getOptionalAttribute(SdkExecutionAttribute.OPERATION_NAME).orElse("request");
            ledger.request(service, operation);
        }
        @Override public void onExecutionFailure(Context.FailedExecution context, ExecutionAttributes attributes) {
            Throwable ex = context.exception();
            if (ex instanceof software.amazon.awssdk.awscore.exception.AwsServiceException aws) {
                int status = aws.statusCode();
                String code = aws.awsErrorDetails() != null && aws.awsErrorDetails().errorCode() != null
                    ? aws.awsErrorDetails().errorCode()
                    : "";
                String msg = aws.awsErrorDetails() != null && aws.awsErrorDetails().errorMessage() != null
                    ? aws.awsErrorDetails().errorMessage()
                    : aws.getMessage();
                String lowerCode = code.toLowerCase(Locale.ROOT);
                String lowerMsg = msg == null ? "" : msg.toLowerCase(Locale.ROOT);
                if (status == 403
                        || lowerCode.contains("accessdenied")
                        || lowerCode.contains("unauthorized")
                        || lowerMsg.contains("not authorized to perform")
                        || lowerMsg.contains("access denied")) {
                    String service = attributes.getOptionalAttribute(SdkExecutionAttribute.SERVICE_NAME).orElse("aws");
                    String operation = attributes.getOptionalAttribute(SdkExecutionAttribute.OPERATION_NAME).orElse("request");
                    ledger.recordAccessDenied(service, operation, code.isEmpty() ? "AccessDenied" : code, status, msg);
                }
            }
        }
    }
    private <T extends AutoCloseable> T register(T c) { clients.add(c); return c; }

    private Map<String, String> identity() { var i = sts().getCallerIdentity(GetCallerIdentityRequest.builder().build()); Jsons.knownAccount(i.account()); return row("kind", "identity", "id", safeId(i.account()), "name", safeId(i.arn())); }
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

    /** Real mutations require the explicitly provisioned lmaws profile. */
    private void requireWriteEnabled() {
        if ("admin".equals(activeProfile())) {
            throw new IllegalStateException("The 'admin' profile is reserved exclusively for lmaws_ IAM policy grants; refusing regular resource mutation");
        }
        if (demo || endpoint != null) return;
        IamPolicies.checkMutationGuard(false, activeProfile(), isLiveEnabled(), false, false, null);
    }

    /** Profiles provisioned for owned writes; every other profile is read-only to lmaws. */
    static final List<String> MUTATING_PROFILES = List.of("lmaws", "lmaws-ec2");

    /** EC2 compute writes: the same profile gate, and us-east-1 only (prices and policy are regional). */
    void requireComputeWriteEnabled() {
        requireWriteEnabled();
        if (!demo && endpoint == null && !"us-east-1".equals(regionName))
            throw new IllegalStateException("live spot sandboxes require us-east-1 (active region: " + regionName + ")");
    }

    private void requireIamPolicyWriteEnabled(String policyName) {
        boolean liveOrEndpoint = demo || endpoint != null || isLiveEnabled();
        IamPolicies.checkMutationGuard(
            true,
            activeProfile(),
            liveOrEndpoint,
            "1".equals(System.getenv("LMAWS_ADMIN_GRANT")),
            isApplyEnabled(),
            policyName
        );
    }

    public static boolean isLiveEnabled() {
        if (Boolean.getBoolean("lmaws.dryRun")) return false;
        return Boolean.getBoolean("lmaws.live") || "1".equals(System.getenv("LMAWS_LIVE"));
    }

    public static boolean isApplyEnabled() {
        if (Boolean.getBoolean("lmaws.dryRun")) return false;
        return Boolean.getBoolean("lmaws.apply") || "1".equals(System.getenv("LMAWS_APPLY"));
    }

    public static String activeProfile() {
        String prop = System.getProperty("lmaws.profile");
        if (prop != null && !prop.isBlank()) return prop;
        String profile = System.getenv("AWS_PROFILE");
        if (profile == null || profile.isBlank()) profile = System.getenv("AWS_DEFAULT_PROFILE");
        return profile == null || profile.isBlank() ? "default" : profile;
    }

    public static String activeRegion() {
        String prop = System.getProperty("lmaws.region");
        if (prop != null && !prop.isBlank()) return prop;
        return System.getenv().getOrDefault("AWS_REGION", System.getenv().getOrDefault("AWS_DEFAULT_REGION", ""));
    }

    private IamRoles iamRoles;
    private IamRoles roleManager() {
        if(iamRoles==null)iamRoles=new IamRoles(demo,this::iam,()->resolvePolicyArn("lmaws_boundary").split(":")[4],this::requireIamRoleAccess);
        return iamRoles;
    }
    private void requireIamRoleAccess(boolean apply) {
        if(demo&&!apply)return;
        if(!"admin".equals(activeProfile())||!"1".equals(System.getenv("LMAWS_ADMIN_GRANT")))
            throw new IllegalStateException("IAM role grants require AWS_PROFILE=admin and LMAWS_ADMIN_GRANT=1");
        if(!demo&&endpoint==null&&!isLiveEnabled())throw new IllegalStateException("IAM role grants require LMAWS_LIVE=1");
        if(apply)IamPolicies.checkMutationGuard(true,activeProfile(),demo||endpoint!=null||isLiveEnabled(),true,isApplyEnabled(),"lmaws_lambda_exec");
        String ci=System.getenv().getOrDefault("CI","");
        if(!demo&&endpoint==null&&(ci.equalsIgnoreCase("true")||ci.equals("1")))throw new IllegalStateException("live IAM role access is forbidden in CI");
    }
    public Map<String,String> iamRoleGet(String name){return roleManager().get(name);}
    public Map<String,String> iamRolePut(String name,String spec,boolean apply){return roleManager().put(name,spec,apply);}
    public Map<String,String> iamRoleDelete(String name,boolean apply){return roleManager().delete(name,apply);}

    public Map<String, String> iamPolicyLint(String documentJson) {
        if (cost != null) cost.request("iam", "LintPolicyDocument");
        IamPolicies.LintResult lint = IamPolicies.lint(documentJson);
        System.out.println(lint.summaryLine());
        return lint.toMap();
    }

    public Map<String, String> iamPolicyGet(String policyName) {
        IamPolicies.requireValidPolicyName(policyName);
        if (cost != null) cost.request("iam", "GetPolicy");
        if (demo) {
            DemoPolicyState state = demoPolicies.get(policyName);
            if (state == null) {
                return row(
                    "kind", "iam_policy",
                    "name", policyName,
                    "arn", "arn:aws:iam::************:policy/" + policyName,
                    "exists", "false",
                    "default_version_id", "",
                    "attachment_count", "0",
                    "version_count", "0",
                    "compact_length", "0",
                    "document", "",
                    "normalized_json", ""
                );
            }
            DemoPolicyVersion def = state.defaultVersion();
            IamPolicies.LintResult lint = IamPolicies.lint(def.document);
            Map<String, String> m = new LinkedHashMap<>();
            m.put("kind", "iam_policy");
            m.put("name", policyName);
            m.put("arn", "arn:aws:iam::************:policy/" + policyName);
            m.put("exists", "true");
            m.put("default_version_id", def.versionId);
            m.put("attachment_count", String.valueOf(state.attachmentCount));
            m.put("version_count", String.valueOf(state.versions.size()));
            m.put("compact_length", String.valueOf(lint.compactLength()));
            m.put("statement_count", String.valueOf(lint.statementCount()));
            m.put("document", lint.prettyDocument());
            m.put("normalized_json", lint.compactDocument());
            return m;
        }
        String policyArn = resolvePolicyArn(policyName);
        Policy policy = getPolicyIfPresent(policyArn);
        if (policy == null) {
            return row(
                "kind", "iam_policy",
                "name", policyName,
                "arn", Jsons.mask(policyArn),
                "exists", "false",
                "default_version_id", "",
                "attachment_count", "0",
                "version_count", "0",
                "compact_length", "0",
                "document", "",
                "normalized_json", ""
            );
        }
        String defVer = policy.defaultVersionId();
        GetPolicyVersionResponse verResp = iam().getPolicyVersion(r -> r.policyArn(policyArn).versionId(defVer));
        String decoded = IamPolicies.decodeAwsDocument(verResp.policyVersion().document());
        List<PolicyVersion> versions = iam().listPolicyVersions(r -> r.policyArn(policyArn)).versions();
        IamPolicies.LintResult lint = IamPolicies.lint(decoded);
        Map<String, String> m = new LinkedHashMap<>();
        m.put("kind", "iam_policy");
        m.put("name", policyName);
        m.put("arn", Jsons.mask(policy.arn() == null ? policyArn : policy.arn()));
        m.put("exists", "true");
        m.put("default_version_id", defVer == null ? "" : defVer);
        m.put("attachment_count", String.valueOf(policy.attachmentCount() == null ? 0 : policy.attachmentCount()));
        m.put("version_count", String.valueOf(versions.size()));
        m.put("compact_length", String.valueOf(lint.compactLength()));
        m.put("statement_count", String.valueOf(lint.statementCount()));
        m.put("document", lint.prettyDocument());
        m.put("normalized_json", lint.compactDocument());
        return m;
    }

    public List<Map<String, String>> iamPolicyVersions(String policyName) {
        IamPolicies.requireValidPolicyName(policyName);
        if (cost != null) cost.request("iam", "ListPolicyVersions");
        if (demo) {
            DemoPolicyState state = demoPolicies.get(policyName);
            if (state == null) return List.of();
            List<Map<String, String>> out = new ArrayList<>();
            for (DemoPolicyVersion v : state.versions) {
                out.add(row(
                    "kind", "iam_policy_version",
                    "name", policyName,
                    "version_id", v.versionId,
                    "is_default", String.valueOf(v.isDefault),
                    "created", v.created
                ));
            }
            return out;
        }
        String policyArn = resolvePolicyArn(policyName);
        Policy policy = getPolicyIfPresent(policyArn);
        if (policy == null) return List.of();
        List<PolicyVersion> versions = iam().listPolicyVersions(r -> r.policyArn(policyArn)).versions();
        List<Map<String, String>> out = new ArrayList<>();
        for (PolicyVersion v : versions) {
            out.add(row(
                "kind", "iam_policy_version",
                "name", policyName,
                "version_id", v.versionId(),
                "is_default", String.valueOf(Boolean.TRUE.equals(v.isDefaultVersion())),
                "created", String.valueOf(v.createDate())
            ));
        }
        return out;
    }

    public Map<String, String> iamPolicyPut(String policyName, String documentJson, boolean apply) {
        IamPolicies.requireValidPolicyName(policyName);
        IamPolicies.requirePassRolePolicyContext(policyName,documentJson);
        IamPolicies.LintResult lint = IamPolicies.lint(documentJson);
        System.out.println(lint.summaryLine());
        lint.requireValid();
        if (apply) {
            requireIamPolicyWriteEnabled(policyName);
        }
        if (cost != null) cost.request("iam", apply ? "PutPolicy" : "DiffPolicy");

        if (demo) {
            DemoPolicyState state = demoPolicies.get(policyName);
            String currentDoc = state == null ? "" : state.defaultVersion().document;
            String currentVer = state == null ? "" : state.defaultVersion().versionId;
            IamPolicies.DiffResult diff = IamPolicies.diff(currentDoc, lint.prettyDocument());
            printDiff(policyName, diff);
            String action = "dry_run";
            String versionId = currentVer;
            String deletedVersionId = "";
            if (apply) {
                if (state == null) {
                    state = new DemoPolicyState(policyName, 0);
                    state.versions.add(new DemoPolicyVersion("v1", true, "2026-01-01T00:00:00Z", lint.prettyDocument()));
                    demoPolicies.put(policyName, state);
                    action = "created";
                    versionId = "v1";
                } else {
                    if (state.versions.size() >= IamPolicies.MAX_POLICY_VERSIONS) {
                        DemoPolicyVersion oldest = state.oldestNonDefault();
                        if (oldest != null) {
                            state.versions.remove(oldest);
                            deletedVersionId = oldest.versionId;
                        }
                    }
                    for (DemoPolicyVersion v : state.versions) v.isDefault = false;
                    String nextVer = "v" + (++state.nextVersionNum);
                    state.versions.add(new DemoPolicyVersion(nextVer, true, Instant.now().toString(), lint.prettyDocument()));
                    action = "updated";
                    versionId = nextVer;
                }
            }
            return buildPutRow(
                policyName,
                "arn:aws:iam::************:policy/" + policyName,
                state != null,
                apply,
                action,
                versionId,
                deletedVersionId,
                lint,
                diff
            );
        }

        String policyArn = resolvePolicyArn(policyName);
        Policy existing = getPolicyIfPresent(policyArn);
        String currentDoc = "";
        String currentVer = "";
        if (existing != null && existing.defaultVersionId() != null) {
            currentVer = existing.defaultVersionId();
            GetPolicyVersionResponse verResp = iam().getPolicyVersion(
                r -> r.policyArn(policyArn).versionId(existing.defaultVersionId()));
            currentDoc = IamPolicies.decodeAwsDocument(verResp.policyVersion().document());
        }
        IamPolicies.DiffResult diff = IamPolicies.diff(currentDoc, lint.prettyDocument());
        printDiff(policyName, diff);

        if (!apply) {
            return buildPutRow(
                policyName,
                Jsons.mask(policyArn),
                existing != null,
                false,
                "dry_run",
                currentVer,
                "",
                lint,
                diff
            );
        }

        String deletedVersionId = "";
        String newVersionId;
        String action;
        if (existing == null) {
            var createResp = iam().createPolicy(r -> r
                .policyName(policyName)
                .policyDocument(lint.prettyDocument())
                .description("Managed session policy for lmaws (" + policyName + ")"));
            Policy created = createResp.policy();
            newVersionId = created != null && created.defaultVersionId() != null ? created.defaultVersionId() : "v1";
            action = "created";
        } else {
            List<PolicyVersion> versions = iam().listPolicyVersions(r -> r.policyArn(policyArn)).versions();
            if (versions.size() >= IamPolicies.MAX_POLICY_VERSIONS) {
                PolicyVersion oldestNonDefault = versions.stream()
                    .filter(v -> !Boolean.TRUE.equals(v.isDefaultVersion()))
                    .min(Comparator
                        .comparing((PolicyVersion v) -> v.createDate() == null ? Instant.EPOCH : v.createDate())
                        .thenComparingInt(v -> parseVersionNumber(v.versionId())))
                    .orElseThrow(() -> new IllegalStateException("Cannot rotate 5 policy versions: no non-default version found"));
                deletedVersionId = oldestNonDefault.versionId();
                iam().deletePolicyVersion(r -> r.policyArn(policyArn).versionId(oldestNonDefault.versionId()));
            }
            CreatePolicyVersionResponse verResp = iam().createPolicyVersion(
                r -> r.policyArn(policyArn).policyDocument(lint.prettyDocument()).setAsDefault(true));
            newVersionId = verResp.policyVersion() != null ? verResp.policyVersion().versionId() : "";
            action = "updated";
        }
        return buildPutRow(
            policyName,
            Jsons.mask(policyArn),
            true,
            true,
            action,
            newVersionId,
            deletedVersionId,
            lint,
            diff
        );
    }

    public Map<String, String> iamPolicyDelete(String policyName, boolean apply) {
        IamPolicies.requireValidPolicyName(policyName);
        if (apply) {
            requireIamPolicyWriteEnabled(policyName);
        }
        if (cost != null) cost.request("iam", apply ? "DeletePolicy" : "CheckDeletePolicy");

        if (demo) {
            DemoPolicyState state = demoPolicies.get(policyName);
            if (state == null) {
                throw new IllegalStateException("IAM policy '" + policyName + "' does not exist");
            }
            if (state.attachmentCount > 0) {
                throw new IllegalStateException(
                    "Refusing to delete IAM policy '" + policyName + "' because it is attached to "
                        + state.attachmentCount + " entity/entities");
            }
            List<String> nonDefault = state.versions.stream()
                .filter(v -> !v.isDefault)
                .map(v -> v.versionId)
                .toList();
            if (apply) {
                demoPolicies.remove(policyName);
            }
            return row(
                "kind", "iam_policy",
                "name", policyName,
                "arn", "arn:aws:iam::************:policy/" + policyName,
                "applied", String.valueOf(apply),
                "action", apply ? "deleted" : "dry_run",
                "attachment_count", "0",
                "deleted_versions", String.join(",", nonDefault)
            );
        }

        String policyArn = resolvePolicyArn(policyName);
        Policy existing = getPolicyIfPresent(policyArn);
        if (existing == null) {
            throw new IllegalStateException("IAM policy '" + policyName + "' does not exist");
        }
        int attachments = existing.attachmentCount() == null ? 0 : existing.attachmentCount();
        if (attachments > 0) {
            throw new IllegalStateException(
                "Refusing to delete IAM policy '" + policyName + "' because it is attached to "
                    + attachments + " entity/entities");
        }
        List<PolicyVersion> versions = iam().listPolicyVersions(r -> r.policyArn(policyArn)).versions();
        List<String> nonDefaultIds = versions.stream()
            .filter(v -> !Boolean.TRUE.equals(v.isDefaultVersion()))
            .map(PolicyVersion::versionId)
            .toList();
        if (apply) {
            for (String verId : nonDefaultIds) {
                iam().deletePolicyVersion(r -> r.policyArn(policyArn).versionId(verId));
            }
            iam().deletePolicy(r -> r.policyArn(policyArn));
        }
        return row(
            "kind", "iam_policy",
            "name", policyName,
            "arn", Jsons.mask(policyArn),
            "applied", String.valueOf(apply),
            "action", apply ? "deleted" : "dry_run",
            "attachment_count", "0",
            "deleted_versions", String.join(",", nonDefaultIds)
        );
    }

    private Map<String, String> buildPutRow(
            String policyName,
            String maskedArn,
            boolean exists,
            boolean applied,
            String action,
            String versionId,
            String deletedVersionId,
            IamPolicies.LintResult lint,
            IamPolicies.DiffResult diff) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("kind", "iam_policy");
        m.put("name", policyName);
        m.put("arn", maskedArn);
        m.put("exists", String.valueOf(exists));
        m.put("applied", String.valueOf(applied));
        m.put("action", action);
        m.put("version_id", versionId == null ? "" : versionId);
        m.put("deleted_version_id", deletedVersionId == null ? "" : deletedVersionId);
        m.put("compact_length", String.valueOf(lint.compactLength()));
        m.put("max_length", String.valueOf(IamPolicies.MANAGED_POLICY_LIMIT));
        m.put("inline_limit", String.valueOf(IamPolicies.INLINE_SESSION_POLICY_LIMIT));
        m.put("statement_count", String.valueOf(lint.statementCount()));
        m.put("allow_read_statements", String.valueOf(lint.allowReadStatements()));
        m.put("allow_scoped_statements", String.valueOf(lint.allowScopedStatements()));
        m.put("deny_statements", String.valueOf(lint.denyStatements()));
        m.put("lint_valid", String.valueOf(lint.valid()));
        m.put("lint_summary", lint.summaryLine());
        m.put("changed", String.valueOf(diff.changed()));
        m.put("added_count", String.valueOf(diff.addedCount()));
        m.put("modified_count", String.valueOf(diff.modifiedCount()));
        m.put("removed_count", String.valueOf(diff.removedCount()));
        m.put("unchanged_count", String.valueOf(diff.unchangedCount()));
        m.put("diff_summary", diff.summary());
        m.put("diff_lines", diff.formattedLines());
        m.put("statement_diffs", Jsons.encode(diff.statementDiffs()));
        m.put("normalized_json", lint.compactDocument());
        m.put("document", lint.prettyDocument());
        return m;
    }

    private static void printDiff(String policyName, IamPolicies.DiffResult diff) {
        System.out.println("IAM policy diff (" + policyName + "): " + diff.summary());
        for (String line : diff.lines()) {
            System.out.println("  " + line);
        }
    }

    private static int parseVersionNumber(String versionId) {
        if (versionId == null) return Integer.MAX_VALUE;
        String digits = versionId.startsWith("v") || versionId.startsWith("V") ? versionId.substring(1) : versionId;
        try {
            return Integer.parseInt(digits);
        } catch (NumberFormatException ex) {
            return Integer.MAX_VALUE;
        }
    }

    private String resolvePolicyArn(String policyName) {
        if (cachedAccountId == null) {
            cachedAccountId = sts().getCallerIdentity(GetCallerIdentityRequest.builder().build()).account();
        }
        return "arn:aws:iam::" + cachedAccountId + ":policy/" + policyName;
    }

    private Policy getPolicyIfPresent(String policyArn) {
        try {
            GetPolicyResponse resp = iam().getPolicy(r -> r.policyArn(policyArn));
            return resp.policy();
        } catch (NoSuchEntityException ex) {
            return null;
        }
    }

    private static final class DemoPolicyVersion {
        final String versionId;
        boolean isDefault;
        final String created;
        final String document;

        DemoPolicyVersion(String versionId, boolean isDefault, String created, String document) {
            this.versionId = versionId;
            this.isDefault = isDefault;
            this.created = created;
            this.document = document;
        }
    }

    private static final class DemoPolicyState {
        final String name;
        int attachmentCount;
        int nextVersionNum = 1;
        final List<DemoPolicyVersion> versions = new ArrayList<>();

        DemoPolicyState(String name, int attachmentCount) {
            this.name = name;
            this.attachmentCount = attachmentCount;
        }

        DemoPolicyVersion defaultVersion() {
            for (DemoPolicyVersion v : versions) {
                if (v.isDefault) return v;
            }
            return versions.get(versions.size() - 1);
        }

        DemoPolicyVersion oldestNonDefault() {
            for (DemoPolicyVersion v : versions) {
                if (!v.isDefault) return v;
            }
            return null;
        }
    }
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
        DemoPolicyState sessionPolicy = new DemoPolicyState("lmaws_session", 0);
        sessionPolicy.versions.add(new DemoPolicyVersion(
            "v1",
            true,
            "2026-01-01T00:00:00Z",
            IamPolicies.lint(IamPolicies.sanitizedBaselinePolicyJson()).prettyDocument()
        ));
        demoPolicies.put("lmaws_session", sessionPolicy);

        DemoPolicyState attachedPolicy = new DemoPolicyState("lmaws_attached_demo", 1);
        attachedPolicy.versions.add(new DemoPolicyVersion(
            "v1",
            true,
            "2026-01-01T00:00:00Z",
            IamPolicies.lint(IamPolicies.sanitizedBaselinePolicyJson()).prettyDocument()
        ));
        demoPolicies.put("lmaws_attached_demo", attachedPolicy);
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
    private Map<String, String> demoCreate(String k, String n, String value, String runId) { String id = n; String key = demoKey(k, id); if(demoResources.containsKey(key))throw new IllegalStateException("demo resource already exists"); Map<String, String> m = row("kind", k, "id", id, "name", n, "created", Instant.now().toString(), "run_id", runId,"tags",Jsons.encode(Map.of("lmaws_test",runId))); if (value != null) m.put("value_metadata", "stored"); demoResources.put(key, m); return new LinkedHashMap<>(m); }
    private static String demoKey(String kind, String id) { return kind + "\u0000" + id; }

    Ec2Client ec2Client() { return ec2(); }
    SsmClient ssmClient() { return ssm(); }
    CloudWatchClient cloudWatchClient() { return cloudwatch(); }
    StsClient stsClientForDoctor() { return sts(); }
    S3Client s3ClientForDoctor() { return s3(); }
    SqsClient sqsClientForDoctor() { return sqs(); }
    DynamoDbClient ddbClientForDoctor() { return ddb(); }
    SsmClient ssmClientForDoctor() { return ssm(); }
    Ec2Client ec2ClientForDoctor() { return ec2(); }

    public List<Map<String, String>> sessionDoctor() {
        return CredentialProcess.sessionDoctor(this);
    }

    public List<Map<String, String>> policySimulate(String policyJson, String probesSpec) {
        return PolicySimulator.simulateCustom(
            demo ? null : iam(),
            cost,
            demo,
            !demo && endpoint == null,
            activeProfile(),
            policyJson,
            probesSpec
        );
    }

    public List<Map<String, String>> policySimulatePrincipal(String policyNameOrArn, String probesSpec) {
        String sourceArn = policyNameOrArn == null ? "" : policyNameOrArn.trim();
        String fallbackDoc = IamPolicies.sanitizedTemplatePolicyJson();
        if (demo) {
            DemoPolicyState st = demoPolicies.get(sourceArn);
            if (st != null && !st.versions.isEmpty()) {
                fallbackDoc = st.defaultVersion().document;
            }
        } else if (!sourceArn.startsWith("arn:aws:iam::")) {
            IamPolicies.requireValidPolicyName(sourceArn);
            sourceArn = resolvePolicyArn(sourceArn);
        }
        return PolicySimulator.simulatePrincipal(
            demo ? null : iam(),
            cost,
            demo,
            !demo && endpoint == null,
            activeProfile(),
            sourceArn,
            fallbackDoc,
            probesSpec
        );
    }

    private void tagBucket(String id,String runId) {
        s3().putBucketTagging(x -> x.bucket(id).tagging(t -> t.tagSet(Tag.builder().key("lmaws_test").value(runId).build())));
    }
}
