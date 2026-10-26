package ai.lmctl.lmaws;

import java.net.URI;
import java.time.*;
import java.util.*;
import java.math.*;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.costexplorer.CostExplorerClient;
import software.amazon.awssdk.services.costexplorer.model.*;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricDataRequest;
import software.amazon.awssdk.services.cloudwatch.model.MetricDataQuery;
import software.amazon.awssdk.services.cloudwatch.model.MetricStat;
import software.amazon.awssdk.services.savingsplans.SavingsplansClient;
import software.amazon.awssdk.services.pricing.PricingClient;
import software.amazon.awssdk.services.pricing.model.GetProductsRequest;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;

/** SDK-only allowlisted read paths. No retries, mutation API, shell or billing-view override. */
public final class SpendAwsSource implements SpendSource {
    private static final int MAX_ROWS=10000,MAX_PAGES=100;
    private final CostLedger ledger;
    private final List<String> regions;
    private final AwsCredentialsProvider credentials;
    private final URI endpoint;
    private final ClientOverrideConfiguration config;
    private final Map<String,Object> clients=new LinkedHashMap<>();
    private final Map<String,List<Map<String,String>>> cache=new LinkedHashMap<>();
    private final Map<String,Map<String,String>> prices=new LinkedHashMap<>();
    private int cacheHits;
    public SpendAwsSource(){this(null);}
    public SpendAwsSource(CostLedger ledger){this(ledger,null,null);}
    SpendAwsSource(CostLedger ledger,URI endpoint){this(ledger,endpoint,null);}
    SpendAwsSource(CostLedger ledger,URI testEndpoint,AwsCredentialsProvider testCredentials){
        this.ledger=ledger;
        if(!AwsBackend.activeProfile().equals("default"))throw new Unavailable("spend","AWS_PROFILE_MUST_BE_DEFAULT");
        String raw=System.getenv("LMAWS_ENDPOINT");this.endpoint=checkedEndpoint(testEndpoint!=null?testEndpoint:raw==null||raw.isBlank()?null:URI.create(raw));
        if(this.endpoint==null&&Set.of("true","1","yes").contains(System.getenv().getOrDefault("CI","").toLowerCase(Locale.ROOT)))throw new Unavailable("spend","LIVE_FORBIDDEN_IN_CI");
        this.credentials=testCredentials!=null?testCredentials:this.endpoint!=null?StaticCredentialsProvider.create(AwsBasicCredentials.create("test","test")):ProfileCredentialsProvider.create("default");
        this.config=ClientOverrideConfiguration.builder().retryPolicy(RetryPolicy.none()).apiCallTimeout(Duration.ofSeconds(25)).apiCallAttemptTimeout(Duration.ofSeconds(15)).build();
        String scope=System.getenv().getOrDefault("LMAWS_SPEND_REGIONS",System.getenv().getOrDefault("AWS_REGION",System.getenv().getOrDefault("AWS_DEFAULT_REGION","us-east-1")));
        regions=Arrays.stream(scope.split(",")).map(String::trim).filter(x->!x.isBlank()).distinct().toList();
        if(regions.isEmpty()||regions.size()>40||regions.stream().anyMatch(x->!x.matches("[a-z]{2}(?:-[a-z]+)+-[0-9]")))throw new Unavailable("spend","INVALID_REGION_SCOPE");
    }
    private static URI checkedEndpoint(URI u){if(u==null)return null;if(!Set.of("127.0.0.1","localhost","[::1]","::1").contains(u.getHost())||!Set.of("http","https").contains(u.getScheme())||u.getUserInfo()!=null)throw new Unavailable("spend","ENDPOINT_MUST_BE_LOOPBACK");return u;}
    private <T> T client(String key,java.util.function.Supplier<T> make){return (T)clients.computeIfAbsent(key,k->make.get());}
    private CostExplorerClient ce(){return client("ce",()->{var b=CostExplorerClient.builder().region(Region.US_EAST_1).credentialsProvider(credentials).overrideConfiguration(config).httpClientBuilder(UrlConnectionHttpClient.builder());if(endpoint!=null)b.endpointOverride(endpoint);return b.build();});}
    private SavingsplansClient plans(){return client("sp",()->{var b=SavingsplansClient.builder().region(Region.US_EAST_1).credentialsProvider(credentials).overrideConfiguration(config).httpClientBuilder(UrlConnectionHttpClient.builder());if(endpoint!=null)b.endpointOverride(endpoint);return b.build();});}
    private PricingClient pricing(){return client("pricing",()->{var b=PricingClient.builder().region(Region.US_EAST_1).credentialsProvider(credentials).overrideConfiguration(config).httpClientBuilder(UrlConnectionHttpClient.builder());if(endpoint!=null)b.endpointOverride(endpoint);return b.build();});}
    private Ec2Client ec2(String region){return client("ec2:"+region,()->{var b=Ec2Client.builder().region(Region.of(region)).credentialsProvider(credentials).overrideConfiguration(config).httpClientBuilder(UrlConnectionHttpClient.builder());if(endpoint!=null)b.endpointOverride(endpoint);return b.build();});}
    private LambdaClient lambda(String region){return client("lambda:"+region,()->{var b=LambdaClient.builder().region(Region.of(region)).credentialsProvider(credentials).overrideConfiguration(config).httpClientBuilder(UrlConnectionHttpClient.builder());if(endpoint!=null)b.endpointOverride(endpoint);return b.build();});}
    private DynamoDbClient dynamo(String region){return client("ddb:"+region,()->{var b=DynamoDbClient.builder().region(Region.of(region)).credentialsProvider(credentials).overrideConfiguration(config).httpClientBuilder(UrlConnectionHttpClient.builder());if(endpoint!=null)b.endpointOverride(endpoint);return b.build();});}
    private CloudWatchClient cw(String region){return client("cw:"+region,()->{var b=CloudWatchClient.builder().region(Region.of(region)).credentialsProvider(credentials).overrideConfiguration(config).httpClientBuilder(UrlConnectionHttpClient.builder());if(endpoint!=null)b.endpointOverride(endpoint);return b.build();});}
    private void charge(String service,String operation){if(ledger!=null)ledger.request(service,operation);}
    private RuntimeException failure(String feature,RuntimeException e){
        if(e instanceof CostLedger.BudgetExceeded||e instanceof Unavailable)return e;
        if(e instanceof AwsServiceException aws){String code=aws.awsErrorDetails()==null?aws.getClass().getSimpleName():aws.awsErrorDetails().errorCode();
            if(feature.equals("resource_level")&&String.valueOf(aws.getMessage()).toLowerCase(Locale.ROOT).matches("(?s).*(not enabled|opt.in|enable.*resource).*"))code="RESOURCE_LEVEL_NOT_ENABLED";
            return new Unavailable(feature,code==null?"AWS_SERVICE_ERROR":code.replaceAll("[^A-Za-z0-9_]",""));}
        return new Unavailable(feature,"SDK_CLIENT_UNAVAILABLE");
    }
    private static String text(Object value){return value==null?"unknown":value.toString();}
    private static Map<String,String> row(Object...pairs){Map<String,String>x=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)x.put(pairs[i].toString(),text(pairs[i+1]));return x;}
    private List<Map<String,String>> remember(String key,List<Map<String,String>> rows){if(rows.size()>MAX_ROWS)throw new Unavailable("spend","RESULT_LIMIT_EXCEEDED");var saved=rows.stream().map(x->Collections.unmodifiableMap(new LinkedHashMap<>(x))).toList();cache.put(key,saved);return saved;}
    private List<Map<String,String>> cached(String key){var result=cache.get(key);if(result!=null)cacheHits++;return result;}
    private static String token(String token,Set<String> seen){if(token==null||token.isBlank())return null;if(!seen.add(token)||seen.size()>MAX_PAGES)throw new Unavailable("spend","PAGINATION_LIMIT_EXCEEDED");return token;}
    @Override public List<Map<String,String>> costs(LocalDate start,LocalDate end,String gran,String dimension,String service,boolean resources){
        SpendSourceChecks.dateRange(start,end);SpendSourceChecks.dimension(dimension);
        if(resources&&(java.time.temporal.ChronoUnit.DAYS.between(start,end)>14||endpoint==null&&start.isBefore(LocalDate.now(ZoneOffset.UTC).minusDays(14))))throw new Unavailable("resource_level","MAXIMUM_14_DAY_LOOKBACK");
        String key="cost:"+start+end+gran+dimension+service+resources;var hit=cached(key);if(hit!=null)return hit;
        List<GroupDefinition> groups=dimension.equals("SERVICE_USAGE_TYPE")?List.of(GroupDefinition.builder().type("DIMENSION").key("SERVICE").build(),GroupDefinition.builder().type("DIMENSION").key("USAGE_TYPE").build()):List.of(GroupDefinition.builder().type("DIMENSION").key(dimension).build());
        Expression filter=service==null||service.isBlank()?null:Expression.builder().dimensions(DimensionValues.builder().key("SERVICE").values(service).build()).build();
        DateInterval period=DateInterval.builder().start(start.toString()).end(end.toString()).build();
        List<Map<String,String>> out=new ArrayList<>();Set<String> seen=new HashSet<>();String next=null;
        try{do{
            charge("costexplorer",resources?"GetCostAndUsageWithResources":"GetCostAndUsage");List<ResultByTime> times;
            if(resources){
                var response=ce().getCostAndUsageWithResources(GetCostAndUsageWithResourcesRequest.builder().timePeriod(period).granularity(gran).metrics("UnblendedCost","AmortizedCost","UsageQuantity").groupBy(groups).filter(filter).nextPageToken(next).build());times=response.resultsByTime();next=token(response.nextPageToken(),seen);
            }else{var response=ce().getCostAndUsage(GetCostAndUsageRequest.builder().timePeriod(period).granularity(gran).metrics("UnblendedCost","AmortizedCost","UsageQuantity").groupBy(groups).filter(filter).nextPageToken(next).build());times=response.resultsByTime();next=token(response.nextPageToken(),seen);}
            for(var time:times)for(var group:time.groups()){
                software.amazon.awssdk.services.costexplorer.model.MetricValue cost=group.metrics().get("UnblendedCost"),amortized=group.metrics().get("AmortizedCost"),usage=group.metrics().get("UsageQuantity");
                if(cost!=null&&cost.unit()!=null&&!cost.unit().equals("USD"))throw new Unavailable("costs","CURRENCY_NOT_USD");
                var x=row("start",time.timePeriod().start(),"end",time.timePeriod().end(),"date",time.timePeriod().start(),"key",String.join("/",group.keys()),"amount_usd",cost==null?"unknown":cost.amount(),"amortized_usd",amortized==null?"unknown":amortized.amount(),"usage_quantity",usage==null?"unknown":usage.amount(),"unit",usage==null?"unknown":usage.unit(),"estimated",time.estimated(),"status","observed");
                if(dimension.equals("SERVICE"))x.put("service",group.keys().getFirst());
                if(dimension.equals("SERVICE_USAGE_TYPE")&&group.keys().size()==2){x.put("service",group.keys().getFirst());x.put("usage_type",group.keys().get(1));}
                out.add(x);if(out.size()>MAX_ROWS)throw new Unavailable("costs","RESULT_LIMIT_EXCEEDED");
            }
        }while(next!=null);}catch(RuntimeException e){throw failure(resources?"resource_level":"costs",e);}return remember(key,out);
    }
    @Override public List<Map<String,String>> inventory(String kind){
        String key="inventory:"+kind;var hit=cached(key);if(hit!=null)return hit;List<Map<String,String>> out=new ArrayList<>();
        try{
            if(kind.equals("savings_plans"))return remember(key,SpendCommitments.plans(plans(),ledger));
            for(String region:regions){Set<String> seen=new HashSet<>();String next=null;do{switch(kind){
                case "ec2"->{charge("ec2","DescribeInstances");var page=ec2(region).describeInstances(DescribeInstancesRequest.builder().nextToken(next).build());for(var reservation:page.reservations())for(var x:reservation.instances())out.add(row("region",region,"instance_id",x.instanceId(),"instance_type",x.instanceTypeAsString(),"state",x.state()==null?"unknown":x.state().nameAsString(),"platform",x.platformDetails(),"public_ip",x.publicIpAddress()==null?"":x.publicIpAddress()));next=token(page.nextToken(),seen);}
                case "eips"->{charge("ec2","DescribeAddresses");for(var x:ec2(region).describeAddresses().addresses())out.add(row("region",region,"allocation_id",x.allocationId(),"public_ip",x.publicIp(),"association_id",x.associationId()==null?"":x.associationId(),"instance_id",x.instanceId()==null?"":x.instanceId()));next=null;}
                case "ebs"->{charge("ec2","DescribeVolumes");var page=ec2(region).describeVolumes(DescribeVolumesRequest.builder().nextToken(next).build());for(var x:page.volumes())out.add(row("region",region,"volume_id",x.volumeId(),"volume_type",x.volumeTypeAsString(),"size_gib",x.size(),"iops",x.iops(),"throughput_mib_s",x.throughput(),"state",x.stateAsString(),"attached_instance_id",x.attachments().isEmpty()?"":x.attachments().getFirst().instanceId()));next=token(page.nextToken(),seen);}
                case "snapshots"->{charge("ec2","DescribeSnapshots");var page=ec2(region).describeSnapshots(DescribeSnapshotsRequest.builder().ownerIds("self").nextToken(next).build());for(var x:page.snapshots())out.add(row("region",region,"snapshot_id",x.snapshotId(),"size_gib",x.volumeSize(),"start_time",x.startTime(),"state",x.stateAsString()));next=token(page.nextToken(),seen);}
                case "reserved_instances"->{charge("ec2","DescribeReservedInstances");for(var x:ec2(region).describeReservedInstances().reservedInstances())out.add(row("region",region,"reserved_id",x.reservedInstancesId(),"instance_type",x.instanceTypeAsString(),"instance_count",x.instanceCount(),"state",x.stateAsString(),"fixed_price",x.fixedPrice(),"duration_seconds",x.duration(),"recurring_hourly",x.recurringCharges().stream().mapToDouble(a->a.amount()==null?0:a.amount()).sum()));next=null;}
                case "lambda"->{charge("lambda","ListFunctions");var page=lambda(region).listFunctions(software.amazon.awssdk.services.lambda.model.ListFunctionsRequest.builder().marker(next).build());for(var x:page.functions())out.add(row("region",region,"function_name",x.functionName(),"resource_id",x.functionArn(),"memory_mb",x.memorySize(),"architecture",x.architecturesAsStrings().isEmpty()?"unknown":x.architecturesAsStrings().getFirst()));next=token(page.nextMarker(),seen);}
                case "dynamodb"->{charge("dynamodb","ListTables");var page=dynamo(region).listTables(software.amazon.awssdk.services.dynamodb.model.ListTablesRequest.builder().exclusiveStartTableName(next).build());for(String name:page.tableNames()){charge("dynamodb","DescribeTable");var x=dynamo(region).describeTable(a->a.tableName(name)).table();out.add(row("region",region,"table_name",name,"table_id",x.tableArn(),"billing_mode",x.billingModeSummary()==null?"PROVISIONED":x.billingModeSummary().billingModeAsString(),"size_bytes",x.tableSizeBytes(),"item_count",x.itemCount(),"read_capacity",x.provisionedThroughput()==null?"0":x.provisionedThroughput().readCapacityUnits(),"write_capacity",x.provisionedThroughput()==null?"0":x.provisionedThroughput().writeCapacityUnits()));}next=token(page.lastEvaluatedTableName(),seen);}
                default->throw new Unavailable(kind,"UNSUPPORTED_INVENTORY");
            }if(out.size()>MAX_ROWS)throw new Unavailable(kind,"RESULT_LIMIT_EXCEEDED");}while(next!=null);}
        }catch(RuntimeException e){throw failure(kind,e);}return remember(key,out);
    }
    @Override public List<Map<String,String>> commitment(String kind,LocalDate start,LocalDate end){String key="commitment:"+kind+start+end;var hit=cached(key);if(hit!=null)return hit;try{return remember(key,SpendCommitments.read(ce(),ledger,kind,start,end));}catch(RuntimeException e){throw failure(kind,e);}}
    @Override public List<Map<String,String>> metrics(List<Metric> queries,Instant start,Instant end){
        if(queries.isEmpty())return List.of();List<Map<String,String>> out=new ArrayList<>();
        for(String region:regions){var scoped=queries.stream().filter(q->q.region().equals(region)).toList();for(int base=0;base<scoped.size();base+=100){var batch=scoped.subList(base,Math.min(base+100,scoped.size()));
            Map<String,Metric> index=new HashMap<>();List<MetricDataQuery> requestQueries=new ArrayList<>();for(Metric q:batch){index.put(q.id(),q);requestQueries.add(MetricDataQuery.builder().id(q.id()).returnData(true).metricStat(MetricStat.builder().period(q.period()).stat(q.statistic()).metric(software.amazon.awssdk.services.cloudwatch.model.Metric.builder().namespace(q.namespace()).metricName(q.name()).dimensions(software.amazon.awssdk.services.cloudwatch.model.Dimension.builder().name(q.dimension()).value(q.resource()).build()).build()).build()).build());}
            Set<String> seen=new HashSet<>();String next=null;try{do{
                if(ledger!=null)ledger.metricRequest("GetMetricData",batch.size());
                var page=cw(region).getMetricData(GetMetricDataRequest.builder().metricDataQueries(requestQueries).startTime(start).endTime(end).nextToken(next).maxDatapoints(100800).build());
                for(var x:page.metricDataResults()){Metric q=index.get(x.id());if(q==null)throw new Unavailable("metrics","UNKNOWN_METRIC_ID");double total=x.values().stream().mapToDouble(Double::doubleValue).sum();if(q.statistic().equals("Average")&&!x.values().isEmpty())total/=x.values().size();
                    out.add(row("metric_id",x.id(),"resource_id",q.resource(),"region",region,"metric",q.name(),"statistic",q.statistic(),"total",Double.isFinite(total)?Double.toString(total):"unknown","datapoints",x.values().size(),"status",x.statusCodeAsString()));}
                next=token(page.nextToken(),seen);if(out.size()>MAX_ROWS)throw new Unavailable("metrics","RESULT_LIMIT_EXCEEDED");
            }while(next!=null);}catch(RuntimeException e){throw failure("metrics",e);}
        }}return out;
    }
    @Override public Map<String,String> ec2Price(String region,String type,String platform){
        String key=region+":"+type+":"+platform;if(prices.containsKey(key)){cacheHits++;return prices.get(key);}
        if(platform!=null&&platform.toLowerCase(Locale.ROOT).contains("sql"))return row("hourly_usd","unknown","pricing_status","bundled_database_license_not_estimated");
        String os=platform!=null&&platform.toLowerCase(Locale.ROOT).contains("windows")?"Windows":"Linux";
        if(platform!=null&&!platform.isBlank()&&!platform.contains("Linux")&&!platform.contains("UNIX")&&!platform.contains("Windows"))return row("hourly_usd","unknown","pricing_status","unsupported_platform");
        var filters=List.of(filter("regionCode",region),filter("instanceType",type),filter("operatingSystem",os),filter("tenancy","Shared"),filter("preInstalledSw","NA"),filter("capacitystatus","Used"));
        try{Set<String> seen=new HashSet<>();String next=null;do{charge("pricing","GetProducts");var page=pricing().getProducts(GetProductsRequest.builder().serviceCode("AmazonEC2").filters(filters).nextToken(next).build());
            for(String json:page.priceList()){
                JsonNode node=JsonNodeParser.create().parse(json);JsonNode terms=node.field("terms").orElse(JsonNode.emptyObjectNode()).field("OnDemand").orElse(JsonNode.emptyObjectNode());
                for(var term:terms.asObject().values())for(var dimension:term.field("priceDimensions").orElse(JsonNode.emptyObjectNode()).asObject().values()){
                    String unit=dimension.field("unit").map(JsonNode::asString).orElse("");if(!unit.equals("Hrs"))continue;
                    String usd=dimension.field("pricePerUnit").orElse(JsonNode.emptyObjectNode()).field("USD").map(JsonNode::asString).orElse("unknown");
                    if(SpendReport.known(usd)){var result=row("hourly_usd",usd,"pricing_status","observed","pricing_basis","AWS Pricing shared-tenancy "+os+" on-demand; excludes credits and commitments");prices.put(key,result);return result;}
                }
            }next=token(page.nextToken(),seen);
        }while(next!=null);}catch(RuntimeException e){throw failure("ec2_price",e);}var result=row("hourly_usd","unknown","pricing_status","no_matching_catalog_product");prices.put(key,result);return result;
    }
    private static software.amazon.awssdk.services.pricing.model.Filter filter(String field,String value){return software.amazon.awssdk.services.pricing.model.Filter.builder().type("TERM_MATCH").field(field).value(value).build();}
    @Override public Map<String,Object> diagnostics(){return Map.of("profile","default","inventory_regions",regions,"inventory_scope","explicit regions only; set LMAWS_SPEND_REGIONS for additional regions","cost_scope","account primary billing view across all regions","cache_hits",cacheHits,"endpoint",endpoint==null?"aws":"loopback","read_only",true);}
    @Override public void close(){for(Object client:clients.values())if(client instanceof AutoCloseable c)try{c.close();}catch(Exception ignored){}clients.clear();if(credentials instanceof AutoCloseable c)try{c.close();}catch(Exception ignored){}}
}
