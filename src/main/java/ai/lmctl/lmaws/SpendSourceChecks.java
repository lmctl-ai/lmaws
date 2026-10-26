package ai.lmctl.lmaws;

import java.time.*;
import java.util.*;
import java.nio.file.*;
import java.net.*;
import com.sun.net.httpserver.HttpServer;
import java.nio.charset.StandardCharsets;
import java.math.BigDecimal;
import software.amazon.awssdk.auth.credentials.*;

/** Actual AWS SDK protocols against loopback fixtures; this main is a JVM-only test entry. */
public final class SpendSourceChecks {
    private static String nativeBinary;
    private SpendSourceChecks(){}
    public static void dateRange(LocalDate start,LocalDate end){if(start==null||end==null||!start.isBefore(end))throw new SpendSource.Unavailable("costs","INVALID_DATE_RANGE");}
    public static void dimension(String name){if(!Set.of("SERVICE","INSTANCE_TYPE","RESOURCE_ID","SERVICE_USAGE_TYPE").contains(name))throw new SpendSource.Unavailable("costs","INVALID_DIMENSION");}
    public static void main(String[]args)throws Exception{nativeBinary=args.length==1?args[0]:null;httpSmoke();}
    public static void httpSmoke() throws Exception {
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        List<String> operations=new ArrayList<>();String[] mode={"normal"};List<String> bodies=new ArrayList<>();
        server.createContext("/",exchange->{
            byte[] requestBytes=exchange.getRequestBody().readAllBytes();
            boolean cbor=String.valueOf(exchange.getRequestHeaders().getFirst("Content-Type")).contains("cbor");
            String body=cbor?Jsons.encodeRaw(plain(software.amazon.awssdk.protocols.jsoncore.JsonNodeParser.builder().jsonFactory(new software.amazon.awssdk.thirdparty.jackson.dataformat.cbor.CBORFactory()).build().parse(requestBytes))):new String(requestBytes,StandardCharsets.UTF_8);
            String target=exchange.getRequestHeaders().getFirst("X-Amz-Target");String op=target==null?"":target.substring(target.lastIndexOf('.')+1);
            if(op.isEmpty()&&body.contains("Action=")){for(String part:body.split("&"))if(part.startsWith("Action="))op=URLDecoder.decode(part.substring(7),StandardCharsets.UTF_8);}
            if(op.isEmpty()&&exchange.getRequestURI().getPath().contains("/operation/"))op=exchange.getRequestURI().getPath().substring(exchange.getRequestURI().getPath().lastIndexOf('/')+1);
            if(op.isEmpty()&&exchange.getRequestURI().getPath().contains("functions"))op="ListFunctions";
            if(op.isEmpty()&&exchange.getRequestURI().getPath().toLowerCase(Locale.ROOT).contains("describesavingsplans"))op="DescribeSavingsPlans";
            operations.add(op);bodies.add(body);int code=200;String response;
            if(mode[0].equals("denied")&&op.startsWith("GetCost")){code=400;response="{\"__type\":\"AccessDeniedException\",\"message\":\"synthetic denied\"}";}
            else if(mode[0].equals("disabled")&&op.equals("GetCostAndUsageWithResources")){code=400;response="{\"__type\":\"DataUnavailableException\",\"message\":\"resource level data is not enabled\"}";}
            else response=fixture(op,body,mode[0]);
            byte[] bytes=cbor?asCbor(software.amazon.awssdk.protocols.jsoncore.JsonNodeParser.create().parse(response)):response.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type",cbor?"application/cbor":response.startsWith("<")?"text/xml":"application/x-amz-json-1.1");
            exchange.sendResponseHeaders(code,bytes.length);try(var out=exchange.getResponseBody()){out.write(bytes);}
        });server.start();
        Path dir=Files.createTempDirectory("lmaws-spend-http-");URI endpoint=URI.create("http://127.0.0.1:"+server.getAddress().getPort());var credentials=StaticCredentialsProvider.create(AwsBasicCredentials.create("test","test"));
        LocalDate end=LocalDate.now(ZoneOffset.UTC);int assertions=0;
        try{
            CostLedger ledger=new CostLedger("transport","transport","us-east-1",dir.resolve("full.jsonl"),new BigDecimal("0.25"),false);
            try(var source=new SpendAwsSource(ledger,endpoint,credentials)){
                var report=SpendReport.collect(source,"all",end,30,10,ledger);
                if(!report.summary().get("status").equals("complete"))throw new AssertionError("SDK report failed: "+report.json());assertions++;
                for(String op:List.of("DescribeInstances","DescribeNetworkInterfaces","DescribeAddresses","DescribeVolumes","DescribeSnapshots","DescribeReservedInstances","ListFunctions","ListTables","DescribeTable","DescribeSavingsPlans","GetMetricData","GetProducts","GetSavingsPlansUtilization","GetSavingsPlansCoverage","GetSavingsPlansPurchaseRecommendation","GetReservationUtilization","GetReservationCoverage","GetReservationPurchaseRecommendation")){if(!operations.contains(op))throw new AssertionError("SDK path not exercised "+op);assertions++;}
                if(!report.section("sp_utilization").getFirst().get("unused_commitment_usd").equals("30"))throw new AssertionError("SP typed numeric projection");assertions++;
                if(!report.section("ri_utilization").getFirst().get("unused_amortized_usd").equals("20"))throw new AssertionError("RI unused cost must not use total amortized fee");assertions++;
                if(!report.section("lambda_spend").getFirst().get("metric_status").equals("complete")||!report.section("dynamodb_spend").getFirst().get("metric_status").equals("complete"))throw new AssertionError("CBOR metric results must actually join workloads");assertions++;
                if(!report.section("ec2_resources").getFirst().get("hourly_usd").equals("0.0104"))throw new AssertionError("parsed on-demand catalog price");assertions++;
                if(bodies.stream().noneMatch(x->x.contains("Owner.1=self")))throw new AssertionError("snapshots must filter owner self");assertions++;
                long old=ledger.ceRequests();source.costs(end.minusDays(30),end,"DAILY","SERVICE","",false);if(ledger.ceRequests()!=old)throw new AssertionError("CE cache charged twice");assertions++;
            }
            mode[0]="pagination";CostLedger paged=new CostLedger("paged","paged","us-east-1",dir.resolve("paged.jsonl"),new BigDecimal("0.25"),false);
            try(var source=new SpendAwsSource(paged,endpoint,credentials)){var rows=source.costs(end.minusDays(2),end,"DAILY","SERVICE","",false);if(rows.size()!=2||paged.ceRequests()!=2)throw new AssertionError("two pages must bill twice");assertions++;}
            mode[0]="cw_pages";CostLedger cwLedger=new CostLedger("cwpages","cwpages","us-east-1",dir.resolve("cwpages.jsonl"),new BigDecimal("0.25"),false);
            try(var source=new SpendAwsSource(cwLedger,endpoint,credentials)){
                var rows=source.metrics(List.of(new SpendSource.Metric("m0","us-east-1","AWS/EC2","NetworkOut","InstanceId","i-synthetic","Sum",3600)),end.minusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant(),end.atStartOfDay(ZoneOffset.UTC).toInstant());
                if(rows.size()!=2||cwLedger.metricRequests()!=2||cwLedger.metricUnits()!=2)throw new AssertionError("every CBOR metric page charged");assertions++;
            }
            mode[0]="denied";try(var source=new SpendAwsSource(null,endpoint,credentials)){boolean denied=false;try{source.costs(end.minusDays(1),end,"DAILY","SERVICE","",false);}catch(SpendSource.Unavailable e){denied=e.reason.equals("AccessDeniedException");}if(!denied)throw new AssertionError("AccessDenied must be precise");assertions++;}
            mode[0]="disabled";try(var source=new SpendAwsSource(null,endpoint,credentials)){boolean disabled=false;try{source.costs(end.minusDays(14),end,"DAILY","RESOURCE_ID","Amazon Elastic Compute Cloud - Compute",true);}catch(SpendSource.Unavailable e){disabled=e.reason.equals("RESOURCE_LEVEL_NOT_ENABLED");}if(!disabled)throw new AssertionError("resource opt-in detection");assertions++;}
            mode[0]="empty";try(var source=new SpendAwsSource(null,endpoint,credentials)){if(!source.inventory("savings_plans").isEmpty()&&!source.inventory("savings_plans").getFirst().getOrDefault("status","").equals("no_data"))throw new AssertionError("absent plans must be explicit");assertions++;if(!source.costs(end.minusDays(1),end,"DAILY","SERVICE","",false).isEmpty())throw new AssertionError("empty CE");assertions++;}
            mode[0]="normal";CostLedger cap=new CostLedger("cap","cap","us-east-1",dir.resolve("cap.jsonl"),new BigDecimal("0.01"),false);
            try(var source=new SpendAwsSource(cap,endpoint,credentials)){source.costs(end.minusDays(1),end,"DAILY","SERVICE","",false);int before=operations.size();boolean refused=false;try{source.costs(end.minusDays(2),end,"DAILY","SERVICE","",false);}catch(CostLedger.BudgetExceeded e){refused=true;}if(!refused||before!=operations.size())throw new AssertionError("cap must refuse before HTTP");assertions++;}
            if(nativeBinary!=null){
                mode[0]="normal";Path nativeDir=Files.createDirectories(dir.resolve("native"));Path schema=nativeDir.resolve("schema.json"),program=nativeDir.resolve("run.lms"),bytecode=nativeDir.resolve("run.dslb");
                ProcessBuilder schemaCommand=new ProcessBuilder(nativeBinary,"--dsl-schema","--json").redirectOutput(schema.toFile()).redirectError(nativeDir.resolve("schema.log").toFile());
                waitFor(schemaCommand.start(),60,"native schema");
                String source="p = _lmcode_ schema="+Jsons.encode(schema.toString().replace('\\','/'))+";\nlet spend = aws.spend(\"all\",30,10,0.25);\nspend.write(\"native-report\");\nend _lmcode_\nsavedsl(p,"+Jsons.encode(bytecode.toString().replace('\\','/'))+");\n";
                Files.writeString(program,source);
                List<String> compile=new ArrayList<>();if(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"))compile.addAll(List.of("cmd.exe","/c"));compile.add(System.getenv().getOrDefault("LMSCRIPT_BIN","lmscript"));compile.add(program.toString());
                ProcessBuilder compiler=new ProcessBuilder(compile).directory(nativeDir.toFile()).redirectOutput(nativeDir.resolve("compile.log").toFile()).redirectErrorStream(true);
                compiler.environment().put("LMAWS_SPEND_LIVE","0");compiler.environment().put("LMAWS_LIVE","0");waitFor(compiler.start(),90,"native fixture compile");
                ProcessBuilder run=new ProcessBuilder(nativeBinary,"--dsl",bytecode.toString()).directory(nativeDir.toFile()).redirectOutput(nativeDir.resolve("run.log").toFile()).redirectErrorStream(true);
                run.environment().putAll(Map.of("AWS_PROFILE","default","AWS_DEFAULT_PROFILE","default","AWS_REGION","us-east-1","LMAWS_SPEND_REGIONS","us-east-1","LMAWS_ENDPOINT",endpoint.toString(),"LMAWS_SPEND_LIVE","1","LMAWS_LIVE","1","CI","true"));
                waitFor(run.start(),180,"native SDK fixture");
                var result=software.amazon.awssdk.protocols.jsoncore.JsonNodeParser.create().parse(Files.readString(nativeDir.resolve("native-report/report.json")));
                if(!result.field("summary").orElseThrow().field("status").orElseThrow().asString().equals("complete"))throw new AssertionError("native SDK fixture returned incomplete report; inspect "+nativeDir);
                assertions++;
            }
        } finally {server.stop(0);}
        System.out.println("PASS "+assertions+" SDK loopback checks: every spend section, pagination, denied, empty, disabled, prices and pre-dispatch cap");
    }
    private static void waitFor(Process process,int seconds,String label)throws Exception{
        if(!process.waitFor(seconds,java.util.concurrent.TimeUnit.SECONDS)){process.destroyForcibly();throw new AssertionError(label+" timed out");}
        if(process.exitValue()!=0)throw new AssertionError(label+" exited "+process.exitValue());
    }
    private static Object plain(software.amazon.awssdk.protocols.jsoncore.JsonNode node){
        if(node.isObject()){Map<String,Object> out=new LinkedHashMap<>();node.asObject().forEach((k,v)->out.put(k,plain(v)));return out;}
        if(node.isArray())return node.asArray().stream().map(SpendSourceChecks::plain).toList();
        if(node.isString())return node.asString();if(node.isNumber())return new java.math.BigDecimal(node.asNumber());if(node.isBoolean())return node.asBoolean();return null;
    }
    private static byte[] asCbor(software.amazon.awssdk.protocols.jsoncore.JsonNode node)throws java.io.IOException {
        var out=new java.io.ByteArrayOutputStream();try(var generator=new software.amazon.awssdk.thirdparty.jackson.dataformat.cbor.CBORFactory().createGenerator(out)){writeNode(generator,node);}return out.toByteArray();
    }
    private static void writeNode(software.amazon.awssdk.thirdparty.jackson.core.JsonGenerator g,software.amazon.awssdk.protocols.jsoncore.JsonNode n)throws java.io.IOException {
        if(n.isObject()){g.writeStartObject();for(var entry:n.asObject().entrySet()){g.writeFieldName(entry.getKey());writeNode(g,entry.getValue());}g.writeEndObject();}
        else if(n.isArray()){g.writeStartArray();for(var value:n.asArray())writeNode(g,value);g.writeEndArray();}
        else if(n.isString())g.writeString(n.asString());else if(n.isNumber())g.writeNumber(Double.parseDouble(n.asNumber()));else if(n.isBoolean())g.writeBoolean(n.asBoolean());else g.writeNull();
    }
    private static String fixture(String op,String body,String mode){
        if(op.equals("GetCostAndUsage")||op.equals("GetCostAndUsageWithResources")){
            if(mode.equals("empty"))return "{\"ResultsByTime\":[]}";
            String next=mode.equals("pagination")&&!body.contains("NextPageToken")?",\"NextPageToken\":\"second\"":"";
            return "{\"ResultsByTime\":[{\"TimePeriod\":{\"Start\":\"2026-10-01\",\"End\":\"2026-10-02\"},\"Estimated\":false,\"Groups\":[{\"Keys\":[\"AWS Lambda\"],\"Metrics\":{\"UnblendedCost\":{\"Amount\":\"1.20\",\"Unit\":\"USD\"},\"AmortizedCost\":{\"Amount\":\"1.10\",\"Unit\":\"USD\"},\"UsageQuantity\":{\"Amount\":\"3\",\"Unit\":\"GB\"}}}]}]"+next+"}";
        }
        if(op.equals("GetSavingsPlansUtilization"))return "{\"Total\":{\"Utilization\":{\"TotalCommitment\":\"720\",\"UsedCommitment\":\"690\",\"UnusedCommitment\":\"30\",\"UtilizationPercentage\":\"95.833333\"}}}";
        if(op.equals("GetSavingsPlansCoverage"))return "{\"SavingsPlansCoverages\":[{\"Coverage\":{\"SpendCoveredBySavingsPlans\":\"100\",\"OnDemandCost\":\"20\",\"TotalCost\":\"120\",\"CoveragePercentage\":\"83.333333\"}}]}";
        if(op.equals("GetSavingsPlansPurchaseRecommendation"))return "{\"SavingsPlansPurchaseRecommendation\":{\"SavingsPlansPurchaseRecommendationSummary\":{\"EstimatedSavingsAmount\":\"7.50\",\"EstimatedSavingsPercentage\":\"10\",\"HourlyCommitmentToPurchase\":\"0.10\",\"TotalRecommendationCount\":\"1\"}}}";
        if(op.equals("GetReservationUtilization"))return "{\"Total\":{\"UtilizationPercentage\":\"80\",\"PurchasedHours\":\"100\",\"TotalActualHours\":\"80\",\"UnusedHours\":\"20\",\"RICostForUnusedHours\":\"20\",\"TotalAmortizedFee\":\"100\"}}";
        if(op.equals("GetReservationCoverage"))return "{\"CoveragesByTime\":[{\"Total\":{\"CoverageHours\":{\"CoverageHoursPercentage\":\"62.5\",\"OnDemandHours\":\"30\",\"ReservedHours\":\"50\",\"TotalRunningHours\":\"80\"}}}]}";
        if(op.equals("GetReservationPurchaseRecommendation"))return "{\"Recommendations\":[{\"RecommendationSummary\":{\"TotalEstimatedMonthlySavingsAmount\":\"7.50\",\"TotalEstimatedMonthlySavingsPercentage\":\"10\",\"CurrencyCode\":\"USD\"}}]}";
        if(op.equals("DescribeSavingsPlans"))return mode.equals("empty")?"{\"savingsPlans\":[]}":"{\"savingsPlans\":[{\"savingsPlanId\":\"synthetic-plan\",\"state\":\"active\",\"savingsPlanType\":\"Compute\",\"start\":\"2026-01-01\",\"end\":\"2027-01-01\",\"commitment\":\"1.0\"}]}";
        if(op.equals("GetProducts")){String price=Jsons.encodeRaw(Map.of("terms",Map.of("OnDemand",Map.of("term",Map.of("priceDimensions",Map.of("dimension",Map.of("unit","Hrs","pricePerUnit",Map.of("USD","0.0104"))))))));return Jsons.encodeRaw(Map.of("PriceList",List.of(price)));}
        if(op.equals("ListFunctions"))return "{\"Functions\":[{\"FunctionName\":\"synthetic-function\",\"FunctionArn\":\"arn:aws:lambda:us-east-1:123456789012:function:synthetic-function\",\"MemorySize\":512,\"Architectures\":[\"x86_64\"]}]}";
        if(op.equals("ListTables"))return "{\"TableNames\":[\"synthetic-table\"]}";
        if(op.equals("DescribeTable"))return "{\"Table\":{\"TableName\":\"synthetic-table\",\"TableArn\":\"arn:aws:dynamodb:us-east-1:123456789012:table/synthetic-table\",\"TableSizeBytes\":2048,\"ItemCount\":8,\"BillingModeSummary\":{\"BillingMode\":\"PROVISIONED\"},\"ProvisionedThroughput\":{\"ReadCapacityUnits\":100,\"WriteCapacityUnits\":50}}}";
        if(op.equals("GetMetricData")){
            
            var json=software.amazon.awssdk.protocols.jsoncore.JsonNodeParser.create().parse(body);
            List<Map<String,Object>> metrics=new ArrayList<>();
            for(var query:json.field("MetricDataQueries").orElseGet(()->json.field("metricDataQueries").orElseThrow()).asArray())metrics.add(Map.of("Id",query.field("Id").orElseGet(()->query.field("id").orElseThrow()).asString(),"Values",List.of(10.0),"StatusCode","Complete"));
            Map<String,Object> response=new LinkedHashMap<>();response.put("MetricDataResults",metrics);
            if(mode.equals("cw_pages")&&!body.contains("NextToken"))response.put("NextToken","cw-next");
            return Jsons.encodeRaw(response);
        }
        String payload=switch(op){
            case "DescribeInstances"->"<reservationSet><item><instancesSet><item><instanceId>i-synthetic</instanceId><instanceType>t3.micro</instanceType><instanceState><name>running</name><code>16</code></instanceState><platformDetails>Linux/UNIX</platformDetails></item></instancesSet></item></reservationSet>";
            case "DescribeNetworkInterfaces"->"<networkInterfaceSet><item><networkInterfaceId>eni-synthetic</networkInterfaceId><association><publicIp>198.51.100.9</publicIp></association><interfaceType>interface</interfaceType></item></networkInterfaceSet>";
            case "DescribeAddresses"->"<addressesSet><item><allocationId>eipalloc-synthetic</allocationId><publicIp>198.51.100.7</publicIp></item></addressesSet>";
            case "DescribeVolumes"->"<volumeSet><item><volumeId>vol-synthetic</volumeId><size>40</size><volumeType>gp2</volumeType><status>available</status><iops>120</iops></item></volumeSet>";
            case "DescribeSnapshots"->"<snapshotSet><item><snapshotId>snap-synthetic</snapshotId><volumeSize>100</volumeSize><status>completed</status></item></snapshotSet>";
            case "DescribeReservedInstances"->"<reservedInstancesSet><item><reservedInstancesId>ri-synthetic</reservedInstancesId><instanceType>t3.micro</instanceType><instanceCount>1</instanceCount><state>active</state><duration>31536000</duration><fixedPrice>0</fixedPrice></item></reservedInstancesSet>";
            case "GetMetricData"->{StringBuilder results=new StringBuilder();for(int n=1;n<=100;n++){String prefix="MetricDataQueries.member."+n+".";Map<String,String> form=new LinkedHashMap<>();for(String part:body.split("&")){String[]kv=part.split("=",2);form.put(URLDecoder.decode(kv[0],StandardCharsets.UTF_8),kv.length==2?URLDecoder.decode(kv[1],StandardCharsets.UTF_8):"");}String id=form.get(prefix+"Id");if(id==null)continue;results.append("<member><Id>").append(id).append("</Id><StatusCode>Complete</StatusCode><Values><member>10</member></Values><Timestamps><member>2026-10-01T00:00:00Z</member></Timestamps></member>");}yield "<GetMetricDataResult><MetricDataResults>"+results+"</MetricDataResults></GetMetricDataResult>";}
            default->"";
        };
        return "<"+op+"Response xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\">"+payload+"</"+op+"Response>";
    }
}
