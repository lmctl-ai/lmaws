package ai.lmctl.lmaws;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Real SDK transports, synthetic credentials, loopback only; never contacts AWS. */
public final class ScenarioTransportChecks {
    static final String ACCOUNT="000000000000", RUN="cafe01", FN="lmaws_transport", RULE="lmaws_transport_rule";
    static final String ARN="arn:aws:lambda:us-east-1:"+ACCOUNT+":function:"+FN;
    static final String RULE_ARN="arn:aws:events:us-east-1:"+ACCOUNT+":rule/"+RULE;
    public static void main(String[] args)throws Exception {
        var requests=Collections.synchronizedList(new ArrayList<String>());
        var foreign=new AtomicBoolean();var ruleExists=new AtomicBoolean();var targetFailed=new AtomicBoolean();var notificationsExist=new AtomicBoolean();
        int port=Integer.parseInt(System.getenv("LMAWS_TEST_PORT"));
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",port),0);
        server.createContext("/",e->{
            String method=e.getRequestMethod(),path=e.getRequestURI().getPath(),query=e.getRequestURI().getQuery();
            String body=new String(e.getRequestBody().readAllBytes(),StandardCharsets.UTF_8),target=e.getRequestHeaders().getFirst("X-Amz-Target");
            requests.add(method+" "+path+" "+query+" "+target+" "+body);
            String tag=foreign.get()?"different-run":RUN,out="{}";int status=200;String type="application/json";
            if(target!=null&&target.endsWith("DescribeRule")){
                if(ruleExists.get())out="{\"Arn\":\""+RULE_ARN+"\"}";
                else {status=400;out="{\"__type\":\"ResourceNotFoundException\",\"message\":\"missing\"}";e.getResponseHeaders().add("x-amzn-ErrorType","ResourceNotFoundException");}
            } else if(target!=null&&target.endsWith("PutRule")){ruleExists.set(true);out="{\"RuleArn\":\""+RULE_ARN+"\"}";}
            else if(target!=null&&(target.endsWith("ListTagsForResource")||target.endsWith("ListTagsOfResource")))out="{\"Tags\":[{\"Key\":\"lmaws_test\",\"Value\":\""+tag+"\"}]}";
            else if(target!=null&&target.endsWith("PutTargets"))out="{\"FailedEntryCount\":"+(targetFailed.get()?1:0)+",\"FailedEntries\":[]}";
            else if(target!=null&&target.endsWith("RemoveTargets"))out="{\"FailedEntryCount\":0}";
            else if(target!=null&&target.endsWith("DeleteRule")){ruleExists.set(false);}
            else if(target!=null&&target.endsWith("DescribeTable"))out="{\"Table\":{\"TableArn\":\"arn:aws:dynamodb:us-east-1:"+ACCOUNT+":table/lmaws_"+RUN+"_table\",\"TableStatus\":\"ACTIVE\"}}";
            else if(path.equals("/2015-03-31/functions")&&method.equals("POST"))out="{\"FunctionArn\":\""+ARN+"\",\"State\":\"Active\"}";
            else if(path.endsWith("/invocations"))out="{\"ok\":true}";
            else if(path.endsWith("/url"))out="{\"FunctionUrl\":\"https://fixture.lambda-url.us-east-1.on.aws/\",\"AuthType\":\"NONE\"}";
            else if(path.startsWith("/2015-03-31/functions/")&&method.equals("GET"))out="{\"Configuration\":{\"FunctionArn\":\""+ARN+"\",\"State\":\"Active\"},\"Tags\":{\"lmaws_test\":\""+tag+"\"}}";
            else if(query!=null&&query.contains("tagging")){type="application/xml";out="<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet><Tag><Key>lmaws_test</Key><Value>"+tag+"</Value></Tag></TagSet></Tagging>";}
            else if(query!=null&&query.contains("notification")&&method.equals("GET")){type="application/xml";out="<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"+(notificationsExist.get()?"<QueueConfiguration><Id>foreign</Id><Queue>arn:aws:sqs:us-east-1:"+ACCOUNT+":other</Queue><Event>s3:ObjectCreated:Put</Event></QueueConfiguration>":"")+"</NotificationConfiguration>";}
            if(method.equals("DELETE")){status=204;out="";}
            e.getResponseHeaders().add("Content-Type",type);byte[] bytes=out.getBytes(StandardCharsets.UTF_8);
            e.sendResponseHeaders(status,status==204?-1:bytes.length);if(bytes.length>0)e.getResponseBody().write(bytes);e.close();
        });server.start();
        try(var backend=new AwsBackend("us-east-1",false)){
            backend.createLambda(FN,"arn:aws:iam::"+ACCOUNT+":role/lmaws_lambda_exec","python3.12","app.handler","def handler(e,c): return e",128,10,RUN);
            backend.invokeLambda(ARN,"{}");backend.lambdaUrl(ARN,"public offline transport fixture");
            check(requests.stream().anyMatch(x->x.contains("InvokeFunctionUrl")&&x.contains("NONE")),"URL permission missing");
            check(requests.stream().anyMatch(x->x.contains("InvokedViaFunctionUrl")&&x.contains("lambda:InvokeFunction")),"URL-only invoke permission missing");
            var create=requests.stream().filter(x->x.startsWith("POST /2015-03-31/functions ")).findFirst().orElseThrow();
            var encoded=(Map<?,?>)io.lmctl.lmcode.Json.parse(create.substring(create.indexOf("{\"")));
            var code=(Map<?,?>)encoded.get("Code");byte[] zip=Base64.getDecoder().decode((String)code.get("ZipFile"));
            try(var in=new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(zip))){check("app.py".equals(in.getNextEntry().getName()),"zip entry");check(new String(in.readAllBytes(),StandardCharsets.UTF_8).contains("def handler"),"zip source");}
            foreign.set(true);int writes=mutationCount(requests);refused(()->backend.deleteLambda(ARN,RUN));refused(()->backend.lambdaUrl(ARN,"reason"));check(writes==mutationCount(requests),"foreign Lambda mutated");foreign.set(false);
            ruleExists.set(true);writes=mutationCount(requests);refused(()->backend.putEventRule(RULE,"rate(1 minute)",RUN));check(writes==mutationCount(requests),"existing rule overwritten");ruleExists.set(false);
            backend.putEventRule(RULE,"rate(1 minute)",RUN);backend.putEventTarget(RULE,ARN,RUN);
            check(requests.stream().anyMatch(x->x.contains("events.amazonaws.com")&&x.contains("SourceArn")&&x.contains(RULE_ARN)),"schedule invoke permission missing");
            targetFailed.set(true);refused(()->backend.putEventTarget(RULE,ARN,RUN));targetFailed.set(false);
            foreign.set(true);writes=mutationCount(requests);refused(()->backend.deleteEventRule(RULE,RUN));refused(()->backend.putEventTarget(RULE,ARN,RUN));check(writes==mutationCount(requests),"foreign rule mutated");foreign.set(false);
            backend.tableTtl("lmaws_"+RUN+"_table","expires_at",RUN);backend.tableItem("lmaws_"+RUN+"_table","entry","value",RUN);
            foreign.set(true);writes=mutationCount(requests);refused(()->backend.tableTtl("lmaws_"+RUN+"_table","expires_at",RUN));refused(()->backend.tableItem("lmaws_"+RUN+"_table","entry","value",RUN));check(writes==mutationCount(requests),"foreign table mutated");foreign.set(false);
            notificationsExist.set(true);writes=mutationCount(requests);refused(()->backend.s3Notification("lmaws-"+RUN+"-bucket",ARN,"s3:ObjectCreated:Put",RUN));check(writes==mutationCount(requests),"existing notifications overwritten");notificationsExist.set(false);
            backend.s3Notification("lmaws-"+RUN+"-bucket",ARN,"s3:ObjectCreated:Put",RUN);
            backend.deleteEventRule(RULE,RUN);backend.deleteLambda(ARN,RUN);
            refused(()->new EventRule("lmaws_bad","rate(",RUN));refused(()->new LambdaFunction(FN,"other","python3.12","app.handler","",128,10,RUN));
            System.out.println("PASS actual Lambda/EventBridge/DynamoDB/S3 SDK transports, permissions, ZIP and foreign-resource refusal");
        }finally{server.stop(0);}
    }
    private static int mutationCount(List<String> requests){return (int)requests.stream().filter(x->x.startsWith("DELETE ")||x.startsWith("PUT ")||x.startsWith("POST ")&&!x.contains("GetFunction")&&!x.contains("Describe")&&!x.contains("ListTags")).count();}
    private static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    private static void refused(Runnable op){try{op.run();}catch(IllegalArgumentException|IllegalStateException|SecurityException expected){return;}throw new AssertionError("unsafe request accepted");}
}
