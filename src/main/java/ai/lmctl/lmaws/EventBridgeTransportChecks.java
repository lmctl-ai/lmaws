package ai.lmctl.lmaws;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/** Exercises EventBridge SDK JSON operations against a loopback transport. */
public final class EventBridgeTransportChecks {
  public static void main(String[] args) throws Exception { run(); }
  public static void run() throws Exception {
    var seen=new ArrayList<String>(); var server=HttpServer.create(new InetSocketAddress("127.0.0.1",18766),0);
    server.createContext("/",e->{var body=e.getRequestBody().readAllBytes();String target=e.getRequestHeaders().getFirst("X-Amz-Target");seen.add(target+" "+new String(body,StandardCharsets.UTF_8));String out=target!=null&&target.contains("PutRule")?"{\"RuleArn\":\"arn:aws:events:us-east-1:000000000000:rule/lmaws_rule\"}":"{}";e.sendResponseHeaders(200,out.getBytes(StandardCharsets.UTF_8).length);e.getResponseBody().write(out.getBytes(StandardCharsets.UTF_8));e.close();}); server.start();
    try {var b=new AwsBackend("us-east-1",false);var r=b.putEventRule("lmaws_rule","rate(1 minute)","evt01");b.putEventTarget("lmaws_rule","arn:aws:lambda:us-east-1:000000000000:function:lmaws_fn","evt01");b.deleteEventRule("lmaws_rule","evt01");b.close();if(seen.size()!=4||seen.stream().noneMatch(x->x.contains("lmaws_test"))||seen.stream().noneMatch(x->x.contains("lmaws-target")))throw new AssertionError("EventBridge SDK request contract: "+seen);} finally {server.stop(0);}
  }
}
