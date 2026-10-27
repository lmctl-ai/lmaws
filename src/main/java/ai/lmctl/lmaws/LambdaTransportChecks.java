package ai.lmctl.lmaws;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Exercises AWS SDK Lambda HTTP serialization through a loopback endpoint. */
public final class LambdaTransportChecks {
  private LambdaTransportChecks() {}
  public static void run() throws Exception {
    var seen=new ArrayList<String>();
    HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",18765),0);
    server.createContext("/", exchange->{byte[] body=exchange.getRequestBody().readAllBytes();String path=exchange.getRequestURI().getPath();String text=new String(body,StandardCharsets.UTF_8);seen.add(exchange.getRequestMethod()+" "+path+" "+text);String out;
      if(path.equals("/2015-03-31/functions")) out="{\"FunctionName\":\"lmaws_transport\",\"FunctionArn\":\"arn:aws:lambda:us-east-1:000000000000:function:lmaws_transport\",\"State\":\"Active\"}";
      else if(path.contains("/invocations")) out="{\"ok\":true}";
      else if(path.contains("/url")) out="{\"FunctionUrl\":\"https://lmaws-transport.lambda-url.local/\",\"AuthType\":\"NONE\"}";
      else out="";
      exchange.sendResponseHeaders(exchange.getRequestMethod().equals("DELETE")?204:200,out.getBytes(StandardCharsets.UTF_8).length);exchange.getResponseBody().write(out.getBytes(StandardCharsets.UTF_8));exchange.close();});
    server.start();
    try {
      var backend=new AwsBackend("us-east-1",false);
      var created=backend.createLambda("lmaws_transport","arn:aws:iam::000000000000:role/lmaws_lambda_exec","python3.12","app.handler","def handler(e,c): return e",256,30,"transport01");
      if(!created.get("arn").contains("lmaws_transport"))throw new AssertionError("create ARN");
      backend.invokeLambda(created.get("arn"),"{}");backend.lambdaUrl(created.get("arn"),"transport test");backend.deleteLambda(created.get("arn"),"transport01");backend.close();
      if(seen.size()!=4||seen.stream().noneMatch(x->x.contains("lmaws_test"))||seen.stream().noneMatch(x->x.contains("lmaws_lambda_exec")))throw new AssertionError("Lambda SDK request contract: "+seen);
    } finally {server.stop(0);}
  }
}
