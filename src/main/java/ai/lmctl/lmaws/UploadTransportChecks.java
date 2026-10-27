package ai.lmctl.lmaws;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.Executors;

/** SDK loopback proof for actual SigV4 presigning and conditional DynamoDB dispatch. */
public final class UploadTransportChecks {
  public static void main(String[] args) throws Exception {
    var seen = new StringBuilder();
    var tag = new java.util.concurrent.atomic.AtomicReference<>("cafe10");
    int requestedPort = Integer.parseInt(System.getenv().getOrDefault("LMAWS_TEST_PORT", "0"));
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", requestedPort), 0);
    server.createContext("/", ex -> respond(ex, seen, tag.get())); var pool=Executors.newCachedThreadPool();server.setExecutor(pool); server.start();
    int port = server.getAddress().getPort(); var dir = Files.createTempDirectory("lmaws-upload-transport-");
    var ledger = new CostLedger("cafe10", "upload_transport", "us-east-1", dir.resolve("cost.jsonl"), new BigDecimal("0.05"), true);
    String endpoint = "http://127.0.0.1:" + port;
    if (!endpoint.equals(System.getenv("LMAWS_ENDPOINT"))) throw new IllegalStateException("loopback test requires LMAWS_ENDPOINT=" + endpoint);
    try (var backend = new AwsBackend("us-east-1", false, ledger)) {
      require(backend.owned("bucket", "lmaws-site-cafe10", "cafe10"), "exact web bucket ownership");
      require(backend.owned("bucket", "lmaws-cafe10-gallery", "cafe10"), "legacy upload bucket ownership");
      require(!backend.owned("bucket", "lmaws-site-cafe10-extra", "cafe10"), "near-match bucket refused");
      tag.set("foreign");require(!backend.owned("bucket","lmaws-site-cafe10","cafe10"),"foreign web bucket tag refused");
      tag.set("");require(!backend.owned("bucket","lmaws-site-cafe10","cafe10"),"missing web bucket run tag refused");
      tag.set("cafe10");
      var signed = backend.s3PresignPut("lmaws-cafe10-gallery", "uploads/demo.png", 512, "image/png", 300, "cafe10");
      String url = signed.get("url");
      require(url.contains("X-Amz-Signature="), "missing SigV4 signature");
      String headers = query(url, "X-Amz-SignedHeaders");
      require(headers.contains("content-length") && headers.contains("content-type") && headers.contains("host"), "signed headers omit content bounds: " + headers);
      var conditional = backend.tableItemConditional("lmaws_cafe10_gallery", "first", "payload", "attribute_not_exists(pk)", "cafe10");
      require("attribute_not_exists(pk)".equals(conditional.get("condition")), "conditional result");
      require(seen.toString().contains("ConditionExpression") && seen.toString().contains("attribute_not_exists(pk)"), "conditional request was not dispatched");
    } finally { server.stop(0); pool.shutdownNow(); }
    System.out.println("PASS actual loopback SDK SigV4 signed headers and DynamoDB condition dispatch");
  }
  private static String query(String url, String key) { for (String p : url.substring(url.indexOf('?') + 1).split("&")) { String[] kv=p.split("=",2); if (kv.length==2 && kv[0].equals(key)) return URLDecoder.decode(kv[1], StandardCharsets.UTF_8); } return ""; }
  private static void respond(HttpExchange ex, StringBuilder seen, String tag) throws java.io.IOException {
    String target=ex.getRequestHeaders().getFirst("X-Amz-Target"); byte[] body=ex.getRequestBody().readAllBytes(); String text=new String(body,StandardCharsets.UTF_8); synchronized(seen){seen.append(text);}
    String out;
    if (target != null && target.contains("DescribeTable")) out="{\"Table\":{\"TableArn\":\"arn:aws:dynamodb:us-east-1:000000000000:table/lmaws_cafe10_gallery\"}}";
    else if (target != null && target.contains("ListTagsOfResource")) out="{\"Tags\":[{\"Key\":\"lmaws_test\",\"Value\":\"cafe10\"}]}";
    else if (target != null && target.contains("PutItem")) out="{}";
    else if (ex.getRequestMethod().equals("GET")) out="<Tagging><TagSet><Tag><Key>lmaws_test</Key><Value>"+tag+"</Value></Tag></TagSet></Tagging>";
    else out="{}";
    byte[] bytes=out.getBytes(StandardCharsets.UTF_8); ex.getResponseHeaders().set("Content-Type","application/json"); ex.sendResponseHeaders(200,bytes.length); ex.getResponseBody().write(bytes); ex.close();
  }
  private static void require(boolean ok,String msg){if(!ok)throw new AssertionError(msg);}
}
