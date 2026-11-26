package ai.lmctl.lmaws;
import java.util.*;
public final class SdkCallRedactionChecks {
 public static void main(String[] args) {
  Object input=Map.of("HttpHeaderConfig",Map.of("HttpHeaderName","X-Origin-Env","Values",List.of("private-origin-marker")),"Environment",List.of(Map.of("Name","API_TOKEN","Value","private-env-marker"),Map.of("Name","PORT","Value","18756")));
  String out=Jsons.encodeRaw(SdkCall.redact(input,Set.of()));
  if(out.contains("private-origin-marker")||out.contains("private-env-marker")||!out.contains("18756"))throw new AssertionError("redaction regression");
  System.out.println("SDK read redaction: ALB header values and case-insensitive environment secrets passed");
 }
}
