package ai.lmctl.lmaws;
import java.util.*;
import java.time.*;
/** Deterministic no-credential fixture for the CloudFront traffic API. */
final class CloudFrontTrafficDemo {
    static String collect(String domain,String start,String end){
        Instant from=parse(start),to=parse(end);if(!from.isBefore(to)||Duration.between(from,to).compareTo(Duration.ofDays(31))>0)throw new IllegalArgumentException("invalid demo range");
        Map<String,Object> d=new LinkedHashMap<>();d.put("id","EDMOEXAMPLE");d.put("domain_name","d111111abcdef8.cloudfront.net");d.put("aliases",List.of(domain));d.put("enabled",true);d.put("logging_enabled",false);d.put("logging_bucket","");d.put("web_acl_id","");d.put("origins",List.of("origin.example.com"));Map<String,Object> m=new LinkedHashMap<>();for(String key:List.of("Requests","BytesDownloaded","4xxErrorRate","5xxErrorRate")){List<Map<String,Object>> points=new ArrayList<>();for(Instant t=from;t.isBefore(to);t=t.plusSeconds(3600)){double req=Duration.between(from,t).toDays()<7?100.0:1000.0;double value=key.equals("Requests")?req:key.equals("BytesDownloaded")?req*4096:key.equals("4xxErrorRate")?0.1:0.0;points.add(Map.of("timestamp",t.toString(),"value",value));}m.put(key,points);}d.put("metrics",m);Map<String,Object> out=new LinkedHashMap<>();out.put("mode","synthetic");out.put("domain",domain);out.put("query_start",from.toString());out.put("query_end",to.toString());out.put("requested_end",to.toString());out.put("metric_region","us-east-1");out.put("period_seconds",3600);out.put("distributions",List.of(d));out.put("warnings",List.of());out.put("query_estimate_usd","0.00000");return Jsons.encodeRaw(out);
    }
    private static Instant parse(String value){try{return Instant.parse(value);}catch(Exception ignored){return LocalDate.parse(value).atStartOfDay(ZoneOffset.UTC).toInstant();}}
}
