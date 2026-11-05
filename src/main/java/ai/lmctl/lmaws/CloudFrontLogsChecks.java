package ai.lmctl.lmaws;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.lang.reflect.Proxy;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.cloudfront.*;
import software.amazon.awssdk.services.cloudfront.model.*;
import software.amazon.awssdk.services.s3.*;
import software.amazon.awssdk.services.s3.model.*;

/** Proxy SDK checks; no HTTP, credentials or AWS changes. */
public final class CloudFrontLogsChecks {
    private static int gets,checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        var cf=(CloudFrontClient)Proxy.newProxyInstance(CloudFrontLogsChecks.class.getClassLoader(),new Class[]{CloudFrontClient.class},(p,m,a)->{
            if(m.getName().equals("getDistributionConfig"))return GetDistributionConfigResponse.builder().distributionConfig(DistributionConfig.builder().logging(LoggingConfig.builder().enabled(true).includeCookies(false).bucket("example-logs.s3.amazonaws.com").prefix("logs").build()).build()).build();
            if(m.getName().equals("close"))return null;
            throw new AssertionError("Unexpected CloudFront operation: "+m.getName());
        });
        byte[] body={1,2,3};
        var s3=(S3Client)Proxy.newProxyInstance(CloudFrontLogsChecks.class.getClassLoader(),new Class[]{S3Client.class},(p,m,a)->{
            if(m.getName().equals("listObjectsV2")){
                var request=(ListObjectsV2Request)a[0];
                check(request.bucket().equals("example-logs"),"bucket comes from legacy config");
                check(request.prefix().equals("logs/DTEST.2026-11-01-"),"directory prefix and UTC day/hour key convention");
                return ListObjectsV2Response.builder().contents(
                    S3Object.builder().key(request.prefix()+"00.a.gz").size(3L).storageClass("STANDARD").build(),
                    S3Object.builder().key(request.prefix()+"00.b.gz").size(3L).storageClass("GLACIER").build()).build();
            }
            if(m.getName().equals("getObject")){
                gets++;var request=(GetObjectRequest)a[0];
                check(request.key().endsWith(".a.gz"),"archived object never downloaded/restored");
                return new ResponseInputStream<>(GetObjectResponse.builder().contentLength(3L).build(),AbortableInputStream.create(new ByteArrayInputStream(body)));
            }
            if(m.getName().equals("close"))return null;
            throw new AssertionError("Unexpected/mutating S3 operation: "+m.getName());
        });
        var backend=new AwsBackend("us-east-1",false,null,"default");
        for(var entry:Map.of("cloudfront",cf,"s3",s3).entrySet()){
            var field=AwsBackend.class.getDeclaredField(entry.getKey());field.setAccessible(true);field.set(backend,entry.getValue());
        }
        Path root=Files.createTempDirectory("cf-log-check-"),out=root.resolve("evidence/raw");
        try {
            var preview=parse(new CloudFrontLogs(backend).collect("DTEST","2026-11-01","2026-11-02",out.toString(),10,0));
            check(gets==0&&!Files.exists(out),"inventory makes no GET and no raw output directory");
            check(preview.get("cookie_logging_enabled").equals(false),"cookie setting exported without cookie values");
            var result=parse(new CloudFrontLogs(backend).collect("DTEST","2026-11-01","2026-11-02",out.toString(),10,10));
            check(gets==1&&result.get("complete").equals(false),"archive skip marks partial");
            var objects=(List<Map<String,Object>>)result.get("objects");
            Path file=Path.of((String)objects.getFirst().get("local_file"));
            check(Arrays.equals(Files.readAllBytes(file),body),"exact listed bytes saved");
            if(FileSystems.getDefault().supportedFileAttributeViews().contains("posix")){
                check(Files.getPosixFilePermissions(file).equals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")),"raw file mode 0600");
                check(Files.getPosixFilePermissions(out).equals(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")),"raw directory mode 0700");
            }
            new CloudFrontLogs(backend).collect("DTEST","2026-11-01","2026-11-02",out.toString(),10,10);
            check(gets==1,"rerun reuses exact-size file without another GET");
            var capped=parse(new CloudFrontLogs(backend).collect("DTEST","2026-11-01","2026-11-02",out.toString(),10,1));
            check(gets==1&&capped.get("complete").equals(false),"byte cap prevents GET and remains partial");
            try{new CloudFrontLogs(backend).collect("bad-id","2026-11-01","2026-11-02",out.toString(),10,1);throw new AssertionError("invalid ID accepted");}catch(IllegalArgumentException expected){}
        } finally {
            backend.close();
            try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}
        }
        System.out.println("PASS "+checks+" CloudFront log prefix, read-only inventory, privacy, archive, cap and cache checks; no AWS");
    }
    private static Map<String,Object> parse(String text){return (Map<String,Object>)io.lmctl.lmcode.Json.parse(text);}
}
