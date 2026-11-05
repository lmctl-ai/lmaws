package ai.lmctl.lmaws;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.cloudfront.model.*;
import software.amazon.awssdk.services.s3.*;
import software.amazon.awssdk.services.s3.model.*;

/** Read-only inventory/download of legacy CloudFront gzip logs. */
final class CloudFrontLogs {
    private final AwsBackend backend;
    CloudFrontLogs(AwsBackend backend){this.backend=backend;}
    String collect(String id,String fromRaw,String toRaw,String output,int maxObjects,int maxBytes){
        if(!"default".equals(backend.profileName())||!"default".equals(AwsBackend.activeProfile()))throw new SecurityException("CloudFront logs require AWS_PROFILE=default");
        if(id==null||!id.matches("[A-Z0-9]+"))throw new IllegalArgumentException("distribution id must be literal A-Z0-9");
        LocalDate from=LocalDate.parse(fromRaw),to=LocalDate.parse(toRaw);if(!from.isBefore(to))throw new IllegalArgumentException("from must precede exclusive to");if(Duration.between(from.atStartOfDay(),to.atStartOfDay()).toDays()>31)throw new IllegalArgumentException("range must be <=31 days");if(maxObjects<1||maxObjects>12000)throw new IllegalArgumentException("maxObjects must be 1..12000");if(maxBytes<0||maxBytes>512*1024*1024)throw new IllegalArgumentException("maxCompressedBytes must be 0..512MiB");
        var config=backend.cloudFrontClient().getDistributionConfig(GetDistributionConfigRequest.builder().id(id).build()).distributionConfig();var log=config==null?null:config.logging();if(log==null||!Boolean.TRUE.equals(log.enabled())||log.bucket()==null)throw new IllegalStateException("legacy CloudFront logging is disabled");String bucket=log.bucket().replaceFirst("\\.s3\\.amazonaws\\.com$","");String configuredPrefix=Objects.toString(log.prefix(),"");String prefix=configuredPrefix.isEmpty()?"":(configuredPrefix.endsWith("/")?configuredPrefix:configuredPrefix+"/");S3Client s3=backend.s3ClientForDoctor();List<Map<String,Object>> objects=new ArrayList<>();long listedBytes=0,downloadedBytes=0;
        Path dir=null;if(maxBytes>0){dir=prepare(output);}
        List<String> warnings=new ArrayList<>();boolean skipped=false;int pages=0;
        outer:for(LocalDate day=from;day.isBefore(to);day=day.plusDays(1)){String keyPrefix=prefix+id+"."+day+"-";String token=null;Set<String> seen=new HashSet<>();do{if(++pages>100)throw new IllegalStateException("S3 pagination limit exceeded");var response=s3.listObjectsV2(ListObjectsV2Request.builder().bucket(bucket).prefix(keyPrefix).continuationToken(token).build());for(var obj:response.contents()){if(!obj.key().endsWith(".gz"))continue;if(objects.size()>=maxObjects){warnings.add("max_objects_reached");skipped=true;break outer;}long size=Objects.requireNonNullElse(obj.size(),0L);listedBytes+=size;Map<String,Object> row=new LinkedHashMap<>();row.put("key",obj.key());row.put("bytes",size);row.put("storage_class",obj.storageClassAsString());row.put("downloaded",false);if(maxBytes==0){row.put("local_file","");row.put("reason","preview");}else if(!Set.of("STANDARD","STANDARD_IA","ONEZONE_IA","INTELLIGENT_TIERING").contains(obj.storageClassAsString())){row.put("local_file","");row.put("reason","archive_storage_class");skipped=true;}else if(downloadedBytes+size>maxBytes){row.put("local_file","");row.put("reason","byte_cap");skipped=true;}else{Path file=dir.resolve(hash(obj.key())+".gz");try{if(Files.exists(file)&&Files.size(file)==size){ownerOnly(file);downloadedBytes+=size;row.put("local_file",file.toString());row.put("downloaded",true);row.put("reason","already_present");}else{try(var in=s3.getObject(GetObjectRequest.builder().bucket(bucket).key(obj.key()).build());var out=Files.newOutputStream(file)){ownerOnly(file);copyBounded(in,out,size);}long actual=Files.size(file);if(actual!=size||downloadedBytes+actual>maxBytes){Files.deleteIfExists(file);row.put("local_file","");row.put("reason","download_size_mismatch");skipped=true;}else{downloadedBytes+=actual;row.put("local_file",file.toString());row.put("downloaded",true);row.put("reason","downloaded");}}}catch(IOException e){row.put("local_file","");row.put("reason","local_io_error");skipped=true;}}objects.add(row);}token=response.nextContinuationToken();if(token!=null&&!seen.add(token))throw new IllegalStateException("S3 pagination repeated");}while(token!=null);}
        Map<String,Object> out=new LinkedHashMap<>();if(objects.isEmpty()){var sample=s3.listObjectsV2(ListObjectsV2Request.builder().bucket(bucket).prefix(prefix).maxKeys(5).build());out.put("prefix_samples",sample.contents().stream().map(x->Map.of("key",x.key(),"bytes",Objects.requireNonNullElse(x.size(),0L),"last_modified",Objects.toString(x.lastModified(),""))).toList());warnings.add("no_matching_date_objects");}out.put("mode","live_read_only");out.put("distribution_id",id);out.put("bucket",bucket);out.put("prefix",prefix);out.put("cookie_logging_enabled",log.includeCookies());out.put("from",from.toString());out.put("to",to.toString());out.put("objects",objects);out.put("totals",Map.of("listed_objects",objects.size(),"listed_bytes",listedBytes,"downloaded_bytes",downloadedBytes));out.put("complete",!skipped);out.put("warnings",warnings);return Jsons.encodeRaw(out);
    }
    private static void ownerOnly(Path file)throws IOException {
        try{Files.setPosixFilePermissions(file,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}
        catch(java.lang.UnsupportedOperationException ignored){file.toFile().setReadable(false,false);file.toFile().setWritable(false,false);file.toFile().setReadable(true,true);file.toFile().setWritable(true,true);}
    }
    private static void copyBounded(InputStream in,OutputStream out,long expected)throws IOException {
        long total=0;byte[] buffer=new byte[65536];
        while(true){int limit=(int)Math.min(buffer.length,expected-total+1);int count=in.read(buffer,0,limit);if(count<0)break;if(count==0)continue;total+=count;if(total>expected)throw new IOException("log grew beyond listed size");out.write(buffer,0,count);}
        if(total!=expected)throw new IOException("log size differs from S3 listing");
    }
    private static Path prepare(String raw){Path p=Path.of(raw).toAbsolutePath().normalize();String s=p.toString().replace('\\','/');if(!(s.contains("/evidence/")||s.contains("/.lmaws-local/")))throw new SecurityException("outputDir must be under evidence or .lmaws-local");try{Files.createDirectories(p);try{Files.setPosixFilePermissions(p,Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));}catch(java.lang.UnsupportedOperationException ignored){}return p;}catch(IOException e){throw new IllegalStateException("cannot create outputDir",e);}}
    private static String hash(String key){try{byte[] d=MessageDigest.getInstance("SHA-256").digest(key.getBytes(java.nio.charset.StandardCharsets.UTF_8));return HexFormat.of().formatHex(d);}catch(GeneralSecurityException e){throw new IllegalStateException(e);}}
}
