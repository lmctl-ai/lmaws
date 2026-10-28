package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.interceptor.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.io.*;
import java.math.BigDecimal;

/** Explicit, restartable sandbox operations; no automatic cleanup or client retry. */
final class S3Objects {
    static final int MAX_KEYS=1000;
    static final long MAX_FILE_BYTES=16L*1024*1024;
    private final AwsBackend backend;
    private final Map<String,String> attached=new HashMap<>();
    private static final ThreadLocal<Scope> ACTIVE=new ThreadLocal<>();
    private static final class Scope {
        final S3OperationLedger ledger;long attempts;final Map<String,Object> context=new LinkedHashMap<>();
        Scope(S3OperationLedger ledger){this.ledger=ledger;context.put("operation_id",UUID.randomUUID().toString());}
    }
    S3Objects(AwsBackend backend){this.backend=backend;}
    static ExecutionInterceptor interceptor() {
        return new ExecutionInterceptor(){@Override public void beforeTransmission(Context.BeforeTransmission context,ExecutionAttributes attributes){
            Scope scope=ACTIVE.get();if(scope==null)throw new IllegalStateException("S3 object request has no durable run admission scope");
            String operation=attributes.getOptionalAttribute(SdkExecutionAttribute.OPERATION_NAME).orElseThrow();
            scope.ledger.recordAttempt(operation,scope.context);scope.attempts++;
        }};
    }
    static Path directory(){return Path.of(System.getenv().getOrDefault("LMAWS_LEDGER_DIR","ledgers"));}
    static String summary(String run){return S3OperationLedger.summary(run,directory());}
    private <T>T scoped(String run,Function<S3OperationLedger,T> action) {
        validateRun(run);BigDecimal cap=new BigDecimal(System.getenv().getOrDefault("LMAWS_MAX_COST_USD","0.05"));
        return operationLocked(run,()->{try(S3OperationLedger ledger=S3OperationLedger.open(run,directory(),cap,backend.region())) {
            Scope previous=ACTIVE.get();ACTIVE.set(new Scope(ledger));
            try{return action.apply(ledger);}finally{if(previous==null)ACTIVE.remove();else ACTIVE.set(previous);}
        }});
    }
    private static <T>T operationLocked(String run,java.util.concurrent.Callable<T> action) {
        Path path=directory().toAbsolutePath().normalize().resolve(run+"-api.lock");Object local=OPERATION_LOCKS[Math.floorMod(path.toString().hashCode(),OPERATION_LOCKS.length)];
        synchronized(local){try{Files.createDirectories(path.getParent());try(var channel=java.nio.channels.FileChannel.open(path,StandardOpenOption.CREATE,StandardOpenOption.WRITE);var lock=channel.lock()){return action.call();}}catch(RuntimeException e){throw e;}catch(Exception e){throw new IllegalStateException("S3 run operation lock failed",e);}}
    }
    private static final Object[] OPERATION_LOCKS=new Object[64];
    static {Arrays.setAll(OPERATION_LOCKS,i->new Object());}
    private S3Client client(){return backend.s3ObjectsClient();}
    private void readGuard(String bucket){validateBucket(bucket);backend.requireS3ObjectRead();}
    private void writeGuard(String bucket){validateBucket(bucket);backend.requireS3ObjectWrite();}
    private String binding(String bucket,boolean write){if(write)writeGuard(bucket);else readGuard(bucket);String run=attached.get(bucket);if(run==null)throw new SecurityException("call s3_bucket_attach or s3_bucket_create_exact in this process before object requests");return run;}
    private void verifyTag(String bucket,String run){
        ACTIVE.get().context.put("bucket",bucket);
        try {
            var tags=client().getBucketTagging(x->x.bucket(bucket)).tagSet();
            if(tags.stream().noneMatch(t->"lmaws_test".equals(t.key())&&run.equals(t.value())))throw new SecurityException("bucket lmaws_test ownership tag does not match the run");
        }catch(S3Exception e){if("NoSuchTagSet".equals(code(e)))throw new SecurityException("existing bucket has no lmaws_test ownership tag");throw e;}
    }
    String create(String bucket,String run) {
        writeGuard(bucket);validateRun(run);
        return createLocked(bucket,()->scoped(run,ledger->{
            boolean absent=false;
            try {verifyTag(bucket,run);}catch(S3Exception e){if("NoSuchBucket".equals(code(e)))absent=true;else throw e;}
            if(!absent){attached.put(bucket,run);ledger.bindBucket(bucket,run);return encode(Map.of("ok",true,"bucket",bucket,"run_id",run,"created",false,"attached",true));}
            // The run operation lock keeps this admission stable until bootstrap tagging completes.
            BigDecimal required=CostLedger.s3PriceForOperation("PutBucketTagging").add(CostLedger.s3PriceForOperation("GetBucketTagging").multiply(BigDecimal.valueOf(2)));
            var budget=ledger.summaryMap();if(new BigDecimal(String.valueOf(budget.get("estimated_cost_usd"))).add(required).compareTo(ledger.cap())>0)throw new CostLedger.BudgetExceeded("insufficient persistent budget to create and verify the bucket tag");
            backend.preflightS3Bootstrap(required);
            ledger.event("bucket_create_intent",Map.of("bucket",bucket,"run_id",run));
            var response=client().createBucket(x->x.bucket(bucket));
            ledger.event("bucket_create_ack",Map.of("bucket",bucket,"run_id",run,"request_id",response.responseMetadata().requestId()));
            // Recheck after the acknowledgement: never replace a concurrently-installed ownership tag.
            boolean alreadyTagged=false;
            try {var current=client().getBucketTagging(x->x.bucket(bucket)).tagSet();if(!current.isEmpty()){if(current.stream().noneMatch(t->"lmaws_test".equals(t.key())&&run.equals(t.value())))throw new SecurityException("concurrent bucket ownership differs; refusing to retag");alreadyTagged=true;}}
            catch(S3Exception e){if(!"NoSuchTagSet".equals(code(e)))throw e;}
            // Bootstrap tagging is permitted only after this invocation received CreateBucket success.
            if(!alreadyTagged)client().putBucketTagging(x->x.bucket(bucket).tagging(t->t.tagSet(Tag.builder().key("lmaws_test").value(run).build())));
            verifyTag(bucket,run);attached.put(bucket,run);ledger.bindBucket(bucket,run);
            return encode(Map.of("ok",true,"bucket",bucket,"run_id",run,"created",true,"attached",true));
        }));
    }
    private static final Object[] CREATION_LOCKS=new Object[64];
    static {Arrays.setAll(CREATION_LOCKS,i->new Object());}
    private static <T>T createLocked(String bucket,java.util.concurrent.Callable<T> action) {
        Path path=directory().toAbsolutePath().normalize().resolve(bucket+"-creation.lock");Object local=CREATION_LOCKS[Math.floorMod(path.toString().hashCode(),CREATION_LOCKS.length)];
        synchronized(local){try{Files.createDirectories(path.getParent());try(var channel=java.nio.channels.FileChannel.open(path,StandardOpenOption.CREATE,StandardOpenOption.WRITE);var lock=channel.lock()){return action.call();}}catch(RuntimeException e){throw e;}catch(Exception e){throw new IllegalStateException("bucket creation lock failed",e);}}
    }
    String attach(String bucket,String run) {
        readGuard(bucket);validateRun(run);
        return scoped(run,ledger->{
            try {verifyTag(bucket,run);}catch(S3Exception e){if("NoSuchBucket".equals(code(e)))return encode(Map.of("ok",false,"exists",false,"bucket",bucket,"http_status",404,"error_code","NoSuchBucket"));throw e;}
            attached.put(bucket,run);ledger.bindBucket(bucket,run);return encode(Map.of("ok",true,"exists",true,"bucket",bucket,"run_id",run,"attached",true));
        });
    }
    String deleteBucket(String bucket,String run) {
        writeGuard(bucket);validateRun(run);
        return scoped(run,ledger->{
            Map<String,Object> receipt=start(bucket,"",0);
            try {
                try{verifyTag(bucket,run);}catch(S3Exception e){if("NoSuchBucket".equals(code(e))){receipt.put("ok",true);receipt.put("exists",false);receipt.put("already_absent",true);finish(receipt);ledger.receipt("DeleteBucket",receipt);return encode(receipt);}throw e;}
                // The service atomically refuses nonempty buckets, including hidden versions. Never empty implicitly.
                var response=client().deleteBucket(x->x.bucket(bucket));success(receipt,response.sdkHttpResponse().statusCode(),response.responseMetadata().requestId());
                receipt.put("exists",false);attached.remove(bucket);ledger.event("bucket_deleted",Map.of("bucket",bucket));
            }catch(SecurityException e){throw e;}catch(Exception e){rethrowBudget(e);failure(receipt,e,true);}
            finish(receipt);ledger.receipt("DeleteBucket",receipt);return encode(receipt);
        });
    }
    String put(String bucket,String key,String path,String options) {
        String run=binding(bucket,true);validateKey(key,false);Map<String,Object> opts=object(options);
        Set<String> accepted=Set.of("content_type","cache_control","metadata","checksum_algorithm","checksum_sha256","expected_sha256","if_none_match","if_match","operation_id");
        if(!accepted.containsAll(opts.keySet()))throw new IllegalArgumentException("unknown S3 put option");
        if(opts.containsKey("checksum_algorithm")&&!"SHA256".equals(opts.get("checksum_algorithm")))throw new IllegalArgumentException("only SHA256 additional checksums are supported");
        String none=string(opts,"if_none_match"),match=string(opts,"if_match");
        if(!none.isEmpty()&&!none.equals("*"))throw new IllegalArgumentException("if_none_match must be '*'");
        if(!none.isEmpty()&&!match.isEmpty())throw new IllegalArgumentException("choose if_none_match or if_match");
        String type=string(opts,"content_type"),cache=string(opts,"cache_control"),operationId=string(opts,"operation_id");
        for(String value:List.of(type,cache,match,operationId))if(value.contains("\r")||value.contains("\n")||value.length()>2048)throw new IllegalArgumentException("invalid S3 header/operation value");
        Map<String,String> metadata=metadata(opts.get("metadata"));
        return scoped(run,ledger->{
            Map<String,Object> receipt=start(bucket,key,0);receipt.put("run_id",run);if(!operationId.isEmpty())ACTIVE.get().context.put("operation_id",operationId);receipt.put("operation_id",ACTIVE.get().context.get("operation_id"));
            receipt.put("stage","prepare");long beforePut=-1;
            try(Payload payload=Payload.copy(Path.of(path))) {
                receipt.put("bytes",payload.bytes);receipt.put("sha256",payload.hex);receipt.put("expected_checksum_sha256",payload.base64);
                String expected=string(opts,"expected_sha256"),checksum=string(opts,"checksum_sha256");
                if(!expected.isEmpty()&&(!expected.matches("[0-9a-fA-F]{64}")||!payload.hex.equalsIgnoreCase(expected)))throw new LocalFailure("LocalChecksumMismatch");
                if(!checksum.isEmpty()&&!checksum.equals(payload.base64))throw new LocalFailure("LocalChecksumMismatch");
                receipt.put("stage","ownership");verifyTag(bucket,run);
                ledger.event("put_intent",Map.of("bucket",bucket,"key",key,"bytes",payload.bytes,"expected_sha256",payload.hex,"operation_id",receipt.get("operation_id")));
                var request=PutObjectRequest.builder().bucket(bucket).key(key).checksumAlgorithm(ChecksumAlgorithm.SHA256).checksumSHA256(payload.base64).metadata(metadata);
                if(!type.isEmpty())request.contentType(type);if(!cache.isEmpty())request.cacheControl(cache);if(!none.isEmpty())request.ifNoneMatch(none);if(!match.isEmpty())request.ifMatch(match);
                receipt.put("stage","put");beforePut=ACTIVE.get().attempts;
                var result=client().putObject(request.build(),RequestBody.fromFile(payload.path));
                success(receipt,result.sdkHttpResponse().statusCode(),result.responseMetadata().requestId());receipt.put("etag",value(result.eTag()));receipt.put("checksum_sha256",value(result.checksumSHA256()));receipt.put("version_id",value(result.versionId()));
                boolean verified=payload.base64.equals(result.checksumSHA256());receipt.put("checksum_verified",verified);
                if(!verified){receipt.put("ok",false);receipt.put("ambiguous",true);receipt.put("error_code","ChecksumReceiptMissingOrMismatch");}
            }catch(SecurityException e){throw e;}catch(Exception e){rethrowBudget(e);failure(receipt,e,beforePut>=0&&ACTIVE.get().attempts>beforePut);}
            finish(receipt);ledger.receipt("PutObject",receipt);return encode(receipt);
        });
    }
    String head(String bucket,String key) {
        String run=binding(bucket,false);validateKey(key,false);
        return scoped(run,ledger->{
            Map<String,Object> receipt=start(bucket,key,0);receipt.put("exists",null);
            try {
                var response=client().headObject(x->x.bucket(bucket).key(key).checksumMode(ChecksumMode.ENABLED));
                success(receipt,response.sdkHttpResponse().statusCode(),response.responseMetadata().requestId());receipt.put("exists",true);receipt.put("size",response.contentLength());receipt.put("etag",value(response.eTag()));receipt.put("last_modified",response.lastModified()==null?"":response.lastModified().toString());receipt.put("content_type",value(response.contentType()));receipt.put("cache_control",value(response.cacheControl()));receipt.put("metadata",response.metadata());receipt.put("checksum_sha256",value(response.checksumSHA256()));receipt.put("version_id",value(response.versionId()));receipt.put("checksum_type",response.sdkHttpResponse().firstMatchingHeader("x-amz-checksum-type").orElse("unknown"));
            }catch(Exception e){rethrowBudget(e);failure(receipt,e,false);if(e instanceof S3Exception aws&&aws.statusCode()==404)receipt.put("exists",false);}
            finish(receipt);ledger.receipt("HeadObject",receipt);return encode(receipt);
        });
    }
    List<Map<String,String>> list(String bucket,String prefix,int max) {
        String run=binding(bucket,false);validateKey(prefix,true);if(max==0)max=MAX_KEYS;if(max<1||max>MAX_KEYS)throw new IllegalArgumentException("max_keys_total must be 1..1000 (0 selects 1000)");final int limit=max;
        return scoped(run,ledger->{
            ACTIVE.get().context.put("bucket",bucket);ACTIVE.get().context.put("prefix",prefix);
            List<Map<String,String>> rows=new ArrayList<>();String token=null;Set<String> seenTokens=new HashSet<>();
            do {
                var request=ListObjectsV2Request.builder().bucket(bucket).prefix(prefix).maxKeys(limit-rows.size());if(token!=null)request.continuationToken(token);
                var page=client().listObjectsV2(request.build());
                if(page.isTruncated()==null)throw new IllegalStateException("S3 listing omitted truncation state");
                if(Boolean.TRUE.equals(page.isTruncated())&&(page.contents().isEmpty()||page.nextContinuationToken()==null||page.nextContinuationToken().isEmpty()))throw new IllegalStateException("S3 pagination did not make bounded progress");
                for(var item:page.contents()) {if(rows.size()>=limit)throw new IllegalStateException("S3 listing exceeded the requested bound");rows.add(Map.of("key",item.key(),"size",String.valueOf(item.size()),"etag",value(item.eTag()),"last_modified",item.lastModified()==null?"":item.lastModified().toString(),"storage_class",item.storageClassAsString()==null?"STANDARD":item.storageClassAsString()));}
                token=Boolean.TRUE.equals(page.isTruncated())?page.nextContinuationToken():null;
                if(token!=null&&(rows.size()>=limit||!seenTokens.add(token)))throw new IllegalStateException("S3 listing is incomplete at the bound or repeated a continuation token; use a narrower prefix");
                if(Boolean.TRUE.equals(page.isTruncated())&&token==null)throw new IllegalStateException("S3 listing is truncated without a continuation token");
            }while(token!=null);
            ledger.event("list_complete",Map.of("bucket",bucket,"prefix",prefix,"keys",rows.size()));return rows;
        });
    }
    List<Map<String,String>> deleteObjects(String bucket,String keysJson) {
        String run=binding(bucket,true);Object parsed=Json.parse(keysJson);if(!(parsed instanceof List<?> keys)||keys.size()>MAX_KEYS)throw new IllegalArgumentException("keys_json must be an array of at most 1000 unique strings");
        LinkedHashSet<String> names=new LinkedHashSet<>();for(Object key:keys){if(!(key instanceof String name))throw new IllegalArgumentException("delete keys must be strings");validateKey(name,false);if(!names.add(name))throw new IllegalArgumentException("duplicate delete key");}
        if(names.isEmpty())return List.of();
        return scoped(run,ledger->{
            ACTIVE.get().context.put("keys",new ArrayList<>(names));
            List<Map<String,String>> rows=new ArrayList<>();long beforeDelete=-1;
            try {
                verifyTag(bucket,run);List<ObjectIdentifier> ids=names.stream().map(k->ObjectIdentifier.builder().key(k).build()).toList();beforeDelete=ACTIVE.get().attempts;
                var response=client().deleteObjects(x->x.bucket(bucket).delete(d->d.objects(ids).quiet(false)));
                Map<String,DeletedObject> deleted=new HashMap<>();for(var d:response.deleted())deleted.put(d.key(),d);
                Map<String,software.amazon.awssdk.services.s3.model.S3Error> errors=new HashMap<>();for(var error:response.errors())errors.put(error.key(),error);
                for(String key:names){var error=errors.get(key);boolean confirmed=error==null&&deleted.containsKey(key);Map<String,String> row=new LinkedHashMap<>();row.put("key",key);row.put("ok",String.valueOf(confirmed));row.put("http_status",String.valueOf(response.sdkHttpResponse().statusCode()));row.put("error_code",error!=null?value(error.code()):confirmed?"":"UnconfirmedDelete");row.put("ambiguous",String.valueOf(error==null&&!confirmed));row.put("request_id",response.responseMetadata().requestId());rows.add(row);}
            }catch(SecurityException e){throw e;}catch(Exception e){rethrowBudget(e);Map<String,Object> failure=start(bucket,"",0);failure(failure,e,beforeDelete>=0&&ACTIVE.get().attempts>beforeDelete);for(String key:names)rows.add(Map.of("key",key,"ok","false","http_status",String.valueOf(failure.get("http_status")),"error_code",String.valueOf(failure.get("error_code")),"ambiguous",String.valueOf(failure.get("ambiguous")),"request_id",String.valueOf(failure.get("request_id"))));}
            ledger.receipt("DeleteObjects",Map.of("bucket",bucket,"outcomes",rows));return rows;
        });
    }
    private static Map<String,Object> start(String bucket,String key,long bytes){var receipt=new LinkedHashMap<String,Object>();receipt.put("ok",false);receipt.put("http_status",0);receipt.put("error_code","");receipt.put("ambiguous",false);receipt.put("bucket",bucket);receipt.put("key",key);if(ACTIVE.get()!=null){ACTIVE.get().context.put("bucket",bucket);ACTIVE.get().context.put("key",key);receipt.put("operation_id",ACTIVE.get().context.get("operation_id"));}receipt.put("etag","");receipt.put("checksum_sha256","");receipt.put("version_id","");receipt.put("request_id","");receipt.put("bytes",bytes);receipt.put("started",Instant.now().toString());return receipt;}
    private static void success(Map<String,Object> receipt,int status,String id){receipt.put("ok",true);receipt.put("http_status",status);receipt.put("request_id",value(id));}
    private static void failure(Map<String,Object> receipt,Exception e,boolean transmitted){
        receipt.put("ok",false);if(e instanceof S3Exception aws){receipt.put("http_status",aws.statusCode());receipt.put("error_code",code(aws));receipt.put("request_id",value(aws.requestId()));receipt.put("ambiguous",transmitted&&(aws.statusCode()>=500||aws.statusCode()==408));}
        else {receipt.put("error_code",e instanceof LocalFailure?e.getMessage():e instanceof IOException?"LocalIO":e.getClass().getSimpleName());receipt.put("ambiguous",transmitted);}
    }
    private static void rethrowBudget(Throwable failure){for(Throwable e=failure;e!=null;e=e.getCause())if(e instanceof CostLedger.BudgetExceeded budget)throw budget;}
    private static void finish(Map<String,Object> receipt){receipt.put("finished",Instant.now().toString());}
    private static String encode(Object value){return Jsons.encode(value);}
    private static String code(S3Exception e){return e.awsErrorDetails()==null?e.getClass().getSimpleName():value(e.awsErrorDetails().errorCode());}
    private static String value(String value){return value==null?"":value;}
    private static void validateRun(String run){if(run==null||!run.matches("[a-z0-9][a-z0-9_-]{0,63}"))throw new IllegalArgumentException("invalid S3 run ID");}
    private static void validateBucket(String bucket){if(bucket==null||bucket.length()>63||!bucket.matches("lmaws-[a-z0-9][a-z0-9.-]*[a-z0-9]"))throw new SecurityException("S3 object buckets must be valid lmaws- names");}
    private static void validateKey(String key,boolean prefix){if(key==null||(!prefix&&key.isEmpty())||key.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>1024||key.indexOf('\0')>=0)throw new IllegalArgumentException("invalid S3 key/prefix");}
    private static Map<String,Object> object(String json){Object value=Json.parse(json);if(!(value instanceof Map<?,?> map))throw new IllegalArgumentException("options_json must be an object");Map<String,Object> out=new LinkedHashMap<>();map.forEach((k,v)->out.put(String.valueOf(k),v));return out;}
    private static String string(Map<String,Object> map,String key){Object value=map.get(key);if(value==null)return "";if(!(value instanceof String text))throw new IllegalArgumentException(key+" must be a string");return text;}
    private static Map<String,String> metadata(Object raw){if(raw==null)return Map.of();if(!(raw instanceof Map<?,?> map))throw new IllegalArgumentException("metadata must be a string map");Map<String,String> values=new LinkedHashMap<>();int bytes=0;for(var entry:map.entrySet()){if(!(entry.getKey() instanceof String key)||!(entry.getValue() instanceof String value)||!key.matches("[A-Za-z0-9_-]{1,128}")||value.contains("\r")||value.contains("\n"))throw new IllegalArgumentException("invalid S3 metadata");bytes+=key.getBytes(java.nio.charset.StandardCharsets.UTF_8).length+value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;values.put(key,value);}if(bytes>2048)throw new IllegalArgumentException("S3 user metadata exceeds 2 KiB");return values;}
    private static final class LocalFailure extends IOException {LocalFailure(String code){super(code);}}
    private static final class Payload implements AutoCloseable {
        final Path path;final long bytes;final String hex,base64;
        Payload(Path path,long bytes,byte[] digest){this.path=path;this.bytes=bytes;this.hex=HexFormat.of().formatHex(digest);this.base64=Base64.getEncoder().encodeToString(digest);}
        static Payload copy(Path input)throws Exception {
            var before=Files.readAttributes(input,BasicFileAttributes.class);if(!before.isRegularFile()||before.size()>MAX_FILE_BYTES)throw new LocalFailure("LocalFileTypeOrSizeLimit");
            Path snapshot=Files.createTempFile("lmaws-s3-payload-",".tmp");long bytes=0;
            try {MessageDigest digest=MessageDigest.getInstance("SHA-256");try(InputStream in=Files.newInputStream(input);OutputStream out=Files.newOutputStream(snapshot)){byte[] buffer=new byte[65536];int n;while((n=in.read(buffer))!=-1){bytes+=n;if(bytes>MAX_FILE_BYTES)throw new LocalFailure("LocalFileSizeLimit");digest.update(buffer,0,n);out.write(buffer,0,n);}}
                var after=Files.readAttributes(input,BasicFileAttributes.class);if(before.size()!=after.size()||!before.lastModifiedTime().equals(after.lastModifiedTime())||!Objects.equals(before.fileKey(),after.fileKey())||bytes!=before.size())throw new LocalFailure("LocalSourceChanged");return new Payload(snapshot,bytes,digest.digest());
            }catch(Exception e){Files.deleteIfExists(snapshot);throw e;}
        }
        @Override public void close()throws IOException{Files.deleteIfExists(path);}
    }
}
