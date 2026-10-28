package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Callable;

/** Fsync-before-send request admission, shared by all executors using one run and ledger directory. */
public final class S3OperationLedger implements AutoCloseable {
    public static final String SCHEMA="lmaws-s3-operations-v1";
    public static final BigDecimal DEFAULT_CAP=new BigDecimal("0.05"), HARD_CAP=new BigDecimal("0.25");
    private static final Object[] JVM_LOCKS=new Object[64];
    static {Arrays.setAll(JVM_LOCKS,i->new Object());}
    private final String run,region;private final Path file,lock;private final BigDecimal cap;private boolean closed;
    private S3OperationLedger(String run,String region,Path file,BigDecimal cap){this.run=run;this.region=region;this.file=file;this.lock=file.resolveSibling(file.getFileName()+".lock");this.cap=cap;}
    public static S3OperationLedger open(String run,Path directory){return open(run,directory,DEFAULT_CAP,"us-east-1");}
    public static S3OperationLedger open(String run,Path directory,BigDecimal requested,String region){
        validateRun(run);validateCap(requested);if(!"us-east-1".equals(region))throw new IllegalArgumentException("S3 object ledger requires us-east-1");
        Path path=directory.toAbsolutePath().normalize().resolve(run+"-s3-operations.jsonl");
        S3OperationLedger ledger=new S3OperationLedger(run,region,path,requested);
        ledger.locked(()->{
            if(!Files.exists(path))ledger.append(Map.of("event","header","schema",SCHEMA,"run_id",run,"region",region,"cap_usd",requested,"price_table",CostLedger.s3PriceTable()));
            else {
                BigDecimal stored=ledger.persistedCap(ledger.read());
                if(requested.compareTo(stored)>0)throw new IllegalArgumentException("cannot increase the persisted S3 run cap; retain the original LMAWS_MAX_COST_USD");
                if(requested.compareTo(stored)<0)ledger.append(Map.of("event","cap_reduced","cap_usd",requested));
            }
            return null;
        });return ledger;
    }
    public Map<String,Object> recordAttempt(String operation){return recordAttempt(operation,Map.of());}
    public Map<String,Object> recordAttempt(String operation,Map<String,?> context){
        checkOpen();validateOperation(operation);
        return locked(()->{
            var events=read();BigDecimal effective=cap.min(persistedCap(events));BigDecimal cost=cost(events),unit=CostLedger.s3PriceForOperation(operation);
            if(cost.add(unit).compareTo(effective)>0)throw new CostLedger.BudgetExceeded("persistent S3 request cap exceeded before "+operation);
            var event=new LinkedHashMap<String,Object>();event.put("event","attempt");event.put("run_id",run);event.put("operation",operation);event.put("unit_price_usd",unit);event.put("estimated_usd",unit);event.put("at",Instant.now().toString());event.put("context",new LinkedHashMap<>(context));append(event);return event;
        });
    }
    public void bindBucket(String bucket,String run){if(!this.run.equals(run)||bucket==null||bucket.length()>63||!bucket.matches("lmaws-[a-z0-9][a-z0-9.-]*[a-z0-9]"))throw new SecurityException("invalid run bucket binding");event("bucket_binding",Map.of("bucket",bucket,"run_id",run));}
    public void receipt(String operation,Map<String,?> receipt){validateOperation(operation);event("receipt",Map.of("operation",operation,"receipt",new LinkedHashMap<>(receipt)));}
    public void event(String name,Map<String,?> values){checkOpen();locked(()->{persistedCap(read());var event=new LinkedHashMap<String,Object>(values);event.put("event",name);event.put("at",Instant.now().toString());append(event);return null;});}
    public Map<String,Object> summaryMap(){checkOpen();return locked(()->summarize(read()));}
    public String summaryJson(){return Jsons.encode(summaryMap());}
    public static String summary(String run,Path directory){
        validateRun(run);Path path=directory.toAbsolutePath().normalize().resolve(run+"-s3-operations.jsonl");
        S3OperationLedger ledger=new S3OperationLedger(run,"us-east-1",path,DEFAULT_CAP);
        // A first no-op must not create a ledger, resolve credentials or make a provider request.
        if(!Files.exists(path))return Jsons.encode(ledger.summarize(List.of()));
        return ledger.summaryJson();
    }
    private Map<String,Object> summarize(List<Map<String,Object>> events){
        BigDecimal effective=events.isEmpty()?cap:persistedCap(events);Map<String,Object> byOperation=new TreeMap<>();long total=0;
        for(var event:events)if("attempt".equals(event.get("event"))){total++;String op=String.valueOf(event.get("operation"));validateOperation(op);var row=(Map<String,Object>)byOperation.computeIfAbsent(op,k->new LinkedHashMap<>(Map.of("requests",0L,"estimated_usd",BigDecimal.ZERO)));row.put("requests",((Number)row.get("requests")).longValue()+1);row.put("estimated_usd",decimal(row.get("estimated_usd")).add(decimal(event.get("estimated_usd"))));}
        var out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);out.put("run_id",run);out.put("region",region);out.put("exists",!events.isEmpty());out.put("cap_usd",effective);out.put("hard_ceiling_usd",HARD_CAP);out.put("attempts",total);out.put("by_operation",byOperation);out.put("estimated_cost_usd",cost(events));out.put("cost_scope","API request attempts; storage and transfer require separate estimates");out.put("price_table",CostLedger.s3PriceTable());out.put("ledger",file.toString());return out;
    }
    private BigDecimal persistedCap(List<Map<String,Object>> events){
        if(events.isEmpty())throw new IllegalStateException("missing S3 ledger header");var header=events.get(0);
        if(!"header".equals(header.get("event"))||!SCHEMA.equals(header.get("schema"))||!run.equals(header.get("run_id"))||!region.equals(header.get("region")))throw new IllegalStateException("S3 ledger header mismatch");
        BigDecimal stored=decimal(header.get("cap_usd"));validateCap(stored);
        for(int i=1;i<events.size();i++) {
            var event=events.get(i);if("header".equals(event.get("event")))throw new IllegalStateException("duplicate S3 ledger header");
            if("cap_reduced".equals(event.get("event"))){BigDecimal lower=decimal(event.get("cap_usd"));validateCap(lower);if(lower.compareTo(stored)>0)throw new IllegalStateException("invalid S3 cap increase record");stored=lower;}
        }return stored;
    }
    private static BigDecimal cost(List<Map<String,Object>> events){BigDecimal total=BigDecimal.ZERO;for(var event:events)if("attempt".equals(event.get("event"))){BigDecimal amount=decimal(event.get("estimated_usd"));if(amount.signum()<0)throw new IllegalStateException("negative S3 charge");total=total.add(amount);}return total;}
    private List<Map<String,Object>> read()throws IOException {
        if(Files.size(file)>64L*1024*1024)throw new IllegalStateException("S3 ledger exceeds 64 MiB safety bound");byte[] bytes=Files.readAllBytes(file);
        if(bytes.length>0&&bytes[bytes.length-1]!='\n')throw new IllegalStateException("torn S3 operation ledger; refusing dispatch rather than losing a charge");
        List<Map<String,Object>> events=new ArrayList<>();for(String line:new String(bytes,StandardCharsets.UTF_8).split("\n")){if(line.isEmpty())continue;Object parsed=Json.parse(line);if(!(parsed instanceof Map<?,?> map))throw new IllegalStateException("invalid S3 ledger record");events.add((Map<String,Object>)map);}return events;
    }
    private void append(Map<String,?> event)throws IOException {
        try(FileChannel channel=FileChannel.open(file,StandardOpenOption.CREATE,StandardOpenOption.WRITE,StandardOpenOption.APPEND)){ByteBuffer bytes=StandardCharsets.UTF_8.encode(Jsons.encode(event)+"\n");while(bytes.hasRemaining())channel.write(bytes);channel.force(true);}
    }
    private <T>T locked(Callable<T> operation){
        Object local=JVM_LOCKS[Math.floorMod(lock.toString().hashCode(),JVM_LOCKS.length)];
        synchronized(local){try{Files.createDirectories(file.getParent());try(FileChannel channel=FileChannel.open(lock,StandardOpenOption.CREATE,StandardOpenOption.WRITE);var guard=channel.lock()){return operation.call();}}catch(RuntimeException e){throw e;}catch(Exception e){throw new IllegalStateException("S3 operation ledger I/O failed; no further request admitted",e);}}
    }
    private static BigDecimal decimal(Object value){try{return new BigDecimal(String.valueOf(value));}catch(Exception e){throw new IllegalStateException("invalid S3 ledger amount",e);}}
    private static void validateCap(BigDecimal cap){if(cap==null||cap.signum()<0||cap.compareTo(HARD_CAP)>0)throw new IllegalArgumentException("S3 run cap must be $0..$0.25");}
    private static void validateRun(String run){if(run==null||!run.matches("[a-z0-9][a-z0-9_-]{0,63}"))throw new IllegalArgumentException("invalid S3 ledger run id");}
    private static void validateOperation(String operation){if(operation==null||!operation.matches("[A-Za-z][A-Za-z0-9]{0,80}"))throw new IllegalArgumentException("invalid S3 operation");}
    private void checkOpen(){if(closed)throw new IllegalStateException("closed S3 ledger");}
    public Path path(){return file;}public String runId(){return run;}public BigDecimal cap(){return cap;}
    @Override public void close(){closed=true;}
}
