package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

/** Locked, checksummed write-ahead evidence; no AWS discovery or lifecycle decisions. */
final class ProvisionJournal implements AutoCloseable {
    private static final long MAX_BYTES=16L*1024*1024;
    private static final int MAX_LINE=256*1024;
    private static final ReentrantLock[] LOCKS=new ReentrantLock[64];
    static {Arrays.setAll(LOCKS, i -> new ReentrantLock());}
    private final ReentrantLock local;
    private FileChannel lockChannel, journal;
    private FileLock fileLock;
    private Map<String,Object> state=new LinkedHashMap<>();
    private long sequence;
    private String previous="";
    private boolean closed;
    private final String id;
    final Path path;

    static ProvisionJournal open(String id, boolean demo) {
        if(id==null || !id.matches("[a-z0-9][a-z0-9_-]{0,63}"))
            throw new IllegalArgumentException("invalid lmprov_id");
        return new ProvisionJournal(id,demo);
    }
    private ProvisionJournal(String id,boolean demo) {
        this.id=id;
        Path root=Path.of(System.getenv().getOrDefault("LMPROV_LEDGER_DIR",
            System.getenv().getOrDefault("LMAWS_LEDGER_DIR",".lmaws-local/provision/host")))
            .toAbsolutePath().normalize().resolve(demo?"demo":"aws");
        path=root.resolve(id+".jsonl");
        local=LOCKS[(path.toString().hashCode() & 0x7fffffff)%LOCKS.length];
        local.lock();
        try {
            Path current=root.getRoot();
            for(Path part:root) {
                current=current.resolve(part);
                if(Files.isSymbolicLink(current))throw new IOException("provisioning ledger cannot traverse symlinks");
            }
            Files.createDirectories(root);
            privatePermissions(root,true);
            Path lockPath=root.resolve(id+".lock");
            if(Files.isSymbolicLink(lockPath)||Files.isSymbolicLink(path))throw new IOException("provisioning journal symlink refused");
            lockChannel=FileChannel.open(lockPath,StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
            privatePermissions(lockPath,false);
            fileLock=lockChannel.lock();
            journal=FileChannel.open(path,StandardOpenOption.CREATE,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
            privatePermissions(path,false);
            replay();
            if(sequence==0) append("header",Map.of("format",1,"lmprov_id",id,"mode",demo?"demo":"aws"));
        } catch(Exception failure) {
            close();
            throw new IllegalStateException("provisioning journal unavailable or invalid; refusing AWS operation",failure);
        }
    }
    private static void privatePermissions(Path path,boolean directory) throws IOException {
        try {Files.setPosixFilePermissions(path,PosixFilePermissions.fromString(directory?"rwx------":"rw-------"));}
        catch(UnsupportedOperationException ignored) {
            var file=path.toFile();
            if(!file.setReadable(false,false)||!file.setReadable(true,true)
                ||!file.setWritable(false,false)||!file.setWritable(true,true))
                throw new IOException("cannot restrict provisioning journal permissions");
        }
    }
    @SuppressWarnings("unchecked")
    private void replay() throws IOException {
        long size=journal.size();
        if(size>MAX_BYTES)throw new IOException("provisioning journal exceeds 16 MiB");
        if(size==0)return;
        ByteBuffer bytes=ByteBuffer.allocate((int)size);
        journal.position(0);
        while(bytes.hasRemaining())if(journal.read(bytes)<0)throw new IOException("short journal read");
        String content=new String(bytes.array(),StandardCharsets.UTF_8);
        if(!content.endsWith("\n"))throw new IOException("torn provisioning journal tail");
        for(String line:content.split("\n")) {
            if(line.isEmpty()||line.length()>MAX_LINE)throw new IOException("invalid provisioning journal line");
            Map<String,Object> wrapper=object(Json.parse(line));
            Map<String,Object> payload=object(wrapper.get("payload"));
            String hash=hash(Jsons.encodeRaw(payload));
            if(!hash.equals(wrapper.get("sha256"))||!previous.equals(payload.get("previous"))
                ||((Number)payload.get("seq")).longValue()!=sequence+1)
                throw new IOException("provisioning journal checksum/sequence mismatch");
            String event=String.valueOf(payload.get("event"));
            Map<String,Object> data=object(payload.get("data"));
            if(sequence==0 && (!"header".equals(event)||!id.equals(data.get("lmprov_id"))))
                throw new IOException("provisioning journal identity mismatch");
            if(sequence>0 && "header".equals(event))throw new IOException("duplicate provisioning journal header");
            if("state".equals(event))state=new LinkedHashMap<>(data);
            previous=hash;sequence++;
        }
    }
    @SuppressWarnings("unchecked")
    private static Map<String,Object> object(Object value) {
        if(!(value instanceof Map<?,?>))throw new IllegalArgumentException("invalid journal object");
        return (Map<String,Object>)value;
    }
    @SuppressWarnings("unchecked")
    Map<String,Object> state() {return object(Json.parse(Jsons.encodeRaw(state)));}
    void save(Map<String,Object> next) {
        append("state",next);
        state=object(Json.parse(Jsons.encodeRaw(next)));
    }
    void request(String operation) {
        append("request",Map.of("operation",operation,"requests",1,"unit_price_usd","0.00",
            "pricing_note","EC2/SSM/STS control-plane calls; lifecycle resource costs are settled separately"));
    }
    void receipt(Map<String,Object> receipt) {append("receipt",object(Json.parse(Jsons.encode(receipt))));}
    private void append(String event,Map<String,Object> data) {
        if(closed)throw new IllegalStateException("closed provisioning journal");
        Map<String,Object> payload=new LinkedHashMap<>();
        payload.put("seq",sequence+1);payload.put("previous",previous);payload.put("event",event);
        payload.put("at",Instant.now().toString());payload.put("data",data);
        // The SDK JSON parser represents numeric tokens as doubles; hash the same normalized form on write and replay.
        payload=object(Json.parse(Jsons.encodeRaw(payload)));
        String hash=hash(Jsons.encodeRaw(payload));
        byte[] line=(Jsons.encodeRaw(Map.of("payload",payload,"sha256",hash))+"\n").getBytes(StandardCharsets.UTF_8);
        try {
            if(line.length>MAX_LINE || journal.size()+line.length>MAX_BYTES)throw new IOException("provisioning journal bound exceeded");
            journal.position(journal.size());
            ByteBuffer buffer=ByteBuffer.wrap(line);
            while(buffer.hasRemaining())journal.write(buffer);
            journal.force(true);
            previous=hash;sequence++;
        } catch(IOException error) {throw new IllegalStateException("cannot durably record provisioning operation",error);}
    }
    static String hash(String text) {
        try {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));}
        catch(Exception error){throw new IllegalStateException("SHA-256 unavailable",error);}
    }
    @Override public void close() {
        if(closed)return;
        closed=true;
        try{if(journal!=null)journal.close();}catch(IOException ignored){}
        try{if(fileLock!=null)fileLock.release();}catch(IOException ignored){}
        try{if(lockChannel!=null)lockChannel.close();}catch(IOException ignored){}
        local.unlock();
    }
}
