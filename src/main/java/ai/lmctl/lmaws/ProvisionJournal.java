package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.UserPrincipal;
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
        Path configured=Path.of(System.getenv().getOrDefault("LMPROV_LEDGER_DIR",
            System.getenv().getOrDefault("LMAWS_LEDGER_DIR",".lmaws-local/provision/host")));
        return open(id,demo,configured);
    }
    static ProvisionJournal open(String id,boolean demo,Path configured) {
        if(id==null || !id.matches("[a-z0-9][a-z0-9_-]{0,63}"))
            throw new IllegalArgumentException("invalid lmprov_id");
        return new ProvisionJournal(id,demo,configured);
    }
    private static final Set<java.nio.file.attribute.PosixFilePermission> DIRECTORY_MODE=
        PosixFilePermissions.fromString("rwx------");
    private static final Set<java.nio.file.attribute.PosixFilePermission> FILE_MODE=
        PosixFilePermissions.fromString("rw-------");
    private static final class PathFailure extends IOException {
        final String check,pathClass,detail;
        PathFailure(String check,String pathClass,String detail){
            super("check="+check+" path_class="+pathClass+" detail="+detail);
            this.check=check;this.pathClass=pathClass;this.detail=detail;
        }
    }
    private static IllegalStateException refusal(Exception error,String check,String pathClass) {
        String detail=error.getClass().getSimpleName();
        if(error instanceof PathFailure failure){check=failure.check;pathClass=failure.pathClass;detail=failure.detail;}
        else if(check.equals("journal_replay")){
            detail=switch(String.valueOf(error.getMessage())){
                case "torn provisioning journal tail" -> "torn_tail";
                case "provisioning journal checksum/sequence mismatch" -> "checksum_or_sequence_mismatch";
                case "provisioning journal identity mismatch" -> "header_identity_mismatch";
                case "duplicate provisioning journal header" -> "duplicate_header";
                case "provisioning journal exceeds 16 MiB" -> "size_limit";
                default -> "invalid_content";
            };
        }
        // Do not forward IOException paths, run IDs, usernames or parser contents.
        return new IllegalStateException("provisioning journal unavailable or invalid: check="+check
            +" path_class="+pathClass+" detail="+detail+"; refusing AWS operation");
    }
    private ProvisionJournal(String id,boolean demo,Path configured) {
        this.id=id;
        Path root;
        try {
            Path base=privateDirectory(configured,"configured-directory");
            root=privateDirectory(base.resolve(demo?"demo":"aws"),"canonical-mode-directory");
        } catch(Exception failure) {throw refusal(failure,"path_canonicalization","configured-directory");}
        path=root.resolve(id+".jsonl");
        // Aliased parents must select the same in-process lock as their canonical path.
        local=LOCKS[(path.toString().hashCode() & 0x7fffffff)%LOCKS.length];
        local.lock();
        String check="lock_open",pathClass="canonical-lock-file";
        try {
            Path lockPath=root.resolve(id+".lock");
            lockChannel=openPrivateFile(lockPath,false,pathClass);
            check="lock_acquire";fileLock=lockChannel.lock();
            check="journal_open";pathClass="canonical-journal-file";
            journal=openPrivateFile(path,true,pathClass);
            check="journal_replay";replay();
            check="journal_header";
            if(sequence==0) append("header",Map.of("format",1,"lmprov_id",id,"mode",demo?"demo":"aws"));
        } catch(Exception failure) {
            close();
            throw refusal(failure,check,pathClass);
        }
    }
    /** Resolve ancestor aliases (notably Darwin /var and /tmp) before security checks. */
    private static Path privateDirectory(Path requested,String pathClass) throws IOException {
        Path absolute=requested.toAbsolutePath().normalize();
        if(Files.isSymbolicLink(absolute))throw new PathFailure("final_component_symlink",pathClass,"refused");
        Path existing=absolute;
        Deque<Path> missing=new ArrayDeque<>();
        while(!Files.exists(existing,LinkOption.NOFOLLOW_LINKS)) {
            if(existing.getFileName()==null||existing.getParent()==null)
                throw new PathFailure("path_canonicalization",pathClass,"no_existing_parent");
            missing.addFirst(existing.getFileName());existing=existing.getParent();
        }
        Path canonical=existing.toRealPath();
        for(Path component:missing) {
            Path child=canonical.resolve(component);
            try {Files.createDirectory(child,PosixFilePermissions.asFileAttribute(DIRECTORY_MODE));}
            catch(FileAlreadyExistsException raced) { /* Revalidate; never repair another directory. */ }
            if(Files.isSymbolicLink(child))throw new PathFailure("final_component_symlink",pathClass,"creation_race_refused");
            canonical=child.toRealPath();
            requireDirectory(canonical,pathClass);
        }
        if(Files.isSymbolicLink(absolute))throw new PathFailure("final_component_symlink",pathClass,"resolution_race_refused");
        Path real=absolute.toRealPath();
        if(!real.equals(canonical))throw new PathFailure("path_canonicalization",pathClass,"parent_changed");
        requireDirectory(real,pathClass);
        return real;
    }
    private static UserPrincipal currentUser(Path path,String pathClass) throws IOException {
        String name=System.getProperty("user.name","");
        if(name.isBlank())throw new PathFailure("current_user_lookup",pathClass,"user_unavailable");
        return path.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(name);
    }
    private static void requireDirectory(Path canonical,String pathClass) throws IOException {
        var attributes=Files.readAttributes(canonical,PosixFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        if(!attributes.isDirectory())throw new PathFailure("directory_type",pathClass,"not_directory");
        if(!attributes.owner().equals(currentUser(canonical,pathClass)))
            throw new PathFailure("directory_owner",pathClass,"not_current_user");
        int mode=((Number)Files.getAttribute(canonical,"unix:mode",LinkOption.NOFOLLOW_LINKS)).intValue()&07777;
        if(!attributes.permissions().equals(DIRECTORY_MODE)||mode!=0700)
            throw new PathFailure("directory_permissions",pathClass,"expected_0700");
    }
    private static FileChannel openPrivateFile(Path file,boolean read,String pathClass) throws IOException {
        if(Files.isSymbolicLink(file))throw new PathFailure("final_component_symlink",pathClass,"refused");
        if(Files.exists(file,LinkOption.NOFOLLOW_LINKS))requireFile(file,pathClass);
        Set<OpenOption> options=new HashSet<>(Set.of(StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS));
        if(read)options.add(StandardOpenOption.READ);
        FileChannel channel=FileChannel.open(file,options,PosixFilePermissions.asFileAttribute(FILE_MODE));
        try {requireFile(file,pathClass);return channel;}
        catch(Exception failure){channel.close();throw failure;}
    }
    private static void requireFile(Path file,String pathClass) throws IOException {
        var attributes=Files.readAttributes(file,PosixFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        if(!attributes.isRegularFile()||!attributes.owner().equals(currentUser(file,pathClass))
            ||!attributes.permissions().equals(FILE_MODE))
            throw new PathFailure("file_permissions",pathClass,"expected_current_user_regular_0600");
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
        } catch(IOException error) {throw refusal(error,"journal_append","canonical-journal-file");}
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
