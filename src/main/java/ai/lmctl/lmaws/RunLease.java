package ai.lmctl.lmaws;

import java.nio.file.*;
import java.nio.channels.*;
import java.util.*;

/** A separate inode keeps run liveness independent of append-only ledger handles. */
final class RunLease implements AutoCloseable {
    private static final Map<Path,State> OWNERS=new HashMap<>();
    private static final class State {FileChannel channel;FileLock lock;int users;}
    private final Path path;private final State state;private final boolean shared;private boolean closed;
    private RunLease(Path path,State state,boolean shared){this.path=path;this.state=state;this.shared=shared;}
    static synchronized RunLease owner(Path ledger){Path key=ledger.toAbsolutePath().normalize();State state=OWNERS.get(key);if(state==null){state=open(key);OWNERS.put(key,state);}state.users++;return new RunLease(key,state,true);}
    static synchronized RunLease recovery(Path ledger){Path key=ledger.toAbsolutePath().normalize();if(OWNERS.containsKey(key))throw new IllegalStateException("run ledger is active");return new RunLease(key,open(key),false);}
    static synchronized boolean busy(Path ledger){Path key=ledger.toAbsolutePath().normalize();if(OWNERS.containsKey(key))return true;Path lock=lockPath(key);if(!Files.exists(lock))return false;try(RunLease probe=recovery(key)){return false;}catch(RuntimeException e){return true;}}
    private static Path lockPath(Path path){return path.resolveSibling(path.getFileName()+".lock");}
    private static State open(Path path){State state=new State();try{Path lock=lockPath(path);if(Files.isSymbolicLink(lock))throw new IllegalStateException("symlink run locks are not accepted");state.channel=FileChannel.open(lock,StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);state.lock=state.channel.tryLock();if(state.lock==null)throw new IllegalStateException("run ledger is busy");return state;}catch(Exception e){try{if(state.channel!=null)state.channel.close();}catch(Exception ignored){}throw new IllegalStateException("run ledger is active or cannot be locked",e);}}
    @Override public synchronized void close(){if(closed)return;closed=true;synchronized(RunLease.class){if(shared&&--state.users>0)return;if(shared)OWNERS.remove(path);try{state.lock.release();state.channel.close();}catch(java.io.IOException e){throw new IllegalStateException("cannot release run lease",e);}}}
}
