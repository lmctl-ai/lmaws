package ai.lmctl.lmaws;

import io.lmctl.lmcode.VmException;
import java.util.*;

/** Bound the Java heap as well as VM allocations, including AWS SDK buffers. */
final class RuntimeBudget {
    static void configure(long bytes,String[] arguments) throws Exception {
        if(bytes<16L*1024*1024) throw VmException.run("LMAWS_MAX_MEMORY_MB memory budget cannot accommodate the runtime (minimum 16 MiB)");
        long heapMb=bytes/(1024*1024)*3/4/4*4;
        long heapBytes=heapMb*1024*1024;
        if(Runtime.getRuntime().maxMemory()<=heapBytes) return;
        if(Long.toString(heapBytes).equals(System.getenv("LMAWS_INTERNAL_HEAP_BYTES"))) throw VmException.run("LMAWS_MAX_MEMORY_MB heap limit was not applied");
        List<String> cmd=new ArrayList<>();cmd.add(ProcessHandle.current().info().command().orElseThrow());cmd.add("-Xmx"+heapMb+"m");
        if(!"runtime".equals(System.getProperty("org.graalvm.nativeimage.imagecode"))) {cmd.add("-cp");cmd.add(System.getProperty("java.class.path"));cmd.add(Main.class.getName());}
        Collections.addAll(cmd,arguments);
        ProcessBuilder child=new ProcessBuilder(cmd).inheritIO();child.environment().put("LMAWS_INTERNAL_HEAP_BYTES",Long.toString(heapBytes));System.exit(child.start().waitFor());
    }
}
