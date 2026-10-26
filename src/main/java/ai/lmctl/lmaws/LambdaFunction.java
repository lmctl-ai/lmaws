package ai.lmctl.lmaws;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Run-owned Lambda definition used by the scenario host.  The object deliberately
 * keeps the deployment contract small: code is supplied as UTF-8 source, the
 * execution role is the pre-created lmaws role, and Function URLs are public
 * only when the caller explicitly opts into NONE authentication.
 */
public final class LambdaFunction {
    private static final Pattern NAME = Pattern.compile("lmaws[-_][a-z0-9_-]{1,62}");
    private static final Pattern ROLE = Pattern.compile("(?:arn:aws:iam::[0-9]+:role/)?lmaws_lambda_exec");
    private final String name, role, runtime, handler, code, runId;
    private final int memoryMb, timeoutSeconds;
    private boolean deleted;
    LambdaFunction(String name, String role, String runtime, String handler, String code,
                   int memoryMb, int timeoutSeconds, String runId) {
        if (name == null || !NAME.matcher(name).matches()) throw new IllegalArgumentException("Lambda name must start with lmaws_ or lmaws-");
        if (role == null || !ROLE.matcher(role).matches()) throw new IllegalArgumentException("only the pre-created lmaws_lambda_exec role is allowed");
        if (!runtime.equals("python3.12") && !runtime.equals("python3.11")) throw new IllegalArgumentException("runtime must be python3.12 or python3.11");
        if (handler == null || !handler.matches("[A-Za-z_][A-Za-z0-9_.-]{0,127}")) throw new IllegalArgumentException("invalid Lambda handler");
        if (code == null || code.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 256 * 1024) throw new IllegalArgumentException("inline Lambda source exceeds 256 KiB");
        if (memoryMb < 128 || memoryMb > 10240 || memoryMb % 1 != 0) throw new IllegalArgumentException("memory must be 128..10240 MiB");
        if (timeoutSeconds < 1 || timeoutSeconds > 900) throw new IllegalArgumentException("timeout must be 1..900 seconds");
        this.name=name;this.role=role;this.runtime=runtime;this.handler=handler;this.code=code;this.memoryMb=memoryMb;this.timeoutSeconds=timeoutSeconds;this.runId=runId;
    }
    public synchronized Map<String,String> status() {
        return row("kind","lambda","name",name,"id",arn(),"arn",arn(),"role","lmaws_lambda_exec","runtime",runtime,"handler",handler,"memory_mb",Integer.toString(memoryMb),"timeout_s",Integer.toString(timeoutSeconds),"run_id",runId,"state",deleted?"deleted":"active");
    }
    public synchronized String arn(){return "arn:aws:lambda:local:000000000000:function:"+name;}
    public synchronized String url(String reason){
        if (deleted) throw new IllegalStateException("Lambda is deleted");
        if (reason == null || reason.isBlank()) throw new IllegalArgumentException("public Function URL auth NONE requires an explicit reason");
        if (reason.length() > 256) throw new IllegalArgumentException("Function URL reason is too long");
        return "https://"+name+".lambda-url.local/";
    }
    public synchronized Map<String,String> invoke(String payload){
        if (deleted) throw new IllegalStateException("Lambda is deleted");
        if (payload == null || payload.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 256*1024) throw new IllegalArgumentException("invoke payload exceeds 256 KiB");
        return row("status","200","function_name",name,"request_id","fake-"+runId,"payload",payload,"cold_start","false");
    }
    public synchronized Map<String,String> delete(){deleted=true;return status();}
    private static Map<String,String> row(String... kv){var m=new LinkedHashMap<String,String>();for(int i=0;i<kv.length;i+=2)m.put(kv[i],kv[i+1]);return m;}
}
