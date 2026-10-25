package ai.lmctl.lmaws;

import io.lmctl.lmcode.*;
import java.nio.file.*;
import java.util.*;

/** Typed registry and run-owned resources; every live session has a single region. */
public final class CloudHost implements AutoCloseable {
    public static final List<String> INVENTORIES=List.of("identity","buckets","instances","vpcs","security_groups","tables","queues","topics","functions","log_groups","alarms","zones","secrets","parameters","clusters","roles");
    private final List<AwsBackend> clients=new ArrayList<>();
    private final List<Sandbox> runs=new ArrayList<>();
    private boolean closed;
    private record Session(AwsBackend backend) {}
    private Session open(String region,boolean demo) {
        AwsBackend backend=new AwsBackend(region,demo || Boolean.getBoolean("lmaws.dryRun"));clients.add(backend);return new Session(backend);
    }
    private Session session(Value value) {return (Session)value.asObject();}
    public Registry registry() {
        Registry r=new Registry();r.context("aws","Cloud");
        r.function("check",List.of("bool"),"void",(c,s,a)->{if(!a[0].asBool())throw VmException.host("check failed");return Value.none();});
        r.method("Cloud","demo",List.of(),"Cloud",(c,s,a)->Value.object("Cloud",open("us-east-1",true)));
        r.method("Cloud","region",List.of("string"),"Cloud",(c,s,a)->Value.object("Cloud",open(text(a[0]),false)));
        for(String inventory:INVENTORIES) r.method("Cloud",inventory,List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.inventory(inventory),c)));
        r.method("Cloud","run",List.of("string","string"),"Run",(c,s,a)->{Sandbox run=new Sandbox(session(s).backend,text(a[0]),Path.of(text(a[1])));runs.add(run);return Value.object("Run",run);});
        r.method("Rows","len",List.of(),"int",(c,s,a)->Value.ofInt(((Rows)s.asObject()).rows.size()));
        r.method("Rows","at",List.of("int"),"Row",(c,s,a)->{Rows rows=(Rows)s.asObject();long i=a[0].asInt();if(i<0||i>=rows.rows.size())throw VmException.host("row index outside inventory");return Value.object("Row",rows.rows.get((int)i));});
        r.method("Rows","csv",List.of("string"),"void",(c,s,a)->{((Rows)s.asObject()).write(text(a[0]));return Value.none();});
        r.method("Rows","json",List.of(),"string",(c,s,a)->Value.ofString(Jsons.encode(((Rows)s.asObject()).rows)));
        r.method("Rows","count",List.of("string","string"),"int",(c,s,a)->Value.ofInt(((Rows)s.asObject()).rows.stream().filter(row->Rows.get(row,text(a[0])).equals(text(a[1]))).count()));
        r.method("Rows","filter",List.of("string","string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(((Rows)s.asObject()).rows.stream().filter(row->Rows.get(row,text(a[0])).equals(text(a[1]))).toList(),c)));
        r.method("Row","get",List.of("string"),"string",(c,s,a)->Value.ofString(Rows.get(row(s),text(a[0]))));
        r.method("Row","number",List.of("string"),"int",(c,s,a)->{String v=Rows.get(row(s),text(a[0]));try{return Value.ofInt(v.isEmpty()?0:Long.parseLong(v));}catch(NumberFormatException e){throw VmException.host("field is not an integer");}});
        for(String kind:List.of("bucket","queue","topic","parameter","log_group","table")) r.method("Run",kind,kind.equals("parameter")?List.of("string","string"):List.of("string"),"Row",(c,s,a)->{var result=((Sandbox)s.asObject()).create(kind,text(a[0]),a.length>1?text(a[1]):"");c.charge(2048);return Value.object("Row",result);});
        r.method("Run","put",List.of("Row","string","string"),"void",(c,s,a)->{((Sandbox)s.asObject()).put(row(a[0]),text(a[1]),text(a[2]));return Value.none();});
        r.method("Run","cleanup",List.of(),"void",(c,s,a)->{((Sandbox)s.asObject()).cleanup();return Value.none();});
        r.method("Run","remaining",List.of(),"int",(c,s,a)->Value.ofInt(((Sandbox)s.asObject()).remaining()));
        return r;
    }
    private static String text(Value value) {
        try{return java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(value.asString().bytes())).toString();}
        catch(java.nio.charset.CharacterCodingException e){throw VmException.host("AWS host strings must contain valid UTF-8");}
    }
    @SuppressWarnings("unchecked") private static Map<String,String> row(Value value) {return (Map<String,String>)value.asObject();}
    public Context context(long budget) {Context c=new Context();c.memoryLimitBytes=budget;c.setObject("aws","Cloud",new Object());return c;}
    @Override public synchronized void close() {
        if(closed)return;
        RuntimeException failure=null;
        for(var run:runs.reversed())try{run.close();}catch(RuntimeException e){failure=e;}
        for(var client:clients)try{client.close();}catch(RuntimeException e){failure=e;}
        if(failure!=null)throw failure;
        closed=true;
    }
}
