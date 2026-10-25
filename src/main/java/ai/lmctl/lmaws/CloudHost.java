package ai.lmctl.lmaws;

import io.lmctl.lmcode.*;
import java.nio.file.*;
import java.util.*;

/** Typed registry and run-owned resources; every live session has a single region. */
public final class CloudHost implements AutoCloseable {
    public static final List<String> INVENTORIES=List.of("identity","buckets","instances","vpcs","security_groups","tables","queues","topics","functions","log_groups","alarms","zones","secrets","parameters","clusters","roles");
    private final List<Session> clients=new ArrayList<>();
    private final List<Sandbox> runs=new ArrayList<>();
    private boolean closed;
    private CostLedger billing;
    private Session measured;
    private String failureCode="", deniedAction="";
    void noteFailure(String code,String action){failureCode=code;deniedAction=action;}
    private record Session(AwsBackend backend,CostLedger cost) {}
    static java.math.BigDecimal costCap() {
        String raw=System.getenv().getOrDefault("LMAWS_MAX_COST_USD","0.05");
        try {
            if(raw.length()>32 || !raw.matches("(?:[0-9]+(?:\\.[0-9]+)?|\\.[0-9]+)"))throw new NumberFormatException();
            var cap=new java.math.BigDecimal(raw);
            if(cap.signum()<0 || cap.compareTo(CostLedger.HARD_CEILING)>0)throw new NumberFormatException();
            return cap;
        } catch(NumberFormatException e){throw new IllegalArgumentException("LMAWS_MAX_COST_USD must be a dollar amount between 0 and 0.25 (default 0.05)");}
    }
    private Session open(String region,boolean demo) {return open(region,demo,"script",false);}
    private Session open(String region,boolean demo,String name,boolean example) {
        boolean offline=demo || Boolean.getBoolean("lmaws.dryRun");
        String selected=region;
        if(selected==null || selected.isBlank())selected=offline?"us-east-1":software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain.builder().build().getRegion().id();
        if(example && billing!=null)throw VmException.host("an example must be the sole cloud session in its program");
        if(billing==null) {
            String nonce=java.util.UUID.randomUUID().toString().replace("-","");String runId="r"+nonce.substring(0,8)+"x"+nonce.substring(8,16);
            Path dir=Path.of(System.getenv().getOrDefault("LMAWS_LEDGER_DIR","ledgers"));
            billing=new CostLedger(runId,name,selected,dir.resolve("lmaws-"+runId+".jsonl"),costCap(),!offline && System.getenv().getOrDefault("LMAWS_ENDPOINT","").isBlank());
        } else if(!billing.region().equals(selected) || !clients.isEmpty() && clients.get(0).backend.isDemo()!=offline)throw VmException.host("one region and mode per whole cost-capped run");
        AwsBackend backend=new AwsBackend(selected,offline,billing);Session session=new Session(backend,billing);clients.add(session);
        if(example)measured=session;
        return session;
    }
    private Session example(String name) {
        if(!name.matches("[a-z][a-z0-9_]{0,63}"))throw VmException.host("invalid example name");
        boolean live="1".equals(System.getenv("LMAWS_LIVE"));
        String region=System.getenv().getOrDefault("AWS_REGION",System.getenv().getOrDefault("AWS_DEFAULT_REGION",""));
        return open(region,!live,name,true);
    }
    private Session session(Value value) {return (Session)value.asObject();}
    public Registry registry() {
        Registry r=new Registry();r.context("aws","Cloud");
        r.function("check",List.of("bool"),"void",(c,s,a)->{if(!a[0].asBool())throw VmException.host("check failed");return Value.none();});
        r.method("Cloud","example",List.of("string"),"Cloud",(c,s,a)->Value.object("Cloud",example(text(a[0]))));
        r.method("Cloud","sweep",List.of("int"),"Rows",(c,s,a)->Value.object("Rows",new Rows(Sandbox.leftovers(session(s).cost.path().toAbsolutePath().getParent(),a[0].asInt()),c)));
        r.method("Cloud","is_demo",List.of(),"bool",(c,s,a)->Value.ofBool(session(s).backend.isDemo()));
        r.method("Cloud","example_run",List.of(),"Run",(c,s,a)->{Session v=session(s);Sandbox run=new Sandbox(v.backend,v.cost.runId(),v.cost.path(),v.cost);runs.add(run);return Value.object("Run",run);});
        r.method("Cloud","demo",List.of(),"Cloud",(c,s,a)->Value.object("Cloud",open("us-east-1",true)));
        r.method("Cloud","region",List.of("string"),"Cloud",(c,s,a)->Value.object("Cloud",open(text(a[0]),false)));
        for(String inventory:INVENTORIES) r.method("Cloud",inventory,List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.inventory(inventory),c)));
        r.method("Cloud","run",List.of("string","string"),"Run",(c,s,a)->{Sandbox run=new Sandbox(session(s).backend,text(a[0]),Path.of(text(a[1])),session(s).cost);runs.add(run);return Value.object("Run",run);});
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
        r.method("Run","estimated_cost",List.of(),"float",(c,s,a)->Value.ofFloat(((Sandbox)s.asObject()).cost()==null?0.0:((Sandbox)s.asObject()).cost().total().doubleValue()));
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
        if(measured!=null)try{finishEvidence(measured);}catch(RuntimeException e){if(failure==null)failure=e;}
        for(var client:clients)try{client.backend.close();}catch(RuntimeException e){if(failure==null)failure=e;}
        closed=true;
        if(failure!=null)throw failure;
    }
    @SuppressWarnings("unchecked") private void finishEvidence(Session session) {
        List<Map<String,Object>> verified=new ArrayList<>();int leftovers=0;
        Map<String,Object> initial=session.cost.report(0);
        try(AutoCloseable ignored=session.cost.cleanupScope()) {
            for(var raw:(List<Map<String,Object>>)initial.get("resources")) {
                String kind=(String)raw.get("kind"),id=(String)raw.get("id");
                boolean present=true;String error="";
                try {
                    session.cost.select(kind,id);
                    long deadline=System.nanoTime()+java.time.Duration.ofSeconds(35).toNanos();
                    do {present=session.backend.exists(kind,id);if(!present)break;Thread.sleep(500);}while(System.nanoTime()<deadline);
                }catch(Exception e){error=e.getClass().getSimpleName();}
                if(present || !error.isEmpty())leftovers++;
                Map<String,Object> result=new LinkedHashMap<>();result.put("kind",kind);result.put("name",raw.get("name"));result.put("absent",!present && error.isEmpty());if(!error.isEmpty())result.put("error_type",error);verified.add(result);
            }
        }catch(Exception e){throw new IllegalStateException("cannot finish cost verification",e);}
        List<Map<String,String>> candidates=Sandbox.leftovers(session.cost.path().toAbsolutePath().getParent(),0).stream().filter(v->Path.of(v.get("ledger")).toAbsolutePath().normalize().equals(session.cost.path().toAbsolutePath().normalize())).toList();
        leftovers=Math.max(leftovers,candidates.size());
        Map<String,Object> report=new LinkedHashMap<>(session.cost.report(leftovers));report.put("provider_verification",verified);report.put("sweeper_leftover_count",candidates.size());report.put("profile",System.getenv().getOrDefault("AWS_PROFILE","default"));report.put("ledger",session.cost.path().toString());report.put("estimated_cost_display",session.cost.displayCost());if(!failureCode.isEmpty())report.put("run_error",failureCode);if(!deniedAction.isEmpty())report.put("denied_action",deniedAction);report.put("finished_at",java.time.Instant.now().toString());
        Path dir=Path.of(System.getenv().getOrDefault("LMAWS_EVIDENCE_DIR",session.cost.live()?"evidence":"data/cost-evidence"));Path output=dir.resolve("live-cost-"+session.cost.example()+"-"+session.cost.runId()+".json");
        try {
            Files.createDirectories(dir);Files.writeString(output,Jsons.encode(report)+"\n",java.nio.charset.StandardCharsets.UTF_8);
        }catch(java.io.IOException e){throw new IllegalStateException("cannot write cost evidence",e);}
        System.out.println("evidence: "+output);System.out.println("estimated cost: "+session.cost.displayCost());
        if(leftovers!=0)throw new IllegalStateException("leftover count is "+leftovers+"; inspect the run ledger");
    }
}
