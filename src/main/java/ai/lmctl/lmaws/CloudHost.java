package ai.lmctl.lmaws;

import io.lmctl.lmcode.*;
import java.nio.file.*;
import java.util.*;

/** Typed registry and run-owned resources; every live session has a single region. */
public final class CloudHost implements AutoCloseable {
    public static final List<String> INVENTORIES=List.of("identity","buckets","instances","vpcs","security_groups","tables","queues","topics","functions","log_groups","alarms","zones","secrets","parameters","clusters","roles");
    private final List<Session> clients=new ArrayList<>();
    private final List<Sandbox> runs=new ArrayList<>();
    private final Map<SpendReport,CostLedger> spendLedgers=new IdentityHashMap<>();
    private final Map<Session,Ec2Compute> compute=new IdentityHashMap<>();
    private final List<Ec2Compute.SpotRun> spots=new ArrayList<>();
    private final List<WebRun> webRuns=new ArrayList<>();
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
        if(!spendLedgers.isEmpty())throw VmException.host("spend must be the sole cost-capped report/session in its host program");
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
        boolean live=AwsBackend.isLiveEnabled();
        String region=AwsBackend.activeRegion();
        return open(region,!live,name,true);
    }
    private Session session(Value value) {return (Session)value.asObject();}
    public Registry registry() {
        Registry r=new Registry();r.context("aws","Cloud");
        r.function("check",List.of("bool"),"void",(c,s,a)->{if(!a[0].asBool())throw VmException.host("check failed");return Value.none();});
        r.method("Cloud","example",List.of("string"),"Cloud",(c,s,a)->Value.object("Cloud",example(text(a[0]))));
        r.method("Cloud","find_prefix",List.of("string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.findPrefix(text(a[0])),c)));
        r.method("Cloud","resource_exists",List.of("string","string"),"bool",(c,s,a)->Value.ofBool(ResourceLookup.exists(session(s).backend,text(a[0]),text(a[1]))));
        r.method("Cloud","leftovers",List.of("string","int"),"Rows",(c,s,a)->{var v=session(s);return Value.object("Rows",new Rows(LedgerCleanup.execute(v.backend,v.cost.path().toAbsolutePath().getParent(),text(a[0]),a[1].asInt(),false),c));});
        r.method("Cloud","cleanup_prefix",List.of("string","int","bool"),"Rows",(c,s,a)->{var v=session(s);return Value.object("Rows",new Rows(LedgerCleanup.execute(v.backend,v.cost.path().toAbsolutePath().getParent(),text(a[0]),a[1].asInt(),a[2].asBool()),c));});
        r.method("Cloud","sweep",List.of("int"),"Rows",(c,s,a)->Value.object("Rows",new Rows(Sandbox.leftovers(session(s).cost.path().toAbsolutePath().getParent(),a[0].asInt()),c)));
        r.method("Cloud","is_demo",List.of(),"bool",(c,s,a)->Value.ofBool(session(s).backend.isDemo()));
        r.method("Cloud","example_run",List.of(),"Run",(c,s,a)->{Session v=session(s);Sandbox run=new Sandbox(v.backend,v.cost.runId(),v.cost.path(),v.cost);runs.add(run);return Value.object("Run",run);});
        r.method("Cloud","spend",List.of("string","int","int","float"),"Spend",(c,s,a)->{
            if(billing!=null||!spendLedgers.isEmpty())throw VmException.host("spend must be the sole cost-capped report/session in its host program");
            String topic=text(a[0]);long days=a[1].asInt(),top=a[2].asInt();double cap=a[3].asFloat();
            if(!Set.of("all","ec2_spend","savings_plans","eip_audit","ebs_audit","bandwidth","lambda_spend","dynamodb_spend").contains(topic))throw VmException.host("unknown spend topic");
            if(days<1||days>366||top<1||top>100||!Double.isFinite(cap)||cap<0||cap>0.25)throw VmException.host("spend: days 1..366, top 1..100 and cap $0..$0.25 required");
            boolean requested="1".equals(System.getenv("LMAWS_SPEND_LIVE"))&&!Boolean.getBoolean("lmaws.dryRun");
            boolean fakeHttp=requested&&!System.getenv().getOrDefault("LMAWS_ENDPOINT","").isBlank();
            boolean live=requested&&!fakeHttp;
            if(live&&(!"1".equals(System.getenv("LMAWS_LIVE"))||!"default".equals(AwsBackend.activeProfile())))throw VmException.host("live spend requires LMAWS_LIVE=1 and AWS_PROFILE=default");
            String ci=System.getenv().getOrDefault("CI","");
            if(live&&(ci.equalsIgnoreCase("true")||ci.equals("1")||ci.equalsIgnoreCase("yes")))throw VmException.host("live spend is forbidden in CI");
            Path dir=live?Path.of(".lmaws-local","spend","ledgers"):Path.of("data","spend-ledgers");
            if(live)SpendOutputs.createPrivate(dir);
            String runId="spend"+java.util.UUID.randomUUID().toString().replace("-","");
            CostLedger ledger=new CostLedger(runId,topic,"us-east-1",dir.resolve(runId+".jsonl"),java.math.BigDecimal.valueOf(cap),live);
            java.time.LocalDate end=live?java.time.LocalDate.now(java.time.ZoneOffset.UTC):java.time.LocalDate.of(2026,10,26);
            SpendReport report;
            try(SpendSource source=requested?new SpendAwsSource(ledger):new SpendFakeSource(ledger)){
                report=SpendReport.collect(source,topic,end,(int)days,(int)top,ledger);
            }
            spendLedgers.put(report,ledger);
            c.charge(256L+report.json().getBytes(java.nio.charset.StandardCharsets.UTF_8).length*2L);
            return Value.object("Spend",report);
        });
        r.method("Spend","section",List.of("string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(((SpendReport)s.asObject()).section(text(a[0])),c)));
        r.method("Spend","json",List.of(),"string",(c,s,a)->Value.ofString(((SpendReport)s.asObject()).json()));
        r.method("Spend","write",List.of("string"),"void",(c,s,a)->{
            SpendReport report=(SpendReport)s.asObject();Path dir=Path.of(text(a[0]));
            if(spendLedgers.get(report).live())SpendOutputs.createPrivate(dir);
            report.write(dir);return Value.none();
        });
        r.method("Spend","is_demo",List.of(),"bool",(c,s,a)->Value.ofBool(!spendLedgers.get((SpendReport)s.asObject()).live()));
        r.method("Spend","estimated_cost",List.of(),"float",(c,s,a)->Value.ofFloat(((SpendReport)s.asObject()).estimatedCost().doubleValue()));
        r.method("Spend","ce_requests",List.of(),"int",(c,s,a)->Value.ofInt(spendLedgers.get((SpendReport)s.asObject()).ceRequests()));
        r.method("Spend","metric_requests",List.of(),"int",(c,s,a)->Value.ofInt(spendLedgers.get((SpendReport)s.asObject()).metricRequests()));
        r.method("Spend","metric_units",List.of(),"int",(c,s,a)->Value.ofInt(spendLedgers.get((SpendReport)s.asObject()).metricUnits()));
        r.method("Cloud","demo",List.of(),"Cloud",(c,s,a)->Value.object("Cloud",open("us-east-1",true)));
        r.method("Cloud","region",List.of("string"),"Cloud",(c,s,a)->Value.object("Cloud",open(text(a[0]),false)));
        for(String inventory:INVENTORIES) r.method("Cloud",inventory,List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.inventory(inventory),c)));
        r.method("Cloud","iam_policy_lint",List.of("string"),"Row",(c,s,a)->{
            Map<String,String> out=(s.asObject() instanceof Session sess)?sess.backend.iamPolicyLint(text(a[0])):IamPolicies.lint(text(a[0])).toMap();
            return rowValue(c,out);
        });
        r.method("Cloud","iam_policy_get",List.of("string"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamPolicyGet(text(a[0]))));
        r.method("Cloud","iam_policy_versions",List.of("string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.iamPolicyVersions(text(a[0])),c)));
        r.method("Cloud","iam_policy_put",List.of("string","string","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamPolicyPut(text(a[0]),text(a[1]),a[2].asBool())));
        r.method("Cloud","iam_policy_delete",List.of("string","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamPolicyDelete(text(a[0]),a[1].asBool())));
        r.method("Cloud","run",List.of("string","string"),"Run",(c,s,a)->{Sandbox run=new Sandbox(session(s).backend,text(a[0]),Path.of(text(a[1])),session(s).cost);runs.add(run);return Value.object("Run",run);});
        r.method("Cloud","web_stack",List.of("string","string","string"),"Web",(c,s,a)->{var v=session(s);WebRun run=new WebRun(v.backend,v.cost,text(a[0]),text(a[1]),text(a[2]));webRuns.add(run);return Value.object("Web",run);});
        r.method("Web","step",List.of("string","string"),"Row",(c,s,a)->rowValue(c,((WebRun)s.asObject()).step(text(a[0]),text(a[1]))));
        r.method("Web","status",List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(((WebRun)s.asObject()).status(),c)));
        r.method("Web","down",List.of(),"Row",(c,s,a)->rowValue(c,((WebRun)s.asObject()).down()));
        registerCompute(r);
        r.method("Rows","len",List.of(),"int",(c,s,a)->Value.ofInt(((Rows)s.asObject()).rows.size()));
        r.method("Rows","at",List.of("int"),"Row",(c,s,a)->{Rows rows=(Rows)s.asObject();long i=a[0].asInt();if(i<0||i>=rows.rows.size())throw VmException.host("row index outside inventory");return Value.object("Row",rows.rows.get((int)i));});
        r.method("Rows","csv",List.of("string"),"void",(c,s,a)->{((Rows)s.asObject()).write(text(a[0]));return Value.none();});
        r.method("Rows","json",List.of(),"string",(c,s,a)->Value.ofString(Jsons.encode(((Rows)s.asObject()).rows)));
        r.method("Rows","count",List.of("string","string"),"int",(c,s,a)->Value.ofInt(((Rows)s.asObject()).rows.stream().filter(row->Rows.get(row,text(a[0])).equals(text(a[1]))).count()));
        r.method("Rows","filter",List.of("string","string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(((Rows)s.asObject()).rows.stream().filter(row->Rows.get(row,text(a[0])).equals(text(a[1]))).toList(),c)));
        r.method("Row","get",List.of("string"),"string",(c,s,a)->Value.ofString(Rows.get(row(s),text(a[0]))));
        r.method("Row","json",List.of(),"string",(c,s,a)->Value.ofString(Jsons.encode(row(s))));
        r.method("Row","number",List.of("string"),"int",(c,s,a)->{String v=Rows.get(row(s),text(a[0]));try{return Value.ofInt(v.isEmpty()?0:Long.parseLong(v));}catch(NumberFormatException e){throw VmException.host("field is not an integer");}});
        for(String kind:List.of("bucket","queue","topic","parameter","log_group","table")) r.method("Run",kind,kind.equals("parameter")?List.of("string","string"):List.of("string"),"Row",(c,s,a)->{var result=((Sandbox)s.asObject()).create(kind,text(a[0]),a.length>1?text(a[1]):"");c.charge(2048);return Value.object("Row",result);});
        r.method("Run","put",List.of("Row","string","string"),"void",(c,s,a)->{((Sandbox)s.asObject()).put(row(a[0]),text(a[1]),text(a[2]));return Value.none();});
        r.method("Run","cleanup",List.of(),"void",(c,s,a)->{((Sandbox)s.asObject()).cleanup();return Value.none();});
        r.method("Run","estimated_cost",List.of(),"float",(c,s,a)->Value.ofFloat(((Sandbox)s.asObject()).cost()==null?0.0:((Sandbox)s.asObject()).cost().total().doubleValue()));
        r.method("Run","remaining",List.of(),"int",(c,s,a)->Value.ofInt(((Sandbox)s.asObject()).remaining()));
        return r;
    }
    private Ec2Compute compute(Value value) {Session v=session(value);return compute.computeIfAbsent(v,x->new Ec2Compute(x.backend));}
    private static Ec2Compute.SpotRun spot(Value value) {return (Ec2Compute.SpotRun)value.asObject();}
    private static Value rows(List<Map<String,String>> data,Context c) {return Value.object("Rows",new Rows(data,c));}
    private static Value one(Map<String,String> data,Context c) {c.charge(2048);return Value.object("Row",data);}
    /** EC2 compute: read-only reports on Cloud, and one run-owned spot nano lifecycle (type Spot). */
    private void registerCompute(Registry r) {
        r.method("Cloud","ec2_instances",List.of("string","string"),"Rows",(c,s,a)->rows(compute(s).instances(text(a[0]),text(a[1])),c));
        r.method("Cloud","cpu_credits",List.of("string","int"),"Rows",(c,s,a)->rows(compute(s).cpuCredits(text(a[0]),a[1].asInt()),c));
        r.method("Cloud","addresses",List.of(),"Rows",(c,s,a)->rows(compute(s).addresses(),c));
        r.method("Cloud","volumes",List.of(),"Rows",(c,s,a)->rows(compute(s).volumes(),c));
        r.method("Cloud","subnets",List.of(),"Rows",(c,s,a)->rows(compute(s).subnets(),c));
        r.method("Cloud","spot_prices",List.of("string","int"),"Rows",(c,s,a)->rows(compute(s).spotPrices(text(a[0]),a[1].asInt()),c));
        r.method("Cloud","public_parameter",List.of("string"),"string",(c,s,a)->Value.ofString(compute(s).publicParameter(text(a[0]))));
        r.method("Cloud","instance_status",List.of("string"),"Row",(c,s,a)->one(compute(s).status(text(a[0])),c));
        r.method("Cloud","spot_run",List.of(),"Spot",(c,s,a)->{
            Session v=session(s);
            if(!spots.isEmpty())throw VmException.host("spot_run: one spot sandbox per host program");
            Ec2Compute.SpotRun run=compute(s).new SpotRun(v.cost.runId(),v.cost.path().toAbsolutePath().getParent(),v.cost.cap());
            spots.add(run);return Value.object("Spot",run);
        });
        r.method("Cloud","spot_recover",List.of("string"),"Row",(c,s,a)->one(compute(s).recover(text(a[0]),session(s).cost.path().toAbsolutePath().getParent()),c));
        r.method("Spot","run_id",List.of(),"string",(c,s,a)->Value.ofString(spot(s).runId));
        r.method("Spot","security_group",List.of("string"),"Row",(c,s,a)->one(spot(s).securityGroup(text(a[0])),c));
        r.method("Spot","launch",List.of("string","string","string","string","float"),"Row",(c,s,a)->one(spot(s).launch(text(a[0]),text(a[1]),text(a[2]),text(a[3]),a[4].asFloat()),c));
        r.method("Spot","http_ingress",List.of("string","string"),"Row",(c,s,a)->one(spot(s).httpIngress(text(a[0]),text(a[1])),c));
        r.method("Spot","launch_web",List.of("string","string","string","string","float","string"),"Row",(c,s,a)->one(spot(s).launchWeb(text(a[0]),text(a[1]),text(a[2]),text(a[3]),a[4].asFloat(),text(a[5])),c));
        r.method("Spot","wait_state",List.of("string","string","int"),"Row",(c,s,a)->one(spot(s).waitState(text(a[0]),text(a[1]),a[2].asInt()),c));
        r.method("Spot","wait_status_ok",List.of("string","int"),"Row",(c,s,a)->one(spot(s).waitStatusOk(text(a[0]),a[1].asInt()),c));
        r.method("Spot","stop",List.of("string"),"Row",(c,s,a)->one(spot(s).stop(text(a[0])),c));
        r.method("Spot","start",List.of("string"),"Row",(c,s,a)->one(spot(s).start(text(a[0])),c));
        r.method("Spot","terminate",List.of("string"),"Row",(c,s,a)->one(spot(s).terminate(text(a[0])),c));
        r.method("Spot","delete_security_group",List.of("string"),"Row",(c,s,a)->one(spot(s).deleteSecurityGroup(text(a[0])),c));
        r.method("Spot","teardown",List.of(),"Row",(c,s,a)->one(spot(s).teardown(),c));
        r.method("Spot","verify",List.of(),"Rows",(c,s,a)->rows(spot(s).verify(),c));
        r.method("Spot","leftovers",List.of(),"Rows",(c,s,a)->rows(spot(s).leftovers(),c));
        r.method("Spot","denied_action",List.of(),"string",(c,s,a)->Value.ofString(spot(s).deniedAction()));
        r.method("Spot","spot_price",List.of(),"float",(c,s,a)->Value.ofFloat(spot(s).spotPrice()));
        r.method("Spot","estimated_cost",List.of(),"float",(c,s,a)->Value.ofFloat(spot(s).estimatedCost()));
    }
    private static String text(Value value) {
        try{return java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(value.asString().bytes())).toString();}
        catch(java.nio.charset.CharacterCodingException e){throw VmException.host("AWS host strings must contain valid UTF-8");}
    }
    @SuppressWarnings("unchecked") private static Map<String,String> row(Value value) {return (Map<String,String>)value.asObject();}
    private static Value rowValue(Context c,Map<String,String> source) {
        long size=128;
        for(var field:source.entrySet()) size=Math.addExact(size,128L+2L*(field.getKey().length()+field.getValue().length()));
        c.charge(size);
        return Value.object("Row",Collections.unmodifiableMap(new LinkedHashMap<>(source)));
    }
    public Context context(long budget) {Context c=new Context();c.memoryLimitBytes=budget;c.setObject("aws","Cloud",new Object());return c;}
    @Override public synchronized void close() {
        if(closed)return;
        RuntimeException failure=null;
        for(var run:webRuns.reversed())try{run.close();}catch(RuntimeException e){failure=e;}
        for(var run:spots.reversed())try{run.close();}catch(RuntimeException e){failure=e;System.err.println("lmaws spot teardown failed: "+Main.safeError(e));}
        for(var run:runs.reversed())try{run.close();}catch(RuntimeException e){failure=e;}
        if(measured!=null)try{finishEvidence(measured);}catch(RuntimeException e){if(failure==null)failure=e;}
        for(var client:clients)try{client.backend.close();}catch(RuntimeException e){if(failure==null)failure=e;}
        for(CostLedger ledger:spendLedgers.values()){
            System.out.println("Cost Explorer requests: "+ledger.ceRequests());
            System.out.println("CloudWatch metric requests: "+ledger.metricRequests()+" (metric units: "+ledger.metricUnits()+")");
            System.out.println("estimated cost: "+ledger.displayCost());
        }
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
        Map<String,Object> report=new LinkedHashMap<>(session.cost.report(leftovers));report.put("provider_verification",verified);report.put("sweeper_leftover_count",candidates.size());report.put("profile",AwsBackend.activeProfile());report.put("ledger",session.cost.path().toString());report.put("estimated_cost_display",session.cost.displayCost());if(!failureCode.isEmpty())report.put("run_error",failureCode);if(!deniedAction.isEmpty())report.put("denied_action",deniedAction);report.put("finished_at",java.time.Instant.now().toString());
        Path dir=Path.of(System.getenv().getOrDefault("LMAWS_EVIDENCE_DIR",session.cost.live()?"evidence":"data/cost-evidence"));Path output=dir.resolve("live-cost-"+session.cost.example()+"-"+session.cost.runId()+".json");
        try {
            Files.createDirectories(dir);Files.writeString(output,Jsons.encode(report)+"\n",java.nio.charset.StandardCharsets.UTF_8);
        }catch(java.io.IOException e){throw new IllegalStateException("cannot write cost evidence",e);}
        System.out.println("evidence: "+output);System.out.println("estimated cost: "+session.cost.displayCost());
        if(leftovers!=0)throw new IllegalStateException("leftover count is "+leftovers+"; inspect the run ledger");
    }
}
