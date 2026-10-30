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
    private final Map<Session,Ec2Provision> provisioning=new IdentityHashMap<>();
    private final List<Ec2Compute.SpotRun> spots=new ArrayList<>();
    private final List<WebRun> webRuns=new ArrayList<>();
    private final List<LambdaFunction> lambdaFunctions=new ArrayList<>();
    private final List<QueueWorker> queueWorkers=new ArrayList<>();
    private final List<EventRule> eventRules=new ArrayList<>();
    private final List<ServerlessRun> serverlessRuns=new ArrayList<>();
    private boolean closed;
    private CostLedger billing;
    private Session measured;
    private String failureCode="", deniedAction="";
    void noteFailure(String code,String action){failureCode=code;deniedAction=action;}
    void noteFailure(Throwable failure,String code,String action){
        failureCode=code;deniedAction=action;
        for(Throwable x=failure;x!=null;x=x.getCause()) {
            if(x instanceof software.amazon.awssdk.awscore.exception.AwsServiceException aws) {
                int status=aws.statusCode();
                String errCode=aws.awsErrorDetails()!=null&&aws.awsErrorDetails().errorCode()!=null?aws.awsErrorDetails().errorCode():"";
                String errMsg=aws.awsErrorDetails()!=null&&aws.awsErrorDetails().errorMessage()!=null?aws.awsErrorDetails().errorMessage():aws.getMessage();
                String lc=errCode.toLowerCase(Locale.ROOT),lm=errMsg==null?"":errMsg.toLowerCase(Locale.ROOT);
                if(status==403||lc.contains("accessdenied")||lc.contains("unauthorized")||lm.contains("not authorized to perform")||lm.contains("access denied")) {
                    if(billing!=null) {
                        Map<String,String> patch=billing.recordAccessDenied(null,null,errCode.isEmpty()?"AccessDenied":errCode,status,errMsg);
                        if(deniedAction.isEmpty())deniedAction=patch.getOrDefault("action","");
                    }
                    break;
                }
            }
        }
    }
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
    private Ec2Provision provision(Value value) {
        Session selected=session(value);
        return provisioning.computeIfAbsent(selected, s -> new Ec2Provision(s.backend));
    }
    private Session session(Value value) {return (Session)value.asObject();}
    public Registry registry() {
        Registry r=new Registry();r.context("aws","Cloud");
        r.function("check",List.of("bool"),"void",(c,s,a)->{if(!a[0].asBool())throw VmException.host("check failed");return Value.none();});
        r.method("Cloud","example",List.of("string"),"Cloud",(c,s,a)->Value.object("Cloud",example(text(a[0]))));
        r.method("Cloud","find_prefix",List.of("string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.findPrefix(text(a[0])),c)));
        r.method("Cloud","s3_bucket_create_exact",List.of("string","string"),"string",(c,s,a)->Value.ofString(session(s).backend.s3Objects().create(text(a[0]),text(a[1]))));
        r.method("Cloud","s3_bucket_attach",List.of("string","string"),"string",(c,s,a)->Value.ofString(session(s).backend.s3Objects().attach(text(a[0]),text(a[1]))));
        r.method("Cloud","s3_bucket_delete",List.of("string","string"),"string",(c,s,a)->Value.ofString(session(s).backend.s3Objects().deleteBucket(text(a[0]),text(a[1]))));
        r.method("Cloud","s3_put_file",List.of("string","string","string","string"),"string",(c,s,a)->Value.ofString(session(s).backend.s3Objects().put(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Cloud","s3_head_object",List.of("string","string"),"string",(c,s,a)->Value.ofString(session(s).backend.s3Objects().head(text(a[0]),text(a[1]))));
        r.method("Cloud","s3_list_objects",List.of("string","string","int"),"Rows",(c,s,a)->{long limit=a[2].asInt();if(limit<0||limit>1000)throw VmException.host("max_keys_total must be 0..1000");return Value.object("Rows",new Rows(session(s).backend.s3Objects().list(text(a[0]),text(a[1]),(int)limit),c));});
        r.method("Cloud","s3_delete_objects",List.of("string","string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.s3Objects().deleteObjects(text(a[0]),text(a[1])),c)));
        r.method("Cloud","s3_ledger_summary",List.of("string"),"string",(c,s,a)->Value.ofString(S3Objects.summary(text(a[0]))));
        r.method("Cloud","s3_publish_path",List.of("string","string","string"),"Rows",(c,s,a)->{ if(!"default".equals(AwsBackend.activeProfile())) throw VmException.host("s3_publish_path is read-only and requires AWS_PROFILE=default"); return Value.object("Rows",new Rows(session(s).backend.s3PublishPath(text(a[0]),text(a[1]),text(a[2])),c)); });
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
        r.method("Cloud","iam_role_get",List.of("string"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamRoleGet(text(a[0]))));
        r.method("Cloud","iam_role_put",List.of("string","string","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamRolePut(text(a[0]),text(a[1]),a[2].asBool())));
        r.method("Cloud","iam_role_delete",List.of("string","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamRoleDelete(text(a[0]),a[1].asBool())));
        r.method("Cloud","iam_policy_lint",List.of("string"),"Row",(c,s,a)->{
            Map<String,String> out=(s.asObject() instanceof Session sess)?sess.backend.iamPolicyLint(text(a[0])):IamPolicies.lint(text(a[0])).toMap();
            return rowValue(c,out);
        });
        r.method("Cloud","iam_policy_lint_instance_role",List.of("string"),"Row",(c,s,a)->{
            Map<String,String> out=(s.asObject() instanceof Session sess)?sess.backend.iamPolicyLintInstanceRole(text(a[0])):IamPolicies.lintInstanceRole(text(a[0])).toMap();
            return rowValue(c,out);
        });
        r.method("Cloud","fleet_roles_discover",List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.fleetRolesDiscover(),c)));
        r.method("Cloud","fleet_roles_ops_needs",List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.fleetRolesOpsNeeds(),c)));
        r.method("Cloud","fleet_roles_plan",List.of(),"Row",(c,s,a)->rowValue(c,session(s).backend.fleetRolesPlan()));
        r.method("Cloud","fleet_roles_apply",List.of("bool","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.fleetRolesApply(a[0].asBool(),a[1].asBool())));
        r.method("Cloud","fleet_roles_rollback",List.of("string","bool","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.fleetRolesRollback(text(a[0]),a[1].asBool(),a[2].asBool())));
        r.method("Cloud","iam_policy_get",List.of("string"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamPolicyGet(text(a[0]))));
        r.method("Cloud","iam_policy_versions",List.of("string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.iamPolicyVersions(text(a[0])),c)));
        r.method("Cloud","iam_policy_put",List.of("string","string","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamPolicyPut(text(a[0]),text(a[1]),a[2].asBool())));
        r.method("Cloud","iam_policy_delete",List.of("string","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.iamPolicyDelete(text(a[0]),a[1].asBool())));
        r.method("Cloud","session_doctor",List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.sessionDoctor(),c)));
        r.method("Cloud","run",List.of("string","string"),"Run",(c,s,a)->{Sandbox run=new Sandbox(session(s).backend,text(a[0]),Path.of(text(a[1])),session(s).cost);runs.add(run);return Value.object("Run",run);});
        r.method("Cloud","web_find",List.of("string","string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(WebRun.find(session(s).backend,text(a[0]),text(a[1])),c)));
        r.method("Cloud","web_stack",List.of("string","string","string"),"Web",(c,s,a)->{if(!webRuns.isEmpty())throw VmException.host("one web run per host program");var v=session(s);WebRun run=new WebRun(v.backend,v.cost,text(a[0]),text(a[1]),text(a[2]));webRuns.add(run);return Value.object("Web",run);});
        r.method("Cloud","serverless_stack",List.of("string","string","string"),"Serverless",(c,s,a)->{var v=session(s);ServerlessRun run=new ServerlessRun(v.backend,v.cost,text(a[0]),text(a[1]),text(a[2]));serverlessRuns.add(run);return Value.object("Serverless",run);});
        r.method("Cloud","serverless_find",List.of("string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.serverlessInventory(text(a[0])),c)));
        r.method("Serverless","step",List.of("string","string"),"Row",(c,s,a)->rowValue(c,((ServerlessRun)s.asObject()).step(text(a[0]),text(a[1]))));
        r.method("Serverless","status",List.of(),"Row",(c,s,a)->rowValue(c,((ServerlessRun)s.asObject()).summary()));
        r.method("Serverless","leftovers",List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(((ServerlessRun)s.asObject()).leftovers(),c)));
        r.method("Serverless","settle",List.of("int"),"Row",(c,s,a)->rowValue(c,((ServerlessRun)s.asObject()).settle(Math.toIntExact(a[0].asInt()))));
        r.method("Serverless","down",List.of(),"Row",(c,s,a)->rowValue(c,((ServerlessRun)s.asObject()).down()));
        r.method("Cloud","lambda_function",List.of("string","string","string","string","string","int","int"),"Lambda",
                (c,s,a)->{ Session v=session(s); int memory=Math.toIntExact(a[5].asInt()), timeout=Math.toIntExact(a[6].asInt()); if(memory>512||timeout>30) throw VmException.host("scenario Lambda caps are memory <=512 MiB and timeout <=30 seconds");
                    String run=v.cost.runId(), log="lmaws_lambda_logs_"+run; LambdaFunction fn=new LambdaFunction(v.backend,text(a[0]),text(a[1]),text(a[2]),text(a[3]),text(a[4]),memory,timeout,run); if(!v.backend.isDemo()) fn.providerArn(v.backend.createLambda(text(a[0]),text(a[1]),text(a[2]),text(a[3]),text(a[4]),memory,timeout,run,log).get("arn")); lambdaFunctions.add(fn); return Value.object("Lambda",fn); });
        r.method("Cloud","lambda_function",List.of("string","string","string","string","string","int","int","string"),"Lambda",
                (c,s,a)->{ Session v=session(s); int memory=Math.toIntExact(a[5].asInt()), timeout=Math.toIntExact(a[6].asInt()); String run=text(a[7]); if(!run.matches("[a-z0-9]{1,24}")) throw VmException.host("invalid run id"); String log="lmaws_lambda_logs_"+run; LambdaFunction fn=new LambdaFunction(v.backend,text(a[0]),text(a[1]),text(a[2]),text(a[3]),text(a[4]),memory,timeout,run); if(!v.backend.isDemo()) fn.providerArn(v.backend.createLambda(text(a[0]),text(a[1]),text(a[2]),text(a[3]),text(a[4]),memory,timeout,run,log).get("arn")); lambdaFunctions.add(fn); return Value.object("Lambda",fn); });
        r.method("Cloud","event_rule",List.of("string","string"),"EventRule",
                (c,s,a)->{ Session v=session(s); EventRule rule=new EventRule(v.backend,text(a[0]),text(a[1]),v.cost.runId()); if(!v.backend.isDemo()) rule.providerArn(v.backend.putEventRule(text(a[0]),text(a[1]),v.cost.runId()).get("arn")); eventRules.add(rule); return Value.object("EventRule",rule); });
        r.method("Cloud","event_rule",List.of("string","string","string"),"EventRule",
                (c,s,a)->{ Session v=session(s); String run=text(a[2]); EventRule rule=new EventRule(v.backend,text(a[0]),text(a[1]),run); if(!v.backend.isDemo()) rule.providerArn(v.backend.putEventRule(text(a[0]),text(a[1]),run).get("arn")); eventRules.add(rule); return Value.object("EventRule",rule); });
        r.method("Cloud","dynamodb_ttl",List.of("string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.tableTtl(text(a[0]),text(a[1]),session(s).cost.runId())));
        r.method("Cloud","dynamodb_ttl",List.of("string","string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.tableTtl(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Cloud","dynamodb_item",List.of("string","string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.tableItem(text(a[0]),text(a[1]),text(a[2]),session(s).cost.runId())));
        r.method("Cloud","dynamodb_item",List.of("string","string","string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.tableItem(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Cloud","dynamodb_item_conditional",List.of("string","string","string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.tableItemConditional(text(a[0]),text(a[1]),text(a[2]),text(a[3]),session(s).cost.runId())));
        r.method("Cloud","dynamodb_item_conditional",List.of("string","string","string","string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.tableItemConditional(text(a[0]),text(a[1]),text(a[2]),text(a[3]),text(a[4]))));
        r.method("Cloud","s3_presigned_put",List.of("string","string","int","string","int"),"Row",(c,s,a)->rowValue(c,session(s).backend.s3PresignPut(text(a[0]),text(a[1]),a[2].asInt(),text(a[3]),Math.toIntExact(a[4].asInt()),session(s).cost.runId())));
        r.method("Cloud","s3_presigned_put",List.of("string","string","int","string","int","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.s3PresignPut(text(a[0]),text(a[1]),a[2].asInt(),text(a[3]),Math.toIntExact(a[4].asInt()),text(a[5]))));
        r.method("Cloud","policy_document",List.of("string"),"string",(c,s,a)->Value.ofString(session(s).backend.managedPolicyDocument(text(a[0]))));
        r.method("Cloud","s3_upload_cleanup",List.of("string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.s3UploadCleanup(text(a[0]),Path.of(text(a[1])))));
        r.method("Cloud","s3_upload_check",List.of("string","string","bool","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.s3UploadCheck(text(a[0]),text(a[1]),a[2].asBool(),Path.of(text(a[3])))));
        r.method("Cloud","publish_grant_probe",List.of("string","string","string"),"Row",(c,s,a)->rowValue(c,PublishGrantProbes.runSingle(session(s).backend,text(a[0]),text(a[1]),text(a[2]))));
        r.method("Cloud","publish_grant_probes",List.of("string"),"Rows",(c,s,a)->rows(PublishGrantProbes.runBatch(session(s).backend,text(a[0])),c));
        r.method("Cloud","publish_grant_probe_kinds",List.of(),"Rows",(c,s,a)->rows(PublishGrantProbes.describeKinds(),c));
        r.method("Cloud","s3_notification",List.of("string","string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.s3Notification(text(a[0]),text(a[1]),text(a[2]),session(s).cost.runId())));
        r.method("Cloud","s3_notification",List.of("string","string","string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.s3Notification(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Lambda","status",List.of(),"Row",(c,s,a)->rowValue(c,((LambdaFunction)s.asObject()).status()));
        r.method("Lambda","url",List.of("string"),"string",(c,s,a)->Value.ofString(((LambdaFunction)s.asObject()).url(text(a[0]))));
        r.method("Lambda","wait_active",List.of("int"),"Row",(c,s,a)->rowValue(c,((LambdaFunction)s.asObject()).waitActive(Math.toIntExact(a[0].asInt()))));
        r.method("Lambda","invoke",List.of("string"),"Row",(c,s,a)->rowValue(c,((LambdaFunction)s.asObject()).invoke(text(a[0]))));
        r.method("Lambda","delete",List.of(),"Row",(c,s,a)->rowValue(c,((LambdaFunction)s.asObject()).delete()));
        r.method("Cloud","sqs_event_source_mapping",List.of("string","string","int"),"QueueWorker",(c,s,a)->{ Session v=session(s); QueueWorker w=v.backend.createEventSourceMapping(text(a[0]),text(a[1]),Math.toIntExact(a[2].asInt()),v.cost.runId()); queueWorkers.add(w); return Value.object("QueueWorker",w); });
        r.method("Cloud","sqs_event_source_mapping",List.of("string","string","int","string"),"QueueWorker",(c,s,a)->{ Session v=session(s); QueueWorker w=v.backend.createEventSourceMapping(text(a[0]),text(a[1]),Math.toIntExact(a[2].asInt()),text(a[3])); queueWorkers.add(w); return Value.object("QueueWorker",w); });
        r.method("Cloud","sqs_event_source_mapping_get",List.of("string","string"),"QueueWorker",(c,s,a)->{ Session v=session(s); return Value.object("QueueWorker",v.backend.resumeEventSourceMapping(text(a[0]),text(a[1]))); });
        r.method("Cloud","sqs_event_source_mappings",List.of("string"),"Rows",(c,s,a)->Value.object("Rows",new Rows(session(s).backend.findEventSourceMappings(text(a[0])),c)));
        r.method("Cloud","sqs_redrive",List.of("string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.setSqsRedrive(text(a[0]),text(a[1]),session(s).cost.runId())));
        r.method("Cloud","sqs_redrive_clear",List.of("string"),"Row",(c,s,a)->rowValue(c,session(s).backend.clearSqsRedrive(text(a[0]),session(s).cost.runId())));
        r.method("Cloud","sqs_redrive",List.of("string","string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.setSqsRedrive(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Cloud","sqs_redrive_clear",List.of("string","string"),"Row",(c,s,a)->rowValue(c,session(s).backend.clearSqsRedrive(text(a[0]),text(a[1]))));
        r.method("QueueWorker","status",List.of(),"Row",(c,s,a)->rowValue(c,((QueueWorker)s.asObject()).status()));
        r.method("QueueWorker","delete",List.of(),"Row",(c,s,a)->rowValue(c,((QueueWorker)s.asObject()).delete()));
        r.method("EventRule","status",List.of(),"Row",(c,s,a)->rowValue(c,((EventRule)s.asObject()).status()));
        r.method("EventRule","target",List.of("string"),"Row",(c,s,a)->rowValue(c,((EventRule)s.asObject()).target(text(a[0]))));
        r.method("EventRule","delete",List.of(),"Row",(c,s,a)->rowValue(c,((EventRule)s.asObject()).delete()));
        r.method("Web","step",List.of("string","string"),"Row",(c,s,a)->rowValue(c,((WebRun)s.asObject()).step(text(a[0]),text(a[1]))));
        r.method("Web","status",List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(((WebRun)s.asObject()).status(),c)));
        r.method("Web","leftovers",List.of(),"Rows",(c,s,a)->Value.object("Rows",new Rows(((WebRun)s.asObject()).leftovers(),c)));
        r.method("Web","down",List.of(),"Row",(c,s,a)->rowValue(c,((WebRun)s.asObject()).down()));
        registerCompute(r);
        registerPolicyBuilder(r);
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
        r.method("Cloud","ec2_provision_run",List.of("string"),"string",(c,s,a)->Value.ofString(provision(s).run(text(a[0]))));
        r.method("Cloud","ec2_provision_describe",List.of("string"),"string",(c,s,a)->Value.ofString(provision(s).describe(text(a[0]))));
        r.method("Cloud","ec2_provision_stop",List.of("string"),"string",(c,s,a)->Value.ofString(provision(s).stop(text(a[0]))));
        r.method("Cloud","ec2_provision_start",List.of("string"),"string",(c,s,a)->Value.ofString(provision(s).start(text(a[0]))));
        r.method("Cloud","ec2_provision_terminate",List.of("string"),"string",(c,s,a)->Value.ofString(provision(s).terminate(text(a[0]))));
        r.method("Cloud","ec2_provision_verify",List.of("string"),"string",(c,s,a)->Value.ofString(provision(s).verify(text(a[0]))));
        r.method("Cloud","ec2_provision_console",List.of("string"),"string",(c,s,a)->Value.ofString(provision(s).console(text(a[0]))));
        r.method("Cloud","ec2_provision_dry_run",List.of("string","string"),"string",(c,s,a)->Value.ofString(provision(s).dryRun(text(a[0]),text(a[1]))));
        r.method("Cloud","ec2_instances",List.of("string","string"),"Rows",(c,s,a)->rows(compute(s).instances(text(a[0]),text(a[1])),c));
        r.method("Cloud","cpu_credits",List.of("string","int"),"Rows",(c,s,a)->rows(compute(s).cpuCredits(text(a[0]),a[1].asInt()),c));
        r.method("Cloud","addresses",List.of(),"Rows",(c,s,a)->rows(compute(s).addresses(),c));
        r.method("Cloud","volumes",List.of(),"Rows",(c,s,a)->rows(compute(s).volumes(),c));
        r.method("Cloud","subnets",List.of(),"Rows",(c,s,a)->rows(compute(s).subnets(),c));
        r.method("Cloud","spot_prices",List.of("string","int"),"Rows",(c,s,a)->rows(compute(s).spotPrices(text(a[0]),a[1].asInt()),c));
        r.method("Cloud","public_parameter",List.of("string"),"string",(c,s,a)->Value.ofString(compute(s).publicParameter(text(a[0]))));
        r.method("Cloud","instance_status",List.of("string"),"Row",(c,s,a)->one(compute(s).status(text(a[0])),c));
        r.method("Cloud","ebs_root_resize",List.of("string","bool","bool"),"Row",(c,s,a)->rowValue(c,session(s).backend.ebsRootResize(text(a[0]),a[1].asBool(),a[2].asBool())));
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
    private static PolicyBuilder policy(Value value) {return (PolicyBuilder)value.asObject();}
    private static Value policyVal(PolicyBuilder pb) {return Value.object("Policy",pb);}
    private void registerPolicyBuilder(Registry r) {
        r.method("Cloud","policy",List.of("string"),"Policy",(c,s,a)->{c.charge(1024);return policyVal(new PolicyBuilder(text(a[0])));});
        r.method("Cloud","policy_fit_inline",List.of("string"),"Row",(c,s,a)->rowValue(c,PolicyAnalyzer.fitInline(text(a[0]))));
        r.method("Cloud","policy_split_managed",List.of("string"),"Rows",(c,s,a)->rows(PolicyAnalyzer.splitManaged(text(a[0]),IamPolicies.MANAGED_POLICY_LIMIT),c));
        r.method("Cloud","policy_diff",List.of("string","string"),"Rows",(c,s,a)->{
            IamPolicies.DiffResult d=IamPolicies.diff(text(a[0]),text(a[1]));
            List<Map<String,String>> list=new ArrayList<>();
            for(var row:d.statementDiffs()){Map<String,String> m=new LinkedHashMap<>();row.forEach((k,v)->m.put(k,String.valueOf(v)));list.add(m);}
            return rows(list,c);
        });
        r.method("Cloud","policy_explain",List.of("string"),"Rows",(c,s,a)->rows(PolicyAnalyzer.explain(text(a[0])),c));
        r.method("Cloud","policy_matrix",List.of("string"),"Rows",(c,s,a)->rows(PolicyAnalyzer.matrix(text(a[0])),c));
        r.method("Cloud","explain_denial",List.of("string"),"Row",(c,s,a)->rowValue(c,PolicyAnalyzer.explainDenial(text(a[0]))));
        r.method("Cloud","policy_from_ledger",List.of("string"),"Row",(c,s,a)->rowValue(c,PolicyAnalyzer.fromLedger(text(a[0]))));
        r.method("Cloud","policy_import_json",List.of("string"),"Row",(c,s,a)->rowValue(c,PolicyAnalyzer.importJson(text(a[0]))));
        r.method("Cloud","policy_simulate",List.of("string","string"),"Rows",(c,s,a)->{
            List<Map<String,String>> out=(s.asObject() instanceof Session sess)?sess.backend.policySimulate(text(a[0]),text(a[1])):PolicySimulator.evaluateOffline(text(a[0]),PolicySimulator.parseProbes(text(a[1])));
            return rows(out,c);
        });
        r.method("Cloud","policy_simulate_principal",List.of("string","string"),"Rows",(c,s,a)->{
            List<Map<String,String>> out=(s.asObject() instanceof Session sess)?sess.backend.policySimulatePrincipal(text(a[0]),text(a[1])):PolicySimulator.evaluateOffline(IamPolicies.sanitizedTemplatePolicyJson(),PolicySimulator.parseProbes(text(a[1])));
            return rows(out,c);
        });
        r.method("Cloud","policy_size_report",List.of("string"),"Rows",(c,s,a)->rows(PolicyAnalyzer.sizeReport(text(a[0])),c));
        r.method("Cloud","policy_cheat_sheet",List.of(),"Rows",(c,s,a)->rows(PolicyAnalyzer.cheatSheet(),c));
        r.method("Policy","allow",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).allow(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","allow_cond",List.of("string","string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).allowCond(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Policy","deny",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).deny(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","deny_cond",List.of("string","string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).denyCond(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Policy","deny_not_action",List.of("string","string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).denyNotAction(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Policy","arn",List.of("string","string","string"),"string",(c,s,a)->Value.ofString(policy(s).arn(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","expand_actions",List.of("string"),"string",(c,s,a)->Value.ofString(policy(s).expandActions(text(a[1-1]))));
        r.method("Policy","classify_action",List.of("string"),"string",(c,s,a)->Value.ofString(policy(s).classifyAction(text(a[0]))));
        r.method("Policy","name_prefix",List.of("string","string","string","string","bool"),"Policy",(c,s,a)->policyVal(policy(s).namePrefix(text(a[0]),text(a[1]),text(a[2]),text(a[3]),a[4].asBool())));
        r.method("Policy","require_tag_on_create",List.of("string","string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).requireTagOnCreate(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Policy","only_tagged",List.of("string","string","string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).onlyTagged(text(a[0]),text(a[1]),text(a[2]),text(a[3]),text(a[4]))));
        r.method("Policy","tag_on_create_actions",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).tagOnCreateActions(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","deny_untagged_create",List.of("string","string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).denyUntaggedCreate(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Policy","deny_delete_unless_tagged",List.of("string","string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).denyDeleteUnlessTagged(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Policy","region_lock",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).regionLock(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","instance_types",List.of("string","string"),"Policy",(c,s,a)->policyVal(policy(s).instanceTypes(text(a[0]),text(a[1]))));
        r.method("Policy","max_volume_gib",List.of("string","int"),"Policy",(c,s,a)->policyVal(policy(s).maxVolumeGib(text(a[0]),a[1].asInt())));
        r.method("Policy","route53_names",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).route53Names(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","cidr_only",List.of("string","string"),"Policy",(c,s,a)->policyVal(policy(s).cidrOnly(text(a[0]),text(a[1]))));
        r.method("Policy","mfa_required",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).mfaRequired(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","time_window",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).timeWindow(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","source_ip",List.of("string","string"),"Policy",(c,s,a)->policyVal(policy(s).sourceIp(text(a[0]),text(a[1]))));
        r.method("Policy","read_only_inventory",List.of(),"Policy",(c,s,a)->policyVal(policy(s).readOnlyInventory()));
        r.method("Policy","s3_bucket_sandbox",List.of("string"),"Policy",(c,s,a)->policyVal(policy(s).s3BucketSandbox(text(a[0]))));
        r.method("Policy","queue_sandbox",List.of("string"),"Policy",(c,s,a)->policyVal(policy(s).queueSandbox(text(a[0]))));
        r.method("Policy","topic_sandbox",List.of("string"),"Policy",(c,s,a)->policyVal(policy(s).topicSandbox(text(a[0]))));
        r.method("Policy","table_sandbox",List.of("string"),"Policy",(c,s,a)->policyVal(policy(s).tableSandbox(text(a[0]))));
        r.method("Policy","parameter_sandbox",List.of("string"),"Policy",(c,s,a)->policyVal(policy(s).parameterSandbox(text(a[0]))));
        r.method("Policy","log_group_sandbox",List.of("string"),"Policy",(c,s,a)->policyVal(policy(s).logGroupSandbox(text(a[0]))));
        r.method("Policy","spot_nano_sandbox",List.of("string","string","int"),"Policy",(c,s,a)->policyVal(policy(s).spotNanoSandbox(text(a[0]),text(a[1]),a[2].asInt())));
        r.method("Policy","static_site_stack",List.of("string","string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).staticSiteStack(text(a[0]),text(a[1]),text(a[2]),text(a[3]))));
        r.method("Policy","billing_viewer",List.of(),"Policy",(c,s,a)->policyVal(policy(s).billingViewer()));
        r.method("Policy","lambda_deployer_by_name",List.of("string"),"Policy",(c,s,a)->policyVal(policy(s).lambdaDeployerByName(text(a[0]))));
        r.method("Policy","lambda_event_source_mapping",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).lambdaEventSourceMapping(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","pass_role_to_service",List.of("string","string"),"Policy",(c,s,a)->policyVal(policy(s).passRoleToService(text(a[0]),text(a[1]))));
        r.method("Policy","pass_role_to_service",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).passRoleToService(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","ci_bucket_deployer",List.of("string","string"),"Policy",(c,s,a)->policyVal(policy(s).ciBucketDeployer(text(a[0]),text(a[1]))));
        r.method("Policy","permission_boundary",List.of("string","string","string"),"Policy",(c,s,a)->policyVal(policy(s).permissionBoundary(text(a[0]),text(a[1]),text(a[2]))));
        r.method("Policy","lmaws_session_policy",List.of("string","string","string","string","string","int"),"Policy",(c,s,a)->policyVal(policy(s).lmawsSessionPolicy(text(a[0]),text(a[1]),text(a[2]),text(a[3]),text(a[4]),a[5].asInt())));
        r.method("Policy","merge_from",List.of("Policy"),"Policy",(c,s,a)->policyVal(policy(s).mergeFrom(policy(a[0]))));
        r.method("Policy","json",List.of(),"string",(c,s,a)->Value.ofString(policy(s).json()));
        r.method("Policy","compact_json",List.of(),"string",(c,s,a)->Value.ofString(policy(s).compactJson()));
        r.method("Policy","lint",List.of(),"Row",(c,s,a)->rowValue(c,policy(s).lint()));
        r.method("Policy","lint_instance_role",List.of(),"Row",(c,s,a)->rowValue(c,policy(s).lintInstanceRole()));
        r.method("Policy","fit_inline",List.of(),"Row",(c,s,a)->rowValue(c,policy(s).fitInline()));
        r.method("Policy","split_managed",List.of(),"Rows",(c,s,a)->rows(policy(s).splitManaged(),c));
        r.method("Policy","diff",List.of("string"),"Rows",(c,s,a)->rows(policy(s).diff(text(a[0])),c));
        r.method("Policy","explain",List.of(),"Rows",(c,s,a)->rows(policy(s).explain(),c));
        r.method("Policy","matrix",List.of(),"Rows",(c,s,a)->rows(policy(s).matrix(),c));
        r.method("Policy","size_report",List.of(),"Rows",(c,s,a)->rows(policy(s).sizeReport(),c));
        r.method("Policy","cheat_sheet",List.of(),"Rows",(c,s,a)->rows(policy(s).cheatSheet(),c));
        r.method("Policy","simulate_run_instances",List.of("string","int","string","string","string"),"Rows",(c,s,a)->rows(policy(s).simulateRunInstances(text(a[0]),(int)a[1].asInt(),text(a[2]),text(a[3]),text(a[4])),c));
        r.method("Policy","simulate_run_instances",List.of("string","int","string","string","string","string"),"Rows",(c,s,a)->rows(policy(s).simulateRunInstances(text(a[0]),(int)a[1].asInt(),text(a[2]),text(a[3]),text(a[4]),text(a[5])),c));
        r.method("Policy","run_instances_probes",List.of("string","int","string","string","string"),"string",(c,s,a)->Value.ofString(policy(s).runInstancesProbes(text(a[0]),(int)a[1].asInt(),text(a[2]),text(a[3]),text(a[4]))));
        r.method("Policy","summary",List.of(),"Row",(c,s,a)->rowValue(c,policy(s).summary()));
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
    void emergencyWebCleanup() {
        try(AutoCloseable scope=billing==null?null:billing.cleanupScope()) {
        for(var worker:queueWorkers.reversed())try{worker.delete();}catch(RuntimeException e){System.err.println("queue worker cleanup incomplete; inspect private ledger");}
        for(var rule:eventRules.reversed())try{rule.delete();}catch(RuntimeException e){System.err.println("event cleanup incomplete; inspect private ledger");}
        for(var function:lambdaFunctions.reversed())try{function.delete();}catch(RuntimeException e){System.err.println("Lambda cleanup incomplete; inspect private ledger");}
        for(var run:serverlessRuns.reversed())try{run.down();}catch(RuntimeException e){System.err.println("serverless cleanup incomplete; inspect private state");}
        for(var run:webRuns.reversed())try{run.emergencyDown();}catch(RuntimeException e){System.err.println("web shutdown cleanup incomplete; inspect private state");}
        }catch(Exception failure){System.err.println("emergency cleanup scope failed; inspect private state");}
    }
    @Override public synchronized void close() {
        if(closed)return;
        RuntimeException failure=null;
        if(!failureCode.isEmpty())emergencyWebCleanup();
        for(var run:serverlessRuns.reversed())try{run.close();}catch(RuntimeException e){failure=e;}
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
        Map<String,Object> report=new LinkedHashMap<>(session.cost.report(leftovers));report.put("provider_verification",verified);report.put("sweeper_leftover_count",candidates.size());report.put("profile",AwsBackend.activeProfile());report.put("ledger",session.cost.path().toString());report.put("estimated_cost_display",session.cost.displayCost());if(!failureCode.isEmpty())report.put("run_error",failureCode);if(!deniedAction.isEmpty())report.put("denied_action",deniedAction);else if(report.get("access_denied_patch") instanceof Map<?,?> p && p.get("action")!=null)report.put("denied_action",p.get("action"));report.put("finished_at",java.time.Instant.now().toString());
        for(var web:webRuns)if(web.cost==session.cost){
            report.put("sdk_estimated_usd",report.get("total_estimated_usd"));
            var total=new java.math.BigDecimal(web.state.getOrDefault("total_estimated_usd","0"));
            report.put("total_estimated_usd",total);report.put("estimated_cost_display","$"+total.setScale(8,java.math.RoundingMode.CEILING).toPlainString());
            report.put("web_status",web.state.getOrDefault("status","new"));report.put("web_verified_leftover_count","down".equals(web.state.get("status"))?0:null);
        }
        for(var run:serverlessRuns)if(run.cost==session.cost){
            report.put("serverless_status",run.state.getOrDefault("status","new"));
            var serverlessTotal=new java.math.BigDecimal(run.state.getOrDefault("total_estimated_usd","0"));report.put("total_estimated_usd",serverlessTotal);report.put("estimated_cost_display","$"+serverlessTotal.setScale(8,java.math.RoundingMode.CEILING).toPlainString());
            report.put("serverless_active_receipt_count",run.leftovers().size());
            report.put("serverless_verified_leftover_count","down".equals(run.state.get("status"))?0:null);
        }
        Path dir=Path.of(System.getenv().getOrDefault("LMAWS_EVIDENCE_DIR",session.cost.live()?"evidence":"data/cost-evidence"));Path output=dir.resolve("live-cost-"+session.cost.example()+"-"+session.cost.runId()+".json");
        try {
            Files.createDirectories(dir);Files.writeString(output,Jsons.encode(report)+"\n",java.nio.charset.StandardCharsets.UTF_8);
        }catch(java.io.IOException e){throw new IllegalStateException("cannot write cost evidence",e);}
        System.out.println("evidence: "+output);System.out.println("estimated cost: "+report.get("estimated_cost_display"));
        if(leftovers!=0)throw new IllegalStateException("leftover count is "+leftovers+"; inspect the run ledger");
    }
}
