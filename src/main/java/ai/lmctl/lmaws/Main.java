package ai.lmctl.lmaws;

import io.lmctl.lmcode.*;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public final class Main {
    public static final String VERSION="0.1.27";
    private static final String HELP="""
        lmaws 0.1.27 — AWS SDK for Java v2 scripting host
        usage: lmaws [--apply] --lmcode FILE [--lmcode FILE ...] | --lmcode-schema [--json] | --lmcode-signatures [--without-std]
               lmaws --credential-process <default|lmaws|lmaws-ec2|lmaws-web> [--source-profile NAME] [--policy-file PATH] [--no-cache]
               lmaws --version | --notices | --help | --self-test
               lmaws --sweep LEDGER_DIR --older-than-hours N
        Environment: LMAWS_OFFLINE=1 offline sessions (no AWS, never live or apply); LMAWS_LOG_FILE=PATH host log lines go there, the
           result frame stays on stdout; LMAWS_DEADLINE_MS=N the host ends after N ms (nonzero, no result frame).
        lmcode context: aws.demo() (offline) or aws.region(\"\") (default profile/region).
        Live writes require AWS_PROFILE=lmaws (or lmaws-ec2 for the spot nano sandbox),
        a new ledger, prefixed names and ownership tags.
        Exceptions for the admin profile (refused for every other mutating call):
        1. lmaws_ IAM policy and Lambda execution-role grants (iam_policy_put/iam_policy_delete, iam_role_put/iam_role_delete)
           require AWS_PROFILE=admin, LMAWS_ADMIN_GRANT=1, LMAWS_LIVE=1 and --apply (LMAWS_APPLY=1).
           iam_role_get and live role previews require the same admin/grant/live flags without --apply.
           Role grants require Lambda-only trust and the same-account lmaws_boundary.
        2. lmaws --credential-process <mode> reads ONLY the selected static source profile
           (`--source-profile NAME` or LMAWS_CREDENTIAL_SOURCE_PROFILE, default agent-issuer)
           from shared credentials/config (ignoring ambient env/web-identity/container/IMDS).
           Names containing admin are refused unless LMAWS_ALLOW_ADMIN_SOURCE=1 is set by a human.
           `default` uses --policy-file or LMAWS_DEFAULT_SESSION_POLICY (default
           ~/.aws/session-tools/tasks/iam-snapshots/local-default-session.json) plus ReadOnlyAccess,
           within STS's 2048-character compact limit; lmaws* modes resolve the source account
           and use its lmaws_session ARN. All modes use awsspot-local-<mode>, 3600s, and a cache
           scoped to the source/policy inputs; they create no resources or permissions.
        3. ebs_root_resize grows an explicitly identified existing gp3 root volume.
           Apply requires admin/grant/live/apply plus human=true; never stops or replaces a host.
           Default can inspect with live=true; admin inspection also requires human=true/grant.
           Persistent EBS expansion is not automatically undone or covered by request-cost caps.
        Run-owned test resources are cleaned up on success and failure. --sweep is always read-only.
        LMAWS_MAX_MEMORY_MB: positive whole MiB, default 4096; bounded heap and VM data.
        LMAWS_MAX_COST_USD: default 0.05, hard whole-run ceiling 0.25.
        aws.example(name) selects local profile live mode only when LMAWS_LIVE=1;
        examples record prices, requests, minutes, teardown, sweeper and cost evidence.
        Read-only spend: aws.spend(topic, days, top_n, cap); synthetic by default.
        Cloud.fleet_costs(spec_json, from, to) reports tag-selected EC2, disks, IPv4,
        charged CPU surplus and Savings Plans; default profile only, dates end-exclusive.
        Real spend requires LMAWS_SPEND_LIVE=1, LMAWS_LIVE=1 and AWS_PROFILE=default.
        CE pages cost about $0.01; GetMetricData counts requested metrics; cap <=$0.25.
        Real spend exports stay under ignored .lmaws-local/spend; no AWS CLI is used.
        No OIDC or AWS credentials in CI; CI uses loopback fakes only.
        Invocation manifest dry mode skips host callbacks and returns typed dry values; use aws.demo() for offline fixtures.
        LMAWS_LIVE=1 is required for real-account writes; read-only inventories use the
        standard AWS credential chain. Secret values and IAM key APIs are not exposed.
        Linux requires glibc >= 2.35; Windows requires the Microsoft VC++ runtime.
        """;
    static long budget() {
        String raw=System.getenv("LMAWS_MAX_MEMORY_MB");if(raw==null)return 4096L*1024*1024;
        try{if(!raw.matches("[0-9]+"))throw new NumberFormatException();long n=Long.parseLong(raw);if(n<=0||n>Long.MAX_VALUE/(1024*1024))throw new NumberFormatException();return n*1024*1024;}catch(NumberFormatException e){throw new IllegalArgumentException("LMAWS_MAX_MEMORY_MB must be positive whole MiB");}
    }
    static byte[] schema(Registry registry) {
        Map<String,Object> functions=new TreeMap<>(),types=new TreeMap<>(),context=new TreeMap<>();
        for(String sig:registry.hostSignatures()) {
            if(sig.startsWith("context ")){String[] fields=sig.substring(8).split(": ",2);context.put(fields[0],fields[1]);continue;}
            Registry.Binding b=registry.resolve(sig);Map<String,Object> spec=new LinkedHashMap<>();spec.put("params",b.parameters);spec.put("returns",b.returns);
            Map<String,Object> target=functions;
            if(b.method) {
                @SuppressWarnings("unchecked") Map<String,Object> methods=(Map<String,Object>)((Map<String,Object>)types.computeIfAbsent(b.type,k->new LinkedHashMap<>(Map.of("methods",new TreeMap<String,Object>())))).get("methods");target=methods;
            }
            @SuppressWarnings("unchecked") List<Object> overloads=(List<Object>)target.computeIfAbsent(b.name,k->new ArrayList<>());overloads.add(spec);
        }
        Map<String,Object> all=new LinkedHashMap<>();all.put("dsl.schema",2);all.put("name","lmaws");all.put("functions",functions);all.put("types",types);all.put("context",context);
        return (Jsons.encode(all)+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    static String safeError(Throwable e) {
        for(Throwable x=e;x!=null;x=x.getCause())if(x instanceof IllegalStateException && x.getMessage()!=null && x.getMessage().startsWith("estimated cost cap exceeded"))return x.getMessage();
        if(e instanceof NumberFormatException)return "invalid integer argument";
        if(e instanceof AwsServiceException aws) {
            String code=aws.awsErrorDetails()==null?"AWS_SERVICE_ERROR":aws.awsErrorDetails().errorCode();
            if(code==null||!code.matches("[A-Za-z0-9_.-]{1,100}"))code="AWS_SERVICE_ERROR";
            if("MalformedPolicyDocument".equals(code)||"MalformedPolicyDocumentException".equals(code)||"MalformedPolicy".equals(code)) {
                String msg=aws.awsErrorDetails()==null?null:aws.awsErrorDetails().errorMessage();
                if(msg!=null&&!msg.isBlank()) {
                    String clean=Jsons.mask(msg.replaceAll("[\\r\\n\\t]+"," ").trim());
                    if(clean.length()>300)clean=clean.substring(0,300);
                    return "AWS "+code+" (HTTP "+aws.statusCode()+"): "+clean;
                }
            }
            return "AWS "+code+" (HTTP "+aws.statusCode()+")";
        }
        if(e instanceof VmException || e instanceof IllegalArgumentException || e instanceof IllegalStateException || e instanceof SecurityException) return Jsons.mask(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());
        return "operation failed ("+e.getClass().getSimpleName()+")";
    }
    // run_lmcode forwards host stdout and has no deadline, so callers that used to read a captured stdout or set a system()
    // timeout say so here. LMAWS_LOG_FILE takes the host's log lines (receipts, evidence, prints) and the terminal frame stays
    // on stdout; LMAWS_DEADLINE_MS ends the host (the shutdown hook still tears down) with no frame, which callers see as a
    // failed run; LMAWS_OFFLINE=1 makes every session offline, for a non-live preview outside protocol dry mode.
    static int run(String[] args) throws Exception {
        PrintStream frameOutput=System.out;
        try{return runHost(args,frameOutput);}finally{System.out.flush();if(System.out!=frameOutput){System.out.close();System.setOut(frameOutput);}}
    }
    private static void startDeadline() {
        String raw=System.getenv("LMAWS_DEADLINE_MS");if(raw==null||raw.isBlank())return;
        long millis;try{millis=Long.parseLong(raw.trim());}catch(NumberFormatException e){throw new IllegalArgumentException("LMAWS_DEADLINE_MS must be a positive number of milliseconds");}
        if(millis<1)throw new IllegalArgumentException("LMAWS_DEADLINE_MS must be a positive number of milliseconds");
        Thread watchdog=new Thread(()->{try{Thread.sleep(millis);}catch(InterruptedException e){return;}System.err.println("lmaws deadline reached after "+millis+" ms");System.exit(124);},"lmaws-deadline");
        watchdog.setDaemon(true);watchdog.start();
    }
    private static int runHost(String[] args,PrintStream frameOutput) throws Exception {
        if(Arrays.asList(args).contains("--credential-process")) return CredentialProcess.runCli(args);
        List<String> remaining=new ArrayList<>();
        if(Arrays.asList(args).contains("--apply") || Arrays.asList(args).contains("--live") || Arrays.asList(args).contains("--profile") || Arrays.asList(args).contains("--region")) {
            boolean apply=false,live=false;
            String profile=null,region=null;
            for(int i=0;i<args.length;i++) {
                String arg=args[i];
                if("--apply".equals(arg)) apply=true;
                else if("--live".equals(arg)) live=true;
                else if("--profile".equals(arg) && i+1<args.length) profile=args[++i];
                else if("--region".equals(arg) && i+1<args.length) region=args[++i];
                else remaining.add(arg);
            }
            if(live) System.setProperty("lmaws.live","true");
            if(apply) System.setProperty("lmaws.apply","true");
            if(profile!=null) System.setProperty("lmaws.profile",profile);
            if(region!=null) System.setProperty("lmaws.region",region);
            args=remaining.toArray(new String[0]);
        } else remaining.addAll(Arrays.asList(args));
        // Reject unknown options before host construction, credentials, journals or SDK clients.
        if(args.length==0 || !Set.of("--version","--help","--notices","--lmcode-schema","--lmcode-signatures","--sweep","--self-test","--lmcode").contains(args[0])) return Reports.failureFrame("cli",new VmException("CLI_USAGE","unknown or missing command"));
        long bytes;try{bytes=budget();CloudHost.costCap();}catch(IllegalArgumentException e){return Reports.failureFrame("cli",new VmException("CLI_USAGE",e.getMessage()));}
        if(Arrays.equals(args,new String[]{"--version"})){System.out.println("lmaws "+VERSION);return 0;}
        if(Arrays.equals(args,new String[]{"--help"})){System.out.print(HELP);return 0;}
        if(Arrays.equals(args,new String[]{"--notices"})){try(InputStream in=Main.class.getResourceAsStream("/THIRD_PARTY_NOTICES")){if(in==null)throw new IOException("notices missing");in.transferTo(System.out);}return 0;}
        if(args.length==1&&args[0].equals("--lmcode-signatures")) { new CloudHost().registry().signatures().forEach(System.out::println); return 0; }
        if(Arrays.equals(args,new String[]{"--lmcode-signatures","--without-std"})) { new CloudHost().registry().hostSignatures().forEach(System.out::println); return 0; }
        if(args.length>=1&&args[0].equals("--lmcode-schema")&&(args.length==1||args.length==2&&args[1].equals("--json"))) { try(CloudHost host=new CloudHost()){System.out.write(schema(host.registry()));} return 0; }
        if(args.length==4&&args[0].equals("--sweep")&&args[2].equals("--older-than-hours")){System.out.println(Jsons.encode(Sandbox.leftovers(Path.of(args[1]),Long.parseLong(args[3]))));return 0;}
        if(Arrays.equals(args,new String[]{"--self-test"})){SafetyChecks.run();AdversarialChecks.run();WebStackChecks.run();CostChecks.run();AccountSearchChecks.run();LedgerCleanupChecks.run();SpendChecks.run();FleetCostsChecks.main(new String[0]);IamPolicyChecks.run();IamRoleChecks.run();CredentialProcessChecks.run();PolicyBuilderChecks.run();FleetRoleChecks.run();PublishGrantProbeChecks.run();LambdaChecks.run();SelfTest.main(new String[0]);return 0;}
        List<String> files=new ArrayList<>();
        for(int i=0;i<args.length;i++){
            if(!args[i].equals("--lmcode")||i+1>=args.length)return Reports.failureFrame("cli",new VmException("CLI_USAGE","expected --lmcode FILE"));
            files.add(args[++i]);
        }
        InvocationResults results;
        try{results=InvocationResults.fromCommand(files);}catch(VmException e){return Reports.failureFrame("cli",e);}
        boolean offline=results.dry()||"1".equals(System.getenv("LMAWS_OFFLINE"));
        System.setProperty("lmaws.dryRun",Boolean.toString(offline));
        if(offline){System.clearProperty("lmaws.live");System.clearProperty("lmaws.apply");}
        try{startDeadline();}catch(IllegalArgumentException e){return Reports.failureFrame("cli",new VmException("CLI_USAGE",e.getMessage()));}
        String logFile=System.getenv("LMAWS_LOG_FILE");
        if(logFile!=null&&!logFile.isBlank())System.setOut(new PrintStream(new FileOutputStream(logFile),true,java.nio.charset.StandardCharsets.UTF_8));
        CloudHost host=new CloudHost();
        Thread shutdown=new Thread(()->{try{host.emergencyWebCleanup();host.close();}catch(RuntimeException failure){System.err.println("lmaws teardown incomplete; inspect the run ledger");}},"lmaws-teardown");
        Runtime.getRuntime().addShutdownHook(shutdown);
        try(host) {
            Registry registry=host.registry();byte[] schema=schema(registry);
            Context context=host.context(bytes);context.setDry(results.dry());RuntimeBudget.configure(bytes,args);
            ResultContract contract=ResultContract.fromSchema(schema);
            List<InvocationResults.Registration> registrations=results.registrations();
            for(InvocationResults.Registration registration:registrations){
                int index=registration.index();String phase="load";
                try{
                    results.select(index,registry,contract);
                    Path input=Path.of(registration.file());
                    io.lmctl.lmcode.Program program=io.lmctl.lmcode.Program.load(Files.readAllBytes(input),schema,registry);
                    phase="run";program.run(context,registry);results.complete(index);
                }catch(VmException failure){host.noteFailure(failure,safeError(failure),"");results.fail(index,phase,safeError(failure).contains("memory budget")?new VmException(failure.code,"LMAWS_MAX_MEMORY_MB: "+failure.getMessage()):failure);break;}
                catch(IOException failure){host.noteFailure(failure,safeError(failure),"");results.fail(index,phase,new VmException(phase.equals("load")?"LOAD_BAD_BYTECODE":"RUN_HOST",failure.getMessage()));break;}
                catch(Exception|OutOfMemoryError failure){
                String action="";
                if(failure instanceof AwsServiceException service && service.awsErrorDetails()!=null){String reason=service.awsErrorDetails().errorMessage();if(reason!=null){var matcher=java.util.regex.Pattern.compile("perform:?\\s+([A-Za-z0-9]+:[A-Za-z0-9]+)").matcher(reason);if(matcher.find())action=matcher.group(1);}}
                host.noteFailure(failure,safeError(failure),action);throw failure;
                }
            }
            host.close();
            return results.writeFrame(frameOutput);
        } finally {try{Runtime.getRuntime().removeShutdownHook(shutdown);}catch(IllegalStateException ignored){}}
    }
    public static void main(String[] args) {
        // Windows console defaults may be legacy code pages; the host protocol is UTF-8.
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out),true,java.nio.charset.StandardCharsets.UTF_8));
        System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err),true,java.nio.charset.StandardCharsets.UTF_8));
        int status;
        try{status=run(args);}catch(OutOfMemoryError e){String text="LMAWS_MAX_MEMORY_MB memory budget exceeded";System.err.println(text);status=Reports.failureFrame("run",VmException.run(text));}
        catch(Exception e){String text=safeError(e);if(text.contains("memory budget"))text="LMAWS_MAX_MEMORY_MB: "+text;System.err.println(text);VmException error=e instanceof VmException v?new VmException(v.code,text):VmException.host(text);if(e instanceof VmException v){error.line=v.line;error.column=v.column;}status=Reports.failureFrame("run",error);}
        if(status!=0)System.exit(status);
    }
}
