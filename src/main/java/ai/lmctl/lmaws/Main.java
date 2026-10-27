package ai.lmctl.lmaws;

import io.lmctl.lmcode.*;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public final class Main {
    public static final String VERSION="0.1.16";
    private static final String HELP="""
        lmaws 0.1.16 — AWS SDK for Java v2 scripting host
        usage: lmaws [--dry-run] [--apply] --dsl FILE | --dsl-schema [--json] | --dsl-signatures [--without-std]
               lmaws --credential-process <default|lmaws|lmaws-ec2|lmaws-web> [--duration SECONDS] [--no-cache]
               lmaws --version | --notices | --help | --self-test
               lmaws --sweep LEDGER_DIR --older-than-hours N
        DSL context: aws.demo() (offline) or aws.region(\"\") (default profile/region).
        Live writes require AWS_PROFILE=lmaws (or lmaws-ec2 for the spot nano sandbox),
        a new ledger, prefixed names and ownership tags.
        Exceptions for the admin profile (refused for every other mutating call):
        1. lmaws_ customer-managed IAM policy writes (iam_policy_put/iam_policy_delete)
           require AWS_PROFILE=admin, LMAWS_ADMIN_GRANT=1, LMAWS_LIVE=1 and --apply (LMAWS_APPLY=1).
        2. lmaws --credential-process <mode> reads ONLY the static admin source profile
           from shared credentials/config (ignoring ambient env/web-identity/container/IMDS)
           to call STS GetCallerIdentity and GetFederationToken (awsspot-local-<mode>, 3600s,
           0600 file cache until 5m before expiry); it creates no resources and changes no permissions.
        Every run is cleaned up on success and failure. --sweep is always read-only.
        LMAWS_MAX_MEMORY_MB: positive whole MiB, default 4096; bounded heap and VM data.
        LMAWS_MAX_COST_USD: default 0.05, hard whole-run ceiling 0.25.
        aws.example(name) selects local profile live mode only when LMAWS_LIVE=1;
        examples record prices, requests, minutes, teardown, sweeper and cost evidence.
        Read-only spend: aws.spend(topic, days, top_n, cap); synthetic by default.
        Real spend requires LMAWS_SPEND_LIVE=1, LMAWS_LIVE=1 and AWS_PROFILE=default.
        CE pages cost about $0.01; GetMetricData counts requested metrics; cap <=$0.25.
        Real spend exports stay under ignored .lmaws-local/spend; no AWS CLI is used.
        No OIDC or AWS credentials in CI; CI uses loopback fakes only.
        --dry-run uses demo sessions: no AWS requests; local reports/ledgers still write.
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
        if(e instanceof AwsServiceException aws) {String code=aws.awsErrorDetails()==null?"AWS_SERVICE_ERROR":aws.awsErrorDetails().errorCode();if(code==null||!code.matches("[A-Za-z0-9_.-]{1,100}"))code="AWS_SERVICE_ERROR";return "AWS "+code+" (HTTP "+aws.statusCode()+")";}
        if(e instanceof VmException || e instanceof IllegalArgumentException || e instanceof IllegalStateException) return Jsons.mask(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());
        return "operation failed ("+e.getClass().getSimpleName()+")";
    }
    static int run(String[] args) throws Exception {
        if(Arrays.asList(args).contains("--credential-process")) return CredentialProcess.runCli(args);
        String[] requested=args;
        if(Arrays.asList(args).contains("--dry-run") || Arrays.asList(args).contains("--apply") || Arrays.asList(args).contains("--live") || Arrays.asList(args).contains("--profile") || Arrays.asList(args).contains("--region")) {
            List<String> remaining=new ArrayList<>();
            boolean dryRun=false,apply=false,live=false;
            String profile=null,region=null;
            for(int i=0;i<args.length;i++) {
                String arg=args[i];
                if("--dry-run".equals(arg)) dryRun=true;
                else if("--apply".equals(arg)) apply=true;
                else if("--live".equals(arg)) live=true;
                else if("--profile".equals(arg) && i+1<args.length) profile=args[++i];
                else if("--region".equals(arg) && i+1<args.length) region=args[++i];
                else remaining.add(arg);
            }
            if(dryRun) System.setProperty("lmaws.dryRun","true");
            if(live && !dryRun) System.setProperty("lmaws.live","true");
            if(apply && !dryRun) System.setProperty("lmaws.apply","true");
            if(profile!=null) System.setProperty("lmaws.profile",profile);
            if(region!=null) System.setProperty("lmaws.region",region);
            args=remaining.toArray(new String[0]);
        }
        long bytes;try{bytes=budget();CloudHost.costCap();}catch(IllegalArgumentException e){System.err.println(e.getMessage());return 2;}
        if(Arrays.equals(args,new String[]{"--version"})){System.out.println("lmaws "+VERSION);return 0;}
        if(Arrays.equals(args,new String[]{"--help"})){System.out.print(HELP);return 0;}
        if(Arrays.equals(args,new String[]{"--notices"})){try(InputStream in=Main.class.getResourceAsStream("/THIRD_PARTY_NOTICES")){if(in==null)throw new IOException("notices missing");in.transferTo(System.out);}return 0;}
        CloudHost host=new CloudHost();
        Thread shutdown=new Thread(()->{try{host.emergencyWebCleanup();host.close();}catch(RuntimeException failure){System.err.println("lmaws teardown incomplete; inspect the run ledger");}},"lmaws-teardown");
        Runtime.getRuntime().addShutdownHook(shutdown);
        try(host) {
            Registry registry=host.registry();byte[] schema=schema(registry);
            if(args.length>=1&&args[0].equals("--dsl-schema")&&(args.length==1||args.length==2&&args[1].equals("--json"))){System.out.write(schema);return 0;}
            if(Arrays.equals(args,new String[]{"--dsl-signatures","--without-std"})){registry.hostSignatures().forEach(System.out::println);return 0;}
            if(Arrays.equals(args,new String[]{"--dsl-signatures"})){registry.signatures().forEach(System.out::println);return 0;}
            if(args.length==4&&args[0].equals("--sweep")&&args[2].equals("--older-than-hours")){System.out.println(Jsons.encode(Sandbox.leftovers(Path.of(args[1]),Long.parseLong(args[3]))));return 0;}
            if(Arrays.equals(args,new String[]{"--self-test"})){SafetyChecks.run();WebStackChecks.run();CostChecks.run();AccountSearchChecks.run();LedgerCleanupChecks.run();SpendChecks.run();IamPolicyChecks.run();CredentialProcessChecks.run();PolicyBuilderChecks.run();LambdaChecks.run();SelfTest.main(new String[0]);return 0;}
            if(args.length!=2||!args[0].equals("--dsl")){System.err.print(HELP);return 2;}
            RuntimeBudget.configure(bytes,requested);
            Path input=Path.of(args[1]);if(Files.size(input)>Math.min(bytes/4,64L*1024*1024))throw VmException.run("LMAWS_MAX_MEMORY_MB bytecode input exceeds memory budget");
            io.lmctl.lmcode.Program program=io.lmctl.lmcode.Program.load(Files.readAllBytes(input),schema,registry);
            try{program.run(host.context(bytes),registry);}catch(Exception|OutOfMemoryError failure){
                String action="";
                if(failure instanceof AwsServiceException service && service.awsErrorDetails()!=null){String reason=service.awsErrorDetails().errorMessage();if(reason!=null){var matcher=java.util.regex.Pattern.compile("perform:?\\s+([A-Za-z0-9]+:[A-Za-z0-9]+)").matcher(reason);if(matcher.find())action=matcher.group(1);}}
                host.noteFailure(safeError(failure),action);throw failure;
            }
            host.close();
            return Reports.ok("null");
        } finally {try{Runtime.getRuntime().removeShutdownHook(shutdown);}catch(IllegalStateException ignored){}}
    }
    public static void main(String[] args) {
        // Windows console defaults may be legacy code pages; the host protocol is UTF-8.
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out),true,java.nio.charset.StandardCharsets.UTF_8));
        System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err),true,java.nio.charset.StandardCharsets.UTF_8));
        int status;
        try{status=run(args);}catch(OutOfMemoryError e){String text="LMAWS_MAX_MEMORY_MB memory budget exceeded";System.err.println(text);status=Reports.error("run",VmException.run(text));}
        catch(Exception e){String text=safeError(e);if(text.contains("memory budget"))text="LMAWS_MAX_MEMORY_MB: "+text;System.err.println(text);VmException error=e instanceof VmException v?new VmException(v.code,text):VmException.host(text);if(e instanceof VmException v){error.line=v.line;error.column=v.column;}status=Reports.error("run",error);}
        if(status!=0)System.exit(status);
    }
}
