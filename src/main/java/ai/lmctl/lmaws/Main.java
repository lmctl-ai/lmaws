package ai.lmctl.lmaws;

import io.lmctl.lmcode.*;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public final class Main {
    public static final String VERSION="0.1.0";
    private static final String HELP="""
        lmaws 0.1.0 — AWS SDK for Java v2 scripting host
        usage: lmaws [--dry-run] --dsl FILE | --dsl-schema [--json] | --dsl-signatures [--without-std]
               lmaws --version | --notices | --help | --self-test
               lmaws --sweep LEDGER_DIR --older-than-hours N
        DSL context: aws.demo() (offline) or aws.region(\"\") (default profile/region).
        Writes require a new run ledger, run-prefixed names and verified ownership tags.
        Every run is cleaned up on success and failure. --sweep is always read-only.
        LMAWS_MAX_MEMORY_MB: positive whole MiB, default 4096; bounded heap and VM data.
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
        if(e instanceof AwsServiceException aws) {String code=aws.awsErrorDetails()==null?"AWS_SERVICE_ERROR":aws.awsErrorDetails().errorCode();if(code==null||!code.matches("[A-Za-z0-9_.-]{1,100}"))code="AWS_SERVICE_ERROR";return "AWS "+code+" (HTTP "+aws.statusCode()+")";}
        if(e instanceof VmException || e instanceof IllegalArgumentException || e instanceof IllegalStateException) return Jsons.mask(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());
        return "operation failed ("+e.getClass().getSimpleName()+")";
    }
    static int run(String[] args) throws Exception {
        String[] requested=args;
        if(args.length==3&&args[0].equals("--dry-run")){System.setProperty("lmaws.dryRun","true");args=Arrays.copyOfRange(args,1,3);}
        else if(args.length==3&&args[2].equals("--dry-run")){System.setProperty("lmaws.dryRun","true");args=Arrays.copyOf(args,2);}
        long bytes;try{bytes=budget();}catch(IllegalArgumentException e){System.err.println(e.getMessage());return 2;}
        if(Arrays.equals(args,new String[]{"--version"})){System.out.println("lmaws "+VERSION);return 0;}
        if(Arrays.equals(args,new String[]{"--help"})){System.out.print(HELP);return 0;}
        if(Arrays.equals(args,new String[]{"--notices"})){try(InputStream in=Main.class.getResourceAsStream("/THIRD_PARTY_NOTICES")){if(in==null)throw new IOException("notices missing");in.transferTo(System.out);}return 0;}
        CloudHost host=new CloudHost();
        Thread shutdown=new Thread(()->{try{host.close();}catch(RuntimeException failure){System.err.println("lmaws teardown incomplete; inspect the run ledger");}},"lmaws-teardown");
        Runtime.getRuntime().addShutdownHook(shutdown);
        try(host) {
            Registry registry=host.registry();byte[] schema=schema(registry);
            if(args.length>=1&&args[0].equals("--dsl-schema")&&(args.length==1||args.length==2&&args[1].equals("--json"))){System.out.write(schema);return 0;}
            if(Arrays.equals(args,new String[]{"--dsl-signatures","--without-std"})){registry.hostSignatures().forEach(System.out::println);return 0;}
            if(Arrays.equals(args,new String[]{"--dsl-signatures"})){registry.signatures().forEach(System.out::println);return 0;}
            if(args.length==4&&args[0].equals("--sweep")&&args[2].equals("--older-than-hours")){System.out.println(Jsons.encode(Sandbox.leftovers(Path.of(args[1]),Long.parseLong(args[3]))));return 0;}
            if(Arrays.equals(args,new String[]{"--self-test"})){SafetyChecks.run();SelfTest.main(new String[0]);return 0;}
            if(args.length!=2||!args[0].equals("--dsl")){System.err.print(HELP);return 2;}
            RuntimeBudget.configure(bytes,requested);
            Path input=Path.of(args[1]);if(Files.size(input)>Math.min(bytes/4,64L*1024*1024))throw VmException.run("LMAWS_MAX_MEMORY_MB bytecode input exceeds memory budget");
            io.lmctl.lmcode.Program program=io.lmctl.lmcode.Program.load(Files.readAllBytes(input),schema,registry);
            program.run(host.context(bytes),registry);
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
