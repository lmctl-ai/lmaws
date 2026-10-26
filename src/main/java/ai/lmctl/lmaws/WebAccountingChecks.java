package ai.lmctl.lmaws;

import java.math.BigDecimal;
import java.nio.file.*;

/** Real-mode accounting without SDK dispatch; run only with the loopback fixture environment. */
public final class WebAccountingChecks {
    public static void main(String[] args) throws Exception {
        if(!"http://127.0.0.1:1".equals(System.getenv("LMAWS_ENDPOINT")))throw new IllegalStateException("accounting test requires its non-routable loopback endpoint");
        Path dir=Files.createTempDirectory("web-accounting-").resolve(".lmweblab-local");
        CostLedger cost=new CostLedger("a1b2c3d4","web_accounting","us-east-1",dir.resolve("cost.jsonl"),new BigDecimal("0.10"),false);
        try(AwsBackend backend=new AwsBackend("us-east-1",false,cost);WebRun web=new WebRun(backend,cost,"a1b2c3d4","example.com",dir.resolve("state.json").toString())){
            web.step("reserve_http","{\"requests\":100,\"bytes\":1048576}");
            web.step("record_http","{\"requests\":3,\"bytes\":100}");
            if(!"3".equals(web.state.get("viewer_requests"))||web.state.containsKey("http_reserved"))throw new AssertionError("real JSON integer accounting did not settle its reservation");
            BigDecimal total=new BigDecimal(web.summary().get("estimated_cost_usd"));
            if(total.compareTo(new BigDecimal("0.000003"))<0||total.compareTo(new BigDecimal("0.000004"))>=0)throw new AssertionError("HTTP request/transfer estimate outside its price-table bounds");
            if(!cost.report(0).get("service_requests").toString().equals("{}"))throw new AssertionError("accounting unexpectedly dispatched an SDK request");
        }
        String receipt=Files.readString(cost.path());
        if(!receipt.contains("cost_web_snapshot")||!receipt.contains("http_transfer_bound_usd_gb"))throw new AssertionError("whole-run cost snapshot/price table missing");
        try(var files=Files.walk(dir.getParent())){for(Path file:files.sorted(java.util.Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}
        System.out.println("PASS real-mode HTTP integer accounting, request/transfer reservation and whole-run ledger; no SDK dispatch");
    }
}
