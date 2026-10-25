package ai.lmctl.lmaws;

import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Focused checks for cost caps, cleanup accounting and durable price metadata. */
public final class CostChecks {
    private CostChecks() {}

    public static void run() throws Exception {
        Path dir = Files.createTempDirectory("lmaws-cost-");
        Path log = dir.resolve("lmaws-cost-check.jsonl");
        CostLedger ledger = new CostLedger("cost01", "cost-check", "us-east-1", log,
                new BigDecimal("0.05"), true);
        ledger.reserveCreate("queue");
        ledger.created("queue", "queue-id", "lmaws_cost01_queue");
        ledger.request("sqs", "CreateQueue");
        ledger.put("queue", "queue-id", 12);
        ledger.request("sqs", "SendMessage");
        try (AutoCloseable ignored = ledger.cleanupScope()) {
            ledger.request("sqs", "DeleteQueue");
            ledger.deleted("queue", "queue-id");
        }
        Map<String,Object> report = ledger.report(0);
        check(((Number) report.get("leftover_count")).intValue() == 0, "leftover count");
        check(((BigDecimal) report.get("total_estimated_usd")).signum() >= 0, "nonnegative estimate");
        check(report.containsKey("price_table"), "embedded price table");
        check(ledger.displayCost().startsWith("$0.00"), "display has currency");
        check(Files.readString(log).contains("cost_header"), "durable cost header");
        check(Files.readString(log).contains("price_table"), "durable prices");

        CostLedger cap = new CostLedger("cap01", "cap-check", "us-east-1", dir.resolve("cap.jsonl"),
                new BigDecimal("0.000001"), true);
        boolean refused = false;
        try { cap.reserveCreate("bucket"); cap.request("metadata", "List"); }
        catch (IllegalStateException expected) { refused = true; }
        check(refused, "cap refuses before mutation");
        try (AutoCloseable ignored = cap.cleanupScope()) { cap.request("metadata", "Delete"); }
        boolean ceiling = false;
        try { new CostLedger("bad", "bad", "us-east-1", dir.resolve("bad.jsonl"), new BigDecimal("0.250001"), true); }
        catch (IllegalArgumentException expected) { ceiling = true; }
        check(ceiling, "hard ceiling enforced");
        java.util.concurrent.atomic.AtomicLong nanos=new java.util.concurrent.atomic.AtomicLong();
        CostLedger timed=new CostLedger("timed01","timed","us-east-1",dir.resolve("timed.jsonl"),CostLedger.DEFAULT_CAP,true,nanos::get);
        timed.reserveCreate("table");timed.created("table","own-table","lmaws_timed01_table");
        timed.put("table","own-table",1023,2);timed.request("Amazon DynamoDB","PutItem");
        nanos.set(30_000_000_000L);timed.deleted("table","own-table");
        var resource=io.lmctl.lmcode.Json.object(io.lmctl.lmcode.Json.parse(Jsons.encode(timed.report(0))));
        var item=io.lmctl.lmcode.Json.object(io.lmctl.lmcode.Json.array(resource.get("resources")).getFirst());
        check(((Number)item.get("minutes_alive")).doubleValue()==0.5,"fractional minutes");
        check(((Number)item.get("request_cost_usd")).doubleValue()==0.00000125,"two 1-KiB DynamoDB write units charged once");
        check(((Number)item.get("storage_cost_usd")).doubleValue()>0,"time-based storage charged");
        CostLedger micro=new CostLedger("micro01","readonly","us-east-1",dir.resolve("micro.jsonl"),new BigDecimal("0.000001"),true);
        micro.request("Amazon SQS","ListQueues");micro.request("Amazon SQS","ListQueues");
        boolean third=false;try{micro.request("Amazon SQS","ListQueues");}catch(IllegalStateException expected){third=true;}
        check(third,"next request refused before transmission");
        var requests=(Map<?,?>)micro.report(0).get("service_requests");
        check(((Number)((Map<?,?>)requests.get("sqs.ListQueues")).get("requests")).longValue()==2,"refused request not counted as sent");
        check(micro.displayCost().equals("$0.00"),"readonly display convention");
        CostLedger rejected=new CostLedger("reject01","rejected","us-east-1",dir.resolve("rejected.jsonl"),CostLedger.DEFAULT_CAP,true);
        rejected.reserveCreate("queue");rejected.request("sqs","CreateQueue");
        rejected.creationRejected("queue","lmaws_reject01_queue","AccessDenied",403);
        check(rejected.displayCost().equals("$0.00000040"),"rejected creation still displays charged request estimate");
        try(AutoCloseable ignored=micro.cleanupScope()){micro.request("Amazon SQS","DeleteQueue");}
        check(micro.total().compareTo(micro.cap())>0,"cleanup may use reserved safety headroom");
        System.out.println("PASS cost caps, exact request units, fractional storage, durable prices and unrestricted teardown");
    }

    private static void check(boolean ok, String label) { if (!ok) throw new AssertionError("cost check failed: " + label); }
}
