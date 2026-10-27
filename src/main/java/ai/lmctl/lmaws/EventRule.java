package ai.lmctl.lmaws;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/** Bounded EventBridge schedule contract for offline scenario tests. */
public final class EventRule {
    private static final Pattern NAME=Pattern.compile("lmaws[-_][a-z0-9_-]{1,62}");
    private final String name,schedule,runId; private String target="",providerArn=""; private boolean deleted; private final AwsBackend backend;
    EventRule(String name,String schedule,String runId){this(null,name,schedule,runId);}
    EventRule(AwsBackend backend,String name,String schedule,String runId){
        if(name==null||!NAME.matcher(name).matches())throw new IllegalArgumentException("EventBridge rule name must start with lmaws_ or lmaws-");
        if(schedule==null||schedule.length()<5||schedule.length()>256||(!schedule.startsWith("rate(")&&!schedule.startsWith("cron(")))throw new IllegalArgumentException("schedule must be a bounded rate(...) or cron(...) expression");
        this.backend=backend;this.name=name;this.schedule=schedule;this.runId=runId;
    }
    public synchronized Map<String,String> target(String lambdaArn){if(deleted)throw new IllegalStateException("rule is deleted");if(lambdaArn==null||!lambdaArn.contains(":function:lmaws"))throw new IllegalArgumentException("EventBridge target must be an lmaws Lambda ARN");target=lambdaArn;if(backend!=null)backend.putEventTarget(name,lambdaArn,runId);return status();}
    public synchronized Map<String,String> status(){var m=new LinkedHashMap<String,String>();m.put("kind","event_rule");m.put("name",name);m.put("id","arn:aws:events:local:000000000000:rule/"+name);m.put("schedule",schedule);m.put("target",target);m.put("run_id",runId);m.put("state",deleted?"deleted":"active");return m;}
    public synchronized Map<String,String> delete(){if(backend!=null)backend.deleteEventRule(name,runId);deleted=true;return status();}
}
