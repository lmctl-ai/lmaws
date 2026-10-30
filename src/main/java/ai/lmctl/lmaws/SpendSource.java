package ai.lmctl.lmaws;

import java.time.*;
import java.util.*;

/** Internal allowlisted, read-only spend data provider. Never a public AWS dispatcher. */
public interface SpendSource extends AutoCloseable {
    record Metric(String id,String region,String namespace,String name,String dimension,String resource,String statistic,int period) {}
    /** Dates are UTC, start inclusive/end exclusive. dimension: SERVICE, INSTANCE_TYPE, RESOURCE_ID, SERVICE_USAGE_TYPE. */
    List<Map<String,String>> costs(LocalDate start,LocalDate end,String granularity,String dimension,String service,boolean resources);
    /** Kinds: ec2, eips, ebs, snapshots, reserved_instances, savings_plans, lambda, dynamodb. Rows carry region. */
    List<Map<String,String>> inventory(String kind);
    /** sp_utilization, sp_coverage, sp_recommendations, ri_utilization, ri_coverage, ri_recommendations. */
    List<Map<String,String>> commitment(String kind,LocalDate start,LocalDate end);
    /** Rows: metric_id,resource_id,region,metric,statistic,total,datapoints,status. Missing data stays unknown. */
    List<Map<String,String>> metrics(List<Metric> queries,Instant start,Instant end);
    /** hourly_usd + basis/status; unknown prices must not silently become zero. */
    Map<String,String> ec2Price(String region,String instanceType,String platform);
    default List<Map<String,String>> savingsPlanRates(String planId) { throw new Unavailable("savings_plan_rates","UNAVAILABLE"); }
    default Map<String,Object> diagnostics(){return Map.of();}
    @Override void close();
    final class Unavailable extends RuntimeException {
        public final String feature,reason;
        public Unavailable(String feature,String reason){super(feature+": "+reason);this.feature=feature;this.reason=reason;}
    }
}
