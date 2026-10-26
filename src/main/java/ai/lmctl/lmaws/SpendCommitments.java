package ai.lmctl.lmaws;

import java.time.LocalDate;
import java.util.*;
import software.amazon.awssdk.services.costexplorer.CostExplorerClient;
import software.amazon.awssdk.services.costexplorer.model.*;
import software.amazon.awssdk.services.savingsplans.SavingsplansClient;
import software.amazon.awssdk.services.savingsplans.model.DescribeSavingsPlansRequest;

/** Typed numeric projections; every paginated CE request has a separate admission charge. */
final class SpendCommitments {
    private SpendCommitments(){}
    private static Map<String,String> row(String...pairs){Map<String,String>x=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)x.put(pairs[i],pairs[i+1]==null?"unknown":pairs[i+1]);return x;}
    private static void charge(CostLedger ledger,String operation){if(ledger!=null)ledger.request("costexplorer",operation);}
    private static String next(String token,Set<String> seen){if(token==null||token.isBlank())return null;if(!seen.add(token)||seen.size()>100)throw new SpendSource.Unavailable("commitment","PAGINATION_LIMIT_EXCEEDED");return token;}
    static List<Map<String,String>> read(CostExplorerClient ce,CostLedger ledger,String kind,LocalDate start,LocalDate end){
        DateInterval period=DateInterval.builder().start(start.toString()).end(end.toString()).build();List<Map<String,String>> out=new ArrayList<>();Set<String> seen=new HashSet<>();String token=null;
        try{
            switch(kind){
                case "sp_utilization"->{
                    charge(ledger,"GetSavingsPlansUtilization");var response=ce.getSavingsPlansUtilization(GetSavingsPlansUtilizationRequest.builder().timePeriod(period).granularity("DAILY").build());
                    var value=response.total()==null?null:response.total().utilization();if(value!=null)out.add(row("total_commitment_usd",value.totalCommitment(),"used_commitment_usd",value.usedCommitment(),"unused_commitment_usd",value.unusedCommitment(),"utilization_percent",value.utilizationPercentage()));
                }
                case "sp_coverage"->{do{
                    charge(ledger,"GetSavingsPlansCoverage");var response=ce.getSavingsPlansCoverage(GetSavingsPlansCoverageRequest.builder().timePeriod(period).granularity("DAILY").maxResults(100).nextToken(token).build());
                    for(var value:response.savingsPlansCoverages())if(value.coverage()!=null){var coverage=value.coverage();out.add(row("date",value.timePeriod()==null?"unknown":value.timePeriod().start(),"coverage_percent",coverage.coveragePercentage(),"covered_spend_usd",coverage.spendCoveredBySavingsPlans(),"ondemand_spend_usd",coverage.onDemandCost(),"total_cost_usd",coverage.totalCost()));}
                    token=next(response.nextToken(),seen);
                }while(token!=null);}
                case "sp_recommendations"->{do{
                    charge(ledger,"GetSavingsPlansPurchaseRecommendation");var response=ce.getSavingsPlansPurchaseRecommendation(GetSavingsPlansPurchaseRecommendationRequest.builder().savingsPlansType("COMPUTE_SP").termInYears("ONE_YEAR").paymentOption("NO_UPFRONT").accountScope("PAYER").lookbackPeriodInDays("THIRTY_DAYS").nextPageToken(token).build());
                    var value=response.savingsPlansPurchaseRecommendation()==null?null:response.savingsPlansPurchaseRecommendation().savingsPlansPurchaseRecommendationSummary();
                    if(value!=null&&out.isEmpty())out.add(row("estimated_roi",value.estimatedROI(),"estimated_savings_amount",value.estimatedSavingsAmount(),"estimated_savings_percent",value.estimatedSavingsPercentage(),"commitment_hourly_to_purchase",value.hourlyCommitmentToPurchase(),"recommendation_count",value.totalRecommendationCount(),"lookback_days","30","term","one year / no upfront"));
                    token=next(response.nextPageToken(),seen);
                }while(token!=null);}
                case "ri_utilization"->{do{
                    charge(ledger,"GetReservationUtilization");var response=ce.getReservationUtilization(GetReservationUtilizationRequest.builder().timePeriod(period).granularity("DAILY").nextPageToken(token).build());var value=response.total();
                    if(value!=null&&out.isEmpty())out.add(row("utilization_percent",value.utilizationPercentage(),"purchased_hours",value.purchasedHours(),"used_hours",value.totalActualHours(),"unused_hours",value.unusedHours(),"unused_amortized_usd",value.riCostForUnusedHours(),"total_amortized_usd",value.totalAmortizedFee(),"net_savings_usd",value.netRISavings()));
                    token=next(response.nextPageToken(),seen);
                }while(token!=null);}
                case "ri_coverage"->{do{
                    charge(ledger,"GetReservationCoverage");var response=ce.getReservationCoverage(GetReservationCoverageRequest.builder().timePeriod(period).granularity("DAILY").nextPageToken(token).build());
                    for(var time:response.coveragesByTime())if(time.total()!=null&&time.total().coverageHours()!=null){var value=time.total().coverageHours();out.add(row("date",time.timePeriod()==null?"unknown":time.timePeriod().start(),"coverage_percent",value.coverageHoursPercentage(),"ondemand_hours",value.onDemandHours(),"covered_hours",value.reservedHours(),"total_running_hours",value.totalRunningHours()));}
                    token=next(response.nextPageToken(),seen);
                }while(token!=null);}
                case "ri_recommendations"->{do{
                    charge(ledger,"GetReservationPurchaseRecommendation");var response=ce.getReservationPurchaseRecommendation(GetReservationPurchaseRecommendationRequest.builder().service("Amazon Elastic Compute Cloud - Compute").accountScope("PAYER").lookbackPeriodInDays("THIRTY_DAYS").termInYears("ONE_YEAR").paymentOption("NO_UPFRONT").nextPageToken(token).build());
                    for(var recommendation:response.recommendations()){var value=recommendation.recommendationSummary();if(value!=null){var projection=row("estimated_monthly_savings_usd",value.totalEstimatedMonthlySavingsAmount(),"estimated_monthly_savings_percent",value.totalEstimatedMonthlySavingsPercentage(),"currency",value.currencyCode(),"lookback_days","30","term","one year / no upfront");if(!out.contains(projection))out.add(projection);}}
                    token=next(response.nextPageToken(),seen);
                }while(token!=null);}
                default->throw new SpendSource.Unavailable("commitment","UNSUPPORTED_KIND");
            }
        }catch(CostLedger.BudgetExceeded|SpendSource.Unavailable e){throw e;}catch(software.amazon.awssdk.awscore.exception.AwsServiceException e){throw new SpendSource.Unavailable(kind,e.awsErrorDetails()==null?e.getClass().getSimpleName():e.awsErrorDetails().errorCode());}
        return out;
    }
    static List<Map<String,String>> plans(SavingsplansClient plans,CostLedger ledger){
        List<Map<String,String>> out=new ArrayList<>();Set<String> seen=new HashSet<>();String token=null;
        do{if(ledger!=null)ledger.request("savingsplans","DescribeSavingsPlans");var response=plans.describeSavingsPlans(DescribeSavingsPlansRequest.builder().nextToken(token).build());
            for(var value:response.savingsPlans())out.add(row("plan_id",value.savingsPlanId(),"start",value.start(),"end",value.end(),"state",value.stateAsString(),"plan_type",value.savingsPlanTypeAsString(),"commitment_hourly",value.commitment()));
            token=next(response.nextToken(),seen);if(out.size()>10000)throw new SpendSource.Unavailable("savings_plans","RESULT_LIMIT_EXCEEDED");
        }while(token!=null);return out;
    }
}
