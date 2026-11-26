package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.util.*;
import static ai.lmctl.lmaws.SdkCall.*;
import static ai.lmctl.lmaws.SdkPrerequisites.*;

/** One secret, two consumers, no value-returning API. The placeholder environment
 * is scoped to this call, never exported to a parent process or serialized. */
final class EgtrySecret {
    static final String ARN="arn:aws:secretsmanager:us-east-1:254332045686:secret:poc-go-fargate-egtry-origin-bn8DfF";
    static final String PLACEHOLDER="{{env:EGTRY_ORIGIN_SECRET}}";
    static final String LISTENER="arn:aws:elasticloadbalancing:us-east-1:254332045686:listener/app/poc-go-fargate/6cecfab750f95823/e941785ccdb0fc7f";
    static Map<String,String> apply(AwsBackend b,String arn,String service,String op,String input,String stateFile,boolean apply) {
        require(ARN.equals(arn),"secret ARN is not allowlisted");
        require(!b.isDemo() && "admin".equals(AwsBackend.activeProfile()) && "1".equals(System.getenv("LMAWS_ADMIN_GRANT")),"live admin and explicit grant required");
        require("us-east-1".equals(b.regionName()),"approved region required");
        require(AwsBackend.isLiveEnabled() && (!apply || AwsBackend.isApplyEnabled()),"live/apply flags required");
        require(!apply || b.endpointActive() || !Set.of("true","1").contains(System.getenv().getOrDefault("CI","").toLowerCase()),"live apply forbidden in CI");
        Object parsed=Json.parse(input);
        validateConsumer(service,op,parsed);
        State st=State.load(stateFile,"go-fargate",true);
        var created=st.find("secretsmanager",arn,"secretsmanager:CreateSecret");
        require(created!=null && !Boolean.TRUE.equals(created.get("adopted")) && SECRET.equals(created.get("name")),"secret creation ledger required");
        account(b);
        // Catch without cause: even a malformed service response/exception must never escape.
        Map<String,String> environment=new HashMap<>();
        try {
            Object meta=get(b,"secretsmanager","DescribeSecret",Map.of("SecretId",arn));
            require(arn.equals(first(meta,"ARN")) && SECRET.equals(first(meta,"Name")),"secret metadata mismatch");
            boolean app=false,poc=false;
            for(Object tag:at(meta,"Tags")) {
                app |= first(tag,"Key").equals("app") && first(tag,"Value").equals("egtry");
                poc |= first(tag,"Key").equals("poc") && first(tag,"Value").equals("go-fargate");
            }
            require(app&&poc,"secret tags mismatch");
            // Preview verifies ownership, never retrieves the value (even if caller env has one).
            if(!apply) {
                environment.put("EGTRY_ORIGIN_SECRET",PLACEHOLDER);
                return call(b,service,op,input,"go-fargate",stateFile,false,environment);
            }
            Object value=get(b,"secretsmanager","GetSecretValue",Map.of("SecretId",arn,"VersionStage","AWSCURRENT"));
            require(arn.equals(first(value,"ARN")) && SECRET.equals(first(value,"Name")) && at(value,"VersionStages").contains("AWSCURRENT"),"secret response mismatch");
            String secret=first(value,"SecretString");
            require(secret.length()>=32 && secret.length()<=1024 && secret.chars().allMatch(c->c>=33&&c<=126),"invalid origin secret");
            environment.put("EGTRY_ORIGIN_SECRET",secret);
            return call(b,service,op,input,"go-fargate",stateFile,true,environment);
        } catch(RuntimeException ex) {
            throw new SecurityException("bounded egtry secret apply failed; secret-bearing diagnostics suppressed");
        } finally { environment.clear(); }
    }
    static void validateConsumer(String service,String op,Object in) {
        Object stripped=Json.parse(Jsons.encodeRaw(in));
        int expected;
        if(service.equals("elbv2")&&op.equals("CreateRule")) {
            require(LISTENER.equals(first(in,"ListenerArn"))&&new java.math.BigDecimal(first(in,"Priority")).compareTo(new java.math.BigDecimal("157"))==0,"only approved listener priority");
            expected=1;
            int headers=0;
            for(Object c:at(stripped,"Conditions")) if(first(c,"HttpHeaderConfig.HttpHeaderName").equals("X-Origin-Env")) {
                require(at(c,"HttpHeaderConfig.Values").equals(List.of(PLACEHOLDER)),"exact secret header placeholder required");
                ((Map<String,Object>)((Map<?,?>)c).get("HttpHeaderConfig")).put("Values",List.of("redacted"));headers++;
            }
            require(headers==1,"one origin secret header required");
        } else if(service.equals("cloudfront")&&op.equals("CreateDistributionWithTags")) {
            require(at(in,"DistributionConfigWithTags.DistributionConfig.Aliases.Items").equals(List.of("egtry-test.egtry.com")),"test distribution alias only");
            expected=2;int headers=0;
            for(Object o:at(stripped,"DistributionConfigWithTags.DistributionConfig.Origins.Items"))
                for(Object h:at(o,"CustomHeaders.Items")) if(first(h,"HeaderName").equals("X-Origin-Env")) {
                    require(first(o,"DomainName").equals("origin-go.lmctl.ai")&&first(h,"HeaderValue").equals(PLACEHOLDER),"approved origin header only");
                    ((Map<String,Object>)h).put("HeaderValue","redacted");headers++;
                }
            require(headers==2,"two origin secret headers required");
        } else throw new SecurityException("secret consumer is not allowlisted");
        require(!Jsons.encodeRaw(stripped).contains("{{env:"),"placeholder outside approved header");
        require(inputOccurrences(Jsons.encodeRaw(in),PLACEHOLDER)==expected,"exact placeholder count required");
    }
    static int inputOccurrences(String s,String x) { return (s.length()-s.replace(x,"").length())/x.length(); }
}
