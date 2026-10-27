package ai.lmctl.lmaws;
import java.util.*;
/** Pure policy regression cases; deliberately never constructs an SDK client. */
public final class S3PathPoliciesChecks {
    static final String ACCOUNT="000000000000", ARN="arn:aws:sts::000000000000:federated-user/fixture+reader", RESOURCE="arn:aws:s3:::fixture-bucket/path/file";
    static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);}
    static String bucket(Object conditions){var statement=new LinkedHashMap<String,Object>();statement.put("Effect","Deny");statement.put("Principal","*");statement.put("Action","s3:PutObject");statement.put("Resource","*");statement.put("Condition",conditions);return Jsons.encodeRaw(Map.of("Statement",List.of(statement)));}
    static String verdict(String policy){var rows=S3PathPolicies.bucket(policy,RESOURCE,ARN,ACCOUNT);return rows.get(rows.size()-1).get("status");}
    static Map<String,Object> condition(String op,String key,String value){return Map.of(op,Map.of(key,value));}
    public static void main(String[] args) {
        check(verdict(bucket(condition("Bool","aws:SecureTransport","false"))).startsWith("allowed"),"HTTPS must not match insecure-transport Deny");
        check(verdict(bucket(condition("Bool","aws:SecureTransport","true"))).startsWith("denied:"),"known true Deny");
        check(verdict(bucket(condition("ArnNotEquals","aws:PrincipalArn","arn:aws:iam::000000000000:role/other"))).startsWith("denied:"),"known principal mismatch must match ArnNotEquals Deny");
        check(verdict(bucket(condition("ArnEquals","aws:PrincipalArn","arn:aws:iam::000000000000:role/other"))).startsWith("allowed"),"principal mismatch must not match ArnEquals Deny");
        check(verdict(bucket(condition("StringNotEquals","aws:SourceVpc","vpc-fixture"))).startsWith("unknown:"),"unknown VPC must remain unknown");
        check(verdict(bucket(condition("Null","aws:SourceVpc","true"))).startsWith("unknown:"),"unobserved network key is not proven absent");
        check(verdict(bucket(condition("ArnEquals","aws:principalarn",ARN))).startsWith("denied:"),"condition keys ignore case; literal plus preserved");
        String opaque=Jsons.encodeRaw(Map.of("Statement",List.of(Map.of("Effect","Deny","NotPrincipal",Map.of("AWS",ARN),"Action","s3:PutObject","Resource","*"))));
        check(verdict(opaque).startsWith("unknown:"),"NotPrincipal requires conservative handling");
        var unknownResource=Map.of("Effect","Deny","Principal","*","Action","S3:PUTOBJECT","Resource","arn:aws:s3:::${custom:Bucket}/*");
        check(verdict(Jsons.encodeRaw(Map.of("Statement",List.of(unknownResource)))).startsWith("unknown:"),"unknown policy variable cannot bypass a Deny");
        check(verdict(bucket(condition("ArnNotEquals","aws:PrincipalArn","arn:aws:iam::${custom:Account}:role/other"))).startsWith("unknown:"),"unresolved condition variables cannot create a false Deny");
        var context=Map.<String,Object>of("aws:PrincipalArn",ARN);
        var allow=Map.of("Effect","Allow","Action","s3:PutObject","Resource","*","Condition",condition("StringEquals","aws:PrincipalArn",ARN.toUpperCase(Locale.ROOT)));
        check(S3PathPolicies.session(Jsons.encodeRaw(Map.of("Statement",List.of(allow))),"s3:PutObject",RESOURCE,context).startsWith("unknown:"),"StringEquals/ArnEquals values are case sensitive");
        var unknown=Map.of("Effect","Deny","Action","s3:PutObject","Resource","*","Condition",condition("StringNotEquals","aws:SourceVpc","vpc-fixture"));
        var plainAllow=Map.of("Effect","Allow","Action","s3:PutObject","Resource","*");
        check(S3PathPolicies.session(Jsons.encodeRaw(Map.of("Statement",List.of(unknown,plainAllow))),"s3:PutObject",RESOURCE,context).startsWith("unknown:"),"missing-context session Deny must block an unsupported Allow conclusion");
        System.out.println("PASS pure S3 path policy conditions, PrincipalArn, unknown network/variables, case rules and Deny precedence");
    }
}
