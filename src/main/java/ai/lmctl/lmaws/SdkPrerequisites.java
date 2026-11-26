package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.util.*;
import static ai.lmctl.lmaws.SdkCall.*;

/** Bounded prerequisites for the explicitly authorized shared egtry service.
 * No general existing-role or bucket-policy write capability is granted. */
final class SdkPrerequisites {
    static final String ACCOUNT="254332045686", SECRET="poc-go-fargate-egtry-origin";
    static final Set<String> ROLES=Set.of("poc-go-fargate-task","poc-go-fargate-exec");
    static final Set<String> BUCKETS=Set.of("www.egtry.com","egtry-v2-254332045686");
    static void require(boolean ok,String reason) { if(!ok) throw new SecurityException(reason); }
    static Object get(AwsBackend b,String service,String op,Object in) { return invoke(b.sdkClient(service),CLIENTS.get(service),op,in); }
    static boolean equal(Object a,Object b) { return canonical(a).equals(canonical(b)); }
    static void keys(Object o,String... keys) {
        require(o instanceof Map<?,?>,"object required");
        require(((Map<?,?>)o).keySet().equals(Set.of(keys)),"unexpected or missing policy/request fields");
    }
    static void account(AwsBackend b) { require(ACCOUNT.equals(b.accountIdForResize()),"approved account required"); }
    static void verifyRole(AwsBackend b,String role,String poc) {
        require(ROLES.contains(role)&&poc.equals("go-fargate"),"unapproved existing role"); account(b);
        Object r=get(b,"iam","GetRole",Map.of("RoleName",role));
        require(first(r,"Role.Arn").equals("arn:aws:iam::"+ACCOUNT+":role/"+role),"role ARN mismatch");
        require(hasTag(get(b,"iam","ListRoleTags",Map.of("RoleName",role)),poc),"role tag mismatch");
    }
    static Object inlinePolicies(AwsBackend b,String role) {
        Object names=get(b,"iam","ListRolePolicies",Map.of("RoleName",role));
        require(!first(names,"IsTruncated").equals("true"),"truncated role policies refused");
        Map<String,Object> out=new TreeMap<>();
        for(Object n:at(names,"PolicyNames")) {
            Object p=get(b,"iam","GetRolePolicy",Map.of("RoleName",role,"PolicyName",n));
            out.put(n.toString(),first(p,"PolicyDocument"));
        }
        return out;
    }
    static void bucketInput(AwsBackend b,Object in) {
        require(BUCKETS.contains(first(in,"Bucket")),"unapproved bucket");
        require(first(in,"ExpectedBucketOwner").equals(ACCOUNT),"ExpectedBucketOwner required");
        if(!b.isDemo()) account(b);
    }
    static void rolePolicy(Object in,State state) {
        keys(in,"RoleName","PolicyName","PolicyDocument");
        String role=first(in,"RoleName");
        require(ROLES.contains(role)&&first(in,"PolicyName").equals("egtry-origin-read"),"unapproved role or inline policy name");
        Object doc=Json.parse(first(in,"PolicyDocument")); keys(doc,"Version","Statement");
        require(first(doc,"Version").equals("2012-10-17"),"policy version required");
        List<Object> statements=at(doc,"Statement");require(statements.size()==1,"exactly one statement required");
        Object st=statements.get(0);keys(st,"Effect","Action","Resource");
        require(first(st,"Effect").equals("Allow"),"Allow required");
        List<Object> resources=at(st,"Resource");
        if(role.endsWith("-task")) {
            require(at(st,"Action").equals(List.of("s3:GetObject")),"task permits GetObject only");
            require(resources.size()==2&&new HashSet<>(resources).equals(Set.of("arn:aws:s3:::www.egtry.com/*","arn:aws:s3:::egtry-v2-254332045686/*")),"exact approved object ARNs required");
        } else {
            require(at(st,"Action").equals(List.of("secretsmanager:GetSecretValue"))&&resources.size()==1,"execution role permits one GetSecretValue only");
            String arn=resources.get(0).toString();
            require(arn.matches("arn:aws:secretsmanager:us-east-1:"+ACCOUNT+":secret:"+SECRET+"-[A-Za-z0-9]{6}"),"exact new secret ARN required");
            require(state.find("secretsmanager",arn,"secretsmanager:CreateSecret")!=null,"secret must be created by this run");
        }
    }
    static Object check(AwsBackend b,String key,Object parsed,Object in,String poc,State state,Map<String,Object> entry,boolean demo) {
        if(key.equals("secretsmanager:CreateSecret")) {
            keys(parsed,"Name","SecretString","Tags");
            require(first(parsed,"Name").equals(SECRET)&&poc.equals("go-fargate"),"only approved new secret name");
            require(ENV.matcher(first(parsed,"SecretString")).matches(),"secret must be an environment placeholder");
            if(!demo) { account(b); secretAbsent(b); }
        }
        if(key.equals("iam:PutRolePolicy")&&ROLES.contains(first(in,"RoleName"))) {
            rolePolicy(in,state);
            if(demo) return null;
            require(entry!=null&&Boolean.TRUE.equals(entry.get("adopted")),"approved existing role requires explicit adoption");
            verifyRole(b,first(in,"RoleName"),poc);
            Object current=inlinePolicies(b,first(in,"RoleName"));
            require(equal(current,entry.get("previousInlinePolicies")),"inline policies changed since adoption");
            require(!((Map<?,?>)current).containsKey("egtry-origin-read"),"refuse overwriting an existing inline policy");
            return current;
        }
        if(key.equals("s3:PutBucketPolicy")) {
            keys(in,"Bucket","ExpectedBucketOwner","Policy","LmawsPreviousPolicy");bucketInput(b,in);
            require(poc.equals("go-fargate"),"approved poc required");
            String previous=first(in,"LmawsPreviousPolicy");
            bucketPolicy(first(in,"Bucket"),previous,first(in,"Policy"),state);
            if(!demo) require(previous.equals(currentPolicy(b,in)),"bucket policy changed since read");
            return previous;
        }
        return null;
    }
    static void secretAbsent(AwsBackend b) {
        try { get(b,"secretsmanager","DescribeSecret",Map.of("SecretId",SECRET)); }
        catch(software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException ex) { return; }
        throw new SecurityException("secret name already exists; refusing CreateSecret");
    }
    static String currentPolicy(AwsBackend b,Object in) {
        return first(get(b,"s3","GetBucketPolicy",Map.of("Bucket",first(in,"Bucket"),"ExpectedBucketOwner",ACCOUNT)),"Policy");
    }
    static void bucketPolicy(String bucket,String previous,String desired,State state) {
        Map<String,Object> old=Json.object(Json.parse(previous)),next=Json.object(Json.parse(desired));
        var oldTop=new LinkedHashMap<>(old);var newTop=new LinkedHashMap<>(next);oldTop.remove("Statement");newTop.remove("Statement");
        require(equal(oldTop,newTop),"existing policy metadata changed");
        List<Object> a=at(old,"Statement"),z=at(next,"Statement");
        require(z.size()==a.size()+1,"only one appended statement permitted");
        for(int i=0;i<a.size();i++) require(equal(a.get(i),z.get(i)),"existing statement changed");
        Object s=z.get(z.size()-1);keys(s,"Sid","Effect","Principal","Action","Resource","Condition");
        require(first(s,"Sid").equals("EgtryTestOacRead")&&a.stream().noneMatch(x->first(x,"Sid").equals("EgtryTestOacRead")),"new unique Sid required");
        require(first(s,"Effect").equals("Allow")&&at(s,"Action").equals(List.of("s3:GetObject")),"OAC read only");
        require(equal(((Map<?,?>)s).get("Principal"),Map.of("Service","cloudfront.amazonaws.com")),"CloudFront service principal only");
        require(at(s,"Resource").equals(List.of("arn:aws:s3:::"+bucket+"/*")),"exact bucket object ARN required");
        String arn=first(s,"Condition.StringEquals.AWS:SourceArn");
        require(arn.matches("arn:aws:cloudfront::"+ACCOUNT+":distribution/[A-Z0-9]+")&&!arn.endsWith("/E3HQY8QHHHAZP7"),"new distribution ARN required");
        require(equal(((Map<?,?>)s).get("Condition"),Map.of("StringEquals",Map.of("AWS:SourceArn",arn))),"only exact SourceArn condition permitted");
        require(state.find("cloudfront",arn,"cloudfront:CreateDistributionWithTags")!=null,"distribution must be created by this run");
    }
    static void recheck(AwsBackend b,String key,Object in,Object rollback) {
        if(key.equals("secretsmanager:CreateSecret")) secretAbsent(b);
        if(key.equals("s3:PutBucketPolicy")) require(rollback.equals(currentPolicy(b,in)),"bucket policy changed immediately before put");
        if(key.equals("iam:PutRolePolicy")&&rollback!=null) require(equal(rollback,inlinePolicies(b,first(in,"RoleName"))),"inline policies changed immediately before put");
    }
    static Object request(String key,Object in) {
        if(!key.equals("s3:PutBucketPolicy")) return in;
        var copy=new LinkedHashMap<>(Json.object(in));copy.remove("LmawsPreviousPolicy");return copy;
    }
}
