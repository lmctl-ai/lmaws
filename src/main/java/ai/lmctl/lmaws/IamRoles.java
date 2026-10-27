package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.*;
import java.util.regex.Pattern;

/** Administrative, bounded reconciliation of a pre-built Lambda execution role. */
public final class IamRoles {
    static final Pattern NAME=Pattern.compile("^lmaws_[a-z0-9_-]{1,64}$");
    static final String BASIC="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole";
    private static final String SYMBOLIC_BOUNDARY="arn:aws:iam::${aws:PrincipalAccount}:policy/lmaws_boundary";
    private final boolean demo;
    private final Supplier<IamClient> iam;
    private final Supplier<String> account;
    private final Consumer<Boolean> access;
    private final Map<String,Snapshot> demoRoles=new HashMap<>();
    private record Snapshot(String arn,Map<String,Object> spec,Map<String,String> tags) {}
    public IamRoles(boolean demo,Supplier<IamClient> iam,Supplier<String> account,Consumer<Boolean> access) {
        this.demo=demo;this.iam=iam;this.account=account;this.access=access;
    }
    public static void requireName(String name) {
        if(name==null||!NAME.matcher(name).matches())throw new IllegalArgumentException("IAM role name must match ^lmaws_[a-z0-9_-]{1,64}$");
    }
    private static Map<String,Object> object(Object value,String label) {
        if(!(value instanceof Map<?,?> source))throw new IllegalArgumentException(label+" must be an object");
        Map<String,Object> out=new TreeMap<>();source.forEach((k,v)->out.put(String.valueOf(k),v));return out;
    }
    private static String text(Object value,String label) {
        if(!(value instanceof String s))throw new IllegalArgumentException(label+" must be a string");return s;
    }
    private static Object canonical(Object value) {
        if(value instanceof Map<?,?> m){Map<String,Object> out=new TreeMap<>();m.forEach((k,v)->out.put(String.valueOf(k),canonical(v)));return out;}
        if(value instanceof List<?> l)return l.stream().map(IamRoles::canonical).toList();
        return value;
    }
    private static String encoded(Object value){return Jsons.encodeRaw(canonical(value));}
    private static String safe(String value){return Jsons.mask(value).replaceAll("(?<![0-9])[0-9]{12}(?![0-9])","************");}
    private static String onlyString(Object value,String label) {
        if(value instanceof List<?> l&&l.size()==1)return text(l.get(0),label);
        return text(value,label);
    }
    static void validateTrust(Object value) {normalizeTrust(value);}
    private static Map<String,Object> normalizeTrust(Object value) {
        var policy=object(value,"trust policy");
        if(!policy.keySet().equals(Set.of("Version","Statement"))||!"2012-10-17".equals(policy.get("Version")))throw new IllegalArgumentException("trust policy only accepts Version 2012-10-17 and Statement");
        if(!(policy.get("Statement") instanceof List<?> statements)||statements.size()!=1)throw new IllegalArgumentException("trust policy requires exactly one Lambda statement");
        var statement=object(statements.get(0),"trust statement");
        if(!Set.of("Sid","Effect","Action","Principal").containsAll(statement.keySet())||!statement.keySet().containsAll(Set.of("Effect","Action","Principal")))throw new IllegalArgumentException("unexpected trust policy field");
        if(!"Allow".equals(statement.get("Effect"))||!"sts:AssumeRole".equals(onlyString(statement.get("Action"),"trust action")))throw new IllegalArgumentException("trust policy only allows sts:AssumeRole");
        var principal=object(statement.get("Principal"),"trust principal");
        if(!principal.keySet().equals(Set.of("Service"))||!"lambda.amazonaws.com".equals(onlyString(principal.get("Service"),"trust service")))throw new IllegalArgumentException("trust principal must be lambda.amazonaws.com only");
        statement.put("Action","sts:AssumeRole");statement.put("Principal",Map.of("Service","lambda.amazonaws.com"));
        if(statement.containsKey("Sid"))text(statement.get("Sid"),"trust Sid");
        return Map.of("Version","2012-10-17","Statement",List.of(statement));
    }
    static void validateBoundary(String value) {
        if(!SYMBOLIC_BOUNDARY.equals(value)&&!value.matches("arn:aws:iam::[0-9]{12}:policy/lmaws_boundary"))throw new IllegalArgumentException("permissions boundary must be lmaws_boundary");
    }
    static void validateManaged(String arn) {
        if(!BASIC.equals(arn)&&!arn.matches("arn:aws:iam::[0-9]{12}:policy/lmaws_lambda_[a-z0-9_-]{1,64}"))throw new IllegalArgumentException("managed policy must be AWSLambdaBasicExecutionRole or a lmaws_lambda_ customer policy");
    }
    public static Map<String,Object> parseSpec(String raw) {
        var spec=object(Json.parse(raw),"role specification");
        if(!spec.keySet().equals(Set.of("trust_policy","permissions_boundary","managed_policies","inline_policies")))throw new IllegalArgumentException("role specification requires trust_policy, permissions_boundary, managed_policies and inline_policies only");
        spec.put("trust_policy",normalizeTrust(spec.get("trust_policy")));
        validateBoundary(text(spec.get("permissions_boundary"),"permissions boundary"));
        if(!(spec.get("managed_policies") instanceof List<?> policies)||policies.size()>10)throw new IllegalArgumentException("managed policies must be an array of at most ten policies");
        Set<String> managed=new TreeSet<>();
        for(Object policy:policies){String arn=text(policy,"managed policy");validateManaged(arn);if(!managed.add(arn))throw new IllegalArgumentException("duplicate managed policy");}
        spec.put("managed_policies",new ArrayList<>(managed));
        var inline=object(spec.get("inline_policies"),"inline policies");
        if(inline.size()>10)throw new IllegalArgumentException("at most ten inline policies are allowed");
        int length=0;
        for(var entry:inline.entrySet()) {
            requireName(entry.getKey());
            Object doc=entry.getValue() instanceof String s?Json.parse(s):entry.getValue();
            doc=object(doc,"inline policy");String serialized=encoded(doc);
            IamPolicies.requirePassRolePolicyContext("role inline",serialized);
            IamPolicies.lint(serialized).requireValid();length+=serialized.length();
            if(length>10240)throw new IllegalArgumentException("role inline policies exceed the aggregate 10240-character limit");
            entry.setValue(doc);
        }
        spec.put("inline_policies",inline);return spec;
    }
    private Map<String,Object> resolved(String raw,String accountId) {
        var spec=parseSpec(raw);String required="arn:aws:iam::"+accountId+":policy/lmaws_boundary";
        String boundary=(String)spec.get("permissions_boundary");
        if(!SYMBOLIC_BOUNDARY.equals(boundary)&&!required.equals(boundary))throw new IllegalArgumentException("permissions boundary account mismatch");
        spec.put("permissions_boundary",required);
        for(Object value:(List<?>)spec.get("managed_policies"))if(!BASIC.equals(value)&&!String.valueOf(value).startsWith("arn:aws:iam::"+accountId+":policy/"))throw new IllegalArgumentException("managed policy account mismatch");
        return spec;
    }
    static String decode(String value){return value==null?"":URLDecoder.decode(value.replace("+","%2B"),StandardCharsets.UTF_8);}
    private static String next(Boolean truncated,String marker,int page,int count) {
        if(page>=100||count>1000)throw new IllegalStateException("IAM role pagination limit exceeded");
        if(!Boolean.TRUE.equals(truncated))return null;
        if(marker==null||marker.isBlank())throw new IllegalStateException("IAM role pagination is truncated without a marker");
        return marker;
    }
    private Snapshot read(String name) {
        if(demo)return demoRoles.get(name);
        IamClient client=iam.get();Role role;
        try{role=client.getRole(r->r.roleName(name)).role();}catch(NoSuchEntityException e){return null;}
        if(role==null)throw new IllegalStateException("IAM GetRole returned no role");
        List<String> managed=new ArrayList<>();Map<String,Object> inline=new TreeMap<>();Map<String,String> tags=new TreeMap<>();String marker=null;int pages=0;
        do {String token=marker;var response=client.listAttachedRolePolicies(r->r.roleName(name).marker(token));
            for(var policy:response.attachedPolicies())managed.add(policy.policyArn());marker=next(response.isTruncated(),response.marker(),++pages,managed.size());
        }while(marker!=null);
        marker=null;pages=0;
        do {String token=marker;var response=client.listRolePolicies(r->r.roleName(name).marker(token));
            for(String policyName:response.policyNames()) {
                var doc=client.getRolePolicy(r->r.roleName(name).policyName(policyName));
                inline.put(policyName,Json.parse(decode(doc.policyDocument())));
            }
            marker=next(response.isTruncated(),response.marker(),++pages,inline.size());
        }while(marker!=null);
        marker=null;pages=0;
        do {String token=marker;var response=client.listRoleTags(r->r.roleName(name).marker(token));
            response.tags().forEach(t->tags.put(t.key(),t.value()));marker=next(response.isTruncated(),response.marker(),++pages,tags.size());
        }while(marker!=null);
        Collections.sort(managed);
        Map<String,Object> spec=new TreeMap<>();spec.put("trust_policy",Json.parse(decode(role.assumeRolePolicyDocument())));
        spec.put("permissions_boundary",role.permissionsBoundary()==null?"":role.permissionsBoundary().permissionsBoundaryArn());
        spec.put("managed_policies",managed);spec.put("inline_policies",inline);
        return new Snapshot(role.arn(),spec,tags);
    }
    private void requireOwned(String name,Snapshot existing,String accountId,boolean deleting) {
        if(!("arn:aws:iam::"+accountId+":role/"+name).equals(existing.arn))throw new IllegalStateException("role ARN/path/account does not match the grant");
        if(!"lambda_exec".equals(existing.tags.get("lmaws_test"))||!"lambda_execution".equals(existing.tags.get("lmaws_role")))throw new IllegalStateException("refusing to adopt or delete an unowned role");
        // Refuse foreign grants before detaching anything, even when the desired spec is safe.
        var old=new TreeMap<>(existing.spec);old.put("permissions_boundary","arn:aws:iam::"+accountId+":policy/lmaws_boundary");
        resolved(encoded(old),accountId);
        if(deleting&&!old.get("permissions_boundary").equals(existing.spec.get("permissions_boundary")))throw new IllegalStateException("refusing to delete a role outside lmaws_boundary");
    }
    private static Map<String,String> output(String name,Snapshot snapshot) {
        Map<String,String> out=new LinkedHashMap<>();out.put("kind","iam_role");out.put("name",name);out.put("exists",String.valueOf(snapshot!=null));
        if(snapshot!=null){out.put("arn",safe(snapshot.arn));out.put("document",safe(encoded(snapshot.spec)));out.put("tags",safe(encoded(snapshot.tags)));
            snapshot.spec.forEach((key,value)->out.put(key,safe(value instanceof String s?s:encoded(value))));}
        return out;
    }
    private static List<String> differences(Snapshot old,Map<String,Object> desired) {
        List<String> changes=new ArrayList<>();
        for(String field:List.of("permissions_boundary","trust_policy","managed_policies","inline_policies")) {
            Object before=old==null?null:old.spec.get(field),after=desired.get(field);
            if(!encoded(before).equals(encoded(after)))changes.add((old==null?"+ ":"~ ")+field+": "+safe(encoded(before))+" -> "+safe(encoded(after)));
        }
        return changes;
    }
    public Map<String,String> get(String name) {requireName(name);access.accept(false);return output(name,read(name));}
    @SuppressWarnings("unchecked") public Map<String,String> put(String name,String document,boolean apply) {
        requireName(name);access.accept(apply);parseSpec(document);
        String accountId=demo?"000000000000":account.get();var desired=resolved(document,accountId);Snapshot old=read(name);
        if(old!=null)requireOwned(name,old,accountId,false);
        if(!demo)iam.get().getPolicy(r->r.policyArn((String)desired.get("permissions_boundary")));
        List<String> changes=differences(old,desired);boolean changed=!changes.isEmpty();
        System.out.println("IAM role diff ("+name+"): "+changes.size()+" changed fields");for(String line:changes)System.out.println("  "+line);
        if(apply&&changed) {
            if(demo)demoRoles.put(name,new Snapshot("arn:aws:iam::000000000000:role/"+name,desired,Map.of("lmaws_test","lambda_exec","lmaws_role","lambda_execution")));
            else {
                IamClient client=iam.get();String boundary=(String)desired.get("permissions_boundary");
                if(old==null)client.createRole(r->r.roleName(name).path("/").assumeRolePolicyDocument(encoded(desired.get("trust_policy"))).permissionsBoundary(boundary)
                    .tags(Tag.builder().key("lmaws_test").value("lambda_exec").build(),Tag.builder().key("lmaws_role").value("lambda_execution").build()));
                else {
                    if(!boundary.equals(old.spec.get("permissions_boundary")))client.putRolePermissionsBoundary(r->r.roleName(name).permissionsBoundary(boundary));
                    if(!encoded(desired.get("trust_policy")).equals(encoded(old.spec.get("trust_policy"))))client.updateAssumeRolePolicy(r->r.roleName(name).policyDocument(encoded(desired.get("trust_policy"))));
                }
                List<String> managed=(List<String>)desired.get("managed_policies");Map<String,Object> inline=(Map<String,Object>)desired.get("inline_policies");
                if(old!=null) {
                    for(String arn:(List<String>)old.spec.get("managed_policies"))if(!managed.contains(arn))client.detachRolePolicy(r->r.roleName(name).policyArn(arn));
                    for(String policy:((Map<String,Object>)old.spec.get("inline_policies")).keySet())if(!inline.containsKey(policy))client.deleteRolePolicy(r->r.roleName(name).policyName(policy));
                }
                for(String arn:managed)if(old==null||!((List<?>)old.spec.get("managed_policies")).contains(arn))client.attachRolePolicy(r->r.roleName(name).policyArn(arn));
                for(var entry:inline.entrySet())if(old==null||!encoded(entry.getValue()).equals(encoded(((Map<?,?>)old.spec.get("inline_policies")).get(entry.getKey()))))client.putRolePolicy(r->r.roleName(name).policyName(entry.getKey()).policyDocument(encoded(entry.getValue())));
            }
        }
        Map<String,String> out=output(name,apply&&changed?new Snapshot("arn:aws:iam::"+accountId+":role/"+name,desired,Map.of("lmaws_test","lambda_exec","lmaws_role","lambda_execution")):old);
        out.put("applied",String.valueOf(apply&&changed));out.put("action",!apply?"dry_run":!changed?"unchanged":old==null?"created":"updated");
        out.put("changed",String.valueOf(changed));out.put("lint_valid","true");out.put("diff_lines",safe(encoded(changes)));out.put("document",safe(encoded(desired)));return out;
    }
    @SuppressWarnings("unchecked") public Map<String,String> delete(String name,boolean apply) {
        requireName(name);access.accept(apply);String accountId=demo?"000000000000":account.get();Snapshot old=read(name);
        if(old!=null)requireOwned(name,old,accountId,true);
        if(apply&&old!=null) {
            if(demo)demoRoles.remove(name);
            else {
                IamClient client=iam.get();var profiles=client.listInstanceProfilesForRole(r->r.roleName(name));
                if(Boolean.TRUE.equals(profiles.isTruncated())||!profiles.instanceProfiles().isEmpty())throw new IllegalStateException("role is attached to an instance profile");
                for(String arn:(List<String>)old.spec.get("managed_policies"))client.detachRolePolicy(r->r.roleName(name).policyArn(arn));
                for(String policy:((Map<String,Object>)old.spec.get("inline_policies")).keySet())client.deleteRolePolicy(r->r.roleName(name).policyName(policy));
                client.deleteRole(r->r.roleName(name));
            }
        }
        Map<String,String> out=output(name,old);out.put("applied",String.valueOf(apply&&old!=null));out.put("action",old==null?"absent":apply?"deleted":"dry_run");return out;
    }
}
