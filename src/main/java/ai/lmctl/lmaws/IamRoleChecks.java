package ai.lmctl.lmaws;

import java.util.*;

/** Offline role invariants; SDK suppliers deliberately fail if a demo reaches them. */
public final class IamRoleChecks {
    private IamRoleChecks() {}
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void reject(Runnable action){checks++;try{action.run();throw new AssertionError("unsafe role accepted");}catch(IllegalArgumentException|IllegalStateException expected){}}
    static Map<String,Object> spec() {
        return new LinkedHashMap<>(Map.of(
            "trust_policy",Map.of("Version","2012-10-17","Statement",List.of(Map.of("Effect","Allow","Action","sts:AssumeRole","Principal",Map.of("Service","lambda.amazonaws.com")))),
            "permissions_boundary","arn:aws:iam::${aws:PrincipalAccount}:policy/lmaws_boundary",
            "managed_policies",List.of(IamRoles.BASIC),"inline_policies",Map.of()));
    }
    private static String json(Map<String,Object> value){return Jsons.encodeRaw(value);}
    public static void run() {
        checks=0;
        IamRoles.requireName("lmaws_lambda_exec");
        for(String name:List.of("admin","lmaws-foo","lmaws_","LMAWS_test","lmaws_a/path","lmaws_"+"a".repeat(65)))reject(()->IamRoles.requireName(name));
        IamRoles.parseSpec(json(spec()));
        for(String boundary:List.of("","arn:aws:iam::*:policy/lmaws_boundary","arn:aws:iam::000000000000:policy/other","arn:aws:iam::000000000000:policy/path/lmaws_boundary")) {
            var value=spec();value.put("permissions_boundary",boundary);reject(()->IamRoles.parseSpec(json(value)));
        }
        for(String service:List.of("ec2.amazonaws.com","*","lambda.amazonaws.com.evil")) {
            var value=spec();value.put("trust_policy",Map.of("Version","2012-10-17","Statement",List.of(Map.of("Effect","Allow","Action","sts:AssumeRole","Principal",Map.of("Service",service)))));reject(()->IamRoles.parseSpec(json(value)));
        }
        var extra=spec();extra.put("unexpected",true);reject(()->IamRoles.parseSpec(json(extra)));
        var mixed=spec();mixed.put("trust_policy",Map.of("Version","2012-10-17","Statement",List.of(Map.of("Effect","Allow","Action",List.of("sts:AssumeRole","sts:TagSession"),"Principal",Map.of("Service","lambda.amazonaws.com")))));reject(()->IamRoles.parseSpec(json(mixed)));
        var rootPrincipal=spec();rootPrincipal.put("trust_policy",Map.of("Version","2012-10-17","Statement",List.of(Map.of("Effect","Allow","Action","sts:AssumeRole","Principal",Map.of("Service","lambda.amazonaws.com","AWS","*")))));reject(()->IamRoles.parseSpec(json(rootPrincipal)));
        for(String arn:List.of("arn:aws:iam::aws:policy/AdministratorAccess","arn:aws:iam::000000000000:policy/lmaws_other","arn:aws:iam::*:policy/lmaws_lambda_test")) {
            var value=spec();value.put("managed_policies",List.of(arn));reject(()->IamRoles.parseSpec(json(value)));
        }
        var duplicate=spec();duplicate.put("managed_policies",List.of(IamRoles.BASIC,IamRoles.BASIC));reject(()->IamRoles.parseSpec(json(duplicate)));
        var pass=spec();pass.put("inline_policies",Map.of("lmaws_session",Map.of("Version","2012-10-17","Statement",List.of(Map.of("Effect","Allow","Action","iam:PassRole","Resource","arn:aws:iam::*:role/lmaws_*","Condition",Map.of("StringEquals",Map.of("iam:PassedToService","lambda.amazonaws.com")))))));reject(()->IamRoles.parseSpec(json(pass)));
        var unscoped=spec();unscoped.put("inline_policies",Map.of("lmaws_data",Map.of("Version","2012-10-17","Statement",List.of(Map.of("Effect","Allow","Action","s3:PutObject","Resource","*")))));reject(()->IamRoles.parseSpec(json(unscoped)));
        int[] accesses={0};var manager=new IamRoles(true,()->{throw new AssertionError("demo constructed IAM client");},()->{throw new AssertionError("demo read account");},apply->accesses[0]++);
        var preview=manager.put("lmaws_lambda_exec",json(spec()),false);
        check("false".equals(preview.get("applied"))&&"dry_run".equals(preview.get("action")),"preview must not mutate");
        check(!"[]".equals(preview.get("diff_lines")),"creation preview must show diff");
        check("false".equals(manager.get("lmaws_lambda_exec").get("exists")),"preview did not create role");
        var created=manager.put("lmaws_lambda_exec",json(spec()),true);check("created".equals(created.get("action")),"demo created role");
        check("true".equals(manager.get("lmaws_lambda_exec").get("exists")),"created role exists");
        var identical=manager.put("lmaws_lambda_exec",json(spec()),true);check("unchanged".equals(identical.get("action"))&&"false".equals(identical.get("applied")),"identical role does not mutate");
        var deletePreview=manager.delete("lmaws_lambda_exec",false);check(!"[]".equals(deletePreview.get("diff_lines")),"delete preview exposes its removals");check("true".equals(manager.get("lmaws_lambda_exec").get("exists")),"delete preview keeps role");
        var removed=manager.delete("lmaws_lambda_exec",true);check("false".equals(removed.get("exists")),"delete result reports absence");check("false".equals(manager.get("lmaws_lambda_exec").get("exists")),"explicit delete removed role");
        var foreign=spec();foreign.put("permissions_boundary","arn:aws:iam::999999999999:policy/lmaws_boundary");reject(()->manager.put("lmaws_lambda_exec",json(foreign),true));
        var foreignPolicy=spec();foreignPolicy.put("managed_policies",List.of("arn:aws:iam::999999999999:policy/lmaws_lambda_data"));reject(()->manager.put("lmaws_lambda_exec",json(foreignPolicy),true));
        check(accesses[0]>0,"guard callback invoked");
        var denied=new IamRoles(false,()->{throw new AssertionError("guard reached IAM");},()->{throw new AssertionError("guard reached STS");},apply->{throw new IllegalStateException("not admin");});
        reject(()->denied.get("lmaws_lambda_exec"));reject(()->denied.put("lmaws_lambda_exec",json(spec()),true));reject(()->denied.delete("lmaws_lambda_exec",true));
        System.out.println("PASS "+checks+" Lambda role trust/boundary/ownership/diff/guard controls; no credentials or AWS access");
    }
}
