package ai.lmctl.lmaws;

/** Guard and fake-transport contract checks for Lambda/EventBridge scenarios. */
public final class LambdaChecks {
    private LambdaChecks() {}
    public static void run() {
        var fn = new LambdaFunction("lmaws_demo_fn", "lmaws_lambda_exec", "python3.12", "app.handler", "def handler(e,c): return e", 256, 30, "demo01");
        if (!fn.arn().contains(":function:lmaws_demo_fn")) throw new AssertionError("Lambda ARN");
        if (!"200".equals(fn.invoke("{}").get("status"))) throw new AssertionError("fake invocation");
        if (!fn.url("scenario test").startsWith("https://")) throw new AssertionError("Function URL");
        expect(() -> new LambdaFunction("unsafe", "lmaws_lambda_exec", "python3.12", "app.handler", "x", 128, 1, "demo01"));
        expect(() -> new LambdaFunction("lmaws_bad", "other-role", "python3.12", "app.handler", "x", 128, 1, "demo01"));
        expect(() -> new LambdaFunction("lmaws_bad", "lmaws_lambda_exec", "python3.12", "app.handler", "x", 127, 1, "demo01"));
        expect(() -> fn.url(""));
        expect(() -> new LambdaFunction("lmaws_bad","lmaws_lambda_exec","python3.12","app.handler","x",513,1,"demo01"));
        expect(() -> new LambdaFunction("lmaws_bad","lmaws_lambda_exec","python3.12","app.handler","x",128,31,"demo01"));
        fn.waitActive(1);expect(()->fn.waitActive(0));expect(()->fn.waitActive(121));
        var rule = new EventRule("lmaws_demo_rule", "rate(1 minute)", "demo01");
        if (!rule.target(fn.arn()).get("target").contains("lmaws_demo_fn")) throw new AssertionError("EventBridge target");
        expect(() -> rule.target("arn:aws:lambda:elsewhere:000000000000:function:lmaws_bad"));
        expect(() -> new EventRule("unsafe", "rate(1 minute)", "demo01"));
    }
    private static void expect(Runnable r){try{r.run();throw new AssertionError("unsafe input accepted");}catch(IllegalArgumentException expected){}}
}
