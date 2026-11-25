#!/usr/bin/env python3
"""recipes/fargate_stack.lms: synthetic plan of the whole registry-driven stack, refusals and teardown guard. No AWS."""
import copy, json, os, pathlib, re, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
host = pathlib.Path(sys.argv[1]).resolve()
work = pathlib.Path(tempfile.mkdtemp(prefix="lmaws-fargate-recipe-"))
jar = next(host.parent.parent.glob("lmaws-*.jar"))
env = dict(os.environ, CLASSPATH=str(jar), PATH=str(host.parent) + os.pathsep + os.environ["PATH"], POC_ORIGIN_SECRET="")
env.pop("POC_ORIGIN_SECRET")
for k in ("LMAWS_LIVE", "LMAWS_APPLY", "LMAWS_ADMIN_GRANT", "LMAWS_ENDPOINT", "AWS_PROFILE"):
    env.pop(k, None)
recipe = ROOT / "recipes" / "fargate_stack.lms"
apps = json.loads((ROOT / "recipes/fargate_apps.example.json").read_text())
two = copy.deepcopy(apps)
second = copy.deepcopy(apps["apps"][0])
second.update(name="admin-ui", hosts=["ui.lmctl.ai"], ecr="poc-go-fargate/admin-ui", port=8081)
second["container"]["portMappings"] = [{"containerPort": 8081, "hostPort": 8081, "protocol": "tcp"}]
two["apps"].append(second)
(work / "apps2.json").write_text(json.dumps(two))
stack = ROOT / "recipes/fargate_stack.config.json"


def run(*args, extra=None, ok=True):
    r = subprocess.run(["lmscript", str(recipe), *args], cwd=work, env=dict(env, **(extra or {})), capture_output=True, text=True, timeout=900)
    assert (r.returncode == 0) == ok, (args, r.returncode, r.stdout[-1500:], r.stderr[-800:])
    return r


checks = 0
# 1. one-app plan from the example registry: the exact poc-up order
r = run("--apps", str(ROOT / "recipes/fargate_apps.example.json"), "--stack", str(stack), "--output", "data/one", "--state", ".lmaws-local/one.state.json")
labels = re.findall(r"^== plan (\S+)", r.stdout, re.M)
order = ["ecr:", "logs:", "logs-retention:", "role:", "role-policy:", "sg:", "sg-ingress:", "acm:", "alb:", "alb-attributes:", "tg:", "tg-attributes:", "listener:", "rule:", "dns-origin:", "cluster:", "task-definition:", "service:", "cloudfront:", "dns-host:"]
pos = [next(i for i, l in enumerate(labels) if l.startswith(p)) for p in order]
assert pos == sorted(pos), (order, labels)
assert len(re.findall(r"sdk call \S+ DRY-RUN poc=go-fargate", r.stdout)) == len(labels) == 25, (len(labels), labels)
assert "APPLY" not in r.stdout.split("PLAN")[0] and not (work / ".lmaws-local/one.state.json").exists(), "plan wrote state"
rep = json.loads((work / "data/one.json").read_text())
assert rep["applied"] is False and all(x["action"].startswith("would") for x in rep["rows"]), rep["rows"][:3]
print("  ok one-app plan: poc-up resource order, 25 dry-run calls, nothing applied, no state file"); checks += 1
# 2. secrets never printed, placeholders kept
assert "{{env:POC_ORIGIN_SECRET}}" in r.stdout and "HeaderValue" not in r.stdout.replace('"HeaderValue":"***"', ""), "origin secret handling"
print("  ok origin secret stays a {{env:...}} placeholder in the plan"); checks += 1
# 3. every call is tagged poc=go-fargate
for line in r.stdout.splitlines():
    if "sdk call" in line and "Create" in line and "CreateSecurityGroup" not in line:
        assert re.search(r'go-fargate', line), line
creates = [l for l in r.stdout.splitlines() if re.search(r"sdk call \w+:(Create|Register|Request)", l)]
assert creates and all('"poc"' in l and '"go-fargate"' in l or "poc=go-fargate" in l and "TagSpecifications" in l for l in creates), creates[:2]
print("  ok all %d create calls carry the poc=go-fargate tag" % len(creates)); checks += 1
# 4. two apps: second target group, Host rule with priority 2, second certificate, listener certificate, distribution, DNS
r = run("--apps", "apps2.json", "--stack", str(stack), "--output", "data/two", "--state", ".lmaws-local/two.state.json")
labels = re.findall(r"^== plan (\S+)", r.stdout, re.M)
for want in ["tg:poc-go-fargate-admin-ui", "rule:ui.lmctl.ai", "acm:ui.lmctl.ai", "listener-cert:ui.lmctl.ai", "cloudfront:ui.lmctl.ai", "dns-host:ui.lmctl.ai:A", "dns-host:ui.lmctl.ai:AAAA", "dns-origin:ui.lmctl.ai", "ecr:poc-go-fargate/admin-ui"]:
    assert want in labels, (want, labels)
rules = [l for l in r.stdout.splitlines() if "elbv2:CreateRule" in l]
assert len(rules) == 2 and '"Priority":1' in rules[0] and '"Priority":2' in rules[1] and "ui.lmctl.ai" in rules[1] and "X-Origin-Env" in rules[1], rules
svc = [l for l in r.stdout.splitlines() if "ecs:CreateService" in l][0]
assert svc.count("targetGroupArn") == 2 and "admin-ui" in svc and "8081" in svc, svc
td = [l for l in r.stdout.splitlines() if "ecs:RegisterTaskDefinition" in l][0]
assert "admin-ui" in td and "valkey" in td and "mediator" in td, "one task definition holds every app and sidecar"
print("  ok two apps: one service lists both target groups, per-host rule/priority/cert/CloudFront/DNS, one task definition"); checks += 1
# 5. guards of the recipe itself
run("--apps", "apps2.json", "--stack", str(stack), "--live", "--apply", "--profile", "default", "--output", "data/x", ok=False)
run("--apps", "apps2.json", "--stack", str(stack), "--live", "--profile", "admin", "--output", "data/x", ok=False)
print("  ok --live refuses the default profile and an admin profile without LMAWS_ADMIN_GRANT=1"); checks += 1
run("--stack", str(stack), ok=False)
r = run("--apps", "apps2.json", "--stack", str(stack), "--preview")
assert '"preview": true' in r.stdout
print("  ok missing --apps refused; --preview prints the plan header only"); checks += 1
# 6. teardown without a state file lists nothing and deletes nothing
r = run("--apps", "apps2.json", "--stack", str(stack), "--down", "--output", "data/down", "--state", ".lmaws-local/none.state.json", ok=False)
assert "nothing" in (r.stdout + r.stderr)
print("  ok --down needs a state file with recorded resources"); checks += 1
print(f"PASS fargate recipe: {checks} checks (synthetic, no AWS)")
