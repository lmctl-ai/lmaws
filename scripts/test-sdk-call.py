#!/usr/bin/env python3
"""Generic guarded SDK call (sdk_call / sdk_operations): ECR, logs, IAM, ECS, ELBv2, EC2, CloudFront, ACM, Route 53.
Loopback only: a fake AWS endpoint on 127.0.0.1 answers every protocol; nothing here can reach AWS."""
from __future__ import annotations
import http.server, json, os, pathlib, re, shutil, subprocess, sys, tempfile, threading, urllib.parse
import xml.etree.ElementTree as ET

ACC = "123456789012"
POC = "t1"
R = "us-east-1"
MUTATING = re.compile(r"^(Create|Register|Request|Put|Update|Delete|Deregister|Attach|Detach|Modify|Authorize|Change)")


def xml(body, status=200, headers=None):
    return status, "text/xml", body, headers or {}


def js(obj, status=200):
    return status, "application/x-amz-json-1.1", json.dumps(obj), {}


class Fake(http.server.BaseHTTPRequestHandler):
    calls: list = []        # (service, action, body) of every request
    tag = POC               # value of the poc tag every probe reports
    records: dict = {}      # route53 (name,type) -> xml string of the record

    def log_message(self, *a):
        pass

    def reply(self, triple):
        status, ctype, body, headers = triple
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self): self.dispatch(b"")
    def do_DELETE(self): self.dispatch(b"")
    def do_PUT(self): self.dispatch(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
    def do_POST(self): self.dispatch(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def dispatch(self, raw):
        if not raw and self.headers.get("Content-Length"):
            raw = self.rfile.read(int(self.headers.get("Content-Length")))
        path = urllib.parse.urlparse(self.path)
        target = self.headers.get("X-Amz-Target", "")
        if target:
            svc, action = target.split(".")
            body = json.loads(raw or b"{}")
            Fake.calls.append((svc, action, body))
            return self.reply(self.json_service(svc, action, body))
        if path.path.startswith("/2020-05-31"):
            Fake.calls.append(("cloudfront", self.command + " " + path.path, raw.decode()))
            return self.reply(self.cloudfront(path, raw))
        if path.path.startswith("/2013-04-01"):
            Fake.calls.append(("route53", self.command + " " + path.path, raw.decode()))
            return self.reply(self.route53(path, raw))
        form = urllib.parse.parse_qs(raw.decode())
        action = form.get("Action", [""])[0]
        version = form.get("Version", [""])[0]
        Fake.calls.append((version, action, form))
        return self.reply(self.query(version, action, form))

    # ---- JSON services
    def json_service(self, svc, action, body):
        arn = f"arn:aws:ecr:{R}:{ACC}:repository/"
        tags = [{"Key": "poc", "Value": Fake.tag}]
        if svc.startswith("AmazonEC2ContainerRegistry"):
            repo = {"repositoryArn": arn + "poc-t1/mediator", "repositoryName": "poc-t1/mediator", "repositoryUri": "x"}
            if action == "ListTagsForResource": return js({"tags": tags})
            if action in ("CreateRepository", "DeleteRepository"): return js({"repository": repo})
            if action == "DescribeRepositories": return js({"repositories": [repo]})
            return js({})
        if svc.startswith("Logs"):
            if action == "ListTagsForResource": return js({"tags": {"poc": Fake.tag}})
            return js({})
        if svc.startswith("AmazonEC2ContainerService"):
            ecs = f"arn:aws:ecs:{R}:{ACC}:"
            if action == "ListTagsForResource": return js({"tags": [{"key": "poc", "value": Fake.tag}]})
            if action == "CreateCluster": return js({"cluster": {"clusterArn": ecs + "cluster/poc-t1", "clusterName": "poc-t1"}})
            if action == "RegisterTaskDefinition":
                return js({"taskDefinition": {"taskDefinitionArn": ecs + "task-definition/poc-t1:3", "family": "poc-t1", "revision": 3}})
            if action in ("CreateService", "UpdateService", "DeleteService"):
                return js({"service": {"serviceArn": ecs + "service/poc-t1/poc-t1", "serviceName": "poc-t1", "desiredCount": body.get("desiredCount", 1)}})
            if action == "DescribeServices": return js({"services": [{"serviceName": "poc-t1", "desiredCount": 1, "runningCount": 1}]})
            return js({})
        if svc.startswith("CertificateManager"):
            if action == "RequestCertificate": return js({"CertificateArn": f"arn:aws:acm:{R}:{ACC}:certificate/c1"})
            if action == "ListTagsForCertificate": return js({"Tags": tags})
            return js({})
        raise AssertionError((svc, action))

    # ---- query services (IAM, ELBv2, EC2, STS)
    def query(self, version, action, form):
        if action == "GetCallerIdentity":
            return xml(f'<GetCallerIdentityResponse><GetCallerIdentityResult><Account>{ACC}</Account><Arn>arn:aws:iam::{ACC}:user/t</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>')
        if version == "2010-05-08":  # IAM
            if action == "CreateRole":
                n = form["RoleName"][0]
                return xml(f'<CreateRoleResponse><CreateRoleResult><Role><Path>/</Path><RoleName>{n}</RoleName><RoleId>R1</RoleId><Arn>arn:aws:iam::{ACC}:role/{n}</Arn><CreateDate>2026-01-01T00:00:00Z</CreateDate></Role></CreateRoleResult></CreateRoleResponse>')
            if action == "ListRoleTags":
                return xml(f'<ListRoleTagsResponse><ListRoleTagsResult><Tags><member><Key>poc</Key><Value>{Fake.tag}</Value></member></Tags><IsTruncated>false</IsTruncated></ListRoleTagsResult></ListRoleTagsResponse>')
            return xml(f'<{action}Response><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></{action}Response>')
        ns = 'xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"'
        if version == "2015-12-01":  # ELBv2
            lb = f"arn:aws:elasticloadbalancing:{R}:{ACC}:loadbalancer/app/poc-t1/1"
            tg = f"arn:aws:elasticloadbalancing:{R}:{ACC}:targetgroup/poc-t1-a/2"
            ls = f"arn:aws:elasticloadbalancing:{R}:{ACC}:listener/app/poc-t1/1/3"
            rl = f"arn:aws:elasticloadbalancing:{R}:{ACC}:listener-rule/app/poc-t1/1/3/4"
            if action == "CreateLoadBalancer":
                return xml(f'<CreateLoadBalancerResponse {ns}><CreateLoadBalancerResult><LoadBalancers><member><LoadBalancerArn>{lb}</LoadBalancerArn><LoadBalancerName>poc-t1</LoadBalancerName><DNSName>poc-t1.elb.example</DNSName></member></LoadBalancers></CreateLoadBalancerResult></CreateLoadBalancerResponse>')
            if action == "CreateTargetGroup":
                return xml(f'<CreateTargetGroupResponse {ns}><CreateTargetGroupResult><TargetGroups><member><TargetGroupArn>{tg}</TargetGroupArn><TargetGroupName>poc-t1-a</TargetGroupName></member></TargetGroups></CreateTargetGroupResult></CreateTargetGroupResponse>')
            if action == "CreateListener":
                return xml(f'<CreateListenerResponse {ns}><CreateListenerResult><Listeners><member><ListenerArn>{ls}</ListenerArn></member></Listeners></CreateListenerResult></CreateListenerResponse>')
            if action == "CreateRule":
                return xml(f'<CreateRuleResponse {ns}><CreateRuleResult><Rules><member><RuleArn>{rl}</RuleArn></member></Rules></CreateRuleResult></CreateRuleResponse>')
            if action == "DescribeTags":
                arn = form.get("ResourceArns.member.1", [""])[0]
                return xml(f'<DescribeTagsResponse {ns}><DescribeTagsResult><TagDescriptions><member><ResourceArn>{arn}</ResourceArn><Tags><member><Key>poc</Key><Value>{Fake.tag}</Value></member></Tags></member></TagDescriptions></DescribeTagsResult></DescribeTagsResponse>')
            if action == "DescribeLoadBalancers":
                return xml(f'<DescribeLoadBalancersResponse {ns}><DescribeLoadBalancersResult><LoadBalancers><member><LoadBalancerArn>{lb}</LoadBalancerArn><LoadBalancerName>poc-t1</LoadBalancerName></member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>')
            return xml(f'<{action}Response {ns}><{action}Result/></{action}Response>')
        if version == "2016-11-15":  # EC2
            e = 'xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"'
            if action == "CreateSecurityGroup":
                return xml(f'<CreateSecurityGroupResponse {e}><requestId>r</requestId><return>true</return><groupId>sg-0abc</groupId></CreateSecurityGroupResponse>')
            if action == "DescribeSecurityGroups":
                return xml(f'<DescribeSecurityGroupsResponse {e}><securityGroupInfo><item><groupId>sg-0abc</groupId><groupName>poc-t1-alb</groupName><tagSet><item><key>poc</key><value>{Fake.tag}</value></item></tagSet></item></securityGroupInfo></DescribeSecurityGroupsResponse>')
            return xml(f'<{action}Response {e}><return>true</return></{action}Response>')
        raise AssertionError((version, action))

    # ---- CloudFront (REST/XML)
    def cloudfront(self, path, raw):
        ns = 'xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"'
        dist = f'<Id>E1ABC</Id><ARN>arn:aws:cloudfront::{ACC}:distribution/E1ABC</ARN><Status>InProgress</Status><LastModifiedTime>2026-01-01T00:00:00Z</LastModifiedTime><InProgressInvalidationBatches>0</InProgressInvalidationBatches><DomainName>d111.cloudfront.net</DomainName>'
        if path.path == "/2020-05-31/tagging":
            return xml(f'<Tags {ns}><Items><Tag><Key>poc</Key><Value>{Fake.tag}</Value></Tag></Items></Tags>')
        if path.path == "/2020-05-31/distribution" and self.command == "POST":
            return xml(f'<Distribution {ns}>{dist}</Distribution>', 201, {"ETag": "E-1", "Location": "x"})
        if self.command == "PUT":
            return xml(f'<Distribution {ns}>{dist}</Distribution>', 200, {"ETag": "E-2"})
        if self.command == "DELETE":
            return 204, "text/xml", "", {}
        raise AssertionError((self.command, path.path))

    # ---- Route 53 (REST/XML)
    def route53(self, path, raw):
        ns = 'xmlns="https://route53.amazonaws.com/doc/2013-04-01/"'
        if self.command == "GET":
            q = urllib.parse.parse_qs(path.query)
            name, typ = q.get("name", [""])[0], q.get("type", [""])[0]
            rec = Fake.records.get((name, typ), "")
            return xml(f'<ListResourceRecordSetsResponse {ns}><ResourceRecordSets>{rec}</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>')
        root = ET.fromstring(raw)
        stripns = lambda s: re.sub(r' xmlns(:\w+)?="[^"]*"', "", s)
        for change in root.iter("{https://route53.amazonaws.com/doc/2013-04-01/}Change"):
            action = change.find("{*}Action").text
            rrs = change.find("{*}ResourceRecordSet")
            name, typ = rrs.find("{*}Name").text, rrs.find("{*}Type").text
            if action == "DELETE":
                Fake.records.pop((name, typ), None)
            else:
                text = stripns(ET.tostring(rrs, encoding="unicode"))
                text = re.sub(r"\bns\d+:", "", text)
                Fake.records[(name, typ)] = f"<ResourceRecordSet>{re.sub(r'^<ResourceRecordSet>|</ResourceRecordSet>$', '', text)}</ResourceRecordSet>"
        return xml(f'<ChangeResourceRecordSetsResponse {ns}><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status><SubmittedAt>2026-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>')


def run_dsl(host, work, source, env):
    src = work / "t.lms"
    src.write_text('s=load_schema(cli="java ai.lmctl.lmaws.Main");\np = _lmcode_ s;\n' + source + '\nend _lmcode_\nr=run_lmcode(p); println(json_stringify(r));\n', encoding="utf-8")
    lms = shutil.which("lmscript") or "lmscript"
    run_env = dict(env, PATH=str(host.parent) + os.pathsep + env.get("PATH", ""))
    result = subprocess.run([lms, str(src)], cwd=work, env=run_env, capture_output=True, text=True, timeout=240)
    assert result.returncode == 0, (result.stdout, result.stderr)
    envelope = json.loads(result.stdout.strip().splitlines()[-1])
    return envelope, result


class T:
    n = 0

    @staticmethod
    def ok(msg):
        T.n += 1
        print("  ok", msg)


def main(host):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    work = pathlib.Path(tempfile.mkdtemp(prefix="lmaws-sdk-call-"))
    empty = work / "empty"; empty.write_text("")
    state = work / "state.json"
    base = dict(os.environ, CLASSPATH=str(next((host.parent.parent).glob("lmaws-*.jar"))), CI="true", AWS_PROFILE="admin", AWS_DEFAULT_PROFILE="admin", LMAWS_ADMIN_GRANT="1", LMAWS_LIVE="1", LMAWS_APPLY="1",
                AWS_REGION=R, LMAWS_ENDPOINT=f"http://127.0.0.1:{server.server_port}", AWS_SHARED_CREDENTIALS_FILE=str(empty),
                AWS_CONFIG_FILE=str(empty), AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_EC2_METADATA_DISABLED="true",
                POC_TEST_SECRET="s3cr3t-value-123")

    def call(svc, op, inp, apply=True, env=None, poc=POC, st=None, out="o"):
        """Runs one sdk_call; returns (envelope, row-or-None, mutating requests it caused)."""
        Fake.calls.clear()
        src = f'let c=aws.region("us-east-1"); let x=c.sdk_call({json.dumps(svc)},{json.dumps(op)},{json.dumps(json.dumps(inp))},{json.dumps(poc)},{json.dumps(str(st or state))},{"true" if apply else "false"}); file_write("{out}.json",x.json());'
        p = work / f"{out}.json"
        p.unlink(missing_ok=True)
        env_, res = run_dsl(host, work, src, env or base)
        row = json.loads(p.read_text()) if p.exists() else None
        if row is None and "refus" not in os.environ.get("X", "x"): print("   (no row)", str(env_)[:300])
        muts = [c for c in Fake.calls if (c[1].split(" ")[0] in ("POST", "PUT", "DELETE")) or (MUTATING.match(c[1]) is not None)]
        return env_, row, muts, res

    def refused(what, *args, **kw):
        env_, row, muts, res = call(*args, **kw)
        assert not env_.get("ok") and row is None and not muts, (what, env_, muts)
        T.ok("refused: " + what)
        return json.dumps(env_)

    tags_list = [{"Key": "poc", "Value": POC}]
    try:
        # ---- discovery and reads
        Fake.calls.clear()
        env_, res = run_dsl(host, work, 'let c=aws.region("us-east-1"); let r=c.sdk_operations("ecs"); file_write("ops.json", r.json());', base)
        ops = json.loads((work / "ops.json").read_text())
        modes = {o["operation"]: o["mode"] for o in (ops if isinstance(ops, list) else ops.get("rows", ops))}
        assert modes["DescribeServices"] == "read" and modes["CreateService"] == "create" and modes["UpdateService"] == "update" and modes["RunTask"] == "denied", modes
        T.ok("sdk_operations classifies read/create/update/delete/denied by name and allowlist")
        read_env = dict(base, AWS_PROFILE="default", AWS_DEFAULT_PROFILE="default", LMAWS_ADMIN_GRANT="0")
        _, row, muts, _ = call("ecr", "DescribeRepositories", {"repositoryNames": ["poc-t1/mediator"]}, env=read_env)
        assert row["mode"] == "read" and row["applied"] == "false" and not muts and "poc-t1/mediator" in row["output"], row
        T.ok("read (DescribeRepositories) runs under the default profile and returns the SDK response as JSON")
        for prof in ("lmaws", "admin"):
            _, row, _, _ = call("ecs", "DescribeServices", {"cluster": "poc-t1", "services": ["poc-t1"]}, env=dict(read_env, AWS_PROFILE=prof, AWS_DEFAULT_PROFILE=prof))
            assert row["mode"] == "read"
        T.ok("reads also allowed for lmaws and admin")
        run_dsl(host, work, 'let c=aws.region("us-east-1"); file_write("raw.json", c.sdk_read("ecr","DescribeRepositories","{\\"repositoryNames\\":[\\"poc-t1/mediator\\"]}"));', read_env)
        raw = json.loads((work / "raw.json").read_text())
        assert raw["repositories"][0]["repositoryArn"] == f"arn:aws:ecr:{R}:{ACC}:repository/poc-t1/mediator", raw
        T.ok("sdk_read returns the raw JSON response with real ARNs for chaining (Row fields are account-masked)")
        refused("read of a secret-returning operation", "secretsmanager", "GetSecretValue", {"SecretId": "x"}, env=read_env)
        refused("read with an unknown profile", "ecs", "DescribeServices", {"cluster": "c"}, env=dict(read_env, AWS_PROFILE="lmaws-ec2", AWS_DEFAULT_PROFILE="lmaws-ec2"))

        # ---- guards: profile, grant, allowlist, tag, state ownership
        create_repo = {"repositoryName": "poc-t1/mediator", "imageScanningConfiguration": {"scanOnPush": True}, "tags": [{"key": "poc", "value": POC}]}
        refused("mutation with profile lmaws", "ecr", "CreateRepository", create_repo, env=dict(base, AWS_PROFILE="lmaws", AWS_DEFAULT_PROFILE="lmaws"))
        refused("mutation without LMAWS_ADMIN_GRANT=1", "ecr", "CreateRepository", create_repo, env=dict(base, LMAWS_ADMIN_GRANT="0"))
        refused("operation outside the allowlist (ecs RunTask)", "ecs", "RunTask", {"taskDefinition": "x"})
        refused("operation outside the allowlist (iam CreateUser)", "iam", "CreateUser", {"UserName": "x"})
        refused("create without the poc tag", "ecr", "CreateRepository", {"repositoryName": "poc-t1/mediator"})
        refused("create with a foreign poc tag", "ecr", "CreateRepository", dict(create_repo, tags=[{"key": "poc", "value": "other"}]))
        refused("update of a resource not in a state file", "logs", "PutRetentionPolicy", {"logGroupName": "/poc/t1", "retentionInDays": 14})
        assert not state.exists()

        # ---- dry run by default: nothing mutates, nothing is written
        _, row, muts, res = call("ecr", "CreateRepository", create_repo, apply=False)
        assert row["applied"] == "false" and row["action"] == "dry_run" and not muts and not state.exists(), (row, muts)
        assert "DRY-RUN" in res.stdout or "dry" in json.dumps(row)
        T.ok("dry run (apply=false) prints the call, sends no mutating request, writes no state")
        no_apply_env = dict(base); no_apply_env.pop("LMAWS_APPLY")
        refused("apply=true without --apply (LMAWS_APPLY)", "ecr", "CreateRepository", create_repo, env=no_apply_env)

        # ---- phase 1 applies
        env_, row, muts, _ = call("ecr", "CreateRepository", create_repo)
        assert row["applied"] == "true" and row["id"].endswith("repository/poc-t1/mediator"), row
        wire = [c for c in muts if c[1] == "CreateRepository"][0][2]
        assert wire["imageScanningConfiguration"]["scanOnPush"] is True and wire["tags"] == [{"key": "poc", "value": POC}] or wire["tags"] == tags_list, wire
        st = json.loads(state.read_text())
        assert st["poc"] == POC and st["tag"] == "poc=t1" and st["resources"][0]["service"] == "ecr" and oct(state.stat().st_mode & 0o777) == "0o600", st
        T.ok("ECR create: scanOnPush and poc tag on the wire, resource recorded in a 0600 state file")

        call("logs", "CreateLogGroup", {"logGroupName": "/poc/t1", "tags": {"poc": POC}})
        _, row, muts, _ = call("logs", "PutRetentionPolicy", {"logGroupName": "/poc/t1", "retentionInDays": 14})
        assert row["applied"] == "true" and [c for c in muts if c[1] == "PutRetentionPolicy"][0][2]["retentionInDays"] == 14
        T.ok("log group create (tag map) and retention update on an owned, tagged group")

        trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
        role = {"RoleName": "poc-t1-exec", "AssumeRolePolicyDocument": trust, "Tags": tags_list}
        refused("IAM role with a lambda trust principal", "iam", "CreateRole", dict(role, AssumeRolePolicyDocument=trust.replace("ecs-tasks", "lambda")))
        refused("IAM role name outside the poc prefix", "iam", "CreateRole", dict(role, RoleName="admin-role"))
        call("iam", "CreateRole", role)
        pol = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
        _, row, muts, _ = call("iam", "AttachRolePolicy", {"RoleName": "poc-t1-exec", "PolicyArn": pol})
        assert row["applied"] == "true"
        refused("attaching AdministratorAccess", "iam", "AttachRolePolicy", {"RoleName": "poc-t1-exec", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        T.ok("IAM service role for ecs-tasks: create + attach only for the trust, name and policy rules")

        call("ecs", "CreateCluster", {"clusterName": "poc-t1", "tags": [{"key": "poc", "value": POC}]})
        td = {"family": "poc-t1", "cpu": "256", "memory": "512", "networkMode": "awsvpc", "requiresCompatibilities": ["FARGATE"],
              "runtimePlatform": {"cpuArchitecture": "ARM64", "operatingSystemFamily": "LINUX"},
              "containerDefinitions": [{"name": "mediator", "image": "x/y:latest", "essential": True, "memory": 96,
                                        "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
                                        "environment": [{"name": "PORT", "value": "8080"}, {"name": "VALKEY_PASSWORD", "value": "{{env:POC_TEST_SECRET}}"}]}],
              "tags": [{"key": "poc", "value": POC}]}
        _, row, muts, res = call("ecs", "RegisterTaskDefinition", td)
        wire = [c for c in muts if c[1] == "RegisterTaskDefinition"][0][2]
        assert wire["containerDefinitions"][0]["portMappings"][0]["containerPort"] == 8080 and wire["runtimePlatform"]["cpuArchitecture"] == "ARM64"
        assert wire["containerDefinitions"][0]["environment"][1]["value"] == "s3cr3t-value-123", "env placeholder not resolved on the wire"
        assert "s3cr3t-value-123" not in res.stdout + res.stderr + json.dumps(row) + state.read_text(), "secret leaked"
        assert "{{env:POC_TEST_SECRET}}" in row["input"] or "***" in row["input"]
        T.ok("task definition from JSON: nested lists/enums marshalled, {{env:}} secret resolved on the wire and never printed or stored")

        sg = {"GroupName": "poc-t1-alb", "Description": "poc=t1 alb", "VpcId": "vpc-1", "TagSpecifications": [{"ResourceType": "security-group", "Tags": tags_list}]}
        refused("security group without the tag", "ec2", "CreateSecurityGroup", {"GroupName": "poc-t1-alb", "Description": "d", "VpcId": "vpc-1"})
        _, row, _, _ = call("ec2", "CreateSecurityGroup", sg)
        assert row["id"] == "sg-0abc"
        call("ec2", "AuthorizeSecurityGroupIngress", {"GroupId": "sg-0abc", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "PrefixListIds": [{"PrefixListId": "pl-1", "Description": "cf"}]}]})
        T.ok("security group create (TagSpecifications) and ingress with a prefix list")

        _, row, muts, _ = call("elbv2", "CreateLoadBalancer", {"Name": "poc-t1", "Subnets": ["subnet-1", "subnet-2"], "SecurityGroups": ["sg-0abc"], "Scheme": "internet-facing", "Type": "application", "Tags": tags_list})
        wire = [c for c in muts if c[1] == "CreateLoadBalancer"][0][2]
        assert wire["Subnets.member.1"] == ["subnet-1"] and wire["Tags.member.1.Key"] == ["poc"] and wire["Scheme"] == ["internet-facing"], wire
        arns = lambda op: [r for r in json.loads(state.read_text())["resources"] if r["op"] == op][0]["arn"]
        lb = arns("CreateLoadBalancer")
        _, row, _, _ = call("elbv2", "CreateTargetGroup", {"Name": "poc-t1-a", "Protocol": "HTTP", "Port": 8080, "VpcId": "vpc-1", "TargetType": "ip", "HealthCheckPath": "/healthz", "Matcher": {"HttpCode": "200"}, "Tags": tags_list})
        tg = arns("CreateTargetGroup")
        _, row, muts, _ = call("elbv2", "CreateListener", {"LoadBalancerArn": lb, "Protocol": "HTTPS", "Port": 443, "Certificates": [{"CertificateArn": f"arn:aws:acm:{R}:{ACC}:certificate/c1"}], "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                                      "DefaultActions": [{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "403", "ContentType": "text/plain", "MessageBody": "forbidden"}}], "Tags": tags_list})
        wire = [c for c in muts if c[1] == "CreateListener"][0][2]
        assert wire["Certificates.member.1.CertificateArn"][0].endswith("certificate/c1") and wire["DefaultActions.member.1.FixedResponseConfig.StatusCode"] == ["403"], wire
        listener = arns("CreateListener")
        _, row, muts, res = call("elbv2", "CreateRule", {"ListenerArn": listener, "Priority": 1, "Tags": tags_list, "Actions": [{"Type": "forward", "TargetGroupArn": tg}],
                                                         "Conditions": [{"Field": "host-header", "HostHeaderConfig": {"Values": ["go.lmctl.ai"]}},
                                                                        {"Field": "http-header", "HttpHeaderConfig": {"HttpHeaderName": "X-Origin-Env", "Values": ["{{env:POC_TEST_SECRET}}"]}}]})
        wire = [c for c in muts if c[1] == "CreateRule"][0][2]
        assert wire["Conditions.member.1.HostHeaderConfig.Values.member.1"] == ["go.lmctl.ai"] and wire["Conditions.member.2.HttpHeaderConfig.HttpHeaderName"] == ["X-Origin-Env"]
        assert wire["Conditions.member.2.HttpHeaderConfig.Values.member.1"] == ["s3cr3t-value-123"] and "s3cr3t-value-123" not in res.stdout + json.dumps(row)
        T.ok("ELBv2 load balancer, target group, HTTPS listener with certificate, host-header + http-header rule (header secret hidden)")
        _, row, _, _ = call("elbv2", "DescribeLoadBalancers", {"Names": ["poc-t1"]}, env=read_env)
        assert "poc-t1.elb.example" in json.dumps(row) or "LoadBalancerArn" in row["output"]
        _, row, muts, _ = call("elbv2", "ModifyTargetGroupAttributes", {"TargetGroupArn": tg, "Attributes": [{"Key": "deregistration_delay.timeout_seconds", "Value": "30"}]})
        assert row["applied"] == "true"

        _, row, _, _ = call("ecs", "CreateService", {"cluster": "poc-t1", "serviceName": "poc-t1", "taskDefinition": "poc-t1:3", "desiredCount": 1, "launchType": "FARGATE",
                                                    "networkConfiguration": {"awsvpcConfiguration": {"subnets": ["subnet-1"], "securityGroups": ["sg-0abc"], "assignPublicIp": "ENABLED"}},
                                                    "loadBalancers": [{"targetGroupArn": tg, "containerName": "mediator", "containerPort": 8080}], "tags": [{"key": "poc", "value": POC}]})
        _, row, muts, _ = call("ecs", "UpdateService", {"cluster": "poc-t1", "service": "poc-t1", "desiredCount": 2})
        wire = [c for c in muts if c[1] == "UpdateService"][0][2]
        assert wire["desiredCount"] == 2 and row["applied"] == "true"
        T.ok("ECS cluster, service create with load balancer, and scale to desired count on an owned service")

        # ---- state/tag ownership on update and delete
        _, row, muts, _ = call("ecs", "UpdateService", {"cluster": "poc-t1", "service": "poc-t1", "desiredCount": 3}, apply=False)
        assert row["action"] == "dry_run" and not muts
        Fake.tag = "somebody-else"
        refused("update of a resource whose live poc tag changed", "ecs", "UpdateService", {"cluster": "poc-t1", "service": "poc-t1", "desiredCount": 0})
        refused("delete of a resource whose live poc tag changed", "ecr", "DeleteRepository", {"repositoryName": "poc-t1/mediator", "force": True})
        Fake.tag = POC
        refused("delete of a resource missing from the state file", "ecr", "DeleteRepository", {"repositoryName": "poc-other/not-ours"})
        refused("state file of another poc", "ecr", "DeleteRepository", {"repositoryName": "poc-t1/mediator"}, poc="t2")
        T.ok("ownership: update/delete need the id in the state file AND the live poc tag; foreign tag, unlisted id and other-poc state are refused")

        before = len(json.loads(state.read_text())["resources"])
        for svc, op, inp in [("ecs", "DeleteService", {"cluster": "poc-t1", "service": "poc-t1", "force": True}), ("elbv2", "DeleteRule", {"RuleArn": None}),
                             ("elbv2", "DeleteListener", {"ListenerArn": listener}), ("elbv2", "DeleteTargetGroup", {"TargetGroupArn": tg}),
                             ("elbv2", "DeleteLoadBalancer", {"LoadBalancerArn": lb}), ("ec2", "DeleteSecurityGroup", {"GroupId": "sg-0abc"}),
                             ("ecs", "DeleteCluster", {"cluster": "poc-t1"}), ("logs", "DeleteLogGroup", {"logGroupName": "/poc/t1"}),
                             ("iam", "DeleteRole", {"RoleName": "poc-t1-exec"}), ("ecr", "DeleteRepository", {"repositoryName": "poc-t1/mediator", "force": True})]:
            if inp.get("RuleArn", 1) is None:
                inp["RuleArn"] = [r for r in json.loads(state.read_text())["resources"] if r["op"] == "CreateRule"][0]["arn"]
            _, row, muts, _ = call(svc, op, inp)
            assert row["applied"] == "true" and any(c[1] == op for c in muts), (op, row)
        left = [r["op"] for r in json.loads(state.read_text())["resources"]]
        assert left == ["RegisterTaskDefinition"], left
        T.ok("tag-guarded deletes of the owned stack in reverse order; state file shrinks to the task definition only")
        _, row, muts, _ = call("ecs", "DeregisterTaskDefinition", {"taskDefinition": "arn:aws:ecs:%s:%s:task-definition/poc-t1:3" % (R, ACC)})
        assert row["applied"] == "true" and json.loads(state.read_text())["resources"] == []
        T.ok("task definition revision deregistered by ARN from the state file")

        # ---- phase 2: CloudFront, ACM, Route 53
        dist = {"DistributionConfigWithTags": {"DistributionConfig": {
            "CallerReference": "t-1", "Comment": "poc=t1", "Enabled": True, "Aliases": {"Quantity": 1, "Items": ["go.lmctl.ai"]},
            "Origins": {"Quantity": 1, "Items": [{"Id": "alb", "DomainName": "origin-go.lmctl.ai",
                "CustomHeaders": {"Quantity": 1, "Items": [{"HeaderName": "X-Origin-Env", "HeaderValue": "{{env:POC_TEST_SECRET}}"}]},
                "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only", "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}}}]},
            "DefaultCacheBehavior": {"TargetOriginId": "alb", "ViewerProtocolPolicy": "redirect-to-https", "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"},
            "ViewerCertificate": {"ACMCertificateArn": f"arn:aws:acm:{R}:{ACC}:certificate/c1", "SSLSupportMethod": "sni-only", "MinimumProtocolVersion": "TLSv1.2_2021"}},
            "Tags": {"Items": [{"Key": "poc", "Value": POC}]}}}
        refused("CreateDistribution without tags is not allowlisted", "cloudfront", "CreateDistribution", {"DistributionConfig": dist["DistributionConfigWithTags"]["DistributionConfig"]})
        untagged = json.loads(json.dumps(dist)); untagged["DistributionConfigWithTags"]["Tags"] = {"Items": []}
        refused("CreateDistributionWithTags without the poc tag", "cloudfront", "CreateDistributionWithTags", untagged)
        _, row, muts, res = call("cloudfront", "CreateDistributionWithTags", dist)
        body = [c for c in muts if c[0] == "cloudfront" and c[1].startswith("POST")][0][2]
        assert "<CNAME>go.lmctl.ai</CNAME>" in body and "<HeaderValue>s3cr3t-value-123</HeaderValue>" in body and "<Key>poc</Key>" in body, body[:400]
        assert "s3cr3t-value-123" not in res.stdout + json.dumps(row)
        did = "E1ABC"
        assert row["id"].endswith("distribution/E1ABC")
        T.ok("CloudFront distribution create from a CLI-shaped config: aliases, ACM cert, origin header secret, poc tag in the XML body")
        _, row, muts, _ = call("cloudfront", "UpdateDistribution", {"Id": did, "IfMatch": "E-1", "DistributionConfig": dist["DistributionConfigWithTags"]["DistributionConfig"]})
        assert row["applied"] == "true" and any(c[0] == "cloudfront" and c[1].startswith("PUT") for c in muts)
        call("acm", "RequestCertificate", {"DomainName": "go.lmctl.ai", "SubjectAlternativeNames": ["origin-go.lmctl.ai"], "ValidationMethod": "DNS", "Tags": tags_list})
        refused("ACM request without the tag", "acm", "RequestCertificate", {"DomainName": "x.lmctl.ai", "ValidationMethod": "DNS"})
        T.ok("CloudFront update on an owned distribution; ACM request (DNS validation, tagged)")

        zone = "Z0TEST"
        def change(action, name, typ, value=None, alias=None):
            rr = {"Name": name, "Type": typ}
            if alias: rr["AliasTarget"] = {"HostedZoneId": "Z2FDTNDATAQYW2", "DNSName": alias, "EvaluateTargetHealth": False}
            else: rr["TTL"] = 300; rr["ResourceRecords"] = [{"Value": value}]
            return {"HostedZoneId": zone, "ChangeBatch": {"Changes": [{"Action": action, "ResourceRecordSet": rr}]}}
        Fake.records[("existing.lmctl.ai.", "A")] = "<ResourceRecordSet><Name>existing.lmctl.ai.</Name><Type>A</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>1.2.3.4</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>"
        refused("Route 53 change of a record this run did not write", "route53", "ChangeResourceRecordSets", change("UPSERT", "existing.lmctl.ai.", "A", "9.9.9.9"))
        _, row, muts, _ = call("route53", "ChangeResourceRecordSets", change("UPSERT", "_abc.go.lmctl.ai.", "CNAME", "_val.acm-validations.aws."))
        assert row["applied"] == "true"
        _, row, muts, _ = call("route53", "ChangeResourceRecordSets", change("UPSERT", "go.lmctl.ai.", "A", alias="d111.cloudfront.net."))
        assert row["applied"] == "true"
        recs = json.loads(state.read_text())["records"]
        assert len(recs) == 2 and all(re.fullmatch(r"[0-9a-f]{64}", v) for v in recs.values()), recs
        _, row, muts, _ = call("route53", "ChangeResourceRecordSets", change("UPSERT", "go.lmctl.ai.", "A", alias="d222.cloudfront.net."))
        assert row["applied"] == "true", row
        T.ok("Route 53: CNAME validation record and alias A record created, content hash recorded, own record updated, foreign record refused")
        Fake.records[("go.lmctl.ai.", "A")] = Fake.records[("go.lmctl.ai.", "A")].replace("d222", "evil")
        refused("Route 53 delete of a record changed by someone else", "route53", "ChangeResourceRecordSets", change("DELETE", "go.lmctl.ai.", "A", alias="evil.cloudfront.net."))
        refused("Route 53 delete of a record not in the state file", "route53", "ChangeResourceRecordSets", change("DELETE", "existing.lmctl.ai.", "A", "1.2.3.4"))
        _, row, muts, _ = call("route53", "ChangeResourceRecordSets", change("DELETE", "_abc.go.lmctl.ai.", "CNAME", "_val.acm-validations.aws."))
        assert row["applied"] == "true" and len(json.loads(state.read_text())["records"]) == 1
        T.ok("Route 53 deletes only exact, unchanged records listed in the state file")
        for svc, op, inp in [("cloudfront", "DeleteDistribution", {"Id": did, "IfMatch": "E-2"}), ("acm", "DeleteCertificate", {"CertificateArn": f"arn:aws:acm:{R}:{ACC}:certificate/c1"})]:
            _, row, muts, _ = call(svc, op, inp)
            assert row["applied"] == "true"
        T.ok("CloudFront distribution and ACM certificate deleted only from the state file and live tag")
        print(f"PASS sdk_call: {T.n} checks (loopback only)")
    finally:
        server.shutdown(); server.server_close()


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]).resolve())
