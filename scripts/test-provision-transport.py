#!/usr/bin/env python3
"""Offline loopback transport checks for the guarded EC2 provisioning API.

This test never contacts AWS.  It exercises the Java SDK's real Query
serialization against a deterministic EC2/SSM fixture and drives the public
LMScript bindings through the same launcher used by the other transport tests.
"""
import http.server
import os
import pathlib
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import threading
import urllib.parse
import json
import shutil
import time
import base64

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION=ET.parse(ROOT/"pom.xml").getroot().find("{http://maven.apache.org/POM/4.0.0}version").text
HOST=os.environ.get("LMAWS_TEST_HOST")
COMMAND=(["cmd.exe","/c",HOST] if HOST and HOST.endswith(".cmd") else [HOST]) if HOST else ["java","-cp",str(ROOT/"target"/f"lmaws-{VERSION}.jar"),"ai.lmctl.lmaws.Main"]


class Fake(http.server.BaseHTTPRequestHandler):
    actions = []
    state = "pending"
    run_count = 0
    error_code = ""
    dry_run = False
    ssm_names = []
    block_run = False
    unsafe_tags = False
    instance_visible = False
    children_present = False
    accepted = threading.Event()
    release = threading.Event()
    boot_count = 0
    decode_denied = False
    impaired = False
    unsafe_child = False
    tags = {
        "provisioner": "lmprov", "lmprov_id": "demo-01",
        "Name": "lmprov-demo-01", "owner": "test", "purpose": "transport"
    }

    def log_message(self, *_args):
        pass

    def reply(self, body, status=200, content_type="text/xml"):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        target = self.headers.get("X-Amz-Target", "")
        if target.endswith("AmazonSSM.GetParameter"):
            try:
                import json as _json
                Fake.ssm_names.append(_json.loads(raw.decode()).get("Name", ""))
            except Exception:
                pass
            self.reply('{"Parameter":{"Value":"ami-0123456789abcdef0"}}', 200, "application/x-amz-json-1.1")
            return
        form = urllib.parse.parse_qs(raw.decode())
        action = form.get("Action", [""])[0]
        Fake.actions.append((action, form))
        ns = "xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\""
        if action == "RunInstances":
            if form.get("DryRun", ["false"])[0].lower() == "true":
                self.reply(f"<Response {ns}><Errors><Error><Code>DryRunOperation</Code><Message>Request would have succeeded</Message></Error></Errors></Response>", 412)
                return
            Fake.run_count += 1
            for values in form.values():
                for candidate in values:
                    if candidate.startswith("demo-") or candidate.startswith("crash-"):
                        Fake.tags["lmprov_id"] = candidate
                        Fake.tags["Name"] = "lmprov-" + candidate
            if not Fake.error_code:
                Fake.instance_visible=True;Fake.children_present=True;Fake.state="running";Fake.boot_count=1
            if Fake.block_run:
                Fake.accepted.set();Fake.release.wait(15)
                return
            if Fake.error_code:
                code = Fake.error_code
                status = 403 if code == "UnauthorizedOperation" else 503 if code=="InternalError" else 400
                self.reply(f"<Response {ns}><Errors><Error><Code>{code}</Code><Message>fixture {code}{' Encoded authorization failure message: SYNTHETIC_ENCODED_TOKEN' if code=='UnauthorizedOperation' else ''}</Message></Error></Errors><RequestId>fixture-request</RequestId></Response>", status)
                return
            self.reply(f"<RunInstancesResponse {ns}><instancesSet><item><instanceId>i-0fixture000000001</instanceId><instanceState><name>running</name></instanceState><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-0fixture00000001</volumeId></ebs></item></blockDeviceMapping><networkInterfaceSet><item><networkInterfaceId>eni-0fixture0000001</networkInterfaceId></item></networkInterfaceSet></item></instancesSet></RunInstancesResponse>")
        elif action == "DescribeImages":
            self.reply(f"<DescribeImagesResponse {ns}><imagesSet><item><imageId>ami-0123456789abcdef0</imageId><imageLocation>canonical/ubuntu</imageLocation><imageState>available</imageState><imageOwnerId>099720109477</imageOwnerId><isPublic>true</isPublic><architecture>arm64</architecture><imageType>machine</imageType><rootDeviceType>ebs</rootDeviceType><virtualizationType>hvm</virtualizationType><rootDeviceName>/dev/sda1</rootDeviceName><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeSize>8</volumeSize></ebs></item></blockDeviceMapping></item></imagesSet></DescribeImagesResponse>")
        elif action == "DescribeVpcs":
            self.reply(f"<DescribeVpcsResponse {ns}><vpcSet><item><vpcId>vpc-0fixture000000001</vpcId><isDefault>true</isDefault></item></vpcSet></DescribeVpcsResponse>")
        elif action == "DescribeSubnets":
            self.reply(f"<DescribeSubnetsResponse {ns}><subnetSet><item><subnetId>subnet-0fixture000001</subnetId><vpcId>vpc-0fixture000000001</vpcId><state>available</state></item></subnetSet></DescribeSubnetsResponse>")
        elif action == "DescribeSecurityGroups":
            self.reply(f"<DescribeSecurityGroupsResponse {ns}><securityGroupInfo><item><groupId>sg-0fixture000000001</groupId><groupName>default</groupName><vpcId>vpc-0fixture000000001</vpcId></item></securityGroupInfo></DescribeSecurityGroupsResponse>")
        elif action == "DescribeInstances":
            requested=[form.get(k.replace(".Name",".Value.1"),[""])[0] for k,v in form.items() if k.endswith(".Name") and v==["tag:lmprov_id"]]
            if not Fake.instance_visible or requested and requested[0]!=Fake.tags.get("lmprov_id") and not Fake.unsafe_tags:
                self.reply(f"<DescribeInstancesResponse {ns}><reservationSet/></DescribeInstancesResponse>")
                return
            tags = {} if Fake.unsafe_tags else Fake.tags
            self.reply(f"<DescribeInstancesResponse {ns}><reservationSet><item><instancesSet><item><instanceId>i-0fixture000000001</instanceId><instanceType>t4g.nano</instanceType><instanceState><name>{Fake.state}</name></instanceState><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-0fixture00000001</volumeId><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMapping><networkInterfaceSet><item><networkInterfaceId>eni-0fixture0000001</networkInterfaceId></item></networkInterfaceSet><tagSet>" + "".join(f"<item><key>{k}</key><value>{v}</value></item>" for k, v in tags.items()) + "</tagSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>")
        elif action == "DescribeVolumes":
            if not Fake.children_present:
                self.reply(f'<Response {ns}><Errors><Error><Code>InvalidVolume.NotFound</Code><Message>gone</Message></Error></Errors></Response>',400) if any(k.startswith("VolumeId") for k in form) else self.reply(f'<DescribeVolumesResponse {ns}><volumeSet/></DescribeVolumesResponse>')
                return
            self.reply(f"<DescribeVolumesResponse {ns}><volumeSet><item><volumeId>vol-0fixture00000001</volumeId><size>10</size><volumeType>gp3</volumeType><tagSet>" + "".join(f"<item><key>{k}</key><value>{v}</value></item>" for k, v in ({} if Fake.unsafe_child else Fake.tags).items()) + "</tagSet></item></volumeSet></DescribeVolumesResponse>")
        elif action == "DescribeNetworkInterfaces":
            if not Fake.children_present:
                self.reply(f'<Response {ns}><Errors><Error><Code>InvalidNetworkInterfaceID.NotFound</Code><Message>gone</Message></Error></Errors></Response>',400) if any(k.startswith("NetworkInterfaceId") for k in form) else self.reply(f'<DescribeNetworkInterfacesResponse {ns}><networkInterfaceSet/></DescribeNetworkInterfacesResponse>')
                return
            self.reply(f"<DescribeNetworkInterfacesResponse {ns}><networkInterfaceSet><item><networkInterfaceId>eni-0fixture0000001</networkInterfaceId><tagSet>" + "".join(f"<item><key>{k}</key><value>{v}</value></item>" for k, v in Fake.tags.items()) + "</tagSet></item></networkInterfaceSet></DescribeNetworkInterfacesResponse>")
        elif action == "DescribeInstanceStatus":
            self.reply(f"<DescribeInstanceStatusResponse {ns}><instanceStatusSet><item><instanceStatus><status>{'impaired' if Fake.impaired else 'ok'}</status></instanceStatus><systemStatus><status>ok</status></systemStatus></item></instanceStatusSet></DescribeInstanceStatusResponse>")
        elif action == "StopInstances":
            Fake.state = "stopped"; self.reply(f"<StopInstancesResponse {ns}/>")
        elif action == "StartInstances":
            Fake.state = "running"; Fake.boot_count+=1; self.reply(f"<StartInstancesResponse {ns}/>")
        elif action == "TerminateInstances":
            Fake.state = "terminated"; Fake.children_present=False; self.reply(f"<TerminateInstancesResponse {ns}/>")
        elif action == "GetConsoleOutput":
            encoded = base64.b64encode(("LMPROV boot="+str(Fake.boot_count)+" id="+Fake.tags["lmprov_id"]).encode()).decode()
            self.reply(f"<GetConsoleOutputResponse {ns}><output>{encoded}</output></GetConsoleOutputResponse>")
        elif action=="DecodeAuthorizationMessage":
            if Fake.decode_denied:self.reply('<ErrorResponse><Error><Code>AccessDenied</Code><Message>decode denied</Message></Error></ErrorResponse>',403)
            else:self.reply('<DecodeAuthorizationMessageResponse><DecodeAuthorizationMessageResult><DecodedMessage>{&quot;allowed&quot;:false,&quot;explicitDeny&quot;:true,&quot;account&quot;:&quot;111122223333&quot;}</DecodedMessage></DecodeAuthorizationMessageResult></DecodeAuthorizationMessageResponse>')
        else:
            self.reply(f"<Response {ns}/>")


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    script = """
let cloud = aws.region("us-east-1");
let cfg = "{\\"lmprov_id\\":\\"demo-01\\",\\"owner\\":\\"test\\",\\"purpose\\":\\"transport\\",\\"volume_gib\\":10}";
file_write("made.json", cloud.ec2_provision_run(cfg));
file_write("describe.json", cloud.ec2_provision_describe("demo-01"));
file_write("stop.json", cloud.ec2_provision_stop("demo-01"));
file_write("start.json", cloud.ec2_provision_start("demo-01"));
file_write("console.json", cloud.ec2_provision_console("demo-01"));
file_write("terminate.json", cloud.ec2_provision_terminate("demo-01"));
"""
    try:
        ledger_root = tempfile.mkdtemp(prefix="lmaws-provision-ledger-")
        runner = shutil.which("lmscript")
        if not runner:
            raise SystemExit("lmscript is required for the provisioning transport test")
        schema = tempfile.NamedTemporaryFile(prefix="lmaws-provision-schema-", suffix=".json", delete=False)
        schema_path = pathlib.Path(schema.name)
        schema.close()
        # Use the checked-in regenerated schema while the immutable host JAR is
        # being rebuilt; this keeps the compiler contract aligned with the new
        # provisioning bindings.
        schema_path.write_bytes((ROOT / "schema/lmaws.dsl.json").read_bytes())
        def invoke(source, profile="default", timeout=90, crash=False):
            with tempfile.TemporaryDirectory(prefix="lmaws-provision-script-") as td:
                path = pathlib.Path(td) / "job.lms"
                output = pathlib.Path(td) / "job.dslb"
                path.write_text('p = _dsl_ schema=' + json.dumps(str(schema_path)) + ';\n' + source + '\nend _dsl_\nsavedsl(p, ' + json.dumps(str(output)) + ');\n')
                compiled = subprocess.run([runner, str(path)], cwd=td, text=True, capture_output=True, timeout=60)
                if compiled.returncode:
                    raise AssertionError(compiled.stdout + compiled.stderr)
                env = dict(os.environ, LMAWS_ENDPOINT=f"http://127.0.0.1:{server.server_port}", LMAWS_LIVE="1", AWS_PROFILE=profile, AWS_REGION="us-east-1", CI="true", LMAWS_LEDGER_DIR=ledger_root, LMPROV_LEDGER_DIR=ledger_root)
                if crash:
                    process=subprocess.Popen(COMMAND+["--dsl",str(output)],cwd=td,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    try:
                        assert Fake.accepted.wait(15), "RunInstances was not accepted before kill"
                    finally:
                        process.kill();stdout,stderr=process.communicate(timeout=15);Fake.release.set()
                    result=subprocess.CompletedProcess(process.args,process.returncode,stdout,stderr)
                else:
                    result = subprocess.run(COMMAND+["--dsl",str(output)], cwd=td, env=env, text=True, capture_output=True, timeout=timeout)
                result.receipts = {p.name: p.read_text() for p in pathlib.Path(td).glob("*.json")}
                return result
        with tempfile.TemporaryDirectory(prefix="lmaws-provision-") as td:
            run = invoke(script)
            if run.returncode:
                raise AssertionError(run.stdout + run.stderr)
            assert "i-0fixture000000001" in run.receipts["made.json"] and "vol-0fixture00000001" in run.receipts["describe.json"] and "boot=2" in run.receipts["console.json"], run.receipts
            assert Fake.run_count == 1, (Fake.run_count, Fake.actions, run.receipts)
            proof=invoke('let c=aws.region("us-east-1");file_write("proof.json",c.ec2_provision_verify("demo-01"));')
            assert json.loads(proof.receipts["proof.json"])["cleanup_complete"],proof.receipts
            retry = invoke('let c = aws.region("us-east-1"); file_write("retry.json", c.ec2_provision_run("{\\"lmprov_id\\":\\"demo-01\\",\\"owner\\":\\"test\\",\\"purpose\\":\\"transport\\",\\"volume_gib\\":10}"));')
            assert retry.returncode == 0 and Fake.run_count == 1 and "i-0fixture000000001" in retry.receipts["retry.json"], "tag lookup must make create idempotent"
            Fake.block_run = True
            Fake.instance_visible = False
            Fake.tags["lmprov_id"] = "crash-01"
            Fake.tags["Name"] = "lmprov-crash-01"
            invoke('let c = aws.region("us-east-1"); c.ec2_provision_run("{\\\"lmprov_id\\\":\\\"crash-01\\\"}");',crash=True)
            Fake.block_run=False
            resumed = invoke('let c = aws.region("us-east-1"); file_write("resumed.json", c.ec2_provision_run("{\\"lmprov_id\\":\\"crash-01\\"}"));')
            assert resumed.returncode == 0 and Fake.run_count == 2 and "i-0fixture000000001" in resumed.receipts["resumed.json"], (Fake.run_count, resumed.returncode, resumed.receipts)
            run_forms = [f for a, f in Fake.actions if a == "RunInstances"]
            assert run_forms and run_forms[0].get("InstanceType") == ["t4g.nano"]
            assert run_forms[0].get("BlockDeviceMapping.1.Ebs.VolumeSize") == ["10"]
            assert run_forms[0].get("BlockDeviceMapping.1.Ebs.VolumeType") == ["gp3"]
            assert run_forms[0].get("BlockDeviceMapping.1.Ebs.DeleteOnTermination") == ["true"]
            assert not any("Spot" in k or "KeyName" in k or "IamInstanceProfile" in k for k in run_forms[0])
            tags = [value for key, values in run_forms[0].items()
                    if ".Tag." in key and key.endswith(".Value") for value in values]
            assert "lmprov" in tags and "demo-01" in tags
            assert Fake.ssm_names and Fake.ssm_names[0].startswith("/aws/service/canonical/ubuntu/")
            # Configuration limits and profile guards fail before any AWS call.
            bad_type = invoke('let c = aws.region("us-east-1"); c.ec2_provision_run("{\\"lmprov_id\\":\\"bad-type\\",\\"instance_type\\":\\"t3.nano\\"}");')
            assert bad_type.returncode != 0 and "t4g.nano" in bad_type.stderr
            bad_disk = invoke('let c = aws.region("us-east-1"); c.ec2_provision_run("{\\"lmprov_id\\":\\"bad-disk\\",\\"volume_gib\\":21}");')
            assert bad_disk.returncode != 0 and "volume_gib" in bad_disk.stderr
            bad_profile = invoke('let c = aws.region("us-east-1"); file_write("bad-profile.json", c.ec2_provision_describe("crash-01"));', "admin")
            assert ((bad_profile.returncode == 0 and '"ok":false' in bad_profile.receipts.get("bad-profile.json", ""))
                    or "refuses" in bad_profile.stderr)
            bad_cap = invoke('let c = aws.region("us-east-1"); c.ec2_provision_run("{\\"lmprov_id\\":\\"bad-cap\\",\\"cap_usd\\":\\"0.2501\\"}");')
            assert bad_cap.returncode != 0 and "cap_usd" in bad_cap.stderr
            Fake.unsafe_tags = True
            Fake.tags["Project"] = "awsspot"
            unsafe = invoke('let c = aws.region("us-east-1"); file_write("unsafe.json", c.ec2_provision_describe("crash-01"));')
            Fake.tags.pop("Project", None)
            Fake.unsafe_tags = False
            assert unsafe.returncode != 0 or '"ok":false' in unsafe.receipts.get("unsafe.json", "") or "refus" in unsafe.stderr, "untagged target must be refused"
            # Dry-run is an authorized, non-mutating RunInstances request. AWS
            # answers with DryRunOperation (HTTP 412); no instance is created.
            before = Fake.run_count
            dry = invoke('let c = aws.region("us-east-1"); file_write("dry.json", c.ec2_provision_run("{\\"lmprov_id\\":\\"dry-01\\",\\"dry\\":true}"));')
            assert dry.returncode == 0 and "DryRunOperation" in dry.receipts["dry.json"] and Fake.run_count == before,(dry.returncode,dry.receipts,dry.stderr,Fake.actions[-8:])
            dry_forms = [f for a, f in Fake.actions if a == "RunInstances" and f.get("DryRun") == ["true"]]
            assert dry_forms, "dry run must dispatch RunInstances DryRun=true"
            # AWS failures are structured and classified without throwing or leaking ids.
            Fake.error_code = "InsufficientInstanceCapacity"
            failed = invoke('let c = aws.region("us-east-1"); file_write("error.json", c.ec2_provision_run("{\\"lmprov_id\\":\\"capacity-01\\"}"));')
            assert failed.returncode==0 and json.loads(failed.receipts["error.json"])["classification"]=="capacity" and not json.loads(failed.receipts["error.json"])["ok"],failed.receipts
            for code, classification in {
                "VcpuLimitExceeded": "quota",
                "InstanceLimitExceeded": "quota",
                "UnauthorizedOperation": "unauthorized",
                "InvalidParameterValue": "invalid_parameter",
                "RequestLimitExceeded": "rate_limit",
                "IncorrectInstanceState": "state_transition",
            }.items():
                Fake.error_code = code
                check = invoke(
                    'let c = aws.region("us-east-1"); file_write("error.json", c.ec2_provision_run("{\\"lmprov_id\\":\\"err-' + code.lower() + '\\"}"));')
                assert check.returncode==0 and json.loads(check.receipts["error.json"])["classification"]==classification and json.loads(check.receipts["error.json"])["error_code"]==code and not json.loads(check.receipts["error.json"])["ok"],(code,check.receipts)
            Fake.error_code="UnauthorizedOperation"
            auth=invoke('let c=aws.region("us-east-1");file_write("auth.json",c.ec2_provision_run("{\\\"lmprov_id\\\":\\\"auth-decode\\\"}"));')
            decoded=json.loads(auth.receipts["auth.json"])
            assert decoded["decode_status"]=="available" and "111122223333" not in decoded["decoded_authorization"] and "explicitDeny" in decoded["decoded_authorization"],decoded
            Fake.decode_denied=True
            denied=invoke('let c=aws.region("us-east-1");file_write("auth.json",c.ec2_provision_run("{\\\"lmprov_id\\\":\\\"auth-no-decode\\\"}"));')
            assert "unknown" in json.loads(denied.receipts["auth.json"])["decode_status"]
            Fake.decode_denied=False
            Fake.error_code="InternalError"
            before=Fake.run_count
            ambiguous=invoke('let c=aws.region("us-east-1");file_write("error.json",c.ec2_provision_run("{\\\"lmprov_id\\\":\\\"server-uncertain\\\"}"));')
            assert json.loads(ambiguous.receipts["error.json"])["ambiguous"] and Fake.run_count==before+1,ambiguous.receipts
            Fake.error_code = ""
            before=Fake.run_count
            capped=invoke('let c=aws.region("us-east-1");file_write("cap.json",c.ec2_provision_run("{\\\"lmprov_id\\\":\\\"cap-zero\\\",\\\"cap_usd\\\":0}"));')
            cap=json.loads(capped.receipts["cap.json"])
            assert not cap["ok"] and not cap["ambiguous"] and Fake.run_count==before,cap
            for profile in ("lmaws","lmaws-ec2","lmaws-web"):
                allowed=invoke('let c=aws.region("us-east-1");file_write("profile.json",c.ec2_provision_describe("crash-01"));',profile)
                assert allowed.returncode==0 and json.loads(allowed.receipts["profile.json"])["ok"],allowed.receipts
            unknown=invoke('let c=aws.region("us-east-1");c.ec2_provision_describe("crash-01");',"unknown-profile")
            assert unknown.returncode!=0 and "refuses" in unknown.stderr
            Fake.impaired=True
            health=invoke('let c=aws.region("us-east-1");file_write("health.json",c.ec2_provision_describe("crash-01"));')
            unhealthy=json.loads(health.receipts["health.json"])
            assert unhealthy["health_failed"] and unhealthy["classification"]=="status_checks_failed" and "LMPROV boot=" in unhealthy["console_tail"],unhealthy
            Fake.impaired=False
            Fake.unsafe_child=True
            before=sum(a=="StopInstances" for a,_ in Fake.actions)
            guarded=invoke('let c=aws.region("us-east-1");file_write("guard.json",c.ec2_provision_stop("crash-01"));')
            assert not json.loads(guarded.receipts["guard.json"])["ok"] and sum(a=="StopInstances" for a,_ in Fake.actions)==before,guarded.receipts
            Fake.unsafe_child=False
            print("PASS EC2 provisioning loopback lifecycle, canonical SSM AMI, tags, on-demand gp3 and no spot/key/profile")
    finally:
        server.shutdown(); server.server_close()


if __name__ == "__main__":
    main()
