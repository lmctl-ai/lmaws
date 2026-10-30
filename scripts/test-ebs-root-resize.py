#!/usr/bin/env python3
"""Guarded EBS resize against loopback AWS protocol fakes; never real AWS."""
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import urllib.parse
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
VERSION = ET.parse(ROOT / "pom.xml").getroot().find("{*}version").text
JAR = ROOT / f"target/lmaws-{VERSION}.jar"
SPEC = dict(account="123456789012", region="us-east-1", instance_id="i-0123456789abcdef0",
            volume_id="vol-0123456789abcdef0", from_gib=150, to_gib=200)


class Fake(http.server.BaseHTTPRequestHandler):
    calls = []
    mutations = []
    size = 150
    modification = None
    scenario = ""

    def log_message(self, *args):
        pass

    def do_POST(self):
        form = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        action = form.get("Action", [""])[0]
        Fake.calls.append(action)
        scenario = Fake.scenario
        if action == "GetCallerIdentity":
            account = "999999999999" if scenario == "account" else SPEC["account"]
            body = f"<GetCallerIdentityResult><Account>{account}</Account><Arn>arn:aws:iam::{account}:user/test</Arn><UserId>test</UserId></GetCallerIdentityResult>"
        elif action == "DescribeInstances":
            ident = "i-99999999999999999" if scenario == "instance" else SPEC["instance_id"]
            volume = "vol-99999999999999999" if scenario == "root" else SPEC["volume_id"]
            state = "stopped" if scenario == "stopped" else "running"
            dot = "true" if scenario == "delete" else "false"
            body = f"<reservationSet><item><instancesSet><item><instanceId>{ident}</instanceId><instanceState><name>{state}</name></instanceState><rootDeviceName>/dev/sda1</rootDeviceName><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>{volume}</volumeId><deleteOnTermination>{dot}</deleteOnTermination></ebs></item></blockDeviceMapping></item></instancesSet></item></reservationSet>"
        elif action == "DescribeVolumes":
            ident = "vol-99999999999999999" if scenario == "volume" else SPEC["volume_id"]
            instance = "i-99999999999999999" if scenario == "attachment" else SPEC["instance_id"]
            kind = "gp2" if scenario == "type" else "gp3"
            size = 175 if scenario == "size" else Fake.size
            device = "/dev/sdf" if scenario == "device" else "/dev/sda1"
            body = f"<volumeSet><item><volumeId>{ident}</volumeId><volumeType>{kind}</volumeType><size>{size}</size><status>in-use</status><attachmentSet><item><volumeId>{ident}</volumeId><instanceId>{instance}</instanceId><device>{device}</device><status>attached</status></item></attachmentSet></item></volumeSet>"
        elif action == "DescribeVolumesModifications":
            item = ""
            if Fake.modification:
                state, target = Fake.modification
                item = f"<item><volumeId>{SPEC['volume_id']}</volumeId><modificationState>{state}</modificationState><targetSize>{target}</targetSize></item>"
            body = f"<volumeModificationSet>{item}</volumeModificationSet>"
        elif action == "ModifyVolume":
            Fake.mutations.append(form)
            assert form["VolumeId"] == [SPEC["volume_id"]]
            assert form["Size"] == ["200"]
            assert set(form) == {"Action", "Version", "VolumeId", "Size"}, form
            Fake.size = 200
            Fake.modification = ("optimizing", 200)
            body = f"<volumeModification><volumeId>{SPEC['volume_id']}</volumeId><modificationState>optimizing</modificationState><targetSize>200</targetSize></volumeModification>"
        else:
            raise AssertionError(f"Unexpected AWS action: {action}")
        response = (f"<{action}Response>{body}</{action}Response>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="ebs-resize-fake-") as td:
            work = Path(td)
            host = work / ("lmaws.cmd" if os.name == "nt" else "lmaws")
            host.write_text(f'@echo off\njava -jar "{JAR}" %*\n' if os.name == "nt"
                            else f'#!/bin/sh\nexec java -jar "{JAR}" "$@"\n')
            host.chmod(0o755)
            empty = work / "empty-config"
            empty.write_text("")
            env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "LMAWS_"))}
            env.pop("CI", None)
            env.update(PATH=str(work) + os.pathsep + env["PATH"], LMAWS_LIVE="1",
                       LMAWS_ENDPOINT=f"http://127.0.0.1:{server.server_port}",
                       LMAWS_ADMIN_GRANT="1", AWS_PROFILE="admin", AWS_REGION="us-east-1",
                       AWS_SHARED_CREDENTIALS_FILE=str(empty), AWS_CONFIG_FILE=str(empty),
                       AWS_EC2_METADATA_DISABLED="true")
            script = work / "run.lms"
            output = work / "result.json"

            def execute(apply=False, human=True, spec=None, overrides=None, ok=True, offline=False):
                payload = json.dumps(json.dumps(spec or SPEC))
                body = (
                    'let p=_dsl_ cli="lmaws";\n'
                    'let cloud=aws.example("ebs_resize_test");\n'
                    f'let result=cloud.ebs_root_resize({payload},{str(apply).lower()},{str(human).lower()});\n'
                    f'file_write({json.dumps(str(output))},result.json());\nend _dsl_\n'
                    'let code=temp_file();savedsl(p,code);\n'
                    'let r=system(concat(dsl_cli(p),concat('
                    + json.dumps((["--dry-run"] if offline else []) + (["--apply"] if apply else []) + ["--dsl"])
                    + ',[code])),{timeoutMs:30000});\nprintln(r.stdout);println(r.stderr);remove_file(code);assert(r.code==0);\n'
                )
                script.write_text(body)
                compiler = shutil.which("lmctl.cmd" if os.name == "nt" else "lmctl") or "lmctl"
                command = ["cmd.exe", "/c", compiler] if os.name == "nt" else [compiler]
                result = subprocess.run(command + [str(script)], cwd=work,
                                        env=dict(env, LMAWS_APPLY="1" if apply else "0", **(overrides or {})),
                                        capture_output=True, text=True, timeout=60)
                assert (result.returncode == 0) == ok, result.stdout + result.stderr
                return json.loads(output.read_text()) if ok else result

            plan = execute(overrides={"AWS_PROFILE": "default"})
            assert plan["changed"] == "true" and plan["applied"] == "false" and not Fake.mutations
            for scenario in ("account", "instance", "root", "delete", "stopped", "volume",
                             "attachment", "type", "size", "device"):
                Fake.scenario = scenario
                execute(apply=True, ok=False)
                assert not Fake.mutations, scenario
            Fake.scenario = ""
            for changes in ({"account": "bad"}, {"to_gib": 149}, {"to_gib": 200.5},
                            {"to_gib": 20000}, {"region": "us-west-2"}, {"unexpected": True}):
                execute(spec=dict(SPEC, **changes), apply=True, ok=False)
                assert not Fake.mutations
            for overrides in ({"AWS_PROFILE": "default"}, {"LMAWS_ADMIN_GRANT": "0"},
                              {"CI": "true"}, {"LMAWS_LIVE": "0"}):
                execute(apply=True, overrides=overrides, ok=False)
                assert not Fake.mutations
            execute(apply=True, human=False, ok=False)
            assert not Fake.mutations
            Fake.modification = ("modifying", 200)
            pending = execute(apply=True)
            assert pending["ready"] == "false" and not Fake.mutations
            Fake.size = 200
            pending = execute(apply=True)
            assert pending["ready"] == "false" and not Fake.mutations
            Fake.modification = ("optimizing", 200)
            assert execute(apply=True)["ready"] == "true" and not Fake.mutations
            Fake.size = 150
            for modification in (("modifying", 300), ("failed", 200)):
                Fake.modification = modification
                execute(apply=True, ok=False)
                assert not Fake.mutations
            Fake.modification = None
            applied = execute(apply=True)
            assert applied["applied"] == "true" and len(Fake.mutations) == 1
            final = execute(apply=True)
            assert final["ready"] == "true" and final["changed"] == "false"
            assert len(Fake.mutations) == 1
            Fake.calls.clear()
            assert execute(offline=True, overrides={"AWS_PROFILE": "default"})["applied"] == "false"
            assert not Fake.calls
        print("PASS EBS root resize: loopback SDK protocol, identity/root/attachment/size guards, in-flight reruns and one size-only ModifyVolume; no AWS")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
