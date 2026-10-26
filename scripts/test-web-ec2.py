#!/usr/bin/env python3
"""Loopback EC2 Query fixture for WebCompute capacity fallback."""
import http.server, os, pathlib, subprocess, tempfile, threading, urllib.parse, shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]

class Fake(http.server.BaseHTTPRequestHandler):
    requests=[]; launches=0; describes=0
    def log_message(self,*args): pass
    def do_POST(self):
        raw=self.rfile.read(int(self.headers.get("Content-Length","0"))); q=urllib.parse.parse_qs(raw.decode(errors="replace")); action=q.get("Action",[""])[0]; Fake.requests.append((action,q,raw))
        if action=="CreateSecurityGroup": self.reply('<CreateSecurityGroupResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><groupId>sg-0123456789abcdef0</groupId></CreateSecurityGroupResponse>')
        elif action=="DescribeSubnets": self.reply('<DescribeSubnetsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><subnetSet><item><subnetId>subnet-1234abcd</subnetId><vpcId>vpc-1234abcd</vpcId><mapPublicIpOnLaunch>true</mapPublicIpOnLaunch></item><item><subnetId>subnet-5678abcd</subnetId><vpcId>vpc-1234abcd</vpcId><mapPublicIpOnLaunch>true</mapPublicIpOnLaunch></item></subnetSet></DescribeSubnetsResponse>')
        elif action=="RunInstances":
            Fake.launches+=1
            if Fake.launches==1:
                body=b'<Response><Errors><Error><Code>InsufficientInstanceCapacity</Code><Message>capacity unavailable</Message></Error></Errors><RequestId>fixture</RequestId></Response>'; self.send_response(400); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
            else: self.reply('<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState><ipAddress>198.51.100.7</ipAddress><subnetId>subnet-5678abcd</subnetId><spotInstanceRequestId>sir-0123456789abcdef0</spotInstanceRequestId></item></instancesSet></RunInstancesResponse>')
        elif action=="DescribeInstances":
            Fake.describes+=1
            if Fake.describes==1:
                body=b'<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code><Message>new instance is not visible yet</Message></Error></Errors><RequestId>fixture</RequestId></Response>';self.send_response(400);self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
            else:self.reply('<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState><ipAddress>198.51.100.7</ipAddress><subnetId>subnet-5678abcd</subnetId><spotInstanceRequestId>sir-0123456789abcdef0</spotInstanceRequestId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>')
        else: self.reply('<AuthorizeSecurityGroupIngressResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"/>')
    def reply(self,text):
        body=text.encode(); self.send_response(200); self.send_header("Content-Type","text/xml"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)

def main():
    maven=shutil.which("mvn.cmd" if os.name=="nt" else "mvn") or "mvn"
    maven_argv=["cmd.exe","/c",maven] if os.name=="nt" else [maven]
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Fake); threading.Thread(target=server.serve_forever,daemon=True).start(); endpoint=f"http://127.0.0.1:{server.server_port}"
    try:
        with tempfile.TemporaryDirectory(prefix="lmaws-web-ec2-") as td:
            td=pathlib.Path(td); cp=td/"cp"; subprocess.run(maven_argv+["-q","dependency:build-classpath",f"-Dmdep.outputFile={cp}"],cwd=ROOT,check=True,timeout=120); classpath=str(ROOT/"target/classes")+os.pathsep+cp.read_text().strip(); src=td/"WebEc2.java"
            src.write_text('''package ai.lmctl.lmaws; public class WebEc2 { public static void main(String[] a){ var b=new AwsBackend("us-east-1",false,null); var w=new WebCompute(b); var cp=new java.util.ArrayList<java.util.Map<String,String>>(); var out=w.create("a1b2c3d4","vpc-1234abcd","subnet-1234abcd","ami-12345678","198.51.100.7/32","t3.nano",8,"#!/bin/bash\\necho lmweblab\\n",0.004,x->cp.add(x)); if(!"subnet-5678abcd".equals(out.get("subnet_id"))||!out.containsKey("instance_type")||cp.size()<3||cp.get(0).containsKey("instance_id")||!cp.get(1).containsKey("instance_id"))throw new AssertionError(out+" checkpoints="+cp.size()); try{w.create("a1b2c3d4","vpc-1234abcd","subnet-1234abcd","ami-12345678","0.0.0.0/0","m7g.large",9,"#!/bin/bash lmweblab",0.004);throw new AssertionError("unsafe inputs accepted");}catch(IllegalArgumentException|SecurityException expected){}b.close(); }}''')
            subprocess.run(["javac","-d",str(td),"-cp",classpath,str(src)],check=True); env=dict(os.environ,LMAWS_ENDPOINT=endpoint,LMAWS_LIVE="1",AWS_PROFILE="lmaws",AWS_REGION="us-east-1",CI="true",AWS_EC2_METADATA_DISABLED="true"); subprocess.run(["java","-cp",classpath+os.pathsep+str(td),"ai.lmctl.lmaws.WebEc2"],cwd=ROOT,env=env,check=True)
            runs=[x for x in Fake.requests if x[0]=="RunInstances"]; assert Fake.describes>=2
            assert len(runs)==2 and runs[0][1]["ClientToken"]!=runs[1][1]["ClientToken"]
            groups=lambda q:[v for k,values in q.items() if "GroupId" in k for v in values]
            subnets=lambda q:[v for k,values in q.items() if k.endswith("SubnetId") for v in values]
            assert groups(runs[0][1])==groups(runs[1][1]) and subnets(runs[1][1])==["subnet-5678abcd"]
            assert b"lmaws_test" in runs[1][2]
            print("PASS WebCompute capacity fallback and fresh-instance visibility backoff: explicit capacity retry, alternate public subnet, distinct tokens, same SG, tags and 8GiB constraints")
    finally: server.shutdown(); server.server_close()
if __name__=="__main__": main()
