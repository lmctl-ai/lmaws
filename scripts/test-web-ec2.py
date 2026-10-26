#!/usr/bin/env python3
"""Loopback EC2 SDK test for WebCompute; no AWS credentials or network."""
import http.server, pathlib, subprocess, tempfile, threading, os, urllib.parse, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
class Fake(http.server.BaseHTTPRequestHandler):
    requests=[]
    def log_message(self,*a): pass
    def do_POST(self):
        raw=self.rfile.read(int(self.headers.get('Content-Length','0'))); q=urllib.parse.parse_qs(raw.decode()); action=q.get('Action',[''])[0]; Fake.requests.append((action,q,raw))
        if action=='CreateSecurityGroup': body='<CreateSecurityGroupResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><groupId>sg-0123456789abcdef0</groupId></CreateSecurityGroupResponse>'
        elif action=='RunInstances': body='<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState><publicIpAddress>198.51.100.7</publicIpAddress><subnetId>subnet-1234abcd</subnetId><placement><availabilityZone>us-east-1a</availabilityZone></placement><spotInstanceRequestId>sir-0123456789abcdef0</spotInstanceRequestId></item></instancesSet></RunInstancesResponse>'
        elif action=='DescribeInstances': body='<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState><ipAddress>198.51.100.7</ipAddress><subnetId>subnet-1234abcd</subnetId><placement><availabilityZone>us-east-1a</availabilityZone></placement><spotInstanceRequestId>sir-0123456789abcdef0</spotInstanceRequestId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>'
        else: body='<AuthorizeSecurityGroupIngressResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"/>'
        data=body.encode(); self.send_response(200); self.send_header('Content-Type','text/xml'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
def main():
    srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fake); threading.Thread(target=srv.serve_forever,daemon=True).start(); ep=f'http://127.0.0.1:{srv.server_port}'
    with tempfile.TemporaryDirectory(prefix='lmaws-web-ec2-') as td:
        td=pathlib.Path(td); cp=td/'cp'; subprocess.run(['mvn','-q','dependency:build-classpath',f'-Dmdep.outputFile={cp}'],cwd=ROOT,check=True); classpath=str(ROOT/'target/classes')+os.pathsep+cp.read_text().strip(); src=td/'WebEc2.java'
        src.write_text('''package ai.lmctl.lmaws; import java.net.*; public class WebEc2 { public static void main(String[] a){ var b=new AwsBackend("us-east-1",false,null); var w=new WebCompute(b); var r=w.create("a1b2c3d4","vpc-1234abcd","subnet-1234abcd","ami-12345678","198.51.100.7/32","t3.nano",8,"#!/bin/bash\\necho lmweblab\\n",0.004); if(!r.get("public_ip").equals("198.51.100.7")) throw new Error(r.toString()); try { w.create("a1b2c3d4","vpc-1234abcd","subnet-1234abcd","ami-12345678","0.0.0.0/0","m7g.large",9,"#!/bin/bash lmweblab",0.004); throw new Error("unsafe input accepted"); } catch(RuntimeException expected){} b.close(); }}''')
        subprocess.run(['javac','-d',str(td),'-cp',classpath,str(src)],check=True); env=dict(os.environ,LMAWS_ENDPOINT=ep,LMAWS_LIVE='1',AWS_PROFILE='lmaws',AWS_REGION='us-east-1',CI='true',AWS_EC2_METADATA_DISABLED='true'); subprocess.run(['java','-cp',classpath+os.pathsep+str(td),'ai.lmctl.lmaws.WebEc2'],cwd=ROOT,env=env,check=True)
        acts=[x[0] for x in Fake.requests]; assert acts[:4]==['CreateSecurityGroup','AuthorizeSecurityGroupIngress','RunInstances','DescribeInstances'],acts
        run=Fake.requests[2][1]
        def field(suffix):
            matches=[v for k,v in run.items() if k.lower()==suffix.lower() or k.lower().endswith("."+suffix.lower())]
            assert matches,(suffix,list(run));return matches
        assert field('InstanceType')==[['t3.nano']]
        assert field('VolumeSize')==[['8']]
        assert field('AssociatePublicIpAddress')==[['true']]
        assert field('HttpTokens')==[['required']]
        assert field('InstanceInitiatedShutdownBehavior')==[['terminate']]
        resources={v[0] for k,v in run.items() if k.endswith('.ResourceType')}
        assert resources=={'instance','volume','network-interface','spot-instances-request'},resources
        import base64
        script=base64.b64decode(run['UserData'][0]).decode()
        assert 'shutdown -h +9' in script and 'echo lmweblab' in script
        assert Fake.requests[1][1].get('IpPermissions.1.IpRanges.1.CidrIp')==['198.51.100.7/32']
        print('PASS loopback EC2 WebCompute create: tagged SG/instance/volume/ENI/spot, nano/8GiB, public IP, IMDSv2, /32; unsafe inputs rejected before request')
    srv.shutdown(); srv.server_close()
if __name__=='__main__': main()
