#!/usr/bin/env python3
"""Loopback AWS SDK serialization test for WebStackAws (no credentials/network)."""
import http.server, json, pathlib, subprocess, tempfile, threading, os, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
class Fake(http.server.BaseHTTPRequestHandler):
    requests=[]
    def log_message(self,*args): pass
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get("Content-Length","0"))); self.requests.append((self.path,self.headers,body)); print("fake",self.path,self.headers.get("X-Amz-Target"),file=sys.stderr)
        if self.path.startswith("/2020-05-31/origin-access-control"):
            out=b'<OriginAccessControl xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Id>oac-fixture</Id><OriginAccessControlConfig><Name>lmaws-oac-a1b2c3d4</Name><Description>x</Description><SigningProtocol>sigv4</SigningProtocol><SigningBehavior>always</SigningBehavior><OriginAccessControlOriginType>s3</OriginAccessControlOriginType></OriginAccessControlConfig></OriginAccessControl>'
            self.reply(out,"text/xml")
        elif self.path.startswith("/2020-05-31/distribution"):
            out=b'<Distribution xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Id>EDFIXTURE</Id><ARN>arn:aws:cloudfront::000000000000:distribution/EDFIXTURE</ARN><Status>InProgress</Status><DomainName>dfixture.cloudfront.net</DomainName><DistributionConfig><CallerReference>fixture</CallerReference><Enabled>true</Enabled><Comment>lmweblab a1b2c3d4</Comment><DefaultRootObject>index.html</DefaultRootObject></DistributionConfig></Distribution>'
            self.reply(out,"text/xml")
        elif self.path.startswith("/2015-12-08/certificates") or self.headers.get("X-Amz-Target","").endswith("RequestCertificate"):
            self.reply(json.dumps({"CertificateArn":"arn:aws:acm:us-east-1:000000000000:certificate/fixture"}).encode(),"application/x-amz-json-1.1")
        else: self.reply(b"{}","application/x-amz-json-1.1")
    def reply(self,body,ctype):
        self.send_response(200); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)

def main():
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Fake); threading.Thread(target=server.serve_forever,daemon=True).start(); endpoint=f"http://127.0.0.1:{server.server_port}"
    with tempfile.TemporaryDirectory(prefix="lmaws-web-http-") as td:
        td=pathlib.Path(td); cpfile=td/"cp.txt"; subprocess.run(["mvn","-q","dependency:build-classpath",f"-Dmdep.outputFile={cpfile}"],cwd=ROOT,check=True)
        cp=str(ROOT/"target/classes")+os.pathsep+cpfile.read_text().strip(); src=td/"WebHttp.java"
        src.write_text('''import ai.lmctl.lmaws.*; import software.amazon.awssdk.services.cloudfront.*; import software.amazon.awssdk.services.acm.*; import software.amazon.awssdk.services.s3.*; import software.amazon.awssdk.services.ec2.*; import software.amazon.awssdk.services.route53.*; import software.amazon.awssdk.regions.*; import software.amazon.awssdk.auth.credentials.*; public class WebHttp { public static void main(String[] a){ var c=CloudFrontClient.builder().region(Region.US_EAST_1).endpointOverride(java.net.URI.create(a[0])).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("x","x"))).build(); var ac=AcmClient.builder().region(Region.US_EAST_1).endpointOverride(java.net.URI.create(a[0])).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("x","x"))).build(); var s=S3Client.builder().region(Region.US_EAST_1).endpointOverride(java.net.URI.create(a[0])).forcePathStyle(true).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("x","x"))).build(); var r=Route53Client.builder().region(Region.AWS_GLOBAL).endpointOverride(java.net.URI.create(a[0])).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("x","x"))).build(); var e=Ec2Client.builder().region(Region.US_EAST_1).endpointOverride(java.net.URI.create(a[0])).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("x","x"))).build(); var w=new WebStackAws(r,c,ac,s,e,"a1b2c3d4","example.com"); String o=w.createOac(); if(!"oac-fixture".equals(o))throw new AssertionError("OAC response not decoded"); var dist=w.createDistribution("lmaws-site-a1b2c3d4","lmaws-site-a1b2c3d4.example.com",o); if(!"EDFIXTURE".equals(dist.id()))throw new AssertionError("distribution response not decoded");w.requestCertificate("lmaws-site-a1b2c3d4.example.com"); }}''')
        subprocess.run(["javac","-cp",cp,str(src)],check=True); subprocess.run(["java","-cp",cp+os.pathsep+str(td),"WebHttp",endpoint],check=True)
        bodies=b"\n".join(x[2] for x in Fake.requests); assert b"lmaws_test" in bodies and b"lmaws-oac-a1b2c3d4" in bodies and b"lmaws-site-a1b2c3d4.example.com" in bodies
        assert b"Aliases" not in bodies, "phase1 distribution sent a custom alias before ACM"
        print("PASS loopback AWS SDK CloudFront OAC/distribution and ACM request serialization; tags and phase1 alias guard verified")
    server.shutdown(); server.server_close()
if __name__ == "__main__": main()
