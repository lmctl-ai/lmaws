#!/usr/bin/env python3
"""Exercise the real AWS SDK transport against a loopback-only fake service."""
import http.server,json,os,pathlib,subprocess,sys,threading,tempfile,urllib.parse

ROOT=pathlib.Path(__file__).resolve().parents[1]
class Fake(http.server.BaseHTTPRequestHandler):
    requests=[]; created={}; lock=threading.Lock()
    def log_message(self,*a): pass
    def do_POST(self): self.handle_request()
    def do_GET(self): self.handle_request()
    def do_PUT(self): self.handle_request()
    def do_DELETE(self): self.handle_request()
    def do_HEAD(self): self.handle_request()
    def handle_request(self):
        n=int(self.headers.get("content-length","0")); body=self.rfile.read(n).decode("utf-8", "replace")
        target=self.headers.get("x-amz-target",""); query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        form=urllib.parse.parse_qs(body); action=query.get("Action",form.get("Action",[""]))[0]
        with self.lock: self.requests.append((self.command,self.path,target,action,body,self.headers.get("host","")))
        op=target.rsplit(".",1)[-1] if target else action
        if target.startswith("AmazonSQS"):
            self.sqs(op,body)
        elif target.startswith("AmazonSSM"):
            self.ssm(op,body)
        elif target.startswith("DynamoDB"):
            self.ddb(op,body)
        elif action in ("CreateTopic","ListTopics","ListTags","DeleteTopic","Publish"):
            self.sns(action,query)
        elif action=="GetCallerIdentity": self.xml("<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000000</Account><Arn>arn:aws:iam::000000000000:user/fake</Arn><UserId>fake</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>")
        elif action=="GetBucketTagging": self.xml("<GetBucketTaggingOutput><TagSet><Tag><Key>lmaws_test</Key><Value>queue01</Value></Tag></TagSet></GetBucketTaggingOutput>")
        elif self.command=="HEAD": self.send(404,"text/plain","")
        elif action=="GetBucketLocation": self.xml("<GetBucketLocationOutput xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>us-east-1</LocationConstraint></GetBucketLocationOutput>")
        elif action=="ListBuckets" or (self.path=="/" and not action and not target and self.command=="GET"): self.xml("<ListAllMyBucketsResult><Buckets><Bucket><Name>lmaws_fixture_bucket</Name><CreationDate>2020-01-01T00:00:00Z</CreationDate></Bucket></Buckets><Owner><ID>fake</ID></Owner></ListAllMyBucketsResult>")
        elif target.startswith("AWSLambda") or self.path.startswith("/2015-03-31/functions") or target.startswith("Logs_") or target.startswith("AmazonEC2ContainerService") or target.startswith("secretsmanager"):
            self.json_inventory("ListFunctions" if self.path.startswith("/2015-03-31/functions") else op)
        elif self.path.endswith("/DescribeAlarms"):
            self.cbor({"MetricAlarms":[{"AlarmName":"fake-alarm","AlarmArn":"arn:aws:cloudwatch:us-east-1:000000000000:alarm:fake-alarm","StateValue":"OK"}]})
        elif "Route53" in target or action=="ListHostedZones" or self.path.startswith("/2013-04-01/hostedzone"): self.xml("<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/ZFAKE</Id><Name>example.test.</Name><Config><PrivateZone>false</PrivateZone></Config><ResourceRecordSetCount>1</ResourceRecordSetCount></HostedZone></HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>")
        elif "Describe" in op or action.startswith("Describe"):
            self.describe(op)
        elif "List" in op or action.startswith("List"):
            self.listing(op)
        else: self.xml("<Response></Response>")
    def sqs(self,op,body):
        x=json.loads(body or "{}")
        if op=="CreateQueue":
            name=x.get("QueueName", "lmaws_queue01_q"); url="http://127.0.0.1:%s/%s"%(self.server.server_port,name)
            self.created[url]="queue"; self.json({"QueueUrl":url})
        elif op=="GetQueueUrl":
            self.error_json("QueueDoesNotExist", "fixture has no pre-existing queue")
        elif op=="ListQueues":
            response={"QueueUrls":["http://127.0.0.1:%s/lmaws_fixture_queue"%self.server.server_port]}
            if "NextToken" not in x: response["NextToken"]="page2"
            self.json(response)
        elif op=="ListQueueTags": self.json({"Tags":{"lmaws_test":"queue01"}})
        elif op=="DeleteQueue": self.json({})
        else: self.json({})
    def ssm(self,op,body):
        x=json.loads(body or "{}"); name=x.get("Name","lmaws_queue01_parameter")
        if op=="DescribeParameters": self.json({"Parameters":[{"Name":"lmaws_fixture_parameter","Type":"String","DataType":"text"}]})
        elif op=="ListTagsForResource": self.json({"TagList":[{"Key":"lmaws_test","Value":"queue01"}]})
        elif op=="PutParameter": self.created[name]="parameter"; self.json({"Version":1,"Tier":"Standard"})
        else: self.json({})
    def ddb(self,op,body):
        x=json.loads(body or "{}"); name=x.get("TableName","lmaws_table01")
        if op=="ListTables": self.json({"TableNames":["lmaws_fixture_table"]})
        elif op=="CreateTable": self.created[name]="table"; self.json({"TableDescription":{"TableName":name,"TableArn":"arn:aws:dynamodb:us-east-1:000000000000:table/"+name,"TableStatus":"ACTIVE"}})
        elif op=="DescribeTable": self.json({"Table":{"TableName":name,"TableArn":"arn:aws:dynamodb:us-east-1:000000000000:table/"+name,"TableStatus":"ACTIVE"}})
        elif op=="ListTagsOfResource": self.json({"Tags":[{"Key":"lmaws_test","Value":"queue01"}]})
        else: self.json({})
    def sns(self,op,q):
        name=q.get("Name",["lmaws_topic01"])[0]; arn="arn:aws:sns:us-east-1:000000000000:"+name
        if op=="CreateTopic": self.xml("<CreateTopicResponse><CreateTopicResult><TopicArn>%s</TopicArn></CreateTopicResult></CreateTopicResponse>"%arn)
        elif op=="ListTopics": self.xml("<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>arn:aws:sns:us-east-1:000000000000:lmaws_fixture_topic</TopicArn></member></Topics></ListTopicsResult></ListTopicsResponse>")
        elif op=="ListTags": self.xml("<ListTagsResponse><ListTagsResult><Tags><member><Key>lmaws_test</Key><Value>queue01</Value></member></Tags></ListTagsResult></ListTagsResponse>")
        else: self.xml("<Response></Response>")
    def describe(self,op):
        data={"DescribeInstances":"<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-fake</instanceId><instanceState><name>stopped</name></instanceState><instanceType>t3.micro</instanceType></item></instancesSet></item></reservationSet></DescribeInstancesResponse>","DescribeVpcs":"<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-fake</vpcId><cidrBlock>10.0.0.0/16</cidrBlock><state>available</state></item></vpcSet></DescribeVpcsResponse>","DescribeSecurityGroups":"<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-fake</groupId><groupName>fake</groupName><vpcId>vpc-fake</vpcId></item></securityGroupInfo></DescribeSecurityGroupsResponse>","DescribeAlarms":"<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member><AlarmName>fake-alarm</AlarmName><AlarmArn>arn:aws:cloudwatch:us-east-1:000000000000:alarm:fake-alarm</AlarmArn><StateValue>OK</StateValue></member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>","DescribeLogGroups":"{}"}
        self.xml(data.get(op,"<Response></Response>"))
    def json_inventory(self,op):
        data={"ListFunctions":{"Functions":[{"FunctionName":"lmaws_fixture_fn","FunctionArn":"arn:aws:lambda:us-east-1:000000000000:function:lmaws_fixture_fn","Runtime":"java21"}]},"DescribeLogGroups":{"logGroups":[{"arn":"arn:aws:logs:us-east-1:000000000000:log-group:lmaws_fixture_log","creationTime":1577836800000,"logGroupName":"lmaws_fixture_log","storedBytes":0,"metricFilterCount":0,"retentionInDays":7}]},"ListTagsLogGroup":{"tags":{"lmaws_test":"queue01"}},"ListSecrets":{"SecretList":[{"ARN":"arn:aws:secretsmanager:us-east-1:000000000000:secret:fixture","Name":"lmaws_fixture_secret"}]},"ListClusters":{"clusterArns":["arn:aws:ecs:us-east-1:000000000000:cluster/lmaws_fixture"]}}
        self.json(data.get(op,{}))
    def listing(self,op):
        data={"ListRoles":"<ListRolesResponse><ListRolesResult><Roles><member><RoleName>lmaws_fixture_role</RoleName><Arn>arn:aws:iam::000000000000:role/lmaws_fixture_role</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate></member></Roles></ListRolesResult></ListRolesResponse>"}
        self.xml(data.get(op,"<Response></Response>"))
    def json(self,obj): self.send(200,"application/x-amz-json-1.1",json.dumps(obj))
    def error_json(self,typ,message): self.send(400,"application/x-amz-json-1.1",json.dumps({"__type":typ,"message":message}))
    def cbor(self,obj): self.send_bytes(200,"application/cbor",cbor(obj))
    def xml(self,text): self.send(200,"text/xml",text)
    def send(self,code,typ,text):
        self.send_bytes(code,typ,text.encode())
    def send_bytes(self,code,typ,b):
        self.send_response(code); self.send_header("Content-Type",typ); self.send_header("x-amzn-requestid","fake"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)

def cbor(v):
    if isinstance(v,bool): return bytes([0xf5 if v else 0xf4])
    if v is None: return b"\xf6"
    if isinstance(v,int): return cbor_uint(0,v) if v>=0 else cbor_uint(1,-1-v)
    if isinstance(v,str):
        b=v.encode(); return cbor_uint(3,len(b))+b
    if isinstance(v,list): return cbor_uint(4,len(v))+b"".join(cbor(x) for x in v)
    if isinstance(v,dict): return cbor_uint(5,len(v))+b"".join(cbor(str(k))+cbor(x) for k,x in v.items())
    raise TypeError(type(v))
def cbor_uint(major,n):
    p=major<<5
    if n<24:return bytes([p+n])
    if n<256:return bytes([p+24,n])
    if n<65536:return bytes([p+25])+n.to_bytes(2,"big")
    return bytes([p+26])+n.to_bytes(4,"big")

def run(host):
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Fake); threading.Thread(target=server.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix="lmaws-fake-") as td:
        d=pathlib.Path(td); src=d/"fake.lms"; out=d/"fake.dslb"
        kinds=["identity","buckets","instances","vpcs","security_groups","tables","queues","topics","functions","log_groups","alarms","zones","secrets","parameters","clusters","roles"]
        lines=['aws = _dsl_ cli="lmaws";','let cloud = aws.region("us-east-1");']
        for k in kinds: lines += [f'let rows_{k} = cloud.{k}();',f'check(rows_{k}.len() > 0);']
        lines += ['check(str_len(rows_identity.at(0).get("id")) > 0);','check(str_starts_with(rows_buckets.at(0).get("name"), "lmaws_"));',
                  'let run = cloud.run("queue01", "ledger");','let q = run.queue("sample");','run.put(q, "message", "payload");',
                  'let b = run.bucket("sample");','run.put(b, "object", "payload");','let t = run.topic("sample");','run.put(t, "message", "payload");',
                  'let p = run.parameter("sample", "value");','run.put(p, "description", "safe");','let tb = run.table("sample");','run.put(tb, "pk", "value");',
                  'let lg = run.log_group("sample");','run.put(lg, "retention_days", "7");','check(run.remaining() == 6);','run.cleanup();','check(run.remaining() == 0);',
                  'end _dsl_','savedsl(aws, "'+str(out)+'");','r = system ${dsl_cli(aws)} --dsl "'+str(out)+'";','println(r);','assert(r.code == 0);']
        src.write_text("\n".join(lines)+"\n")
        env=dict(os.environ,LMAWS_ENDPOINT="http://127.0.0.1:%d"%server.server_port,LMAWS_FAKE="1")
        lines[0]='aws = _dsl_ cli='+json.dumps(str(host))+';'
        src.write_text("\n".join(lines)+"\n")
        p=subprocess.run(["lmscript",str(src)],cwd=d,env=env,text=True,capture_output=True,timeout=240)
        assert p.returncode==0,(p.stdout,p.stderr,Fake.requests[-20:], lines[55] if len(lines)>55 else "")
    server.shutdown();
    assert Fake.requests and all(r[5].startswith("127.0.0.1:") for r in Fake.requests),"non-loopback request"
    assert any("CreateQueue" in r[2] for r in Fake.requests),"SDK create request missing"
    assert any("DeleteQueue" in r[2] for r in Fake.requests),"SDK teardown request missing"
    print("PASS fake AWS SDK transport: 16 inventories, queue create/update/ownership/cleanup, loopback-only")
if __name__=="__main__": run(pathlib.Path(sys.argv[1]).resolve())
