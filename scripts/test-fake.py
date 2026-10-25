#!/usr/bin/env python3
"""Exercise the real AWS SDK transport against a loopback-only fake service."""
import http.server,json,os,pathlib,subprocess,sys,threading,tempfile,urllib.parse,hashlib,shutil,xml.etree.ElementTree as ET

ROOT=pathlib.Path(__file__).resolve().parents[1]
class Fake(http.server.BaseHTTPRequestHandler):
    requests=[]; created={}; ever=set(); deleted=set(); objects={}; lock=threading.Lock()
    def log_message(self,*a): pass
    def do_POST(self): self.handle_request()
    def do_GET(self): self.handle_request()
    def do_PUT(self): self.handle_request()
    def do_DELETE(self): self.handle_request()
    def do_HEAD(self): self.handle_request()
    def handle_request(self):
        n=int(self.headers.get("content-length","0")); body=self.rfile.read(n).decode("utf-8", "replace")
        target=self.headers.get("x-amz-target",""); query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
        form=urllib.parse.parse_qs(body); action=query.get("Action",form.get("Action",[""]))[0]
        with self.lock: self.requests.append((self.command,self.path,target,action,body,self.headers.get("host","")))
        op=target.rsplit(".",1)[-1] if target else action
        if target.startswith("AmazonSQS"):
            self.sqs(op,body)
        elif target.startswith("AmazonSSM"):
            self.ssm(op,body)
        elif target.startswith("DynamoDB"):
            self.ddb(op,body)
        elif action in ("CreateTopic","ListTopics","ListTags","ListTagsForResource","DeleteTopic","Publish"):
            self.sns(action,{**query,**form})
        elif action=="GetCallerIdentity": self.xml("<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000000</Account><Arn>arn:aws:iam::000000000000:user/fake</Arn><UserId>fake</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>")
        elif urllib.parse.urlsplit(self.path).path.startswith("/lmaws-"): return self.s3(query,body)
        elif action=="GetBucketTagging" or "tagging" in query: self.send_bytes(200,"application/xml",b'<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>lmaws_test</Key><Value>queue01</Value></Tag></TagSet></Tagging>')
        elif self.command=="HEAD": self.send(404,"text/plain","")
        elif action=="GetBucketLocation": self.xml("<GetBucketLocationOutput xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>us-east-1</LocationConstraint></GetBucketLocationOutput>")
        elif "list-type" in query: self.xml("<ListBucketResult><Name>fixture</Name><Prefix></Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>")
        elif action=="ListBuckets" or (self.path=="/" and not action and not target and self.command=="GET"): self.xml("<ListAllMyBucketsResult><Buckets><Bucket><Name>lmaws_fixture_bucket</Name><CreationDate>2020-01-01T00:00:00Z</CreationDate></Bucket></Buckets><Owner><ID>fake</ID></Owner></ListAllMyBucketsResult>")
        elif target.startswith("AWSLambda") or self.path.startswith("/2015-03-31/functions") or target.startswith("Logs_") or target.startswith("AmazonEC2ContainerService") or target.startswith("secretsmanager"):
            self.json_inventory("ListFunctions" if self.path.startswith("/2015-03-31/functions") else op,body)
        elif self.path.endswith("/DescribeAlarms"):
            self.cbor({"MetricAlarms":[{"AlarmName":"fake-alarm","AlarmArn":"arn:aws:cloudwatch:us-east-1:000000000000:alarm:fake-alarm","StateValue":"OK"}]})
        elif "Route53" in target or action=="ListHostedZones" or self.path.startswith("/2013-04-01/hostedzone"): self.xml("<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/ZFAKE</Id><Name>example.test.</Name><Config><PrivateZone>false</PrivateZone></Config><ResourceRecordSetCount>1</ResourceRecordSetCount></HostedZone></HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>")
        elif "Describe" in op or action.startswith("Describe"):
            self.describe(op)
        elif "List" in op or action.startswith("List"):
            self.listing(op)
        else: self.xml("<Response></Response>")
    def remember(self,kind,identifier,tags):
        assert tags and tags.get("lmaws_test"), (kind,"missing ownership tag")
        self.created[(kind,identifier)]=dict(tags); self.ever.add(kind)
    def sqs(self,op,body):
        x=json.loads(body or "{}")
        url=x.get("QueueUrl","")
        if op=="CreateQueue":
            name=x["QueueName"]; assert name.startswith("lmaws_")
            url="http://127.0.0.1:%s/%s"%(self.server.server_port,name)
            self.remember("queue",url,x.get("tags",{}));self.json({"QueueUrl":url})
        elif op=="GetQueueUrl":
            found=[i for k,i in self.created if k=="queue" and i.endswith("/"+x["QueueName"])]
            if found:self.json({"QueueUrl":found[0]})
            else:self.error_json("QueueDoesNotExist","no existing fixture queue")
        elif op=="ListQueues":
            page="2" if "NextToken" in x else "1"
            response={"QueueUrls":["http://127.0.0.1:%s/lmaws_fixture_queue%s"%(self.server.server_port,page)]}
            if page=="1":response["NextToken"]="page2"
            self.json(response)
        elif op=="ListQueueTags":self.json({"Tags":self.created.get(("queue",url),{})})
        elif op=="SendMessage":
            if x.get("MessageBody")=="deny-fixture":self.error_json("AccessDenied","TOP_SECRET_SENTINEL")
            else:self.json({"MD5OfMessageBody":hashlib.md5(x.get("MessageBody","").encode()).hexdigest(),"MessageId":"fake-message-id"})
        elif op=="DeleteQueue":
            assert ("queue",url) in self.created,"attempted foreign queue delete"
            self.created.pop(("queue",url));self.json({})
        else:self.json({})
    def ssm(self,op,body):
        x=json.loads(body or "{}");name=x.get("Name",x.get("ResourceId",""))
        if op=="DescribeParameters":self.json({"Parameters":[{"Name":"lmaws_fixture_parameter","Type":"String"}]})
        elif op=="ListTagsForResource":self.json({"TagList":[{"Key":k,"Value":v} for k,v in self.created.get(("parameter",name),{}).items()]})
        elif op=="PutParameter":
            assert x.get("Tier")=="Standard", "parameter tier must be explicitly free-tier Standard"
            if not x.get("Overwrite"):
                assert name.startswith("lmaws_")
                self.remember("parameter",name,{t["Key"]:t["Value"] for t in x.get("Tags",[])})
            else:assert ("parameter",name) in self.created
            self.json({"Version":1,"Tier":"Standard"})
        elif op=="DeleteParameter":self.created.pop(("parameter",name));self.json({})
        else:self.json({})
    def ddb(self,op,body):
        x=json.loads(body or "{}");name=x.get("TableName",x.get("ResourceArn","").rsplit("/",1)[-1]);arn="arn:aws:dynamodb:us-east-1:000000000000:table/"+name
        if op=="ListTables":self.json({"TableNames":["lmaws_fixture_table"]})
        elif op=="CreateTable":
            assert name.startswith("lmaws_")
            self.remember("table",name,{t["Key"]:t["Value"] for t in x.get("Tags",[])})
            self.json({"TableDescription":{"TableName":name,"TableArn":arn,"TableStatus":"ACTIVE"}})
        elif op=="DescribeTable":
            if name in self.deleted:self.error_json("ResourceNotFoundException","table deleted")
            else:self.json({"Table":{"TableName":name,"TableArn":arn,"TableStatus":"ACTIVE"}})
        elif op=="ListTagsOfResource":self.json({"Tags":[{"Key":k,"Value":v} for k,v in self.created.get(("table",name),{}).items()]})
        elif op=="DeleteTable":self.created.pop(("table",name));self.deleted.add(name);self.json({"TableDescription":{"TableName":name,"TableStatus":"DELETING"}})
        else:self.json({})
    def sns(self,op,q):
        name=q.get("Name",[""])[0];arn=q.get("ResourceArn",q.get("TopicArn",["arn:aws:sns:us-east-1:000000000000:"+name]))[0]
        if op=="CreateTopic":
            assert name.startswith("lmaws_")
            tags={q[k][0]:q[k[:-3]+"Value"][0] for k in q if k.startswith("Tags.member.") and k.endswith("Key")}
            self.remember("topic",arn,tags)
            self.xml("<CreateTopicResponse><CreateTopicResult><TopicArn>%s</TopicArn></CreateTopicResult></CreateTopicResponse>"%arn)
        elif op=="ListTopics":self.xml("<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>arn:aws:sns:us-east-1:000000000000:lmaws_fixture_topic</TopicArn></member></Topics></ListTopicsResult></ListTopicsResponse>")
        elif op in ("ListTags","ListTagsForResource"):
            tags="".join("<member><Key>%s</Key><Value>%s</Value></member>"%(k,v) for k,v in self.created.get(("topic",arn),{}).items())
            self.xml("<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>"+tags+"</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>")
        elif op=="DeleteTopic":self.created.pop(("topic",arn));self.xml("<DeleteTopicResponse/>")
        elif op=="Publish":self.xml("<PublishResponse><PublishResult><MessageId>fake</MessageId></PublishResult></PublishResponse>")
        else:self.xml("<Response/>")
    def s3(self,query,body):
        parts=urllib.parse.unquote(urllib.parse.urlsplit(self.path).path).strip("/").split("/",1);bucket=parts[0];key=parts[1] if len(parts)>1 else None
        identity=("bucket",bucket)
        if self.command=="HEAD":return self.send(404,"application/xml","")
        if "tagging" in query:
            if self.command=="PUT":
                doc=ET.fromstring(body);tags={t.findtext("{*}Key"):t.findtext("{*}Value") for t in doc.findall(".//{*}Tag")}
                self.remember("bucket",bucket,tags);return self.send(200,"application/xml","")
            tags="".join("<Tag><Key>%s</Key><Value>%s</Value></Tag>"%(k,v) for k,v in self.created[identity].items())
            return self.xml('<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>'+tags+'</TagSet></Tagging>')
        if "list-type" in query:
            objects="".join("<Contents><Key>"+k+"</Key></Contents>" for k in sorted(self.objects.get(bucket,set())))
            return self.xml("<ListBucketResult><Name>"+bucket+"</Name><IsTruncated>false</IsTruncated>"+objects+"</ListBucketResult>")
        if self.command=="PUT":
            if key is not None:self.objects.setdefault(bucket,set()).add(key)
            return self.send(200,"application/xml","")
        if self.command=="DELETE":
            if key is not None:self.objects.setdefault(bucket,set()).discard(key)
            else:
                assert not self.objects.get(bucket),"bucket deleted with objects"
                self.created.pop(identity)
            return self.send(204,"application/xml","")
        return self.xml("<Response/>")
    def describe(self,op):
        data={"DescribeInstances":"<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-fake</instanceId><instanceState><name>stopped</name></instanceState><instanceType>t3.micro</instanceType></item></instancesSet></item></reservationSet></DescribeInstancesResponse>","DescribeVpcs":"<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-fake</vpcId><cidrBlock>10.0.0.0/16</cidrBlock><state>available</state></item></vpcSet></DescribeVpcsResponse>","DescribeSecurityGroups":"<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-fake</groupId><groupName>fake</groupName><vpcId>vpc-fake</vpcId></item></securityGroupInfo></DescribeSecurityGroupsResponse>","DescribeAlarms":"<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member><AlarmName>fake-alarm</AlarmName><AlarmArn>arn:aws:cloudwatch:us-east-1:000000000000:alarm:fake-alarm</AlarmArn><StateValue>OK</StateValue></member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>","DescribeLogGroups":"{}"}
        self.xml(data.get(op,"<Response></Response>"))
    def json_inventory(self,op,body="{}"):
        x=json.loads(body or "{}");name=x.get("logGroupName","")
        if op=="CreateLogGroup":
            assert name.startswith("lmaws_")
            self.remember("log_group",name,x.get("tags",{}));return self.json({})
        if op=="ListTagsLogGroup":return self.json({"tags":self.created.get(("log_group",name),{})})
        if op=="DeleteLogGroup":self.created.pop(("log_group",name));return self.json({})
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
        self.send_response(code); self.send_header("Content-Type",typ); self.send_header("x-amzn-requestid","fake"); self.send_header("x-amz-bucket-region","us-east-1"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)

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
    host_prefix=(["cmd.exe","/c",str(host)] if host.suffix==".cmd" else [str(host)])
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Fake)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    env=dict(os.environ,LMAWS_ENDPOINT="http://127.0.0.1:%d"%server.server_port,AWS_EC2_METADATA_DISABLED="true",AWS_PROFILE="lmaws-fake-no-such-profile")
    env.pop("LMAWS_LIVE",None)
    runner=shutil.which("lmscript");assert runner,"lmscript missing"
    try:
        with tempfile.TemporaryDirectory(prefix="lmaws-fake-") as td:
            work=pathlib.Path(td);schema=work/"schema.json"
            schema.write_bytes(subprocess.check_output(host_prefix+["--dsl-schema"],env=env,timeout=30))
            def execute(name,body,expected=0):
                src=work/(name+".lms");out=work/(name+".dslb")
                src.write_text('p = _dsl_ schema='+json.dumps(str(schema))+';\n'+body+'\nend _dsl_\nsavedsl(p, '+json.dumps(str(out))+');\n')
                compiled=subprocess.run([runner,str(src)],cwd=work,env=env,text=True,encoding="utf-8",capture_output=True,timeout=60)
                assert compiled.returncode==0,compiled.stderr
                result=subprocess.run(host_prefix+["--dsl",str(out)],cwd=work,env=env,text=True,encoding="utf-8",capture_output=True,timeout=180)
                assert result.returncode==expected,(name,result.returncode,result.stdout,result.stderr,Fake.requests[-8:])
                assert "TOP_SECRET_SENTINEL" not in result.stdout+result.stderr,"AWS error message leaked"
                return result
            kinds=["identity","buckets","instances","vpcs","security_groups","tables","queues","topics","functions","log_groups","alarms","zones","secrets","parameters","clusters","roles"]
            lines=['let cloud = aws.region("us-east-1");']
            for kind in kinds:
                lines += ['let rows_'+kind+' = cloud.'+kind+'();','check(rows_'+kind+'.len() == '+('2' if kind=='queues' else '1')+');']
            lines += ['check(rows_instances.at(0).get("state") == "stopped");','check(rows_parameters.at(0).get("value") == "[redacted]");','let run = cloud.run("queue01", "lmaws-main.jsonl");']
            for kind in ['queue','bucket','topic','parameter','table','log_group']:
                args='"sample", "nonsecret"' if kind=='parameter' else '"sample"'
                lines += ['let resource_'+kind+' = run.'+kind+'('+args+');','run.put(resource_'+kind+', "'+('retention_days' if kind=='log_group' else 'object')+'", "'+('7' if kind=='log_group' else 'payload')+'");']
            lines += ['check(run.remaining() == 6);','run.cleanup();','check(run.remaining() == 0);']
            execute('all-services','\n'.join(lines))
            assert not Fake.created,('resources not deleted',Fake.created)
            execute('failure','let cloud = aws.region("us-east-1"); let run = cloud.run("failure01", "lmaws-failure.jsonl"); let q = run.queue("cleanup"); check(false);',3)
            assert not Fake.created,'exception teardown failed'
            execute('redaction','let cloud = aws.region("us-east-1"); let run = cloud.run("deny01", "lmaws-deny.jsonl"); let q = run.queue("error"); run.put(q, "message", "deny-fixture");',3)
            assert not Fake.created,'AWS error teardown failed'
            assert Fake.ever=={'queue','bucket','topic','parameter','table','log_group'},Fake.ever
            assert all(request[5].startswith('127.0.0.1:') for request in Fake.requests),'non-loopback HTTP host'
            assert not any('DeleteQueue' in r[2] and 'lmaws_fixture' in r[4] for r in Fake.requests),'legacy fixture mutated'
            proof=dict(inventories=16,write_lifecycles=6,pagination_rows=2,exception_teardown=True,aws_error_redaction=True,all_created_deleted=True,http_requests=len(Fake.requests),loopback_only=True)
            (pathlib.Path(tempfile.gettempdir())/'lmaws-fake-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
            print('PASS fake SDK: 16 inventories, 6 tagged lifecycles, pagination, failure teardown, AWS error redaction; all deleted')
    finally:server.shutdown();server.server_close()
if __name__=="__main__":run(pathlib.Path(sys.argv[1]).resolve())
