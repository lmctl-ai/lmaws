#!/usr/bin/env python3
"""Exercise the real AWS SDK transport against a loopback-only fake service."""
import fake_ec2,http.server,json,os,pathlib,subprocess,sys,threading,tempfile,urllib.parse,hashlib,shutil,xml.etree.ElementTree as ET

ROOT=pathlib.Path(__file__).resolve().parents[1]
class Fake(http.server.BaseHTTPRequestHandler):
    requests=[]; created={}; ever=set(); deleted=set(); objects={}; iam_policies={
        "arn:aws:iam::000000000000:policy/lmaws_attached_test": {
            "name": "lmaws_attached_test",
            "arn": "arn:aws:iam::000000000000:policy/lmaws_attached_test",
            "attachment_count": 1,
            "next_ver": 2,
            "versions": [{"id": "v1", "default": True, "created": "2026-01-01T00:00:00Z", "doc": '{"Version":"2012-10-17","Statement":[{"Sid":"Reads","Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}'}]
        }
    }; lock=threading.Lock()
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
        elif action in ("GetPolicy","GetPolicyVersion","ListPolicyVersions","CreatePolicy","CreatePolicyVersion","DeletePolicyVersion","DeletePolicy"):
            self.iam_policy(action,{**query,**form})
        elif action=="GetFederationToken":
            q={**query,**form}
            fname=q.get("Name",[""])[0];dur=int(q.get("DurationSeconds",["3600"])[0])
            if fname=="awsspot-local-fail":
                return self.send_bytes(403,"text/xml",b"<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>TOP_SECRET_SENTINEL</Message></Error></ErrorResponse>")
            assert fname in ("awsspot-local-default","awsspot-local-lmaws","awsspot-local-lmaws-ec2","awsspot-local-lmaws-web"),fname
            assert 900<=dur<=129600,dur
            if fname=="awsspot-local-default":
                assert q.get("PolicyArns.member.1.arn",[""])[0]=="arn:aws:iam::aws:policy/ReadOnlyAccess",q
                assert "DenySecretValueRetrieval" in q.get("Policy",[""])[0],q
            else:
                assert q.get("PolicyArns.member.1.arn",[""])[0]=="arn:aws:iam::000000000000:policy/lmaws_session",q
                assert "Policy" not in q,q
            self.xml("<GetFederationTokenResponse><GetFederationTokenResult><Credentials><AccessKeyId>ASIAFAKECREDPROC</AccessKeyId><SecretAccessKey>FAKESECRETCREDPROC</SecretAccessKey><SessionToken>FAKETOKENCREDPROC</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></GetFederationTokenResult></GetFederationTokenResponse>")
        elif action=="GetCallerIdentity": self.xml("<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000000</Account><Arn>arn:aws:iam::000000000000:user/fake</Arn><UserId>fake</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>")
        elif urllib.parse.urlsplit(self.path).path.startswith("/lmaws-"): return self.s3(query,body)
        elif action=="GetBucketTagging" or "tagging" in query: self.send_bytes(200,"application/xml",b'<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>lmaws_test</Key><Value>queue01</Value></Tag></TagSet></Tagging>')
        elif self.command=="HEAD": self.send(404,"text/plain","")
        elif action=="GetBucketLocation": self.xml("<GetBucketLocationOutput xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>us-east-1</LocationConstraint></GetBucketLocationOutput>")
        elif "list-type" in query: self.xml("<ListBucketResult><Name>fixture</Name><Prefix></Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>")
        elif action=="ListBuckets" or (self.path=="/" and not action and not target and self.command=="GET"): self.xml("<ListAllMyBucketsResult><Buckets><Bucket><Name>lmaws_fixture_bucket</Name><BucketRegion>us-west-2</BucketRegion><CreationDate>2020-01-01T00:00:00Z</CreationDate></Bucket></Buckets><Owner><ID>fake</ID></Owner></ListAllMyBucketsResult>")
        elif target.startswith("AWSLambda") or self.path.startswith("/2015-03-31/functions") or target.startswith("Logs_") or target.startswith("AmazonEC2ContainerService") or target.startswith("secretsmanager"):
            self.json_inventory("ListFunctions" if self.path.startswith("/2015-03-31/functions") else op,body)
        elif action in fake_ec2.EC2_ACTIONS and fake_ec2.handle(self,action,{**query,**form}): pass
        elif self.path.endswith("/GetMetricStatistics"):
            self.cbor({"Label":"metric","Datapoints":[{"Timestamp":CborTag(1,1793000000),"Average":1.5,"Maximum":2.0,"Sum":18.0,"Unit":"Count"}]})
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
        if op=="GetParameter":
            if not name.startswith("/aws/service/"):return self.error_json("AccessDeniedException","private parameter")
            return self.json({"Parameter":{"Name":name,"Type":"String","Value":"ami-0123456789abcdef0","Version":1}})
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
    def iam_policy(self,op,q):
        arn=q.get("PolicyArn",[""])[0];name=q.get("PolicyName",[""])[0];ver_id=q.get("VersionId",[""])[0];doc=q.get("PolicyDocument",[""])[0]
        if op=="GetPolicy":
            pol=self.iam_policies.get(arn)
            if not pol:return self.send(404,"text/xml","<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>Policy not found</Message></Error></ErrorResponse>")
            def_ver=next(v["id"] for v in pol["versions"] if v["default"])
            return self.xml(f"<GetPolicyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><GetPolicyResult><Policy><PolicyName>{pol['name']}</PolicyName><Arn>{pol['arn']}</Arn><DefaultVersionId>{def_ver}</DefaultVersionId><AttachmentCount>{pol['attachment_count']}</AttachmentCount><CreateDate>2026-01-01T00:00:00Z</CreateDate><UpdateDate>2026-01-01T00:00:00Z</UpdateDate></Policy></GetPolicyResult></GetPolicyResponse>")
        elif op=="GetPolicyVersion":
            pol=self.iam_policies.get(arn)
            ver=next((v for v in (pol["versions"] if pol else []) if v["id"]==ver_id),None)
            if not ver:return self.send(404,"text/xml","<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>Version not found</Message></Error></ErrorResponse>")
            encoded=urllib.parse.quote(ver["doc"],safe="")
            is_def="true" if ver["default"] else "false"
            return self.xml(f"<GetPolicyVersionResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><GetPolicyVersionResult><PolicyVersion><Document>{encoded}</Document><VersionId>{ver['id']}</VersionId><IsDefaultVersion>{is_def}</IsDefaultVersion><CreateDate>{ver['created']}</CreateDate></PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>")
        elif op=="ListPolicyVersions":
            pol=self.iam_policies.get(arn)
            if not pol:return self.send(404,"text/xml","<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>Policy not found</Message></Error></ErrorResponse>")
            members="".join(f"<member><VersionId>{v['id']}</VersionId><IsDefaultVersion>{'true' if v['default'] else 'false'}</IsDefaultVersion><CreateDate>{v['created']}</CreateDate></member>" for v in pol["versions"])
            return self.xml(f"<ListPolicyVersionsResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><ListPolicyVersionsResult><Versions>{members}</Versions><IsTruncated>false</IsTruncated></ListPolicyVersionsResult></ListPolicyVersionsResponse>")
        elif op=="CreatePolicy":
            assert name.startswith("lmaws_"),name
            arn=f"arn:aws:iam::000000000000:policy/{name}"
            self.iam_policies[arn]={"name":name,"arn":arn,"attachment_count":0,"next_ver":2,"versions":[{"id":"v1","default":True,"created":"2026-01-01T00:00:01Z","doc":doc}]}
            return self.xml(f"<CreatePolicyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><CreatePolicyResult><Policy><PolicyName>{name}</PolicyName><Arn>{arn}</Arn><DefaultVersionId>v1</DefaultVersionId><AttachmentCount>0</AttachmentCount></Policy></CreatePolicyResult></CreatePolicyResponse>")
        elif op=="CreatePolicyVersion":
            pol=self.iam_policies[arn]
            assert len(pol["versions"])<5,"AWS IAM allows at most 5 policy versions"
            set_def=q.get("SetAsDefault",["false"])[0].lower()=="true"
            if set_def:
                for v in pol["versions"]:v["default"]=False
            vid=f"v{pol['next_ver']}";pol["next_ver"]+=1
            created=f"2026-01-01T00:00:0{pol['next_ver']}Z"
            pol["versions"].append({"id":vid,"default":set_def,"created":created,"doc":doc})
            return self.xml(f"<CreatePolicyVersionResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><CreatePolicyVersionResult><PolicyVersion><VersionId>{vid}</VersionId><IsDefaultVersion>{'true' if set_def else 'false'}</IsDefaultVersion><CreateDate>{created}</CreateDate></PolicyVersion></CreatePolicyVersionResult></CreatePolicyVersionResponse>")
        elif op=="DeletePolicyVersion":
            pol=self.iam_policies[arn]
            ver=next(v for v in pol["versions"] if v["id"]==ver_id)
            assert not ver["default"],"cannot delete default policy version"
            pol["versions"]=[v for v in pol["versions"] if v["id"]!=ver_id]
            return self.xml("<DeletePolicyVersionResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"/>")
        elif op=="DeletePolicy":
            pol=self.iam_policies[arn]
            assert pol["attachment_count"]==0,"cannot delete attached policy"
            assert len(pol["versions"])==1 and pol["versions"][0]["default"],"must delete non-default versions before DeletePolicy"
            self.iam_policies.pop(arn)
            return self.xml("<DeletePolicyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"/>")
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
    def ec2_error(self,code,message): self.send(400,"text/xml","<Response><Errors><Error><Code>%s</Code><Message>%s</Message></Error></Errors><RequestID>fake</RequestID></Response>"%(code,message))
    def error_json(self,typ,message): self.send(400,"application/x-amz-json-1.1",json.dumps({"__type":typ,"message":message}))
    def cbor(self,obj): self.send_bytes(200,"application/cbor",cbor(obj))
    def xml(self,text): self.send(200,"text/xml",text)
    def send(self,code,typ,text):
        self.send_bytes(code,typ,text.encode())
    def send_bytes(self,code,typ,b):
        self.send_response(code); self.send_header("Content-Type",typ); self.send_header("x-amzn-requestid","fake"); self.send_header("x-amz-bucket-region","us-east-1"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)

class CborTag:
    def __init__(self,tag,value): self.tag=tag;self.value=value
def cbor(v):
    if isinstance(v,CborTag): return cbor_uint(6,v.tag)+cbor(v.value)
    if isinstance(v,float): return fake_ec2.cbor_float(v)
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
    env=dict(os.environ,LMAWS_FAST_WAITS="1",LMAWS_ENDPOINT="http://127.0.0.1:%d"%server.server_port,AWS_EC2_METADATA_DISABLED="true",AWS_PROFILE="lmaws-fake-no-such-profile")
    env.pop("LMAWS_LIVE",None)
    runner=shutil.which("lmscript");assert runner,"lmscript missing"
    try:
        with tempfile.TemporaryDirectory(prefix="lmaws-fake-") as td:
            work=pathlib.Path(td);schema=work/"schema.json"
            schema.write_bytes(subprocess.check_output(host_prefix+["--dsl-schema"],env=env,timeout=30))
            def execute(name,body,expected=0,extra=None,extra_env=None,extra_flags=None):
                src=work/(name+".lms");out=work/(name+".dslb")
                src.write_text('p = _dsl_ schema='+json.dumps(str(schema))+';\n'+body+'\nend _dsl_\nsavedsl(p, '+json.dumps(str(out))+');\n')
                compiled=subprocess.run([runner,str(src)],cwd=work,env=env,text=True,encoding="utf-8",capture_output=True,timeout=60)
                assert compiled.returncode==0,compiled.stderr
                run_env=dict(env,**(extra or {}),**(extra_env or {}))
                flags=list(extra_flags or [])
                result=subprocess.run(host_prefix+flags+["--dsl",str(out)],cwd=work,env=run_env,text=True,encoding="utf-8",capture_output=True,timeout=180)
                assert result.returncode==expected,(name,result.returncode,result.stdout,result.stderr,Fake.requests[-8:])
                assert "TOP_SECRET_SENTINEL" not in result.stdout+result.stderr,"AWS error message leaked"
                return result
            kinds=["identity","buckets","instances","vpcs","security_groups","tables","queues","topics","functions","log_groups","alarms","zones","secrets","parameters","clusters","roles"]
            lines=['let cloud = aws.region("us-east-1");']
            for kind in kinds:
                lines += ['let rows_'+kind+' = cloud.'+kind+'();','check(rows_'+kind+'.len() == '+('2' if kind=='queues' else '1')+');']
            lines += ['check(rows_instances.at(0).get("state") == "stopped"); check(rows_instances.at(0).get("tagged") == "false"); check(rows_buckets.at(0).get("region") == "us-west-2");','check(rows_parameters.at(0).get("value") == "[redacted]");','let run = cloud.run("queue01", "lmaws-main.jsonl");']
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

            # IAM managed-policy fake transport + 4-way profile/mutation guard + 5-version rotation + attached delete refusal
            valid_doc=json.dumps({"Version":"2012-10-17","Statement":[{"Sid":"Reads","Effect":"Allow","Action":["sts:GetCallerIdentity","s3:ListAllMyBuckets"],"Resource":"*"},{"Sid":"Named","Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::lmaws-*"}]})
            # 1) admin profile refused on regular resource mutation
            admin_reg=execute('admin-regular-refused','let cloud = aws.region("us-east-1"); let run = cloud.run("adm01", "lmaws-adm.jsonl"); let q = run.queue("blocked");',3,extra_env={"AWS_PROFILE":"admin","LMAWS_ADMIN_GRANT":"1"})
            assert "reserved exclusively for lmaws_ IAM policy grants" in admin_reg.stdout+admin_reg.stderr
            # 2) lmaws profile refused on IAM policy write
            lmaws_iam=execute('lmaws-iam-refused','let cloud = aws.region("us-east-1"); let r = cloud.iam_policy_put("lmaws_session", '+json.dumps(valid_doc)+', true);',3,extra_env={"AWS_PROFILE":"lmaws","LMAWS_ADMIN_GRANT":"1"},extra_flags=["--apply"])
            assert "AWS_PROFILE=admin" in lmaws_iam.stdout+lmaws_iam.stderr
            # 3) admin without LMAWS_ADMIN_GRANT=1 refused on IAM policy write
            no_grant=execute('admin-no-grant','let cloud = aws.region("us-east-1"); let r = cloud.iam_policy_put("lmaws_session", '+json.dumps(valid_doc)+', true);',3,extra_env={"AWS_PROFILE":"admin","LMAWS_ADMIN_GRANT":"0"},extra_flags=["--apply"])
            assert "LMAWS_ADMIN_GRANT=1" in no_grant.stdout+no_grant.stderr
            # 4) admin without --apply refused on IAM policy write
            no_apply=execute('admin-no-apply','let cloud = aws.region("us-east-1"); let r = cloud.iam_policy_put("lmaws_session", '+json.dumps(valid_doc)+', true);',3,extra_env={"AWS_PROFILE":"admin","LMAWS_ADMIN_GRANT":"1"})
            assert "--apply" in no_apply.stdout+no_apply.stderr
            # 5) Dry-run put makes zero IAM mutations, then apply creates v1, rotates across 6 puts (deleting oldest non-default v1 at 5-version cap), refuses deleting attached policy, and deletes unattached policy
            iam_script='\n'.join([
                'let cloud = aws.region("us-east-1");',
                'let doc = ' + json.dumps(valid_doc) + ';',
                'let lint = cloud.iam_policy_lint(doc);',
                'check(lint.get("valid") == "true");',
                'let absent = cloud.iam_policy_get("lmaws_session");',
                'check(absent.get("exists") == "false");',
                'let dry = cloud.iam_policy_put("lmaws_session", doc, false);',
                'check(dry.get("applied") == "false");',
                'check(dry.get("action") == "dry_run");',
                'check(cloud.iam_policy_get("lmaws_session").get("exists") == "false");',
                'let c1 = cloud.iam_policy_put("lmaws_session", doc, true);',
                'check(c1.get("action") == "created");',
                'check(c1.get("version_id") == "v1");',
                'check(cloud.iam_policy_put("lmaws_session", doc, true).get("version_id") == "v2");',
                'check(cloud.iam_policy_put("lmaws_session", doc, true).get("version_id") == "v3");',
                'check(cloud.iam_policy_put("lmaws_session", doc, true).get("version_id") == "v4");',
                'let c5 = cloud.iam_policy_put("lmaws_session", doc, true);',
                'check(c5.get("version_id") == "v5");',
                'check(c5.get("deleted_version_id") == "");',
                'let c6 = cloud.iam_policy_put("lmaws_session", doc, true);',
                'check(c6.get("version_id") == "v6");',
                'check(c6.get("deleted_version_id") == "v1");',
                'let vers = cloud.iam_policy_versions("lmaws_session");',
                'check(vers.len() == 5);',
                'check(vers.at(0).get("version_id") == "v2");',
                'check(vers.at(4).get("version_id") == "v6");',
                'check(vers.at(4).get("is_default") == "true");',
                'let got = cloud.iam_policy_get("lmaws_session");',
                'check(got.get("exists") == "true");',
                'check(got.get("default_version_id") == "v6");',
                'check(got.get("arn") == "arn:aws:iam::************:policy/lmaws_session");',
                'let del = cloud.iam_policy_delete("lmaws_session", true);',
                'check(del.get("action") == "deleted");',
                'check(del.get("deleted_versions") == "v2,v3,v4,v5");',
                'check(cloud.iam_policy_get("lmaws_session").get("exists") == "false");',
            ])
            execute('iam-lifecycle',iam_script,0,extra_env={"AWS_PROFILE":"admin","LMAWS_ADMIN_GRANT":"1"},extra_flags=["--apply"])
            attached_del=execute('iam-delete-attached-refused','let cloud = aws.region("us-east-1"); cloud.iam_policy_delete("lmaws_attached_test", true);',3,extra_env={"AWS_PROFILE":"admin","LMAWS_ADMIN_GRANT":"1"},extra_flags=["--apply"])
            assert "attached to 1 entity/entities" in attached_del.stdout+attached_del.stderr

            # Credential-process CLI + session_doctor fake transport checks
            test_aws_dir=work/"aws_cfg";test_cache_dir=work/"cred_cache"
            test_aws_dir.mkdir();test_cache_dir.mkdir()
            (test_aws_dir/"credentials").write_text("[agent-issuer]\naws_access_key_id = AKIAFAKEADMIN\naws_secret_access_key = SECRETFAKEADMIN\n")
            (test_aws_dir/"config").write_text("[default]\nregion = us-east-1\ncredential_process = lmaws --credential-process default\n[profile lmaws]\nregion = us-east-1\ncredential_process = lmaws --credential-process lmaws\n[profile lmaws-ec2]\nregion = us-east-1\ncredential_process = lmaws --credential-process lmaws-ec2\n[profile lmaws-web]\nregion = us-east-1\ncredential_process = lmaws --credential-process lmaws-web\n")
            test_policy=test_aws_dir/"session-tools/tasks/iam-snapshots/local-default-session.json"
            test_policy.parent.mkdir(parents=True)
            test_policy.write_text(json.dumps({"Statement": [{"Sid":"DenySecretValueRetrieval","Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}))
            cp_env=dict(env,LMAWS_TEST_AWS_DIR=str(test_aws_dir),LMAWS_CREDENTIAL_CACHE_DIR=str(test_cache_dir))
            for mode in ("default","lmaws"):
                cp_res=subprocess.run(host_prefix+["--credential-process",mode],cwd=work,env=cp_env,text=True,encoding="utf-8",capture_output=True,timeout=60)
                assert cp_res.returncode==0,(mode,cp_res.stdout,cp_res.stderr)
                assert cp_res.stderr==""
                cp_json=json.loads(cp_res.stdout)
                assert cp_json["Version"]==1 and cp_json["AccessKeyId"]=="ASIAFAKECREDPROC" and cp_json["Expiration"]=="2099-01-01T00:00:00Z"
            req_count_before=len(Fake.requests)
            cp_cached=subprocess.run(host_prefix+["--credential-process","lmaws"],cwd=work,env=cp_env,text=True,encoding="utf-8",capture_output=True,timeout=60)
            assert cp_cached.returncode==0 and len(Fake.requests)==req_count_before,"disk 0600 cache should avoid STS call"
            cp_bad_src=subprocess.run(host_prefix+["--credential-process","lmaws","--source-profile","lmaws"],cwd=work,env=cp_env,text=True,encoding="utf-8",capture_output=True,timeout=60)
            assert cp_bad_src.returncode==1 and cp_bad_src.stdout=="" and cp_bad_src.stderr.strip()=="AWS scoped profile unavailable; check the isolated source profile and session policy; agents never use admin."

            doctor_script="\n".join([
                'let cloud = aws.region("us-east-1");',
                'let rows = cloud.session_doctor();',
                'check(rows.len() == 12);',
                'check(rows.filter("kind", "profile").len() == 4);',
                'check(rows.filter("kind", "probe").len() == 8);',
                'check(rows.filter("status", "allowed").len() == 6);',
                'check(rows.filter("status", "denied_by_guardrail").len() == 2);',
            ])
            execute('session-doctor',doctor_script,0,extra_env={"AWS_PROFILE":"lmaws","LMAWS_TEST_AWS_DIR":str(test_aws_dir),"LMAWS_CREDENTIAL_CACHE_DIR":str(test_cache_dir)})

            assert Fake.ever=={'queue','bucket','topic','parameter','table','log_group'},Fake.ever
            ec2_proof=fake_ec2.tests(execute,env)
            assert all(request[5].startswith('127.0.0.1:') for request in Fake.requests),'non-loopback HTTP host'
            assert not any('DeleteQueue' in r[2] and 'lmaws_fixture' in r[4] for r in Fake.requests),'legacy fixture mutated'
            proof=dict(ec2=ec2_proof,inventories=16,write_lifecycles=6,pagination_rows=2,exception_teardown=True,aws_error_redaction=True,all_created_deleted=True,http_requests=len(Fake.requests),loopback_only=True)
            (pathlib.Path(tempfile.gettempdir())/'lmaws-fake-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
            print('PASS fake SDK: 16 inventories, 6 tagged lifecycles, EC2 spot nano lifecycle/refusals/teardown, pagination, failure teardown, AWS error redaction; all deleted')
    finally:server.shutdown();server.server_close()
if __name__=="__main__":run(pathlib.Path(sys.argv[1]).resolve())
