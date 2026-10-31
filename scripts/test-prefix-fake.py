#!/usr/bin/env python3
"""Real SDK serialization/pagination against loopback; never contacts AWS."""
import http.server,json,os,pathlib,shutil,subprocess,sys,tempfile,threading,urllib.parse
ROOT=pathlib.Path(__file__).resolve().parents[1]
class Fake(http.server.BaseHTTPRequestHandler):
    requests=[];deny=False;deleted=set();deletes=[]
    def log_message(self,*args):pass
    def do_GET(self):self.reply()
    def do_POST(self):self.reply()
    def send(self,value,kind='json',status=200):
        body=json.dumps(value).encode() if kind=='json' else value.encode() if isinstance(value,str) else value
        self.send_response(status);self.send_header('Content-Type',{'json':'application/x-amz-json-1.1','xml':'text/xml','cbor':'application/x-amz-cbor-1.1'}[kind]);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def reply(self):
        raw=self.rfile.read(int(self.headers.get('Content-Length','0')));target=self.headers.get('X-Amz-Target','');form=urllib.parse.parse_qs(raw.decode('utf-8','replace'));query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        action=(form.get('Action') or query.get('Action') or [''])[0];op=target.rsplit('.',1)[-1] if target else action
        data=json.loads(raw) if raw.startswith(b'{') else {};self.requests.append((target,op,data,form,self.path))
        port=self.server.server_port
        if 'AmazonSQS' in target:
            if op=='ListQueues':
                assert data['QueueNamePrefix']=='lmaws'
                if self.deny:return self.send({'__type':'AccessDeniedException','message':'test denied'},status=403)
                names=['lmaws_runprefix_queue'] if not data.get('NextToken') else ['lmaws-queue-two','lmawsOther','foreign']
                reply={'QueueUrls':[f'http://127.0.0.1:{port}/'+n for n in names if n not in self.deleted]}
                if not data.get('NextToken'):reply['NextToken']='page2'
                return self.send(reply)
            if op=='DeleteQueue':
                name=data['QueueUrl'].rsplit('/',1)[-1];self.deletes.append(name);self.deleted.add(name);return self.send({})
            if op=='GetQueueUrl':
                name=data['QueueName']
                if name in self.deleted:return self.send({'__type':'QueueDoesNotExist','message':'fixture absent'},status=400)
                return self.send({'QueueUrl':f'http://127.0.0.1:{port}/'+name})
            if op=='ListQueueTags':return self.send({'Tags':{'lmaws_test':'runprefix','secret_token':'test-secret-must-not-leak'}})
            if op=='GetQueueAttributes':return self.send({'Attributes':{'CreatedTimestamp':'1577836800','QueueArn':'arn:aws:sqs:us-east-1:000000000000:'+data['QueueUrl'].rsplit('/',1)[-1]}})
        if target.startswith('AmazonSSM'):
            if op=='DescribeParameters':
                assert data['ParameterFilters']==[{'Key':'Name','Option':'BeginsWith','Values':['lmaws']}]
                return self.send({'Parameters':[{'Name':'lmaws_parameter','Type':'String','LastModifiedDate':1577836800}]})
            return self.send({'TagList':[{'Key':'lmaws_test','Value':'runprefix'}]})
        if target.startswith('Logs_'):
            if op=='DescribeLogGroups':
                assert data['logGroupNamePrefix']=='lmaws'
                return self.send({'logGroups':[{'logGroupName':'lmaws_logs','creationTime':1577836800000}]})
            return self.send({'tags':{'lmaws_test':'runprefix'}})
        if action=='DescribeTags':
            resource=(form.get('Filter.1.Value.1') or [''])[0]
            names={'i-fixture':('instance','lmaws_instance'),'vpc-fixture':('vpc','lmaws_vpc'),'sg-fixture':('security-group','lmaws_sg')}
            selected=names if resource=='lmaws*' else {resource:names[resource]} if resource in names else {}
            entries=''
            for ident,(kind,name) in selected.items():
                for key,value in [('Name',name),('lmaws_test','runprefix')]:entries+=f'<item><resourceId>{ident}</resourceId><resourceType>{kind}</resourceType><key>{key}</key><value>{value}</value></item>'
            return self.send('<DescribeTagsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><tagSet>'+entries+'</tagSet></DescribeTagsResponse>','xml')
        if action=='DescribeSecurityGroups':return self.send('<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><securityGroupInfo/></DescribeSecurityGroupsResponse>','xml')
        if action=='DescribeStacks':return self.send('<DescribeStacksResponse xmlns="http://cloudformation.amazonaws.com/doc/2010-05-15/"><DescribeStacksResult><Stacks><member><StackName>lmaws_stack</StackName><StackId>arn:aws:cloudformation:us-east-1:000000000000:stack/lmaws_stack/id</StackId><CreationTime>2020-01-01T00:00:00Z</CreationTime><StackStatus>CREATE_COMPLETE</StackStatus><Tags><member><Key>lmaws_test</Key><Value>runprefix</Value></member></Tags></member></Stacks></DescribeStacksResult></DescribeStacksResponse>','xml')
        if 'EC2ContainerService' in target:
            if op=='ListClusters':return self.send({'clusterArns':['arn:aws:ecs:us-east-1:000000000000:cluster/lmaws_cluster']})
            assert data.get('include')==['TAGS']
            return self.send({'clusters':[{'clusterArn':'arn:aws:ecs:us-east-1:000000000000:cluster/lmaws_cluster','clusterName':'lmaws_cluster','tags':[{'key':'lmaws_test','value':'runprefix'}]}]})
        if self.path.startswith('/2015-03-31/functions'):return self.send({'Functions':[{'FunctionName':'lmaws_function','FunctionArn':'arn:aws:lambda:us-east-1:000000000000:function:lmaws_function','LastModified':'2020-01-01T00:00:00.000+0000'}]})
        if self.path.startswith('/2017-03-31/tags/'):return self.send({'Tags':{'lmaws_test':'runprefix','secret_token':'test-secret-must-not-leak'}})
        if 'DynamoDB' in target:return self.send({'TableNames':[]})
        if 'secretsmanager' in target:return self.send({'SecretList':[]})
        if self.path.startswith('/2013-04-01/hostedzone'):return self.send('<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones/><IsTruncated>false</IsTruncated></ListHostedZonesResponse>','xml')
        if action=='ListTopics':return self.send('<ListTopicsResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/"><ListTopicsResult><Topics/></ListTopicsResult></ListTopicsResponse>','xml')
        if 'cbor' in self.headers.get('Content-Type',''):return self.send(bytes([0xa0]),'cbor')
        if self.command=='GET' and self.path=='/':return self.send('<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets/></ListAllMyBucketsResult>','xml')
        raise AssertionError(('unhandled SDK request',target,action,self.path))

def main(host):
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fake);threading.Thread(target=server.serve_forever,daemon=True).start()
    env=dict(os.environ,CI='true',LMAWS_LIVE='1',AWS_PROFILE='nonexistent-fake-profile',AWS_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',LMAWS_ENDPOINT=f'http://127.0.0.1:{server.server_port}')
    for key in ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN']:env.pop(key,None)
    argv=['cmd.exe','/c',str(host)] if host.suffix=='.cmd' else [str(host)]
    try:
        with tempfile.TemporaryDirectory(prefix='lmaws-prefix-fake-') as directory:
            work=pathlib.Path(directory);schema=work/'schema.json';schema.write_bytes(subprocess.check_output(argv+['--lmcode-schema'],env=env,timeout=30))
            program=work/'prefix.lms';binary=work/'prefix.dslb';output=work/'rows.json'
            program.write_text('p=_dsl_ schema='+json.dumps(str(schema))+';\nlet cloud=aws.region("us-east-1"); let rows=cloud.find_prefix("lmaws"); file_write('+json.dumps(str(output))+',rows.json());\nend _dsl_\nsavedsl(p,'+json.dumps(str(binary))+');\n')
            p=subprocess.run([shutil.which('lmscript'),str(program)],cwd=work,env=env,capture_output=True,text=True,timeout=60);assert p.returncode==0,p.stderr
            p=subprocess.run(argv+['--lmcode',str(binary)],cwd=work,env=env,capture_output=True,text=True,timeout=180);assert p.returncode==0,(p.stderr,Fake.requests)
            rows=json.loads(output.read_text());names={row['name'] for row in rows};expected={'lmaws_runprefix_queue','lmaws-queue-two','lmawsOther','lmaws_instance','lmaws_vpc','lmaws_sg','lmaws_function','lmaws_logs','lmaws_parameter','lmaws_cluster','lmaws_stack'}
            assert names==expected,(names,expected);assert len(rows)==len(expected),'duplicate account resources'
            assert all(row['run_id']=='runprefix' and row['lmaws_test']=='true' for row in rows)
            assert '000000000000' not in output.read_text()
            assert 'test-secret-must-not-leak' not in output.read_text()
            assert len([r for r in Fake.requests if r[1]=='ListQueues'])==2,'SQS pagination was lost'
            assert any(r[1]=='DescribeStacks' for r in Fake.requests)
            assert any(r[1]=='DescribeParameters' and r[2].get('ParameterFilters') for r in Fake.requests)
            # Recover only a resource with matching prefix, run tag and durable creation proof.
            ledger_dir=work/'owned-ledgers';ledger_dir.mkdir();name='lmaws_runprefix_queue';url=f'http://127.0.0.1:{server.server_port}/'+name
            records=[dict(event='intent',action='create',kind='queue',id=name,name=name,run_id='runprefix',state='pending',time='2020-01-01T00:00:00Z'),dict(event='created',action='create',kind='queue',id=url,name=name,run_id='runprefix',state='active',time='2020-01-01T00:00:00Z')]
            (ledger_dir/'lmaws-runprefix.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in records))
            def execute_body(body,profile='default'):
                src=work/'action.lms';bc=work/'action.dslb';src.write_text('p=_dsl_ schema='+json.dumps(str(schema))+';\n'+body+'\nend _dsl_\nsavedsl(p,'+json.dumps(str(bc))+');\n')
                cp=subprocess.run([shutil.which('lmscript'),str(src)],cwd=work,env=env,capture_output=True,text=True,timeout=60);assert cp.returncode==0,cp.stderr
                return subprocess.run(argv+['--lmcode',str(bc)],cwd=work,env=dict(env,AWS_PROFILE=profile,LMAWS_LEDGER_DIR=str(ledger_dir)),capture_output=True,text=True,timeout=180)
            denied=execute_body('let c=aws.example("cleanup_fixture");let rows=c.cleanup_prefix("lmaws",24,true);')
            assert denied.returncode!=0 and not Fake.deletes,'default profile was allowed to delete'
            dry=execute_body('let c=aws.example("cleanup_fixture");let rows=c.cleanup_prefix("lmaws",24,false);')
            assert dry.returncode==0 and not Fake.deletes,(dry.stderr,Fake.deletes)
            applied=execute_body('let c=aws.example("cleanup_fixture");let rows=c.cleanup_prefix("lmaws",24,true);file_write("cleanup.json",rows.json());','lmaws')
            assert applied.returncode==0,(applied.stderr,Fake.requests)
            assert Fake.deletes==[name],(Fake.deletes,applied.stdout,(work/"cleanup.json").read_text())
            assert 'cleanup dry-run plan:' in applied.stdout
            cleaned=json.loads((work/'cleanup.json').read_text());assert any(row['name']==name and row['status']=='deleted' and row['provider_absent']=='true' for row in cleaned),cleaned
            absence=execute_body('let c=aws.example("independent_fixture");check(c.resource_exists("queue","'+name+'") == false);')
            assert absence.returncode==0,absence.stderr
            Fake.deny=True;output.unlink();p=subprocess.run(argv+['--lmcode',str(binary)],cwd=work,env=env,capture_output=True,text=True,timeout=180);assert p.returncode!=0,'denial became a false zero';assert not output.exists()
            print('PASS real SDK prefix pushdown, pagination, tags/ages, eleven resources, masks, denial, qualified deletion and default-profile absence; loopback only')
    finally:server.shutdown();server.server_close()
if __name__=='__main__':main(pathlib.Path(sys.argv[1]).resolve())
