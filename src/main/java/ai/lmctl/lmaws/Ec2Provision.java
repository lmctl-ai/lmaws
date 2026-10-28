package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;

/** On-demand provisioning is separate from every lmaws sandbox and the existing fleet. */
final class Ec2Provision {
    static final String AMI_PARAMETER="/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id";
    private static final Set<String> PROFILES=Set.of("default","lmaws","lmaws-ec2","lmaws-web");
    private static final Set<String> CONFIG_KEYS=Set.of("lmprov_id","region","instance_type","volume_gib","ami_parameter","owner","purpose","public_ipv4","cap_usd","max_runtime_seconds","dry");
    private final AwsBackend backend;
    private final ThreadLocal<String> lastCall=new ThreadLocal<>();
    Ec2Provision(AwsBackend backend){this.backend=backend;}
    private Ec2Client ec2(){return backend.provisioningEc2Client();}
    @SuppressWarnings("unchecked") private static Map<String,Object> object(Object value){if(!(value instanceof Map<?,?>))throw new IllegalArgumentException("JSON object required");return (Map<String,Object>)value;}
    private static String text(Object value){return value==null?"":String.valueOf(value);}
    private static int integer(Object value,int low,int high,String name){if(!(value instanceof Number n)||!Double.isFinite(n.doubleValue())||n.doubleValue()!=Math.rint(n.doubleValue())||n.doubleValue()<low||n.doubleValue()>high)throw new IllegalArgumentException(name+" must be an integer "+low+".."+high);return n.intValue();}
    private static void id(String value){if(value==null||!value.matches("[a-z0-9][a-z0-9_-]{0,63}"))throw new IllegalArgumentException("lmprov_id must be 1..64 lowercase letters/digits/underscore/hyphen");}
    private void guard(boolean mutation,boolean dry){
        if(!PROFILES.contains(backend.profileName())||!backend.profileName().equals(AwsBackend.activeProfile()))throw new SecurityException("provisioning refuses admin/unknown or mismatched profile");
        if(!"us-east-1".equals(backend.region()))throw new SecurityException("provisioning requires us-east-1");
        if(mutation&&!backend.isDemo()&&!backend.hasFakeEndpoint()&&(!AwsBackend.isLiveEnabled()||(!dry&&!AwsBackend.isApplyEnabled())))throw new SecurityException("live provisioning requires LMAWS_LIVE=1 and --apply; dry requests require live opt-in only");
    }
    private Map<String,Object> config(String raw){
        if(raw==null||raw.length()>16384)throw new IllegalArgumentException("provision config exceeds 16 KiB");
        Map<String,Object> in=object(Json.parse(raw));
        for(String key:in.keySet())if(!CONFIG_KEYS.contains(key))throw new IllegalArgumentException("unsupported provision config: "+key);
        String value=text(in.get("lmprov_id"));id(value);
        Map<String,Object> out=new TreeMap<>();out.put("lmprov_id",value);
        out.put("region",in.getOrDefault("region","us-east-1"));out.put("instance_type",in.getOrDefault("instance_type","t4g.nano"));
        if(!out.get("region").equals("us-east-1")||!out.get("region").equals(backend.region()))throw new IllegalArgumentException("region must be us-east-1");
        if(!out.get("instance_type").equals("t4g.nano"))throw new IllegalArgumentException("only t4g.nano is permitted");
        out.put("volume_gib",integer(in.getOrDefault("volume_gib",10),1,20,"volume_gib"));
        String parameter=text(in.getOrDefault("ami_parameter",AMI_PARAMETER));
        if(!parameter.matches("/aws/service/canonical/ubuntu/server/(?:24\\.04|noble)/stable/current/arm64/hvm/ebs-gp3/ami-id"))throw new IllegalArgumentException("a Canonical Ubuntu 24.04 arm64 gp3 AMI parameter is required");
        out.put("ami_parameter",parameter);
        for(String key:List.of("owner","purpose")){
            String item=text(in.getOrDefault(key,key.equals("owner")?"lmctl":"on-demand-provisioning"));
            if(!item.matches("[A-Za-z0-9_.:/=+@ -]{1,128}"))throw new IllegalArgumentException(key+" must be a bounded tag value");out.put(key,item);
        }
        for(String key:List.of("public_ipv4","dry")){Object b=in.getOrDefault(key,false);if(!(b instanceof Boolean))throw new IllegalArgumentException(key+" must be boolean");out.put(key,b);}
        out.put("max_runtime_seconds",integer(in.getOrDefault("max_runtime_seconds",3600),60,3600,"max_runtime_seconds"));
        BigDecimal cap=new BigDecimal(text(in.getOrDefault("cap_usd","0.25")));
        String env=System.getenv("LMAWS_MAX_COST_USD");if(env!=null&&!env.isBlank())cap=cap.min(new BigDecimal(env));
        if(cap.signum()<0||cap.compareTo(ProvisionCosts.HARD_CAP)>0)throw new IllegalArgumentException("cap_usd must be 0..0.25");
        out.put("cap_usd",cap.stripTrailingZeros().toPlainString());return out;
    }
    private static String configHash(Map<String,Object> config){Map<String,Object> stable=new TreeMap<>(config);stable.remove("dry");return ProvisionJournal.hash(Jsons.encodeRaw(Json.parse(Jsons.encodeRaw(stable))));}
    private static Map<String,Object> ok(String status){Map<String,Object> out=new LinkedHashMap<>();out.put("ok",true);out.put("status",status);out.put("http_status",200);out.put("error_code","");out.put("ambiguous",false);return out;}
    private <T>T call(ProvisionJournal journal,String action,Supplier<T> work){journal.request(action);lastCall.set(action);return work.get();}
    private interface Work {Map<String,Object> run(ProvisionJournal journal,Map<String,Object> state);}
    private String execute(String value,String operation,boolean mutation,boolean dry,Work work){
        id(value);guard(mutation,dry);lastCall.set(operation);Instant started=Instant.now();
        try(ProvisionJournal journal=ProvisionJournal.open(value,backend.isDemo())){
            Map<String,Object> state=journal.state();Map<String,Object> receipt;
            try{receipt=work.run(journal,state);}catch(RuntimeException failure){
                // A rejected start never began a billing segment. A transport-uncertain start
                // keeps the conservative pending estimate until a provider observation settles it.
                if(!dry&&"StartInstances".equals(lastCall.get())&&failure instanceof AwsServiceException aws&&aws.statusCode()<500&&state.containsKey("pending_start_prior_state")){
                    state.put("state",state.remove("pending_start_prior_state"));state.put("active_segment_seconds",0);
                }
                // Invalid ownership/configuration is never disguised as an AWS success.
                String failedAction=failure instanceof AwsServiceException?lastCall.get():operation;
                receipt=error(journal,failure,failedAction);
                if("RunInstances".equals(failedAction)&&!Boolean.TRUE.equals(receipt.get("ok"))&&!state.containsKey("instance_id")){
                    if(Boolean.TRUE.equals(receipt.get("ambiguous")))state.put("launch_ambiguous",true);
                    else if(!Boolean.TRUE.equals(state.get("launch_ambiguous")))state.put("state","failed");
                }
                if(!Boolean.TRUE.equals(receipt.get("ok"))){state.put("last_aws_error_code",receipt.get("error_code"));state.put("last_aws_error_message",receipt.get("message"));state.put("last_error_at",Instant.now().toString());}
            }
            receipt.put("lmprov_id",value);receipt.put("operation",operation);receipt.put("started",started.toString());receipt.put("finished",Instant.now().toString());
            receipt.put("journal_path",journal.path.toString());
            receipt.put("synthetic",backend.isDemo());
            receipt.put("confirmed",Boolean.TRUE.equals(receipt.get("ok"))&&!Boolean.TRUE.equals(receipt.get("dry_run"))&&!Boolean.FALSE.equals(receipt.get("confirmed_transition")));
            receipt.put("pending",Boolean.FALSE.equals(receipt.get("confirmed_transition")));
            for(String key:List.of("config_hash","ami_id","instance_id","volume_id","volume_ids","network_interface_ids","last_aws_error_code","last_aws_error_message","last_error_at"))if(state.containsKey(key)&&!receipt.containsKey(key))receipt.put(key,state.get(key));
            if(state.get("config") instanceof Map<?,?>){Map<String,Object> cfg=object(state.get("config"));receipt.put("config",cfg);receipt.put("cost",ProvisionCosts.summary(state,cfg,Instant.now()));}
            state.put("last_receipt",receipt);journal.save(state);journal.receipt(receipt);
            lastCall.remove();return Jsons.encode(receipt);
        }
    }
    private Map<String,Object> error(ProvisionJournal journal,RuntimeException failure,String operation){
        Map<String,Object> out=new LinkedHashMap<>();String code=failure instanceof SecurityException?"OwnershipGuard":failure instanceof IllegalArgumentException?"InvalidConfig":"LocalFailure";
        String message=text(failure.getMessage());int status=0;String requestId="";
        if(failure instanceof AwsServiceException aws){status=aws.statusCode();requestId=text(aws.requestId());if(aws.awsErrorDetails()!=null){code=text(aws.awsErrorDetails().errorCode());message=text(aws.awsErrorDetails().errorMessage());}}
        if("LocalFailure".equals(code)&&message.contains("cost cap"))code="CostCapExceeded";
        boolean authorized=code.equals("DryRunOperation");out.put("ok",authorized);out.put("status",authorized?"DryRunOperation":"failed");out.put("dry_run",authorized);
        out.put("http_status",status);out.put("error_code",code);out.put("request_id",requestId);out.put("action",operation);
        String classification=authorized?"authorized":code.equals("RequestLimitExceeded")||code.contains("Throttl")?"rate_limit":code.contains("Capacity")?"capacity":code.contains("LimitExceeded")||code.contains("Quota")?"quota":status==403||code.contains("Unauthorized")||code.contains("AccessDenied")?"unauthorized":code.startsWith("InvalidParameter")||code.equals("InvalidConfig")?"invalid_parameter":code.contains("State")?"state_transition":code.equals("OwnershipGuard")?"guard":code.equals("CostCapExceeded")?"budget":status==0?"local_or_transport":"aws_error";
        out.put("classification",classification);out.put("message",safe(message,4096));
        out.put("ambiguous",!authorized&&(status>=500||failure instanceof software.amazon.awssdk.core.exception.SdkClientException));
        if(code.contains("Unauthorized")){
            var match=Pattern.compile("(?i)encoded authorization failure message[: ]+([A-Za-z0-9_+/=-]{8,8192})").matcher(message);
            if(match.find())try{
                String token=match.group(1);String decoded=call(journal,"DecodeAuthorizationMessage",()->backend.provisioningStsClient().decodeAuthorizationMessage(x->x.encodedMessage(token)).decodedMessage());
                out.put("decoded_authorization",safe(decoded,8192));out.put("decode_status","available");
            }catch(RuntimeException denied){out.put("decode_status","unknown: needs sts:DecodeAuthorizationMessage");}
            else out.put("decode_status","no encoded authorization message provided");
        }
        return out;
    }
    private static String safe(String raw,int limit){String result=Jsons.mask(raw).replaceAll("(?<![0-9])[0-9]{12}(?![0-9])","************");return result.length()>limit?result.substring(result.length()-limit):result;}
    private void rememberConfig(Map<String,Object> state,Map<String,Object> cfg){
        String hash=configHash(cfg);if(state.containsKey("config_hash")&&!hash.equals(state.get("config_hash")))throw new IllegalArgumentException("lmprov_id already has a different immutable config");
        state.put("config",cfg);state.put("config_hash",hash);state.put("volume_gib",cfg.get("volume_gib"));state.put("public_ipv4",cfg.get("public_ipv4"));state.putIfAbsent("state","requested");
        state.putIfAbsent("client_token","lmprov-"+ProvisionJournal.hash(text(cfg.get("lmprov_id"))+hash).substring(0,56));
    }
    private static Map<String,String> tagMap(List<Tag> tags){Map<String,String> result=new LinkedHashMap<>();for(Tag t:tags)if(result.put(t.key(),t.value())!=null)throw new SecurityException("duplicate ownership tag");return result;}
    private Instance find(ProvisionJournal journal,Map<String,Object> state,String value){
        if(backend.isDemo())return demoInstance(state,value);
        List<Instance> found=new ArrayList<>();String next=null;Set<String> tokens=new HashSet<>();
        do{
            final String token=next;var page=call(journal,"DescribeInstances",()->ec2().describeInstances(x->x.filters(Filter.builder().name("tag:provisioner").values("lmprov").build(),Filter.builder().name("tag:lmprov_id").values(value).build()).nextToken(token).maxResults(100)));
            for(var r:page.reservations())for(Instance i:r.instances()){
                Map<String,String> tags=tagMap(i.tags());
                if(!"lmprov".equals(tags.get("provisioner"))||!value.equals(tags.get("lmprov_id"))||"awsspot".equals(tags.get("Project")))throw new SecurityException("refusing untagged, foreign or awsspot instance");
                if(!"t4g.nano".equals(i.instanceTypeAsString())||i.spotInstanceRequestId()!=null||i.iamInstanceProfile()!=null||i.keyName()!=null&&!i.keyName().isBlank())throw new SecurityException("existing instance violates provisioning limits");
                found.add(i);if(found.size()>1)throw new SecurityException("duplicate lmprov_id; refusing ambiguous ownership");
            }
            next=page.nextToken();if(next!=null&&(!tokens.add(next)||tokens.size()>100))throw new IllegalStateException("instance pagination is unbounded or repeated");
        }while(next!=null&&!next.isBlank());
        if(found.isEmpty()){
            if(state.containsKey("instance_id")&&!"terminated".equals(state.get("state")))throw new IllegalStateException("recorded instance is not visible by ownership tags; refusing recreation");
            return null;
        }
        Instance instance=found.get(0);
        if(state.containsKey("instance_id")&&!state.get("instance_id").equals(instance.instanceId()))throw new SecurityException("instance identity changed for lmprov_id");
        if(state.containsKey("volume_id")&&!text(state.get("volume_id")).isBlank()
            &&instance.blockDeviceMappings().stream().filter(b->b.ebs()!=null).map(b->b.ebs().volumeId()).noneMatch(v->v.equals(state.get("volume_id")))
            &&!"terminated".equals(instance.state().nameAsString()))throw new SecurityException("root volume identity changed for lmprov_id");
        return instance;
    }
    private Instance demoInstance(Map<String,Object> state,String value){
        if(!state.containsKey("instance_id"))return null;
        String iid=text(state.get("instance_id"));String volume=text(state.get("volume_id"));
        return Instance.builder().instanceId(iid).instanceType("t4g.nano").state(InstanceState.builder().name(text(state.get("state"))).build()).rootDeviceName("/dev/sda1")
            .blockDeviceMappings(InstanceBlockDeviceMapping.builder().deviceName("/dev/sda1").ebs(EbsInstanceBlockDevice.builder().volumeId(volume).deleteOnTermination(true).build()).build())
            .tags(Tag.builder().key("provisioner").value("lmprov").build(),Tag.builder().key("lmprov_id").value(value).build()).build();
    }
    private void verifyChildren(ProvisionJournal j,Instance instance,String value) {
        if(backend.isDemo())return;
        List<String> volumes=instance.blockDeviceMappings().stream().filter(x->x.ebs()!=null).map(x->x.ebs().volumeId()).toList();
        if(volumes.size()!=1||!Boolean.TRUE.equals(instance.blockDeviceMappings().get(0).ebs().deleteOnTermination()))throw new SecurityException("provision instance must retain exactly one DeleteOnTermination root volume");
        var response=call(j,"DescribeVolumes",()->ec2().describeVolumes(x->x.volumeIds(volumes)));
        if(response.volumes().size()!=1)throw new SecurityException("root volume ownership is unknown");
        Volume volume=response.volumes().get(0);requireTags(volume.tags(),value);
        if(!volumes.contains(volume.volumeId())||!"gp3".equals(volume.volumeTypeAsString())||volume.size()==null||volume.size()<1||volume.size()>20)throw new SecurityException("attached root volume violates size/type limits");
        List<String> interfaces=instance.networkInterfaces().stream().map(InstanceNetworkInterface::networkInterfaceId).toList();
        if(interfaces.size()!=1)throw new SecurityException("provision instance must retain exactly one network interface");
        var nics=call(j,"DescribeNetworkInterfaces",()->ec2().describeNetworkInterfaces(x->x.networkInterfaceIds(interfaces))).networkInterfaces();
        if(nics.size()!=1)throw new SecurityException("network interface ownership is unknown");
        requireTags(nics.get(0).tagSet(),value);
        if(!interfaces.contains(nics.get(0).networkInterfaceId()))throw new SecurityException("network interface identity mismatch");
    }
    private static void requireTags(List<Tag> tags,String value){
        Map<String,String> actual=tagMap(tags);
        if(!"lmprov".equals(actual.get("provisioner"))||!value.equals(actual.get("lmprov_id"))
            ||actual.entrySet().stream().anyMatch(t->t.getKey().equalsIgnoreCase("Project")&&t.getValue().equalsIgnoreCase("awsspot")))throw new SecurityException("foreign, untagged or awsspot child resource refused");
    }
    private Map<String,Object> observe(ProvisionJournal journal,Map<String,Object> state,Instance instance,boolean details){
        if(instance==null){Map<String,Object> absent=ok("absent");absent.put("state","absent");absent.put("exists",false);return absent;}
        String observed=instance.state()==null?"unknown":instance.state().nameAsString();
        Map<String,Object> out=ok(observed);out.put("state",observed);out.put("exists",true);out.put("instance_id",instance.instanceId());out.put("instance_type",instance.instanceTypeAsString());
        List<String> volumes=instance.blockDeviceMappings().stream().filter(x->x.ebs()!=null).map(x->x.ebs().volumeId()).filter(Objects::nonNull).toList();
        out.put("volume_ids",volumes);out.put("volume_id",volumes.isEmpty()?text(state.get("volume_id")):volumes.get(0));out.put("network_interface_ids",instance.networkInterfaces().isEmpty()?state.getOrDefault("network_interface_ids",List.of()):instance.networkInterfaces().stream().map(InstanceNetworkInterface::networkInterfaceId).toList());
        out.put("state_transition_reason",safe(text(instance.stateTransitionReason()),4096));
        if(instance.stateReason()!=null)out.put("state_reason",Map.of("code",text(instance.stateReason().code()),"message",safe(text(instance.stateReason().message()),4096)));
        if(details){
            if(backend.isDemo()){out.put("system_status","ok");out.put("instance_status","ok");out.put("boot_count",state.getOrDefault("boot_count",1));}
            else{
                var status=call(journal,"DescribeInstanceStatus",()->ec2().describeInstanceStatus(x->x.instanceIds(instance.instanceId()).includeAllInstances(true)));
                if(status.instanceStatuses().isEmpty()){out.put("system_status","not-yet-reported");out.put("instance_status","not-yet-reported");}
                else{var s=status.instanceStatuses().get(0);out.put("system_status",s.systemStatus()==null?"unknown":s.systemStatus().statusAsString());out.put("instance_status",s.instanceStatus()==null?"unknown":s.instanceStatus().statusAsString());}
            }
            boolean impaired="impaired".equals(out.get("system_status"))||"impaired".equals(out.get("instance_status"));
            String reason=instance.stateReason()==null?"":text(instance.stateReason().code());
            boolean failedReason=!reason.isBlank()&&!Set.of("Client.UserInitiatedShutdown","Client.InstanceInitiatedShutdown","Client.UserInitiatedHibernate").contains(reason);
            out.put("health_failed",impaired||failedReason);out.put("classification",impaired?"status_checks_failed":failedReason?"state_transition":"");
            if(!impaired&&!failedReason)out.put("console_tail","");
            if(impaired||failedReason){
                out.put("health_failed",true);out.put("classification",impaired?"status_checks_failed":"state_transition");
                try{out.put("console_tail",consoleText(journal,state,instance.instanceId()));}catch(RuntimeException denied){out.put("console_error",error(journal,denied,"GetConsoleOutput"));}
            }
        }
        if(state.get("config") instanceof Map<?,?>){ProvisionCosts.settle(state,observed,Instant.now());}
        state.putAll(out);state.remove("pending_start_prior_state");state.put("last_observed_state",observed);return out;
    }
    private void resolve(ProvisionJournal journal,Map<String,Object> state,Map<String,Object> cfg){
        if(state.containsKey("ami_id"))return;
        if(backend.isDemo()){state.put("ami_id","ami-0123456789abcdef0");state.put("root_device","/dev/sda1");state.put("subnet_id","subnet-synthetic");state.put("security_group_id","sg-synthetic");journal.save(state);return;}
        String ami=call(journal,"GetParameter",()->backend.provisioningSsmClient().getParameter(x->x.name(text(cfg.get("ami_parameter")))).parameter().value());
        if(ami==null||!ami.matches("ami-[0-9a-f]{8,17}"))throw new IllegalArgumentException("Canonical parameter returned invalid AMI id");
        var images=call(journal,"DescribeImages",()->ec2().describeImages(x->x.imageIds(ami).owners("099720109477")));
        if(images.images().size()!=1)throw new SecurityException("Canonical AMI lookup is not unique");Image image=images.images().get(0);
        if(!ami.equals(image.imageId())||!"099720109477".equals(image.ownerId())||!"arm64".equals(image.architectureAsString())||!"ebs".equals(image.rootDeviceTypeAsString())||!"hvm".equals(image.virtualizationTypeAsString())||image.state()!=ImageState.AVAILABLE||image.rootDeviceName()==null||!image.rootDeviceName().matches("/dev/(?:sda1|xvda)"))throw new SecurityException("AMI is not Canonical arm64 EBS/HVM");
        int minimum=image.blockDeviceMappings().stream().filter(b->image.rootDeviceName().equals(b.deviceName())&&b.ebs()!=null&&b.ebs().volumeSize()!=null).mapToInt(b->b.ebs().volumeSize()).max().orElse(1);
        if(((Number)cfg.get("volume_gib")).intValue()<minimum)throw new IllegalArgumentException("volume_gib is smaller than the AMI root snapshot");
        var vpcs=call(journal,"DescribeVpcs",()->ec2().describeVpcs(x->x.filters(Filter.builder().name("is-default").values("true").build()))).vpcs();
        if(vpcs.size()!=1||!Boolean.TRUE.equals(vpcs.get(0).isDefault()))throw new SecurityException("a unique default VPC is required");String vpc=vpcs.get(0).vpcId();
        var subnets=call(journal,"DescribeSubnets",()->ec2().describeSubnets(x->x.filters(Filter.builder().name("vpc-id").values(vpc).build()))).subnets().stream().filter(s->vpc.equals(s.vpcId())&&s.state()==SubnetState.AVAILABLE).sorted(Comparator.comparing(Subnet::subnetId)).toList();
        if(subnets.isEmpty())throw new IllegalStateException("default VPC has no available subnet");
        var groups=call(journal,"DescribeSecurityGroups",()->ec2().describeSecurityGroups(x->x.filters(Filter.builder().name("vpc-id").values(vpc).build(),Filter.builder().name("group-name").values("default").build()))).securityGroups();
        if(groups.size()!=1||!vpc.equals(groups.get(0).vpcId())||!"default".equals(groups.get(0).groupName()))throw new SecurityException("unique default security group required");
        state.put("ami_id",ami);state.put("root_device",image.rootDeviceName());state.put("subnet_id",subnets.get(0).subnetId());state.put("security_group_id",groups.get(0).groupId());journal.save(state);
    }
    private RunInstancesRequest launchRequest(Map<String,Object> state,Map<String,Object> cfg,boolean dry){
        String value=text(cfg.get("lmprov_id"));List<Tag> tags=List.of(Tag.builder().key("provisioner").value("lmprov").build(),Tag.builder().key("lmprov_id").value(value).build(),Tag.builder().key("Name").value("lmprov-"+value).build(),Tag.builder().key("owner").value(text(cfg.get("owner"))).build(),Tag.builder().key("purpose").value(text(cfg.get("purpose"))).build());
        List<TagSpecification> specifications=List.of(ResourceType.INSTANCE,ResourceType.VOLUME,ResourceType.NETWORK_INTERFACE).stream().map(t->TagSpecification.builder().resourceType(t).tags(tags).build()).toList();
        return RunInstancesRequest.builder().imageId(text(state.get("ami_id"))).instanceType("t4g.nano").minCount(1).maxCount(1).clientToken(text(state.get("client_token"))).dryRun(dry)
            .userData(Base64.getEncoder().encodeToString(bootScript(value).getBytes(StandardCharsets.UTF_8))).tagSpecifications(specifications)
            .blockDeviceMappings(BlockDeviceMapping.builder().deviceName(text(state.get("root_device"))).ebs(EbsBlockDevice.builder().volumeSize(((Number)cfg.get("volume_gib")).intValue()).volumeType(VolumeType.GP3).deleteOnTermination(true).encrypted(true).build()).build())
            .networkInterfaces(InstanceNetworkInterfaceSpecification.builder().deviceIndex(0).subnetId(text(state.get("subnet_id"))).groups(text(state.get("security_group_id"))).associatePublicIpAddress(Boolean.TRUE.equals(cfg.get("public_ipv4"))).deleteOnTermination(true).build())
            .metadataOptions(InstanceMetadataOptionsRequest.builder().httpTokens(HttpTokensState.REQUIRED).httpEndpoint(InstanceMetadataEndpointState.ENABLED).build()).build();
    }
    static String bootScript(String value){id(value);return "#cloud-boothook\n#!/bin/sh\nset -eu\nmkdir -p /var/lib/lmprov\ntest -f /var/lib/lmprov/boots || : > /var/lib/lmprov/boots\nn=$(($(wc -l < /var/lib/lmprov/boots)+1))\nprintf 'boot=%s id=%s\\n' \"$n\" '"+value+"' >> /var/lib/lmprov/boots\nsync /var/lib/lmprov/boots\nprintf 'LMPROV boot=%s id=%s\\n' \"$n\" '"+value+"' > /dev/console\n";}
    String run(String raw){Map<String,Object> cfg=config(raw);String value=text(cfg.get("lmprov_id"));boolean dry=Boolean.TRUE.equals(cfg.get("dry"));
        return execute(value,"RunInstances",true,dry,(journal,state)->{
            rememberConfig(state,cfg);journal.save(state);Instance existing=find(journal,state,value);
            if(existing==null&&"terminated".equals(state.get("state"))){Map<String,Object> out=ok("terminated");out.put("state","terminated");out.put("idempotent",true);return out;}
            if(existing!=null){Map<String,Object> out=observe(journal,state,existing,true);out.put("reattached",true);return out;}
            ProvisionCosts.admit(state,cfg,Instant.now());resolve(journal,state,cfg);journal.save(state);
            if(dry){if(backend.isDemo()){Map<String,Object> out=ok("DryRunOperation");out.put("dry_run",true);out.put("http_status",412);return out;}call(journal,"RunInstances",()->ec2().runInstances(launchRequest(state,cfg,true)));throw new IllegalStateException("AWS did not return DryRunOperation");}
            state.putIfAbsent("started_epoch",Instant.now().getEpochSecond());state.putIfAbsent("last_settled_epoch",state.get("started_epoch"));state.put("state","pending");journal.save(state);
            if(backend.isDemo()){state.put("instance_id","i-0"+ProvisionJournal.hash(value).substring(0,16));state.put("volume_id","vol-0"+ProvisionJournal.hash(value).substring(0,16));state.put("boot_count",1);Map<String,Object> out=observe(journal,state,demoInstance(state,value),true);state.put("state","running");out.put("state","running");out.put("status","created");return out;}
            var response=call(journal,"RunInstances",()->ec2().runInstances(launchRequest(state,cfg,false)));
            if(response.instances().size()!=1)throw new IllegalStateException("RunInstances did not confirm exactly one instance");
            Map<String,Object> out=observe(journal,state,response.instances().get(0),false);out.put("status","created");out.put("request_id",response.responseMetadata().requestId());journal.save(state);return out;
        });
    }
    String describe(String value){return execute(value,"DescribeInstances",false,false,(j,s)->observe(j,s,find(j,s,value),true));}
    String stop(String value){return transition(value,"stop",false);}
    String start(String value){return transition(value,"start",false);}
    String terminate(String value){return transition(value,"terminate",false);}
    String dryRun(String value,String operation){if(!Set.of("stop","start","terminate").contains(operation))throw new IllegalArgumentException("dry operation must be stop/start/terminate");return transition(value,operation,true);}
    private String transition(String value,String operation,boolean dry){String action=operation.equals("start")?"StartInstances":operation.equals("stop")?"StopInstances":"TerminateInstances";
        return execute(value,action,true,dry,(j,s)->{
            Instance instance=find(j,s,value);if(instance==null){Map<String,Object> out=ok("absent");out.put("state","absent");return out;}
            Map<String,Object> observed=observe(j,s,instance,false);String current=text(observed.get("state"));
            if(!dry&&(operation.equals("stop")&&Set.of("stopped","stopping").contains(current)||operation.equals("start")&&Set.of("running","pending").contains(current)||operation.equals("terminate")&&Set.of("terminated","shutting-down").contains(current))){observed.put("idempotent",true);return observed;}
            if(!Set.of("terminated","shutting-down").contains(current))verifyChildren(j,instance,value);
            if(operation.equals("start")){
                if(!s.containsKey("config"))throw new SecurityException("start requires the original local config/cost journal");
                ProvisionCosts.admit(s,object(s.get("config")),Instant.now());
            }
            if(backend.isDemo()){
                if(dry){Map<String,Object> out=ok("DryRunOperation");out.put("dry_run",true);out.put("http_status",412);return out;}
                if(operation.equals("start"))s.put("boot_count",((Number)s.getOrDefault("boot_count",1)).intValue()+1);
                ProvisionCosts.settle(s,operation.equals("stop")?"stopped":operation.equals("start")?"running":"terminated",Instant.now());
                Map<String,Object> out=observe(j,s,demoInstance(s,value),true);out.put("status",operation.equals("start")?"started":text(s.get("state")));return out;
            }
            String iid=instance.instanceId();
            if(operation.equals("start")&&!dry){s.put("pending_start_prior_state",current);ProvisionCosts.settle(s,"pending",Instant.now());}
            s.put("last_requested_operation",operation);s.put("last_requested_at",Instant.now().toString());j.save(s);
            if(operation.equals("stop"))call(j,action,()->ec2().stopInstances(x->x.instanceIds(iid).dryRun(dry)));
            else if(operation.equals("start"))call(j,action,()->ec2().startInstances(x->x.instanceIds(iid).dryRun(dry)));
            else call(j,action,()->ec2().terminateInstances(x->x.instanceIds(iid).dryRun(dry)));
            if(dry)throw new IllegalStateException("AWS did not return DryRunOperation");
            Map<String,Object> out=ok(operation+"_requested");out.put("state",current);out.put("instance_id",iid);out.put("confirmed_transition",false);return out;
        });
    }
    private String consoleText(ProvisionJournal j,Map<String,Object> state,String iid){
        if(backend.isDemo())return "LMPROV boot="+state.getOrDefault("boot_count",1)+" id="+object(state.get("config")).get("lmprov_id");
        String output=call(j,"GetConsoleOutput",()->ec2().getConsoleOutput(x->x.instanceId(iid).latest(true))).output();
        if(output==null)return "";
        if(output.length()>1024*1024)throw new IllegalStateException("console output exceeds 1 MiB encoded bound");
        try{return safe(new String(Base64.getDecoder().decode(output.replaceAll("\\s", "")),StandardCharsets.UTF_8),65536);}catch(IllegalArgumentException malformed){throw new IllegalStateException("GetConsoleOutput returned malformed base64");}
    }
    String verify(String value){return execute(value,"VerifyProvisionResources",false,false,(j,s)->{
        Instance instance=find(j,s,value);Map<String,Object> out=observe(j,s,instance,false);
        if(backend.isDemo()){
            boolean gone=instance==null||"terminated".equals(s.get("state"));out.put("leftovers",gone?0:3);out.put("root_volume_absent",gone);out.put("network_interfaces_absent",gone);out.put("cleanup_complete",gone);return out;
        }
        List<String> volumes=new ArrayList<>(),interfaces=new ArrayList<>();Set<String> tokens=new HashSet<>();String next=null;
        do{
            String pageToken=next;var page=call(j,"DescribeVolumes",()->ec2().describeVolumes(x->x.filters(Filter.builder().name("tag:provisioner").values("lmprov").build(),Filter.builder().name("tag:lmprov_id").values(value).build()).nextToken(pageToken).maxResults(100)));
            for(var v:page.volumes()){requireTags(v.tags(),value);if(volumes.contains(v.volumeId()))throw new IllegalStateException("duplicate volume in inventory");volumes.add(v.volumeId());if(volumes.size()>1000)throw new IllegalStateException("volume inventory exceeds bound");}
            next=page.nextToken();if(next!=null&&(!tokens.add(next)||tokens.size()>100))throw new IllegalStateException("invalid volume pagination");
        }while(next!=null&&!next.isBlank());
        next=null;tokens.clear();
        do{
            String pageToken=next;var page=call(j,"DescribeNetworkInterfaces",()->ec2().describeNetworkInterfaces(x->x.filters(Filter.builder().name("tag:provisioner").values("lmprov").build(),Filter.builder().name("tag:lmprov_id").values(value).build()).nextToken(pageToken).maxResults(100)));
            for(var nic:page.networkInterfaces()){requireTags(nic.tagSet(),value);if(interfaces.contains(nic.networkInterfaceId()))throw new IllegalStateException("duplicate interface in inventory");interfaces.add(nic.networkInterfaceId());if(interfaces.size()>1000)throw new IllegalStateException("interface inventory exceeds bound");}
            next=page.nextToken();if(next!=null&&(!tokens.add(next)||tokens.size()>100))throw new IllegalStateException("invalid interface pagination");
        }while(next!=null&&!next.isBlank());
        boolean volumeAbsent=false,nicsAbsent=true;
        String volumeId=text(s.get("volume_id"));
        if(!volumeId.isBlank())try{var found=call(j,"DescribeVolumes",()->ec2().describeVolumes(x->x.volumeIds(volumeId)));volumeAbsent=found.volumes().isEmpty();}catch(Ec2Exception e){if(e.awsErrorDetails()!=null&&"InvalidVolume.NotFound".equals(e.awsErrorDetails().errorCode()))volumeAbsent=true;else throw e;}
        Object known=s.get("network_interface_ids");
        if(known instanceof List<?> ids)for(Object raw:ids){String nic=text(raw);try{var found=call(j,"DescribeNetworkInterfaces",()->ec2().describeNetworkInterfaces(x->x.networkInterfaceIds(nic)));if(!found.networkInterfaces().isEmpty())nicsAbsent=false;}catch(Ec2Exception e){if(e.awsErrorDetails()==null||!"InvalidNetworkInterfaceID.NotFound".equals(e.awsErrorDetails().errorCode()))throw e;}}
        else nicsAbsent=false;
        int count=(instance==null||"terminated".equals(text(out.get("state")))?0:1)+volumes.size()+interfaces.size();
        boolean complete=count==0&&volumeAbsent&&nicsAbsent;
        out.put("leftovers",count);out.put("volume_ids_remaining",volumes);out.put("network_interface_ids_remaining",interfaces);out.put("root_volume_absent",volumeAbsent);out.put("network_interfaces_absent",nicsAbsent);out.put("cleanup_complete",complete);return out;
    });}
    String console(String value){return execute(value,"GetConsoleOutput",false,false,(j,s)->{Instance instance=find(j,s,value);Map<String,Object> out=observe(j,s,instance,false);if(instance!=null)out.put("output",consoleText(j,s,instance.instanceId()));return out;});}
}
