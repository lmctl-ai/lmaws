package ai.lmctl.lmaws;

import java.util.*;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;

/** Guarded online growth of one explicitly identified root gp3 volume. */
final class EbsResize {
    private static final String ACCOUNT = "[0-9]{12}";
    private static final String INSTANCE = "i-[0-9a-f]{8,17}";
    private static final String VOLUME = "vol-[0-9a-f]{8,17}";
    private final AwsBackend backend;
    EbsResize(AwsBackend backend) { this.backend = backend; }

    Map<String,String> resize(String raw, boolean apply, boolean human) {
        Map<String,Object> spec = parse(raw);
        String account = text(spec,"account"), region = text(spec,"region");
        String instanceId = text(spec,"instance_id"), volumeId = text(spec,"volume_id");
        int from = integer(spec,"from_gib"), target = integer(spec,"to_gib");
        if(!account.matches(ACCOUNT)) throw new IllegalArgumentException("account must be a 12-digit account id");
        if(!region.equals("us-east-1")) throw new IllegalArgumentException("EBS resize is restricted to us-east-1");
        if(!instanceId.matches(INSTANCE)) throw new IllegalArgumentException("instance_id must be an EC2 instance id");
        if(!volumeId.matches(VOLUME)) throw new IllegalArgumentException("volume_id must be an EBS volume id");
        if(from<1 || target<1 || target>16384 || target<=from) throw new IllegalArgumentException("to_gib must be greater than from_gib and at most 16384");
        if(!backend.region().equals(region)) throw new IllegalArgumentException("backend region does not match spec");
        if(apply) requireHuman(true, human);
        if(backend.isDemo()) return demo(spec,apply);
        if(!AwsBackend.isLiveEnabled()) throw new SecurityException("live EBS inspection requires LMAWS_LIVE=1");
        if("admin".equals(backend.profileName())) requireHuman(false,human);
        else if(!"default".equals(backend.profileName()) || apply) throw new SecurityException("EBS inspection requires default; human apply requires admin");
        String caller=backend.accountIdForResize();
        if(!account.equals(caller)) throw new IllegalArgumentException("spec account does not match caller account");
        Ec2Client ec2=backend.ec2ClientForResize();
        Instance instance=describeInstance(ec2,instanceId);
        if(instance==null) throw new IllegalArgumentException("instance was not found");
        if(!instanceId.equals(instance.instanceId())) throw new IllegalArgumentException("returned instance id mismatch");
        if(!instance.state().nameAsString().equals("running")) throw new IllegalStateException("instance must be running");
        InstanceBlockDeviceMapping root=null;
        for(InstanceBlockDeviceMapping b:instance.blockDeviceMappings()) if(b.deviceName().equals(instance.rootDeviceName())) {root=b;break;}
        if(root==null || root.ebs()==null || !volumeId.equals(root.ebs().volumeId())) throw new IllegalArgumentException("volume is not the instance root volume");
        if(root.ebs().deleteOnTermination()==null || root.ebs().deleteOnTermination()) throw new IllegalArgumentException("root volume must have DeleteOnTermination=false");
        Volume volume=describeVolume(ec2,volumeId);
        if(volume==null) throw new IllegalArgumentException("volume was not found");
        if(!volumeId.equals(volume.volumeId())) throw new IllegalArgumentException("returned volume id mismatch");
        if(!"gp3".equals(volume.volumeTypeAsString())) throw new IllegalArgumentException("root volume must be gp3");
        if(!"in-use".equals(volume.stateAsString())) throw new IllegalStateException("volume must be in-use");
        if(volume.attachments().size()!=1 || !instanceId.equals(volume.attachments().get(0).instanceId()) || !"attached".equals(volume.attachments().get(0).stateAsString()) || !instance.rootDeviceName().equals(volume.attachments().get(0).device())) throw new IllegalArgumentException("volume must have exactly one attached mapping to the requested root device");
        int actual=volume.size();
        VolumeModification mod=ec2.describeVolumesModifications(DescribeVolumesModificationsRequest.builder().volumeIds(volumeId).build()).volumesModifications().stream().findFirst().orElse(null);
        String modState=mod==null?"completed":mod.modificationStateAsString();
        int modTarget=mod==null?actual:(mod.targetSize()==null?actual:mod.targetSize());
        if(actual!=from && actual!=target) throw new IllegalArgumentException("from_gib does not match the current volume size");
        if(mod!=null && !volumeId.equals(mod.volumeId())) throw new IllegalArgumentException("returned modification volume id mismatch");
        if(mod!=null && "failed".equals(modState)) throw new IllegalStateException("previous EBS modification failed; inspect before retrying");
        if(mod!=null && !Set.of("optimizing","completed","modifying").contains(modState)) throw new IllegalStateException("unknown EBS modification state");
        if(mod!=null && !"completed".equals(modState)) {
            if(modTarget!=target) throw new IllegalStateException("another target size is being modified");
            return row(spec,actual,target,actual!=target,false,modState,actual==target && "optimizing".equals(modState));
        }
        if(actual==target) return row(spec,actual,target,false,false,modState,true);
        if(actual!=from) throw new IllegalArgumentException("volume size is not the requested from_gib");
        if(!apply) return row(spec,actual,target,true,false,"planned",false);
        ec2.modifyVolume(ModifyVolumeRequest.builder().volumeId(volumeId).size(target).build());
        return row(spec,actual,target,true,true,modificationState(ec2,volumeId),false);
    }

    private void requireHuman(boolean apply, boolean human) {
        if(!"admin".equals(backend.profileName()) || !"admin".equals(AwsBackend.activeProfile()) || !"admin".equals(System.getenv().getOrDefault("AWS_PROFILE", ""))) throw new SecurityException("EBS resize requires AWS_PROFILE=admin");
        if(!"1".equals(System.getenv("LMAWS_ADMIN_GRANT"))) throw new SecurityException("EBS resize requires LMAWS_ADMIN_GRANT=1");
        if(!"1".equals(System.getenv("LMAWS_LIVE"))) throw new SecurityException("EBS resize requires LMAWS_LIVE=1");
        if(apply && !"1".equals(System.getenv("LMAWS_APPLY"))) throw new SecurityException("EBS resize apply requires LMAWS_APPLY=1");
        if(!human) throw new SecurityException("admin EBS access requires the human confirmation flag");
        if("true".equalsIgnoreCase(System.getenv("CI")) || "1".equals(System.getenv("CI"))) throw new SecurityException("admin EBS access is forbidden in CI");
    }

    private static Instance describeInstance(Ec2Client ec2,String id) {
        var r=ec2.describeInstances(DescribeInstancesRequest.builder().instanceIds(id).build());
        return r.reservations().stream().flatMap(x->x.instances().stream()).findFirst().orElse(null);
    }
    private static Volume describeVolume(Ec2Client ec2,String id) {
        var r=ec2.describeVolumes(DescribeVolumesRequest.builder().volumeIds(id).build());
        return r.volumes().stream().findFirst().orElse(null);
    }
    private static String modificationState(Ec2Client ec2,String id) {
        var r=ec2.describeVolumesModifications(DescribeVolumesModificationsRequest.builder().volumeIds(id).build());
        return r.volumesModifications().stream().findFirst().map(x->x.modificationStateAsString()).orElse("completed");
    }
    private static Map<String,String> row(Map<String,Object> spec,int old,int target,boolean changed,boolean applied,String state,boolean ready) {
        Map<String,String> out=new LinkedHashMap<>();
        out.put("instance_id",text(spec,"instance_id"));out.put("volume_id",text(spec,"volume_id"));out.put("old_gib",Integer.toString(old));out.put("current_gib",Integer.toString(old));out.put("target_gib",Integer.toString(target));out.put("changed",Boolean.toString(changed));out.put("applied",Boolean.toString(applied));out.put("state",state);out.put("modification_state",state);out.put("ready",Boolean.toString(ready));out.put("region",text(spec,"region"));return out;
    }
    private static Map<String,String> demo(Map<String,Object> spec,boolean apply) { return row(spec,apply?integer(spec,"to_gib"):integer(spec,"from_gib"),integer(spec,"to_gib"),!apply,apply,apply?"optimizing":"planned",apply); }
    @SuppressWarnings("unchecked") private static Map<String,Object> parse(String raw) {
        Object value=io.lmctl.lmcode.Json.parse(raw);
        if(!(value instanceof Map<?,?> m)) throw new IllegalArgumentException("resize spec must be an object");
        Map<String,Object> out=new LinkedHashMap<>();for(var e:m.entrySet()) out.put(String.valueOf(e.getKey()),e.getValue());
        if(!out.keySet().equals(Set.of("account","region","instance_id","volume_id","from_gib","to_gib"))) throw new IllegalArgumentException("resize spec fields must be exactly account, region, instance_id, volume_id, from_gib, to_gib");
        return out;
    }
    private static String text(Map<String,Object> m,String key){Object x=m.get(key);if(!(x instanceof String s)||s.isBlank())throw new IllegalArgumentException(key+" must be a non-empty string");return s;}
    private static int integer(Map<String,Object> m,String key){Object x=m.get(key);if(!(x instanceof Number n)||n.doubleValue()!=n.intValue())throw new IllegalArgumentException(key+" must be an integer");return n.intValue();}
}
