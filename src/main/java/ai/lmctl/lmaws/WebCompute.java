package ai.lmctl.lmaws;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;
import java.util.function.Consumer;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;

/** Persistent run-owned EC2 web node lifecycle for the lmweblab up/test/down flow. */
final class WebCompute {
    private static final String OWNER = "lmaws_test";
    private final AwsBackend backend;
    WebCompute(AwsBackend backend) { this.backend = Objects.requireNonNull(backend); }

    Map<String,String> create(String runId, String vpcId, String subnetId, String ami,
                              String cidr, String instanceType, int volumeGiB,
                              String userData, double maxPrice) {
        return create(runId,vpcId,subnetId,ami,cidr,instanceType,volumeGiB,userData,maxPrice,null);
    }
    Map<String,String> create(String runId, String vpcId, String subnetId, String ami,
                              String cidr, String instanceType, int volumeGiB,
                              String userData, double maxPrice, Consumer<Map<String,String>> checkpoint) {
        WebStack.requireRun(runId); WebStack.requireHttpCidr(cidr); WebStack.requireNano(instanceType, volumeGiB);
        if (!vpcId.matches("vpc-[0-9a-z]{1,32}") || !subnetId.matches("subnet-[0-9a-z]{1,32}")) throw new IllegalArgumentException("web compute requires explicit VPC and subnet");
        if (!ami.matches("ami-[0-9a-z]{8,32}")) throw new IllegalArgumentException("web compute requires an AMI id");
        if (userData == null || !userData.startsWith("#!") || !userData.contains("lmweblab") || userData.getBytes(StandardCharsets.UTF_8).length>16000) throw new IllegalArgumentException("web compute user data must identify lmweblab");
        if (!(maxPrice > 0.0 && Double.isFinite(maxPrice) && maxPrice <= Ec2Compute.ON_DEMAND.get(instanceType).doubleValue())) throw new IllegalArgumentException("web compute spot max price must be positive and within the nano On-Demand ceiling");
        backend.requireComputeWriteEnabled(); Ec2Client ec2 = backend.ec2Client();
        String sgName = WebStack.resourceName(runId, "web-sg");
        String sg = ec2.createSecurityGroup(x -> x.groupName(sgName).description("lmweblab run-owned web ingress").vpcId(vpcId)
                .tagSpecifications(TagSpecification.builder().resourceType(ResourceType.SECURITY_GROUP).tags(tag(OWNER, runId), tag("Name", sgName)).build())).groupId();
        if(checkpoint!=null)checkpoint.accept(Map.of("security_group_id",sg));
        boolean launched = false;
        try {
            ec2.authorizeSecurityGroupIngress(x -> x.groupId(sg).ipPermissions(IpPermission.builder().ipProtocol("tcp").fromPort(80).toPort(80).ipRanges(IpRange.builder().cidrIp(cidr).description("lmweblab caller").build()).build()));
            String script = "#!/bin/bash\n# bound cost before any boot setup can fail\nshutdown -h +9\n" + userData;
            String encoded = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_8));
            List<String> subnetCandidates = candidateSubnets(ec2, vpcId, subnetId);
            List<String> typeCandidates = instanceType.equals("t4g.nano") ? List.of("t4g.nano", "t3.nano") : List.of("t3.nano", "t4g.nano");
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(180).toNanos(); int attempts = 0;
            for (String candidateType : typeCandidates) for (String candidateSubnet : subnetCandidates) {
                if (++attempts > 12 || System.nanoTime() > deadline) throw new IllegalStateException("web capacity fallback exceeded 12 attempts or 180 seconds");
                String candidateAmi = candidateType.equals(instanceType) ? ami : publicAmi(candidateType);
                double candidatePrice = Math.min(maxPrice, Ec2Compute.ON_DEMAND.get(candidateType).doubleValue());
                String token = "lmaws-" + runId + "-" + candidateType.replace('.', '-') + "-" + Integer.toHexString((candidateAmi + candidateSubnet).hashCode());
                try {
                    RunInstancesResponse response = run(ec2, candidateAmi, candidateType, candidateSubnet, sg, candidatePrice, encoded, token, runId, volumeGiB);
                    if (response.instances().isEmpty()) throw new IllegalStateException("EC2 returned no web instance");
                    launched = true; Instance i = response.instances().get(0);
                    if(checkpoint!=null)checkpoint.accept(Map.of("instance_id",i.instanceId(),"security_group_id",sg));
                    i = waitRunning(ec2, i.instanceId());
                    String publicIp = i.publicIpAddress() == null ? "" : i.publicIpAddress();
                    if (publicIp.isBlank()) throw new IllegalStateException("web instance did not receive a public IPv4");
                    var out = new LinkedHashMap<>(Map.of("instance_id", i.instanceId(), "security_group_id", sg, "subnet_id", candidateSubnet, "vpc_id", vpcId, "state", i.state().nameAsString(), "public_ip", publicIp, "run_id", runId, "instance_type", candidateType, "ami", candidateAmi, "max_price", Double.toString(candidatePrice)));
                    if (checkpoint != null) checkpoint.accept(Map.copyOf(out));
                    return out;
                } catch (Ec2Exception capacity) { if (!capacityCode(capacity)) throw capacity; }
            }
            throw new IllegalStateException("all web spot capacity candidates were rejected");

        } finally { if (!launched) try { ec2.deleteSecurityGroup(x -> x.groupId(sg)); } catch (RuntimeException ignored) { } }
    }

    private RunInstancesResponse run(Ec2Client ec2,String ami,String type,String subnet,String sg,double price,String encoded,String token,String runId,int volumeGiB) {
        return ec2.runInstances(x -> x.imageId(ami).instanceType(InstanceType.fromValue(type)).minCount(1).maxCount(1).clientToken(token)
                .networkInterfaces(InstanceNetworkInterfaceSpecification.builder().deviceIndex(0).subnetId(subnet).groups(sg).associatePublicIpAddress(true).build())
                .metadataOptions(InstanceMetadataOptionsRequest.builder().httpTokens(HttpTokensState.REQUIRED).httpEndpoint(InstanceMetadataEndpointState.ENABLED).build()).instanceInitiatedShutdownBehavior(ShutdownBehavior.TERMINATE).creditSpecification(CreditSpecificationRequest.builder().cpuCredits("standard").build()).userData(encoded)
                .instanceMarketOptions(m -> m.marketType(MarketType.SPOT).spotOptions(s -> s.spotInstanceType(SpotInstanceType.ONE_TIME).maxPrice(Double.toString(price))))
                .blockDeviceMappings(BlockDeviceMapping.builder().deviceName("/dev/xvda").ebs(EbsBlockDevice.builder().volumeSize(volumeGiB).volumeType(VolumeType.GP3).deleteOnTermination(true).encrypted(true).build()).build())
                .tagSpecifications(tagSpec(ResourceType.INSTANCE, runId, WebStack.resourceName(runId, "app")),tagSpec(ResourceType.VOLUME, runId, WebStack.resourceName(runId, "app-volume")),tagSpec(ResourceType.NETWORK_INTERFACE, runId, WebStack.resourceName(runId, "app-eni")),tagSpec(ResourceType.SPOT_INSTANCES_REQUEST, runId, WebStack.resourceName(runId, "spot"))));
    }
    private static boolean capacityCode(Ec2Exception e){String c=e.awsErrorDetails()==null?"":e.awsErrorDetails().errorCode();return Set.of("InsufficientInstanceCapacity","InsufficientInstanceCapacityInAvailabilityZone","InsufficientSpotInstanceCapacity").contains(c);}
    private List<String> candidateSubnets(Ec2Client ec2,String vpc,String requested){LinkedHashSet<String> out=new LinkedHashSet<>();out.add(requested);for(var s:ec2.describeSubnets(x->x.filters(Filter.builder().name("vpc-id").values(vpc).build(),Filter.builder().name("map-public-ip-on-launch").values("true").build())).subnets())if(!requested.equals(s.subnetId()))out.add(s.subnetId());return out.stream().limit(6).toList();}
    private String publicAmi(String type){String n=type.equals("t4g.nano")?"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64";return backend.ssmClient().getParameter(x->x.name(n)).parameter().value();}

    Map<String,String> delete(String runId, String instanceId, String securityGroupId) {
        WebStack.requireRun(runId); if (!instanceId.isEmpty()&&!instanceId.matches("i-[0-9a-f]{8,32}") || !securityGroupId.matches("sg-[0-9a-f]{8,32}")) throw new IllegalArgumentException("invalid web compute identifiers");
        backend.requireComputeWriteEnabled(); Ec2Client ec2 = backend.ec2Client();
        Instance instance=null;
        if(!instanceId.isEmpty())try{instance=ec2.describeInstances(x->x.instanceIds(instanceId)).reservations().stream().flatMap(r->r.instances().stream()).findFirst().orElse(null);}catch(Ec2Exception e){if(!"InvalidInstanceID.NotFound".equals(e.awsErrorDetails().errorCode()))throw e;}
        String spotRequest = "";
        if (instance != null) { String owner = instance.tags().stream().filter(t -> OWNER.equals(t.key())).map(Tag::value).findFirst().orElse(""); String name = instance.tags().stream().filter(t -> "Name".equals(t.key())).map(Tag::value).findFirst().orElse(""); if (!runId.equals(owner) || !name.equals(WebStack.resourceName(runId, "app"))) throw new SecurityException("refusing instance without exact run ownership"); spotRequest = instance.spotInstanceRequestId() == null ? "" : instance.spotInstanceRequestId(); ec2.terminateInstances(x -> x.instanceIds(instanceId)); }
        final String requestId = spotRequest;
        if (instance != null) waitGone(ec2, instanceId);
        if (!requestId.isBlank()) waitSpotClosed(ec2, requestId);
        SecurityGroup sg=null;
        try{sg=ec2.describeSecurityGroups(x->x.groupIds(securityGroupId)).securityGroups().stream().findFirst().orElse(null);}catch(Ec2Exception e){if(!"InvalidGroup.NotFound".equals(e.awsErrorDetails().errorCode()))throw e;}
        if (sg != null) { String owner = sg.tags().stream().filter(t -> OWNER.equals(t.key())).map(Tag::value).findFirst().orElse(""); String name = sg.tags().stream().filter(t -> "Name".equals(t.key())).map(Tag::value).findFirst().orElse(""); if (!runId.equals(owner) || !name.equals(WebStack.resourceName(runId, "web-sg"))) throw new SecurityException("refusing security group without exact run ownership"); deleteGroupEventually(ec2, securityGroupId); }
        return new LinkedHashMap<>(Map.of("run_id", runId, "instance_id", instanceId, "security_group_id", securityGroupId, "status", "teardown_requested"));
    }
    List<Map<String,String>> inventory(String run) {
        WebStack.requireRun(run); Ec2Client ec2=backend.ec2Client();Filter mine=Filter.builder().name("tag:"+OWNER).values(run).build();
        List<Map<String,String>> rows=new ArrayList<>();int pages=0;
        for(var page:ec2.describeInstancesPaginator(x->x.filters(mine))){if(++pages>100)throw new IllegalStateException("web instance page cap");for(var r:page.reservations())for(var item:r.instances())if(!"terminated".equals(item.state().nameAsString()))rows.add(Map.of("kind","instance","id",item.instanceId(),"name",item.tags().stream().filter(t->"Name".equals(t.key())).map(Tag::value).findFirst().orElse("")));}
        pages=0;for(var page:ec2.describeSecurityGroupsPaginator(x->x.filters(mine))){if(++pages>100)throw new IllegalStateException("web SG page cap");for(var item:page.securityGroups())rows.add(Map.of("kind","security_group","id",item.groupId(),"name",item.groupName()));}
        pages=0;for(var page:ec2.describeVolumesPaginator(x->x.filters(mine))){if(++pages>100)throw new IllegalStateException("web volume page cap");for(var item:page.volumes())if(!"deleted".equals(item.stateAsString()))rows.add(Map.of("kind","volume","id",item.volumeId()));}
        pages=0;for(var page:ec2.describeNetworkInterfacesPaginator(x->x.filters(mine))){if(++pages>100)throw new IllegalStateException("web ENI page cap");for(var item:page.networkInterfaces())rows.add(Map.of("kind","eni","id",item.networkInterfaceId()));}
        pages=0;for(var page:ec2.describeSpotInstanceRequestsPaginator(x->x.filters(mine))){if(++pages>100)throw new IllegalStateException("web spot page cap");for(var item:page.spotInstanceRequests())if(Set.of("open","active").contains(item.stateAsString()))rows.add(Map.of("kind","spot_request","id",item.spotInstanceRequestId()));}
        return rows;
    }
    private static Tag tag(String key, String value) { return Tag.builder().key(key).value(value).build(); }
    private static TagSpecification tagSpec(ResourceType type, String runId, String name) { return TagSpecification.builder().resourceType(type).tags(tag(OWNER, runId), tag("Name", name)).build(); }
    private static void waitGone(Ec2Client ec2, String id) {
        long deadline = System.nanoTime() + java.time.Duration.ofMinutes(10).toNanos();
        while (System.nanoTime() < deadline) {
            try { var rs = ec2.describeInstances(x -> x.instanceIds(id)).reservations(); if (rs.isEmpty() || rs.stream().flatMap(r -> r.instances().stream()).allMatch(i -> i.state() != null && i.state().nameAsString().equals("terminated"))) return; }
            catch (Ec2Exception e) { if (e.awsErrorDetails().errorCode().startsWith("InvalidInstanceID")) return; throw e; }
            try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("web cleanup interrupted",e); }
        }
        throw new IllegalStateException("timed out waiting for web instance termination");
    }
    private static Instance waitRunning(Ec2Client ec2, String id) {
        long deadline = System.nanoTime() + java.time.Duration.ofMinutes(10).toNanos();
        while (System.nanoTime() < deadline) {
            var rs = ec2.describeInstances(x -> x.instanceIds(id)).reservations();
            var found = rs.stream().flatMap(r -> r.instances().stream()).findFirst().orElse(null);
            if (found != null && found.state() != null && found.state().nameAsString().equals("running")) return found;
            if (found != null && found.state() != null && Set.of("terminated", "shutting-down", "stopped").contains(found.state().nameAsString())) throw new IllegalStateException("web instance entered " + found.state().nameAsString());
            try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("web wait interrupted", e); }
        }
        throw new IllegalStateException("timed out waiting for web instance running");
    }
    private static void deleteGroupEventually(Ec2Client ec2, String id) {
        long deadline = System.nanoTime() + java.time.Duration.ofMinutes(5).toNanos();
        while (System.nanoTime() < deadline) {
            try { ec2.deleteSecurityGroup(x -> x.groupId(id)); return; }
            catch (Ec2Exception e) { if (!"DependencyViolation".equals(e.awsErrorDetails().errorCode())) throw e; }
            try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("web cleanup interrupted",e); }
        }
        throw new IllegalStateException("timed out deleting web security group");
    }
    private static void waitSpotClosed(Ec2Client ec2, String id) {
        long deadline = System.nanoTime() + java.time.Duration.ofMinutes(5).toNanos();
        while (System.nanoTime() < deadline) {
            var found = ec2.describeSpotInstanceRequests(x -> x.spotInstanceRequestIds(id)).spotInstanceRequests();
            if (found.isEmpty() || found.stream().allMatch(r -> Set.of("cancelled", "closed", "failed").contains(r.stateAsString()))) return;
            try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("spot wait interrupted", e); }
        }
        throw new IllegalStateException("timed out waiting for spot request closure");
    }
}
