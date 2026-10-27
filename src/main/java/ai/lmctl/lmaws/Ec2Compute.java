package ai.lmctl.lmaws;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;

/**
 * EC2 compute for scripts: read-only fleet, price, address, volume and subnet reports, and one
 * run-owned spot nano lifecycle. Every mutation is limited to resources this run created and
 * tagged lmaws_test=&lt;run id&gt; at creation; instances tagged Project=awsspot are always refused.
 */
final class Ec2Compute {
    static final List<String> NANO = List.of("t4g.nano", "t3.nano");
    /** us-east-1 Linux On-Demand USD/hour (2026-10); the spot max price may not exceed it. */
    static final Map<String, BigDecimal> ON_DEMAND = Map.of("t4g.nano", new BigDecimal("0.0042"), "t3.nano", new BigDecimal("0.0052"));
    static final BigDecimal GP3_GB_MONTH = new BigDecimal("0.08");
    static final int ROOT_GIB = 8, MAX_LIFETIME_SECONDS = 600;
    static final String FLEET_KEY = "Project", FLEET_VALUE = "awsspot", OWNER = "lmaws_test";

    private final AwsBackend backend;
    Ec2Compute(AwsBackend backend) { this.backend = backend; }
    private boolean demo() { return backend.isDemo(); }
    private Ec2Client ec2() { return backend.ec2Client(); }

    // ---------- read-only reports ----------

    List<Map<String, String>> instances(String key, String value) {
        if (!key.isEmpty() && !key.matches("[A-Za-z0-9_.:/=+@ -]{1,128}")) throw new IllegalArgumentException("ec2_instances: invalid tag key");
        if (demo()) return Demo.instances().stream().filter(r -> key.isEmpty() || (value.isEmpty() ? !r.getOrDefault(tagColumn(key), "").isEmpty() : value.equals(r.get(tagColumn(key))))).toList();
        var request = DescribeInstancesRequest.builder();
        if (!key.isEmpty() && value.isEmpty()) request.filters(Filter.builder().name("tag-key").values(key).build());
        else if (!key.isEmpty()) request.filters(Filter.builder().name("tag:" + key).values(value).build());
        List<Instance> found = new ArrayList<>();
        for (var page : bounded(ec2().describeInstancesPaginator(request.build())))
            for (var r : page.reservations()) found.addAll(r.instances());
        Map<String, Volume> roots = new HashMap<>();
        List<String> ids = found.stream().flatMap(i -> i.blockDeviceMappings().stream()).filter(b -> b.ebs() != null).map(b -> b.ebs().volumeId()).distinct().toList();
        if (!ids.isEmpty()) for (var page : bounded(ec2().describeVolumesPaginator(x -> x.volumeIds(ids)))) for (var v : page.volumes()) roots.put(v.volumeId(), v);
        List<Map<String, String>> rows = new ArrayList<>();
        for (Instance i : found) {
            String profileArn = i.iamInstanceProfile() == null ? "" : Jsons.mask(nz(i.iamInstanceProfile().arn()));
            String profileName = profileArn.contains("/") ? profileArn.substring(profileArn.lastIndexOf('/') + 1) : "";
            Map<String, String> row = row("kind", "instance", "id", i.instanceId(), "name", tag(i.tags(), "Name"), "project", tag(i.tags(), "Project"), "role", tag(i.tags(), "Role"),
                    "state", i.state() == null ? "" : i.state().nameAsString(), "type", i.instanceTypeAsString(),
                    "az", i.placement() == null ? "" : i.placement().availabilityZone(), "subnet", nz(i.subnetId()), "vpc", nz(i.vpcId()),
                    "private_ip", nz(i.privateIpAddress()), "public_ip", nz(i.publicIpAddress()),
                    "market", i.instanceLifecycle() == null ? "on-demand" : i.instanceLifecycleAsString(), "spot_request", nz(i.spotInstanceRequestId()),
                    "launch_time", i.launchTime() == null ? "" : i.launchTime().toString(), "root_device", nz(i.rootDeviceName()),
                    "iam_instance_profile", profileName, "iam_instance_profile_arn", profileArn,
                    OWNER, tag(i.tags(), OWNER));
            for (var b : i.blockDeviceMappings()) {
                if (b.ebs() == null || !Objects.equals(b.deviceName(), i.rootDeviceName())) continue;
                Volume v = roots.get(b.ebs().volumeId());
                row.put("root_volume", b.ebs().volumeId());
                row.put("root_delete_on_termination", String.valueOf(Boolean.TRUE.equals(b.ebs().deleteOnTermination())));
                if (v != null) { row.put("root_size_gib", String.valueOf(v.size())); row.put("root_type", v.volumeTypeAsString()); }
            }
            rows.add(row);
        }
        return rows;
    }

    List<Map<String, String>> addresses() {
        if (demo()) return Demo.addresses();
        List<Map<String, String>> rows = new ArrayList<>();
        for (Address a : ec2().describeAddresses().addresses())
            rows.add(row("kind", "address", "id", nz(a.allocationId()), "public_ip", nz(a.publicIp()), "domain", a.domainAsString(),
                    "association", nz(a.associationId()), "instance", nz(a.instanceId()), "eni", nz(a.networkInterfaceId()), "private_ip", nz(a.privateIpAddress()),
                    "name", tag(a.tags(), "Name"), "project", tag(a.tags(), "Project"), "role", tag(a.tags(), "Role"),
                    "idle", String.valueOf(a.associationId() == null || a.associationId().isBlank())));
        return rows;
    }

    List<Map<String, String>> volumes() {
        if (demo()) return Demo.volumes();
        List<Map<String, String>> rows = new ArrayList<>();
        for (var page : bounded(ec2().describeVolumesPaginator(DescribeVolumesRequest.builder().build())))
            for (Volume v : page.volumes()) {
                VolumeAttachment at = v.attachments().isEmpty() ? null : v.attachments().get(0);
                rows.add(row("kind", "volume", "id", v.volumeId(), "az", v.availabilityZone(), "size_gib", String.valueOf(v.size()), "type", v.volumeTypeAsString(),
                        "state", v.stateAsString(), "iops", String.valueOf(v.iops() == null ? 0 : v.iops()), "throughput", String.valueOf(v.throughput() == null ? 0 : v.throughput()),
                        "instance", at == null ? "" : nz(at.instanceId()), "device", at == null ? "" : nz(at.device()),
                        "delete_on_termination", at == null ? "" : String.valueOf(Boolean.TRUE.equals(at.deleteOnTermination())),
                        "name", tag(v.tags(), "Name"), "project", tag(v.tags(), "Project"), "role", tag(v.tags(), "Role"), OWNER, tag(v.tags(), OWNER)));
            }
        return bounded(rows);
    }

    List<Map<String, String>> subnets() {
        if (demo()) return Demo.subnets();
        Set<String> defaults = new HashSet<>();
        for (Vpc v : ec2().describeVpcs().vpcs()) if (Boolean.TRUE.equals(v.isDefault())) defaults.add(v.vpcId());
        Set<String> fleet = fleetSubnets();
        List<Map<String, String>> rows = new ArrayList<>();
        for (Subnet s : ec2().describeSubnets().subnets())
            rows.add(row("kind", "subnet", "id", s.subnetId(), "az", s.availabilityZone(), "vpc", s.vpcId(), "default_vpc", String.valueOf(defaults.contains(s.vpcId())),
                    "default_for_az", String.valueOf(Boolean.TRUE.equals(s.defaultForAz())), "cidr", nz(s.cidrBlock()),
                    "available_ips", String.valueOf(s.availableIpAddressCount() == null ? 0 : s.availableIpAddressCount()),
                    "map_public_ip", String.valueOf(Boolean.TRUE.equals(s.mapPublicIpOnLaunch())), "fleet", String.valueOf(fleet.contains(s.subnetId()))));
        return rows;
    }

    /** Latest Linux/UNIX spot price per (type, AZ) within the last `hours`. */
    List<Map<String, String>> spotPrices(String types, long hours) {
        List<String> wanted = Arrays.stream(types.split(",")).map(String::trim).filter(t -> !t.isEmpty()).distinct().toList();
        if (wanted.isEmpty() || wanted.size() > 20 || wanted.stream().anyMatch(t -> !t.matches("[a-z0-9]+\\.[a-z0-9]+")))
            throw new IllegalArgumentException("spot_prices: 1..20 instance types like t4g.nano,t3.nano");
        if (hours < 1 || hours > 720) throw new IllegalArgumentException("spot_prices: hours must be 1..720");
        if (demo()) return Demo.prices(wanted);
        Map<String, SpotPrice> latest = new TreeMap<>();
        var request = DescribeSpotPriceHistoryRequest.builder().instanceTypesWithStrings(wanted).productDescriptions("Linux/UNIX")
                .startTime(Instant.now().minus(Duration.ofHours(hours))).build();
        for (var page : bounded(ec2().describeSpotPriceHistoryPaginator(request)))
            for (SpotPrice p : page.spotPriceHistory()) {
                String k = p.instanceTypeAsString() + "\u0000" + p.availabilityZone();
                SpotPrice old = latest.get(k);
                if (old == null || p.timestamp().isAfter(old.timestamp())) latest.put(k, p);
            }
        List<Map<String, String>> rows = new ArrayList<>();
        for (SpotPrice p : latest.values())
            rows.add(row("kind", "spot_price", "type", p.instanceTypeAsString(), "az", p.availabilityZone(), "price", p.spotPrice(),
                    "on_demand", ON_DEMAND.containsKey(p.instanceTypeAsString()) ? ON_DEMAND.get(p.instanceTypeAsString()).toPlainString() : "", "timestamp", p.timestamp().toString()));
        return rows;
    }

    Map<String, String> status(String id) {
        requireInstanceId(id);
        if (demo()) return Demo.status(id);
        var described = describeInstance(id);
        Map<String, String> row = row("kind", "instance_status", "id", id, "state", described == null ? "absent" : described.state().nameAsString(),
                "system_status", "", "instance_status", "", "az", described == null ? "" : described.placement().availabilityZone(),
                "type", described == null ? "" : described.instanceTypeAsString(), "spot_request", described == null ? "" : nz(described.spotInstanceRequestId()),
                OWNER, described == null ? "" : tag(described.tags(), OWNER), "project", described == null ? "" : tag(described.tags(), FLEET_KEY));
        if (described != null) {
            var st = ec2().describeInstanceStatus(x -> x.instanceIds(id).includeAllInstances(true)).instanceStatuses();
            if (!st.isEmpty()) {
                row.put("system_status", st.get(0).systemStatus() == null ? "" : st.get(0).systemStatus().statusAsString());
                row.put("instance_status", st.get(0).instanceStatus() == null ? "" : st.get(0).instanceStatus().statusAsString());
            }
        }
        return row;
    }

    /** Public AWS parameters only (for example the latest AMI ids under /aws/service/). */
    String publicParameter(String name) {
        if (name == null || !name.matches("/aws/service/[A-Za-z0-9_./-]{1,200}") || name.contains(".."))
            throw new IllegalArgumentException("public_parameter: only public /aws/service/... names");
        if (demo()) return name.contains("arm64") ? "ami-0f1c7e00000a6401" : "ami-0f1c7e0000086401";
        return backend.ssmClient().getParameter(x -> x.name(name)).parameter().value();
    }

    static final List<String> CREDIT_METRICS = List.of("CPUCreditBalance", "CPUCreditUsage", "CPUSurplusCreditBalance", "CPUSurplusCreditsCharged", "CPUUtilization");

    /** Hourly CloudWatch statistics of the burstable-credit metrics for one instance. */
    List<Map<String, String>> cpuCredits(String ids, long hours) {
        List<String> list = Arrays.stream(ids.split(",")).map(String::trim).filter(x -> !x.isEmpty()).distinct().toList();
        if (list.isEmpty() || list.size() > 20) throw new IllegalArgumentException("cpu_credits: 1..20 instance ids, comma separated");
        if (hours < 1 || hours > 168) throw new IllegalArgumentException("cpu_credits: hours must be 1..168");
        List<Map<String, String>> rows = new ArrayList<>();
        for (String id : list) rows.addAll(cpuCreditsOne(id, hours));
        return rows;
    }

    private List<Map<String, String>> cpuCreditsOne(String id, long hours) {
        requireInstanceId(id);
        List<Map<String, String>> rows = new ArrayList<>();
        if (demo()) {
            for (String metric : CREDIT_METRICS) {
                int k = id.endsWith("1") ? 0 : id.endsWith("2") ? 1 : 2;  // dev-a, dev-b, bastion fixtures
                double base = switch (metric) { case "CPUCreditBalance" -> new double[]{1980, 1260, 118}[k]; case "CPUCreditUsage" -> new double[]{31, 112, 2.4}[k]; case "CPUUtilization" -> new double[]{13, 47, 2}[k]; default -> 0; };
                for (long h = hours; h >= 1; h--) {
                    double v = base == 0 ? 0 : base * (1 + 0.08 * Math.sin(h / 3.0));
                    rows.add(row("kind", "metric", "instance", id, "metric", metric, "time", Instant.parse("2026-10-26T00:00:00Z").minus(Duration.ofHours(h)).toString(), "average", String.format(Locale.ROOT, "%.4f", v), "maximum", String.format(Locale.ROOT, "%.4f", v * 1.1), "sum", String.format(Locale.ROOT, "%.4f", v * 12)));
                }
            }
            return rows;
        }
        Instant end = Instant.now(), start = end.minus(Duration.ofHours(hours));
        for (String metric : CREDIT_METRICS) {
            var points = backend.cloudWatchClient().getMetricStatistics(x -> x.namespace("AWS/EC2").metricName(metric)
                    .dimensions(d -> d.name("InstanceId").value(id)).startTime(start).endTime(end).period(3600)
                    .statisticsWithStrings("Average", "Maximum", "Sum")).datapoints();
            for (var p : points.stream().sorted(Comparator.comparing(software.amazon.awssdk.services.cloudwatch.model.Datapoint::timestamp)).toList())
                rows.add(row("kind", "metric", "instance", id, "metric", metric, "time", p.timestamp().toString(),
                        "average", text(p.average()), "maximum", text(p.maximum()), "sum", text(p.sum())));
        }
        return rows;
    }

    Set<String> fleetSubnets() {
        if (demo()) return Set.of("subnet-0fixturefleet");
        Set<String> out = new HashSet<>();
        var request = DescribeInstancesRequest.builder().filters(Filter.builder().name("tag:" + FLEET_KEY).values(FLEET_VALUE).build()).build();
        for (var page : bounded(ec2().describeInstancesPaginator(request)))
            for (var r : page.reservations()) for (var i : r.instances()) if (i.subnetId() != null) out.add(i.subnetId());
        for (Volume v : ec2().describeVolumes(x -> x.filters(Filter.builder().name("tag:" + FLEET_KEY).values(FLEET_VALUE).build())).volumes())
            out.add("az:" + v.availabilityZone());
        return out;
    }

    Instance describeInstance(String id) {
        try {
            for (var r : ec2().describeInstances(x -> x.instanceIds(id)).reservations()) for (var i : r.instances()) return i;
            return null;
        } catch (Ec2Exception e) {
            if (code(e).startsWith("InvalidInstanceID")) return null;
            throw e;
        }
    }

    /**
     * Retry teardown for an earlier run of this machine: requires that run's local spot ledger
     * (proof of ownership) and touches only resources tagged lmaws_test=&lt;run id&gt;, never the fleet.
     */
    Map<String, String> recover(String runId, Path ledgerDir) {
        backend.requireComputeWriteEnabled();
        if (runId == null || !runId.matches("[a-z0-9]{1,24}")) throw new IllegalArgumentException("spot_recover: run id required");
        if (!Files.exists(ledgerDir.resolve("lmaws-spot-" + runId + ".jsonl"))) throw new IllegalArgumentException("spot_recover: no local spot ledger for this run; refusing");
        if (demo()) return row("run_id", runId, "instances", "0", "groups", "0", "spot_requests", "closed");
        Filter mine = Filter.builder().name("tag:" + OWNER).values(runId).build();
        int terminated = 0, groupsDeleted = 0;
        for (var r : ec2().describeInstances(x -> x.filters(mine)).reservations())
            for (var i : r.instances()) {
                if (FLEET_VALUE.equals(tag(i.tags(), FLEET_KEY)) || List.of("terminated", "shutting-down").contains(i.state().nameAsString())) continue;
                ec2().terminateInstances(x -> x.instanceIds(i.instanceId())); terminated++;
            }
        for (var g : ec2().describeSecurityGroups(x -> x.filters(mine)).securityGroups())
            if (runId.equals(tag(g.tags(), OWNER))) { try { ec2().deleteSecurityGroup(x -> x.groupId(g.groupId())); groupsDeleted++; } catch (Ec2Exception e) { if (!code(e).equals("DependencyViolation")) throw e; } }
        List<String> open = ec2().describeSpotInstanceRequests(x -> x.filters(mine)).spotInstanceRequests().stream()
                .filter(r -> List.of("open", "active").contains(r.stateAsString()) && runId.equals(tag(r.tags(), OWNER))).map(SpotInstanceRequest::spotInstanceRequestId).toList();
        String requests = "closed";
        if (!open.isEmpty()) {
            try { ec2().cancelSpotInstanceRequests(x -> x.spotInstanceRequestIds(open)); requests = "cancelled"; }
            catch (Ec2Exception e) { requests = "open (" + code(e) + ")"; }
        }
        return row("run_id", runId, "instances", String.valueOf(terminated), "groups", String.valueOf(groupsDeleted), "spot_requests", requests);
    }

    // ---------- run-owned spot lifecycle ----------

    /** One run: a security group and at most one live nano instance, torn down on every path. */
    final class SpotRun implements AutoCloseable {
        final String runId, name; private final Path ledger; private final BigDecimal cap;
        private final Set<String> instances = new LinkedHashSet<>(), groups = new LinkedHashSet<>(), dead = new HashSet<>();
        private final Map<String, String> instanceAz = new HashMap<>(), instanceType = new HashMap<>();
        private Instant firstLaunch, terminatedAt; private BigDecimal observedPrice = BigDecimal.ZERO; private boolean tornDown;
        private final Map<String, Map<String, String>> demoState = new HashMap<>();

        SpotRun(String runId, Path ledgerDir, BigDecimal cap) {
            if (runId == null || !runId.matches("[a-z0-9]{1,24}")) throw new IllegalArgumentException("run id must be 1-24 lowercase letters or digits");
            this.runId = runId; this.name = "lmaws_" + runId; this.cap = cap;
            backend.requireComputeWriteEnabled();
            try { Files.createDirectories(ledgerDir); this.ledger = ledgerDir.resolve("lmaws-spot-" + runId + ".jsonl"); Files.createFile(ledger); }
            catch (java.io.IOException e) { throw new IllegalStateException("spot ledger must be a new file", e); }
            log("run", "", "started");
        }

        Map<String, String> securityGroup(String vpc) {
            if (!vpc.matches("vpc-[0-9a-z]{1,32}")) throw new IllegalArgumentException("security_group: vpc id required");
            if (!groups.isEmpty()) throw new IllegalStateException("security_group: this run already owns " + groups.size() + " group");
            String id;
            if (demo()) id = "sg-fixture" + runId.substring(0, Math.min(8, runId.length()));
            else id = ec2().createSecurityGroup(x -> x.groupName(name).description("lmaws_test disposable spot sandbox; no inbound rules").vpcId(vpc)
                    .tagSpecifications(tags(ResourceType.SECURITY_GROUP))).groupId();
            groups.add(id); log("security_group", id, "created");
            return row("kind", "security_group", "id", id, "name", name, "vpc", vpc, "inbound_rules", "0", OWNER, runId);
        }

        Map<String, String> launch(String type, String ami, String subnet, String group, double maxPrice) {
            return launchConfigured(type,ami,subnet,group,maxPrice,"#!/bin/sh\necho lmaws_test spot sandbox > /var/tmp/lmaws_test\n",false);
        }

        Map<String,String> launchWeb(String type,String ami,String subnet,String group,double maxPrice,String userData) {
            if(userData==null || !userData.startsWith("#!") || userData.getBytes(StandardCharsets.UTF_8).length>16384)
                throw new IllegalArgumentException("launch_web: user data must be a shebang script at most 16 KiB");
            return launchConfigured(type,ami,subnet,group,maxPrice,userData,true);
        }

        Map<String,String> httpIngress(String group,String cidr) {
            backend.requireComputeWriteEnabled(); WebStack.requireHttpCidr(cidr);
            if(!groups.contains(group))throw new IllegalArgumentException("http_ingress: group must be created by this run");
            if(!demo()) {
                var found=ec2().describeSecurityGroups(x->x.groupIds(group)).securityGroups();
                if(found.size()!=1 || !runId.equals(tag(found.get(0).tags(),OWNER)))throw new IllegalArgumentException("http_ingress: run tag mismatch");
                ec2().authorizeSecurityGroupIngress(x->x.groupId(group).ipPermissions(IpPermission.builder().ipProtocol("tcp").fromPort(80).toPort(80).ipRanges(IpRange.builder().cidrIp(cidr).description("lmaws_test web HTTP").build()).build()));
            }
            log("security_group",group,"http_ingress");return row("status","allowed","port","80","cidr",cidr);
        }

        private Map<String, String> launchConfigured(String type, String ami, String subnet, String group, double maxPrice,String script,boolean publicIp) {
            if (!NANO.contains(type)) throw new IllegalArgumentException("launch: only t4g.nano or t3.nano (got " + type + ")");
            if (!ami.matches("ami-[0-9a-f]{8,32}")) throw new IllegalArgumentException("launch: ami id required");
            if (!subnet.matches("subnet-[0-9a-z]{1,32}")) throw new IllegalArgumentException("launch: subnet id required");
            if (!groups.contains(group)) throw new IllegalArgumentException("launch: security group must be created by this run");
            if (instances.stream().anyMatch(i -> !dead.contains(i))) throw new IllegalStateException("launch: this run already has a live instance");
            BigDecimal price = BigDecimal.valueOf(maxPrice);
            if (!(maxPrice > 0) || price.compareTo(ON_DEMAND.get(type)) > 0) throw new IllegalArgumentException("launch: max price must be > 0 and <= On-Demand " + ON_DEMAND.get(type) + " USD/h");
            BigDecimal worst = price.multiply(BigDecimal.valueOf(MAX_LIFETIME_SECONDS)).divide(BigDecimal.valueOf(3600), 10, RoundingMode.CEILING).add(ebsCost(MAX_LIFETIME_SECONDS));
            if (worst.compareTo(cap) > 0) throw new IllegalStateException("launch: worst-case cost " + worst.toPlainString() + " exceeds cap " + cap.toPlainString() + " (LMAWS_MAX_COST_USD)");
            Set<String> fleet = fleetSubnets();
            if (fleet.contains(subnet)) throw new IllegalArgumentException("launch: refusing a subnet used by the Project=awsspot fleet");
            log("instance", type, "intent");
            if (demo()) {
                String id = "i-0fixture" + String.format("%08d", instances.size() + 1);
                instances.add(id); instanceAz.put(id, "us-east-1b"); instanceType.put(id, type); firstLaunch = firstLaunch == null ? Instant.now() : firstLaunch;
                demoState.put(id, row("state", "pending", "system_status", "initializing", "instance_status", "initializing"));
                observedPrice = new BigDecimal("0.0016");
                log("instance", id, "created");
                return row("kind", "instance", "status", "launched", "id", id, "type", type, "az", "us-east-1b", "subnet", subnet, "spot_request", "sir-fixture0001", "max_price", price.toPlainString(), "public_ip", "");
            }
            String rootDevice = ec2().describeImages(x -> x.imageIds(ami)).images().stream().findFirst().map(Image::rootDeviceName).orElse("/dev/sda1");
            String userData = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_8));
            try {
                var response = ec2().runInstances(x -> x.imageId(ami).instanceType(type).minCount(1).maxCount(1).userData(userData)
                        .clientToken(runId + "-" + type.replace('.', '-'))
                        .instanceMarketOptions(m -> m.marketType(MarketType.SPOT).spotOptions(s -> s.maxPrice(price.toPlainString())
                                .spotInstanceType(SpotInstanceType.ONE_TIME).instanceInterruptionBehavior(InstanceInterruptionBehavior.TERMINATE)))
                        .networkInterfaces(n -> n.deviceIndex(0).subnetId(subnet).groups(group).associatePublicIpAddress(publicIp).deleteOnTermination(true))
                        .blockDeviceMappings(b -> b.deviceName(rootDevice).ebs(e -> e.volumeSize(ROOT_GIB).volumeType(VolumeType.GP3).deleteOnTermination(true)))
                        .metadataOptions(o -> o.httpTokens(HttpTokensState.REQUIRED))
                        .tagSpecifications(tags(ResourceType.INSTANCE), tags(ResourceType.VOLUME), tags(ResourceType.NETWORK_INTERFACE), tags(ResourceType.SPOT_INSTANCES_REQUEST)));
                Instance i = response.instances().get(0);
                instances.add(i.instanceId()); instanceAz.put(i.instanceId(), i.placement().availabilityZone()); instanceType.put(i.instanceId(), type);
                if (firstLaunch == null) firstLaunch = Instant.now();
                log("instance", i.instanceId(), "created");
                observedPrice = latestPrice(type, i.placement().availabilityZone());
                return row("kind", "instance", "status", "launched", "id", i.instanceId(), "type", type, "az", i.placement().availabilityZone(), "subnet", subnet,
                        "spot_request", nz(i.spotInstanceRequestId()), "max_price", price.toPlainString(), "public_ip", nz(i.publicIpAddress()));
            } catch (AwsServiceException e) {
                String code = code(e);
                log("instance", type, "rejected:" + code + ": " + privateMessage(e));
                if (!KNOWN_LAUNCH_FAILURES.contains(code) && !code.contains("ServiceLinkedRole") && !code.startsWith("Unsupported")) throw e;
                return row("kind", "instance", "status", code, "type", type, "subnet", subnet, "message", launchAdvice(code));
            }
        }

        /** Polls until `state` (pending|running|stopped|terminated) or the bounded wait ends. */
        Map<String, String> waitState(String id, String state, long seconds) {
            owned(id);
            if (!List.of("running", "stopped", "terminated").contains(state)) throw new IllegalArgumentException("wait_state: running, stopped or terminated");
            long limit = boundedWait(seconds);
            Instant start = Instant.now();
            String current = "";
            while (true) {
                current = demo() ? demoAdvance(id, state) : stateOf(id);
                if (current.equals(state) || Duration.between(start, Instant.now()).getSeconds() >= limit) break;
                sleep(5000);
            }
            if (current.equals("terminated")) { dead.add(id); if (terminatedAt == null) terminatedAt = Instant.now(); }
            return row("id", id, "state", current, "wanted", state, "seconds", String.valueOf(Duration.between(start, Instant.now()).toMillis() / 1000.0), "timed_out", String.valueOf(!current.equals(state)));
        }

        Map<String, String> waitStatusOk(String id, long seconds) {
            owned(id);
            long limit = boundedWait(seconds);
            Instant start = Instant.now();
            Map<String, String> last;
            while (true) {
                last = demo() ? demoStatus(id) : status(id);
                boolean ok = "ok".equals(last.get("system_status")) && "ok".equals(last.get("instance_status"));
                if (ok || Duration.between(start, Instant.now()).getSeconds() >= limit || "terminated".equals(last.get("state"))) {
                    last.put("seconds", String.valueOf(Duration.between(start, Instant.now()).toMillis() / 1000.0)); last.put("timed_out", String.valueOf(!ok)); return last;
                }
                sleep(10000);
            }
        }

        Map<String, String> terminate(String id) { owned(id); return change(id, "terminate"); }
        Map<String, String> stop(String id) { owned(id); return change(id, "stop"); }
        Map<String, String> start(String id) { owned(id); return change(id, "start"); }

        private Map<String, String> change(String id, String action) {
            log("instance", id, "intent:" + action);
            if (demo()) {
                Map<String, String> s = demoState.get(id);
                if (action.equals("stop")) return row("id", id, "action", action, "status", "UnsupportedOperation", "message", "a one-time spot instance cannot be stopped; terminate it");
                if (action.equals("start")) return row("id", id, "action", action, "status", "IncorrectInstanceState", "message", "only stopped instances can be started");
                s.put("state", "shutting-down");
                return row("id", id, "action", action, "status", "requested", "state", "shutting-down");
            }
            try {
                String next = switch (action) {
                    case "terminate" -> ec2().terminateInstances(x -> x.instanceIds(id)).terminatingInstances().get(0).currentState().nameAsString();
                    case "stop" -> ec2().stopInstances(x -> x.instanceIds(id)).stoppingInstances().get(0).currentState().nameAsString();
                    default -> ec2().startInstances(x -> x.instanceIds(id)).startingInstances().get(0).currentState().nameAsString();
                };
                log("instance", id, action + ":" + next);
                return row("id", id, "action", action, "status", "requested", "state", next);
            } catch (Ec2Exception e) {
                String code = code(e);
                if (code.startsWith("UnauthorizedOperation") || code.startsWith("AuthFailure")) throw e;
                log("instance", id, action + ":" + code);
                return row("id", id, "action", action, "status", code, "message", action.equals("stop") ? "a one-time spot instance cannot be stopped; terminate it" : "AWS refused " + action);
            }
        }

        Map<String, String> deleteSecurityGroup(String id) {
            if (!groups.contains(id)) throw new IllegalArgumentException("delete_security_group: not created by this run");
            if (!demo()) {
                var found = ec2().describeSecurityGroups(x -> x.groupIds(id)).securityGroups();
                if (found.isEmpty() || !runId.equals(tag(found.get(0).tags(), OWNER))) throw new IllegalStateException("delete_security_group: ownership tag mismatch");
                Instant deadline = Instant.now().plusSeconds(180);
                while (true) {
                    try { ec2().deleteSecurityGroup(x -> x.groupId(id)); break; }
                    catch (Ec2Exception e) {
                        if (code(e).startsWith("InvalidGroup.NotFound")) break;
                        if (!code(e).equals("DependencyViolation") || Instant.now().isAfter(deadline)) throw e;
                        sleep(10000);
                    }
                }
            }
            groups.remove(id); log("security_group", id, "deleted");
            return row("id", id, "status", "deleted");
        }

        /** Terminates owned instances, waits for them, deletes the group; safe to call twice. */
        Map<String, String> teardown() {
            RuntimeException refused = null;
            for (String id : instances) {
                if (dead.contains(id)) continue;
                try { owned(id); } catch (IllegalArgumentException e) { log("instance", id, "teardown_refused"); refused = e; continue; }
                String s = demo() ? demoState.get(id).get("state") : stateOf(id);
                if (!s.equals("terminated") && !s.equals("shutting-down") && !s.equals("absent")) change(id, "terminate");
                waitTerminal(id);
            }
            // A refused instance still holds the group; report instead of looping on DependencyViolation.
            if (refused != null) throw new IllegalStateException("teardown incomplete: " + refused.getMessage() + "; inspect the spot ledger");
            for (String g : new ArrayList<>(groups)) deleteSecurityGroup(g);
            String requests = closeSpotRequests();
            tornDown = true; log("run", "", "torn_down");
            return row("instances", String.valueOf(instances.size()), "terminated", String.valueOf(dead.size()), "groups_left", String.valueOf(groups.size()), "spot_requests", requests);
        }

        /**
         * One-time requests normally close by themselves when the instance terminates, but EC2 can
         * leave them active/fulfilled for minutes (about 160 s measured). Wait up to 240 s, then cancel this run's requests;
         * a policy denial is recorded as the exact action an administrator must allow.
         */
        private String closeSpotRequests() {
            if (demo() || instances.isEmpty()) return "closed";
            Filter mine = Filter.builder().name("tag:" + OWNER).values(runId).build();
            Instant deadline = Instant.now().plusSeconds(240);  // measured: EC2 closed one after ~160 s
            List<String> open;
            while (true) {
                open = ec2().describeSpotInstanceRequests(x -> x.filters(mine)).spotInstanceRequests().stream()
                        .filter(r -> List.of("open", "active").contains(r.stateAsString()) && runId.equals(tag(r.tags(), OWNER))).map(SpotInstanceRequest::spotInstanceRequestId).toList();
                if (open.isEmpty()) return "closed";
                if (Instant.now().isAfter(deadline)) break;
                sleep(10000);
            }
            final List<String> ids = open;
            try {
                ec2().cancelSpotInstanceRequests(x -> x.spotInstanceRequestIds(ids));
                log("spot_request", String.join(",", ids), "cancelled");
                return "cancelled";
            } catch (Ec2Exception e) {
                log("spot_request", String.join(",", ids), "cancel_refused:" + code(e) + ": " + privateMessage(e));
                if (code(e).startsWith("UnauthorizedOperation")) deniedAction = "ec2:CancelSpotInstanceRequests";
                return "open (" + code(e) + ")";
            }
        }
        private String deniedAction = "";
        String deniedAction() { return deniedAction; }

        private void waitTerminal(String id) {
            Instant deadline = Instant.now().plusSeconds(240);
            while (true) {
                String s = demo() ? demoAdvance(id, "terminated") : stateOf(id);
                if (s.equals("terminated") || s.equals("absent")) { dead.add(id); if (terminatedAt == null) terminatedAt = Instant.now(); return; }
                if (Instant.now().isAfter(deadline)) throw new IllegalStateException("instance did not terminate within 240 seconds; inspect the spot ledger");
                sleep(5000);
            }
        }

        /** Provider-side proof for this run's resources (instances, volumes, ENIs, groups, spot requests). */
        List<Map<String, String>> verify() {
            List<Map<String, String>> rows = new ArrayList<>();
            if (demo()) {
                for (String id : instances) rows.add(row("kind", "instance", "id", id, "state", demoState.get(id).get("state"), "clean", String.valueOf("terminated".equals(demoState.get(id).get("state")))));
                rows.add(row("kind", "volume", "count", "0", "clean", "true"));
                rows.add(row("kind", "network_interface", "count", "0", "clean", "true"));
                rows.add(row("kind", "security_group", "count", String.valueOf(groups.size()), "clean", String.valueOf(groups.isEmpty())));
                rows.add(row("kind", "spot_request", "state", "closed", "status", "instance-terminated-by-user", "clean", "true"));
                return rows;
            }
            Filter mine = Filter.builder().name("tag:" + OWNER).values(runId).build();
            for (String id : instances) { String s = stateOf(id); rows.add(row("kind", "instance", "id", id, "state", s, "clean", String.valueOf(s.equals("terminated") || s.equals("absent")))); }
            long volumes = ec2().describeVolumes(x -> x.filters(mine)).volumes().stream().filter(v -> !"deleted".equals(v.stateAsString())).count();
            rows.add(row("kind", "volume", "count", String.valueOf(volumes), "clean", String.valueOf(volumes == 0)));
            long enis = ec2().describeNetworkInterfaces(x -> x.filters(mine)).networkInterfaces().size();
            rows.add(row("kind", "network_interface", "count", String.valueOf(enis), "clean", String.valueOf(enis == 0)));
            long sgs = ec2().describeSecurityGroups(x -> x.filters(mine)).securityGroups().size();
            rows.add(row("kind", "security_group", "count", String.valueOf(sgs), "clean", String.valueOf(sgs == 0)));
            for (var r : ec2().describeSpotInstanceRequests(x -> x.filters(mine)).spotInstanceRequests()) {
                boolean closed = !List.of("open", "active").contains(r.stateAsString());
                rows.add(row("kind", "spot_request", "id", r.spotInstanceRequestId(), "state", r.stateAsString(), "status", r.status() == null ? "" : nz(r.status().code()), "clean", String.valueOf(closed)));
            }
            return rows;
        }

        /** Account-wide search by the lmaws_test tag key and lmaws names; never authority to delete. */
        List<Map<String, String>> leftovers() {
            if (demo()) return List.of();
            List<Map<String, String>> rows = new ArrayList<>();
            Filter key = Filter.builder().name("tag-key").values(OWNER).build();
            for (var page : bounded(ec2().describeInstancesPaginator(DescribeInstancesRequest.builder().filters(key).build())))
                for (var r : page.reservations()) for (var i : r.instances())
                    if (!"terminated".equals(i.state().nameAsString())) rows.add(row("kind", "instance", "id", i.instanceId(), "state", i.state().nameAsString(), "name", tag(i.tags(), "Name")));
            for (var page : bounded(ec2().describeInstancesPaginator(DescribeInstancesRequest.builder().filters(Filter.builder().name("tag:Name").values("lmaws*").build()).build())))
                for (var r : page.reservations()) for (var i : r.instances())
                    if (!"terminated".equals(i.state().nameAsString()) && rows.stream().noneMatch(x -> i.instanceId().equals(x.get("id")))) rows.add(row("kind", "instance", "id", i.instanceId(), "state", i.state().nameAsString(), "name", tag(i.tags(), "Name")));
            for (Volume v : ec2().describeVolumes(x -> x.filters(key)).volumes()) rows.add(row("kind", "volume", "id", v.volumeId(), "state", v.stateAsString(), "name", tag(v.tags(), "Name")));
            for (var n : ec2().describeNetworkInterfaces(x -> x.filters(key)).networkInterfaces()) rows.add(row("kind", "network_interface", "id", n.networkInterfaceId(), "state", n.statusAsString(), "name", tag(n.tagSet(), "Name")));
            for (var g : ec2().describeSecurityGroups().securityGroups())
                if (g.groupName().startsWith("lmaws") || !tag(g.tags(), OWNER).isEmpty()) rows.add(row("kind", "security_group", "id", g.groupId(), "state", "exists", "name", g.groupName()));
            for (var r : ec2().describeSpotInstanceRequests(x -> x.filters(key)).spotInstanceRequests())
                if (List.of("open", "active").contains(r.stateAsString())) rows.add(row("kind", "spot_request", "id", r.spotInstanceRequestId(), "state", r.stateAsString(), "name", tag(r.tags(), "Name")));
            return rows;
        }

        double spotPrice() { return observedPrice.doubleValue(); }

        /** Observed spot price x minutes alive plus the 8 GiB gp3 root for the same time. */
        double estimatedCost() {
            if (firstLaunch == null) return 0.0;
            long seconds = Math.max(1, Duration.between(firstLaunch, terminatedAt == null ? Instant.now() : terminatedAt).getSeconds());
            return observedPrice.multiply(BigDecimal.valueOf(seconds)).divide(BigDecimal.valueOf(3600), 10, RoundingMode.CEILING).add(ebsCost(seconds)).doubleValue();
        }

        private void owned(String id) {
            requireInstanceId(id);
            if (!instances.contains(id)) throw new IllegalArgumentException("refusing " + id + ": not created by this run");
            if (demo()) return;
            Instance i = describeInstance(id);
            if (i == null) return;
            if (FLEET_VALUE.equals(tag(i.tags(), FLEET_KEY))) throw new IllegalArgumentException("refusing an instance tagged " + FLEET_KEY + "=" + FLEET_VALUE);
            if (!runId.equals(tag(i.tags(), OWNER))) throw new IllegalArgumentException("refusing " + id + ": lmaws_test tag does not match this run");
        }

        private long boundedWait(long seconds) {
            if (seconds < 1 || seconds > MAX_LIFETIME_SECONDS) throw new IllegalArgumentException("wait: 1.." + MAX_LIFETIME_SECONDS + " seconds");
            if (firstLaunch == null) return seconds;
            long left = MAX_LIFETIME_SECONDS - Duration.between(firstLaunch, Instant.now()).getSeconds();
            return Math.max(0, Math.min(seconds, left));
        }

        private String stateOf(String id) { Instance i = describeInstance(id); return i == null ? "absent" : i.state().nameAsString(); }

        private String demoAdvance(String id, String wanted) {
            Map<String, String> s = demoState.get(id);
            String next = switch (s.get("state")) { case "pending" -> "running"; case "shutting-down" -> "terminated"; default -> s.get("state"); };
            if (wanted.equals("running") && next.equals("running")) { s.put("system_status", "ok"); s.put("instance_status", "ok"); }
            if (next.equals("terminated")) { s.put("system_status", ""); s.put("instance_status", ""); }
            s.put("state", next); return next;
        }

        private Map<String, String> demoStatus(String id) {
            Map<String, String> s = demoState.get(id);
            return row("kind", "instance_status", "id", id, "state", s.get("state"), "system_status", s.get("system_status"), "instance_status", s.get("instance_status"), "az", instanceAz.get(id), "type", instanceType.get(id), OWNER, runId);
        }

        private TagSpecification tags(ResourceType type) {
            return TagSpecification.builder().resourceType(type).tags(Tag.builder().key(OWNER).value(runId).build(), Tag.builder().key("Name").value(name).build()).build();
        }

        private BigDecimal latestPrice(String type, String az) {
            try {
                for (Map<String, String> r : spotPrices(type, 3)) if (az.equals(r.get("az"))) return new BigDecimal(r.get("price"));
            } catch (RuntimeException ignored) { }
            return ON_DEMAND.get(type);
        }

        private void log(String kind, String id, String event) {
            String line = Jsons.encodeRaw(Map.of("time", Instant.now().toString(), "run_id", runId, "kind", kind, "id", id, "event", event)) + "\n";
            try { Files.writeString(ledger, line, StandardCharsets.UTF_8, StandardOpenOption.APPEND); }
            catch (java.io.IOException e) { throw new IllegalStateException("cannot append spot ledger", e); }
        }

        @Override public void close() {
            if (tornDown && groups.isEmpty() && dead.containsAll(instances)) return;
            teardown();
        }
    }

    static final Set<String> KNOWN_LAUNCH_FAILURES = Set.of("InsufficientInstanceCapacity", "SpotMaxPriceTooLow", "MaxSpotInstanceCountExceeded",
            "InsufficientCapacity", "Unsupported", "InvalidParameterCombination", "InvalidParameterValue", "UnauthorizedOperation");

    /** AWS message for the private run ledger only: account ids and long encoded blobs removed. */
    static String privateMessage(AwsServiceException e) {
        String m = e.awsErrorDetails() == null ? "" : String.valueOf(e.awsErrorDetails().errorMessage());
        m = m.replaceAll("\\b\\d{12}\\b", "<account>").replaceAll("[A-Za-z0-9_-]{100,}", "<encoded>");
        return m.length() > 400 ? m.substring(0, 400) : m;
    }

    static String launchAdvice(String code) {
        if (code.contains("ServiceLinkedRole")) return "the EC2 Spot service-linked role (AWSServiceRoleForEC2Spot) is missing and this profile may not create it; an administrator must create it once";
        return switch (code) {
            case "InsufficientInstanceCapacity", "InsufficientCapacity" -> "no spot capacity for this type in this AZ now; try the other nano type or another AZ";
            case "SpotMaxPriceTooLow" -> "the max price is below the current spot price; raise it up to the On-Demand price";
            case "MaxSpotInstanceCountExceeded" -> "the account spot instance quota is used up; wait or request a quota increase";
            case "UnauthorizedOperation" -> "denied by the session policy: ec2:RunInstances on one of instance/volume/network-interface/spot-instances-request/subnet/image/security-group";
            case "InvalidParameterValue", "InvalidParameterCombination" -> "AWS rejected a launch parameter for this type/subnet; the private spot ledger has the message";
            default -> "the type is not supported in this AZ; try another subnet";
        };
    }

    // ---------- helpers ----------

    private static BigDecimal ebsCost(long seconds) {
        return GP3_GB_MONTH.multiply(BigDecimal.valueOf(ROOT_GIB)).multiply(BigDecimal.valueOf(seconds)).divide(BigDecimal.valueOf(43200L * 60), 10, RoundingMode.CEILING);
    }
    private static String text(Double v) { return v == null ? "" : String.valueOf(v); }
    static String code(AwsServiceException e) { return e.awsErrorDetails() == null || e.awsErrorDetails().errorCode() == null ? "AWS_SERVICE_ERROR" : e.awsErrorDetails().errorCode(); }
    private static void requireInstanceId(String id) { if (id == null || !id.matches("i-[0-9a-z]{1,32}")) throw new IllegalArgumentException("instance id required (i-...)"); }
    private static String tag(List<Tag> tags, String key) { return tags == null ? "" : tags.stream().filter(t -> key.equals(t.key())).map(Tag::value).findFirst().orElse(""); }
    private static String tagColumn(String key) { return key.equals(OWNER) ? OWNER : key.toLowerCase(Locale.ROOT); }
    private static String nz(String s) { return s == null ? "" : s; }
    static Map<String, String> row(String... kv) { Map<String, String> m = new LinkedHashMap<>(); for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], kv[i + 1] == null ? "" : kv[i + 1]); return m; }
    private static <T> List<T> bounded(List<T> rows) { if (rows.size() > 10000) throw new IllegalStateException("EC2 report exceeds 10000 rows"); return rows; }
    private static <T> List<T> bounded(Iterable<T> pages) {
        List<T> out = new ArrayList<>(); Instant deadline = Instant.now().plusSeconds(60);
        for (T p : pages) { out.add(p); if (out.size() > 100 || Instant.now().isAfter(deadline)) throw new IllegalStateException("EC2 pagination exceeded 100 pages or 60 seconds"); }
        return out;
    }
    private static void sleep(long ms) {
        // Loopback fake endpoints only (tests): real AWS polling keeps its intervals.
        if ("1".equals(System.getenv("LMAWS_FAST_WAITS")) && !System.getenv().getOrDefault("LMAWS_ENDPOINT", "").isBlank()) ms = Math.min(ms, 20);
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("wait interrupted", e); }
    }

    /** Synthetic account used by demo sessions and picture-first examples; ids are fixtures. */
    static final class Demo {
        static List<Map<String, String>> instances() {
            return List.of(
                row("kind", "instance", "id", "i-0fixture00000001", "name", "dev-a", "project", "fixture", "role", "current", "state", "running", "type", "t4g.xlarge", "az", "us-east-1e", "subnet", "subnet-0fixturefleet", "vpc", "vpc-fixture", "private_ip", "10.0.0.11", "public_ip", "", "market", "on-demand", "spot_request", "", "launch_time", "2026-10-01T00:00:00Z", "root_device", "/dev/sda1", "iam_instance_profile", "example-legacy-wide-role", "iam_instance_profile_arn", "arn:aws:iam::************:instance-profile/example-legacy-wide-role", OWNER, "", "root_volume", "vol-0fixture000001", "root_delete_on_termination", "false", "root_size_gib", "150", "root_type", "gp3"),
                row("kind", "instance", "id", "i-0fixture00000002", "name", "dev-b", "project", "fixture", "role", "standby", "state", "running", "type", "t4g.xlarge", "az", "us-east-1e", "subnet", "subnet-0fixturefleet", "vpc", "vpc-fixture", "private_ip", "10.0.0.12", "public_ip", "", "market", "on-demand", "spot_request", "", "launch_time", "2026-10-20T00:00:00Z", "root_device", "/dev/sda1", "iam_instance_profile", "example-legacy-wide-role", "iam_instance_profile_arn", "arn:aws:iam::************:instance-profile/example-legacy-wide-role", OWNER, "", "root_volume", "vol-0fixture000002", "root_delete_on_termination", "true", "root_size_gib", "150", "root_type", "gp3"),
                row("kind", "instance", "id", "i-0fixture00000003", "name", "bastion", "project", "fixture", "role", "bastion", "state", "running", "type", "t3.nano", "az", "us-east-1a", "subnet", "subnet-0fixturea", "vpc", "vpc-fixture", "private_ip", "10.0.1.5", "public_ip", "198.51.100.7", "market", "on-demand", "spot_request", "", "launch_time", "2026-01-01T00:00:00Z", "root_device", "/dev/xvda", "iam_instance_profile", "example-bastion-controller", "iam_instance_profile_arn", "arn:aws:iam::************:instance-profile/example-bastion-controller", OWNER, "", "root_volume", "vol-0fixture000003", "root_delete_on_termination", "true", "root_size_gib", "8", "root_type", "gp3"),
                row("kind", "instance", "id", "i-0fixture00000004", "name", "retired-spot", "project", "fixture", "role", "retired", "state", "stopped", "type", "t4g.large", "az", "us-east-1e", "subnet", "subnet-0fixturefleet", "vpc", "vpc-fixture", "private_ip", "10.0.0.13", "public_ip", "", "market", "spot", "spot_request", "sir-fixture0000", "launch_time", "2026-09-01T00:00:00Z", "root_device", "/dev/sda1", "iam_instance_profile", "example-retired-role", "iam_instance_profile_arn", "arn:aws:iam::************:instance-profile/example-retired-role", OWNER, ""));
        }
        static List<Map<String, String>> addresses() {
            return List.of(
                row("kind", "address", "id", "eipalloc-fixture01", "public_ip", "198.51.100.7", "domain", "vpc", "association", "eipassoc-fixture01", "instance", "i-0fixture00000003", "eni", "eni-fixture03", "private_ip", "10.0.1.5", "name", "bastion", "project", "fixture", "role", "bastion", "idle", "false"),
                row("kind", "address", "id", "eipalloc-fixture02", "public_ip", "198.51.100.8", "domain", "vpc", "association", "eipassoc-fixture02", "instance", "i-0fixture00000002", "eni", "eni-fixture02", "private_ip", "10.0.0.12", "name", "service", "project", "fixture", "role", "service", "idle", "false"),
                row("kind", "address", "id", "eipalloc-fixture03", "public_ip", "198.51.100.9", "domain", "vpc", "association", "", "instance", "", "eni", "", "private_ip", "", "name", "spare", "project", "", "role", "", "idle", "true"));
        }
        static List<Map<String, String>> volumes() {
            return List.of(
                row("kind", "volume", "id", "vol-0fixture000001", "az", "us-east-1e", "size_gib", "150", "type", "gp3", "state", "in-use", "iops", "3000", "throughput", "125", "instance", "i-0fixture00000001", "device", "/dev/sda1", "delete_on_termination", "false", "name", "ai-root", "project", "fixture", "role", "current", OWNER, ""),
                row("kind", "volume", "id", "vol-0fixture000002", "az", "us-east-1e", "size_gib", "150", "type", "gp3", "state", "in-use", "iops", "3000", "throughput", "125", "instance", "i-0fixture00000002", "device", "/dev/sda1", "delete_on_termination", "true", "name", "standby-root", "project", "fixture", "role", "standby", OWNER, ""),
                row("kind", "volume", "id", "vol-0fixture000003", "az", "us-east-1a", "size_gib", "8", "type", "gp3", "state", "in-use", "iops", "3000", "throughput", "125", "instance", "i-0fixture00000003", "device", "/dev/xvda", "delete_on_termination", "true", "name", "bastion-root", "project", "fixture", "role", "bastion", OWNER, ""),
                row("kind", "volume", "id", "vol-0fixture000004", "az", "us-east-1e", "size_gib", "100", "type", "gp3", "state", "available", "iops", "3000", "throughput", "125", "instance", "", "device", "", "delete_on_termination", "", "name", "retained-migration", "project", "fixture", "role", "retired", OWNER, ""));
        }
        static List<Map<String, String>> subnets() {
            List<Map<String, String>> rows = new ArrayList<>();
            String[] az = {"a", "b", "c", "d", "e", "f"};
            for (String z : az) rows.add(row("kind", "subnet", "id", z.equals("e") ? "subnet-0fixturefleet" : "subnet-0fixture" + z, "az", "us-east-1" + z, "vpc", "vpc-fixture", "default_vpc", "true", "default_for_az", "true", "cidr", "172.31.0.0/20", "available_ips", "4000", "map_public_ip", "true", "fleet", String.valueOf(z.equals("e"))));
            return rows;
        }
        static List<Map<String, String>> prices(List<String> types) {
            String[] az = {"a", "b", "c", "d", "e", "f"};
            double[] t4g = {0.0017, 0.0016, 0.0019, 0.0018, 0, 0.0021}, t3 = {0.0021, 0.0019, 0.0024, 0.0020, 0.0023, 0.0022};
            List<Map<String, String>> rows = new ArrayList<>();
            for (String type : types) for (int i = 0; i < az.length; i++) {
                double p = type.equals("t3.nano") ? t3[i] : type.equals("t4g.nano") ? t4g[i] : 0.01 + i * 0.001;
                if (p == 0) continue;
                rows.add(row("kind", "spot_price", "type", type, "az", "us-east-1" + az[i], "price", String.format(Locale.ROOT, "%.6f", p), "on_demand", ON_DEMAND.containsKey(type) ? ON_DEMAND.get(type).toPlainString() : "", "timestamp", "2026-10-26T00:00:00Z"));
            }
            return rows;
        }
        static Map<String, String> status(String id) {
            return instances().stream().filter(r -> id.equals(r.get("id"))).findFirst()
                .map(r -> row("kind", "instance_status", "id", id, "state", r.get("state"), "system_status", "running".equals(r.get("state")) ? "ok" : "not-applicable", "instance_status", "running".equals(r.get("state")) ? "ok" : "not-applicable", "az", r.get("az"), "type", r.get("type"), "spot_request", r.get("spot_request"), OWNER, "", "project", r.get("project")))
                .orElse(row("kind", "instance_status", "id", id, "state", "absent"));
        }
    }
}
