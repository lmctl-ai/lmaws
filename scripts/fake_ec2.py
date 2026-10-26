#!/usr/bin/env python3
"""Loopback fake for the EC2 compute API (spot nano lifecycle and read-only reports).

Imported by test-fake.py. The fake enforces the same tag contract as the lmaws-ec2 session
policy (lmaws_test on instance, volume, network-interface and spot request at creation; nano
types only; 8 GiB roots; tagged security groups) so a host regression fails here first.
"""
import struct, threading

FLEET_ID = "i-0f1ee70000000001"
FLEET_SUBNET = "subnet-0f1ee70000000001"
NANO = {"t4g.nano", "t3.nano"}
EC2_ACTIONS = {"RunInstances", "DescribeInstances", "DescribeInstanceStatus", "TerminateInstances", "StopInstances",
               "StartInstances", "CreateSecurityGroup", "DeleteSecurityGroup", "DescribeSecurityGroups", "DescribeImages",
               "DescribeVolumes", "DescribeNetworkInterfaces", "DescribeSpotInstanceRequests", "DescribeSpotPriceHistory",
               "DescribeSubnets", "DescribeAddresses", "DescribeVpcs", "CancelSpotInstanceRequests"}


class State:
    lock = threading.Lock()
    instances = {}   # id -> dict(type, state, tags, subnet, az, stuck)
    groups = {}      # id -> dict(name, tags, vpc, busy)
    calls = []       # (action, params)
    seq = 0

    @classmethod
    def reset(cls):
        with cls.lock:
            cls.instances = {FLEET_ID: dict(type="t4g.xlarge", state="running", tags={"Project": "awsspot", "Role": "current", "Name": "fleet"},
                                            subnet=FLEET_SUBNET, az="us-east-1e", stuck=False)}
            cls.groups = {}
            cls.calls = []

    @classmethod
    def live(cls, run=None):
        return [i for i, x in cls.instances.items() if i != FLEET_ID and x["state"] != "terminated" and (run is None or x["tags"].get("lmaws_test") == run)]


State.reset()


def values(p, prefix):
    out = []
    n = 1
    while prefix + "." + str(n) in p:
        out.append(p[prefix + "." + str(n)][0]); n += 1
    return out


def filters(p):
    out = {}
    n = 1
    while "Filter.%d.Name" % n in p:
        out[p["Filter.%d.Name" % n][0]] = values(p, "Filter.%d.Value" % n); n += 1
    return out


def tagspecs(p):
    out = {}
    n = 1
    while "TagSpecification.%d.ResourceType" % n in p:
        tags = {}
        m = 1
        while "TagSpecification.%d.Tag.%d.Key" % (n, m) in p:
            tags[p["TagSpecification.%d.Tag.%d.Key" % (n, m)][0]] = p["TagSpecification.%d.Tag.%d.Value" % (n, m)][0]; m += 1
        out[p["TagSpecification.%d.ResourceType" % n][0]] = tags; n += 1
    return out


def tagset(tags):
    return "<tagSet>" + "".join("<item><key>%s</key><value>%s</value></item>" % kv for kv in tags.items()) + "</tagSet>"


def match(tags, f):
    for name, wanted in f.items():
        if name == "tag-key" and not any(k in tags for k in wanted): return False
        if name.startswith("tag:"):
            have = tags.get(name[4:])
            if have is None or not any(have == w or (w.endswith("*") and have.startswith(w[:-1])) for w in wanted): return False
    return True


def advance(x):
    if x["state"] == "pending" and not x["stuck"]: x["state"] = "running"
    elif x["state"] == "shutting-down": x["state"] = "terminated"


def instance_xml(i, x):
    lifecycle = "" if i == FLEET_ID else "<instanceLifecycle>spot</instanceLifecycle><spotInstanceRequestId>sir-%s</spotInstanceRequestId>" % i[2:12]
    return ("<item><instanceId>%s</instanceId><instanceType>%s</instanceType><instanceState><code>16</code><name>%s</name></instanceState>"
            "<placement><availabilityZone>%s</availabilityZone></placement><subnetId>%s</subnetId><vpcId>vpc-0fa4e00000000001</vpcId>"
            "<privateIpAddress>10.0.0.9</privateIpAddress><rootDeviceName>/dev/sda1</rootDeviceName>"
            "<blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-0aa%s</volumeId><deleteOnTermination>%s</deleteOnTermination></ebs></item></blockDeviceMapping>%s%s</item>") % (
        i, x["type"], x["state"], x["az"], x["subnet"], i[5:], "false" if i == FLEET_ID else "true", lifecycle, tagset(x["tags"]))


def handle(h, action, p):
    """Serve one EC2 Query action; h is the BaseHTTPRequestHandler. Returns False to use the legacy fixture."""
    with State.lock:
        State.calls.append((action, p))
        f = filters(p)
        if action == "DescribeInstances":
            ids = values(p, "InstanceId")
            if not ids and not f: return False
            items = []
            for i, x in State.instances.items():
                if (ids and i not in ids) or not match(x["tags"], f): continue
                if i in ids: advance(x)
                items.append(instance_xml(i, x))
            if ids and not items:
                return h.ec2_error("InvalidInstanceID.NotFound", "no such instance") or True
            h.xml("<DescribeInstancesResponse><reservationSet>" + "".join("<item><instancesSet>%s</instancesSet></item>" % x for x in items) + "</reservationSet></DescribeInstancesResponse>")
        elif action == "RunInstances":
            t = p["InstanceType"][0]
            specs = tagspecs(p)
            if p.get("DryRun", [""])[0].lower() == "true":
                if t in NANO and specs.get("instance", {}).get("lmaws_test"):
                    return h.ec2_error("DryRunOperation", "Request would have succeeded, but DryRun flag is set.") or True
                return h.ec2_error("UnauthorizedOperation", "You are not authorized to perform this operation.") or True
            assert t in NANO, "non-nano type reached RunInstances: " + t
            for kind in ("instance", "volume", "network-interface", "spot-instances-request"):
                assert specs.get(kind, {}).get("lmaws_test"), ("missing lmaws_test tag at creation", kind, specs)
            assert p["InstanceMarketOptions.MarketType"][0] == "spot"
            assert p["InstanceMarketOptions.SpotOptions.SpotInstanceType"][0] == "one-time"
            assert int(p["BlockDeviceMapping.1.Ebs.VolumeSize"][0]) <= 8 and p["BlockDeviceMapping.1.Ebs.VolumeType"][0] == "gp3"
            assert p["BlockDeviceMapping.1.Ebs.DeleteOnTermination"][0] == "true"
            assert p["NetworkInterface.1.AssociatePublicIpAddress"][0] == "false", "public IPv4 requested"
            group = p["NetworkInterface.1.SecurityGroupId.1"][0]
            assert State.groups.get(group, {}).get("tags", {}).get("lmaws_test"), "untagged security group used"
            if p["ImageId"][0].endswith("ca9a"):
                return h.ec2_error("InsufficientInstanceCapacity", "no capacity") or True
            State.seq += 1
            i = "i-0aa%013d" % State.seq
            tags = dict(specs["instance"])
            if p["ImageId"][0].endswith("f1ee7"): tags["Project"] = "awsspot"
            State.instances[i] = dict(type=t, state="pending", tags=tags, subnet=p["NetworkInterface.1.SubnetId"][0], az="us-east-1b",
                                      stuck=p["NetworkInterface.1.SubnetId"][0].endswith("57c4"))
            h.xml("<RunInstancesResponse><reservationId>r-1</reservationId><instancesSet>%s</instancesSet></RunInstancesResponse>" % instance_xml(i, State.instances[i]))
        elif action == "DescribeInstanceStatus":
            items = "".join("<item><instanceId>%s</instanceId><instanceState><name>%s</name></instanceState><systemStatus><status>%s</status></systemStatus><instanceStatus><status>%s</status></instanceStatus></item>" % (
                i, State.instances[i]["state"], *(["ok", "ok"] if State.instances[i]["state"] == "running" else ["initializing", "initializing"])) for i in values(p, "InstanceId") if i in State.instances)
            h.xml("<DescribeInstanceStatusResponse><instanceStatusSet>%s</instanceStatusSet></DescribeInstanceStatusResponse>" % items)
        elif action in ("TerminateInstances", "StopInstances", "StartInstances"):
            i = values(p, "InstanceId")[0]
            x = State.instances[i]
            assert i != FLEET_ID and x["tags"].get("lmaws_test") and x["tags"].get("Project") != "awsspot", "fleet or untagged instance mutated"
            if action == "StopInstances": return h.ec2_error("UnsupportedOperation", "one-time spot") or True
            if action == "StartInstances": return h.ec2_error("IncorrectInstanceState", "not stopped") or True
            x["state"] = "shutting-down"
            h.xml("<TerminateInstancesResponse><instancesSet><item><instanceId>%s</instanceId><currentState><code>32</code><name>shutting-down</name></currentState></item></instancesSet></TerminateInstancesResponse>" % i)
        elif action == "CreateSecurityGroup":
            name = p["GroupName"][0]; tags = tagspecs(p).get("security-group", {})
            if p.get("DryRun", [""])[0].lower() == "true":
                if name.startswith("lmaws_") and tags.get("lmaws_test"):
                    return h.ec2_error("DryRunOperation", "Request would have succeeded, but DryRun flag is set.") or True
                return h.ec2_error("UnauthorizedOperation", "You are not authorized to perform this operation.") or True
            assert name.startswith("lmaws_") and tags.get("lmaws_test"), ("security group without lmaws name/tag", name, tags)
            g = "sg-0aa%013d" % (len(State.groups) + 1)
            State.groups[g] = dict(name=name, tags=tags, vpc=p["VpcId"][0], busy=True)
            h.xml("<CreateSecurityGroupResponse><groupId>%s</groupId></CreateSecurityGroupResponse>" % g)
        elif action == "DeleteSecurityGroup":
            g = p["GroupId"][0]
            assert State.groups[g]["tags"].get("lmaws_test"), "foreign security group deleted"
            if State.groups[g]["busy"]:  # one DependencyViolation while the ENI detaches
                State.groups[g]["busy"] = False
                return h.ec2_error("DependencyViolation", "in use") or True
            assert not State.live(State.groups[g]["tags"]["lmaws_test"]), "security group deleted before its instance"
            State.groups.pop(g)
            h.xml("<DeleteSecurityGroupResponse><return>true</return></DeleteSecurityGroupResponse>")
        elif action == "DescribeSecurityGroups":
            ids = values(p, "GroupId")
            if not ids and not f: return False
            items = "".join("<item><groupId>%s</groupId><groupName>%s</groupName><vpcId>%s</vpcId>%s</item>" % (g, x["name"], x["vpc"], tagset(x["tags"]))
                            for g, x in State.groups.items() if (not ids or g in ids) and match(x["tags"], f))
            h.xml("<DescribeSecurityGroupsResponse><securityGroupInfo>%s</securityGroupInfo></DescribeSecurityGroupsResponse>" % items)
        elif action == "DescribeImages":
            h.xml("<DescribeImagesResponse><imagesSet><item><imageId>%s</imageId><rootDeviceName>/dev/sda1</rootDeviceName></item></imagesSet></DescribeImagesResponse>" % values(p, "ImageId")[0])
        elif action == "DescribeVolumes":
            items = []
            for i, x in State.instances.items():
                if x["state"] == "terminated": continue
                tags = {"Project": "awsspot"} if i == FLEET_ID else x["tags"]
                if not match(tags, f): continue
                v = "vol-0aa" + i[5:]
                if values(p, "VolumeId") and v not in values(p, "VolumeId"): continue
                items.append("<item><volumeId>%s</volumeId><size>%s</size><availabilityZone>%s</availabilityZone><status>in-use</status><volumeType>gp3</volumeType><attachmentSet><item><instanceId>%s</instanceId><device>/dev/sda1</device><deleteOnTermination>%s</deleteOnTermination></item></attachmentSet>%s</item>" % (
                    v, 150 if i == FLEET_ID else 8, x["az"], i, "false" if i == FLEET_ID else "true", tagset(tags)))
            h.xml("<DescribeVolumesResponse><volumeSet>%s</volumeSet></DescribeVolumesResponse>" % "".join(items))
        elif action == "DescribeNetworkInterfaces":
            items = "".join("<item><networkInterfaceId>eni-0aa%s</networkInterfaceId><status>in-use</status>%s</item>" % (i[5:], tagset(x["tags"]).replace("tagSet", "tagSet"))
                            for i, x in State.instances.items() if i != FLEET_ID and x["state"] != "terminated" and match(x["tags"], f))
            h.xml("<DescribeNetworkInterfacesResponse><networkInterfaceSet>%s</networkInterfaceSet></DescribeNetworkInterfacesResponse>" % items)
        elif action == "DescribeSpotInstanceRequests":
            items = "".join("<item><spotInstanceRequestId>sir-%s</spotInstanceRequestId><state>%s</state><status><code>%s</code></status>%s</item>" % (
                i[2:12], "closed" if x["state"] == "terminated" else "active", "instance-terminated-by-user" if x["state"] == "terminated" else "fulfilled", tagset(x["tags"]))
                for i, x in State.instances.items() if i != FLEET_ID and match(x["tags"], f))
            h.xml("<DescribeSpotInstanceRequestsResponse><spotInstanceRequestSet>%s</spotInstanceRequestSet></DescribeSpotInstanceRequestsResponse>" % items)
        elif action == "CancelSpotInstanceRequests":
            h.xml("<CancelSpotInstanceRequestsResponse><spotInstanceRequestSet/></CancelSpotInstanceRequestsResponse>")
        elif action == "DescribeSpotPriceHistory":
            items = "".join("<item><instanceType>%s</instanceType><productDescription>Linux/UNIX</productDescription><spotPrice>%s</spotPrice><timestamp>2026-10-26T0%d:00:00.000Z</timestamp><availabilityZone>us-east-1%s</availabilityZone></item>" % (t, price, hour, az)
                            for t in values(p, "InstanceType") for az, price in (("a", "0.001900"), ("b", "0.001600")) for hour in (1, 2))
            h.xml("<DescribeSpotPriceHistoryResponse><spotPriceHistorySet>%s</spotPriceHistorySet></DescribeSpotPriceHistoryResponse>" % items)
        elif action == "DescribeSubnets":
            h.xml("<DescribeSubnetsResponse><subnetSet>" + "".join("<item><subnetId>%s</subnetId><availabilityZone>%s</availabilityZone><vpcId>vpc-0fa4e00000000001</vpcId><defaultForAz>true</defaultForAz><cidrBlock>172.31.0.0/20</cidrBlock><availableIpAddressCount>4000</availableIpAddressCount></item>" % s
                  for s in ((FLEET_SUBNET, "us-east-1e"), ("subnet-0aa0000000000b", "us-east-1b"))) + "</subnetSet></DescribeSubnetsResponse>")
        elif action == "DescribeVpcs":
            h.xml("<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0fa4e00000000001</vpcId><cidrBlock>172.31.0.0/16</cidrBlock><state>available</state><isDefault>true</isDefault></item></vpcSet></DescribeVpcsResponse>")
        elif action == "DescribeAddresses":
            h.xml("<DescribeAddressesResponse><addressesSet><item><allocationId>eipalloc-0aa1</allocationId><publicIp>198.51.100.10</publicIp><domain>vpc</domain></item></addressesSet></DescribeAddressesResponse>")
        else:
            return False
    return True


def cbor_float(v):
    return b"\xfb" + struct.pack(">d", v)


def tests(execute, schema_env):
    """Runs the EC2 compute fake scenarios through the real host and SDK transport."""
    sent = lambda action: [c for c in State.calls if c[0] == action]
    # Read-only reports.
    execute("ec2-reads", "\n".join([
        'let cloud = aws.region("us-east-1");',
        'let fleet = cloud.ec2_instances("Project", "awsspot"); check(fleet.len() == 1); check(fleet.at(0).get("root_size_gib") == "150");',
        'check(fleet.at(0).get("root_delete_on_termination") == "false");',
        'let prices = cloud.spot_prices("t4g.nano,t3.nano", 3); check(prices.len() == 4); check(prices.at(0).get("timestamp") == "2026-10-26T02:00:00Z");',
        'let ami = cloud.public_parameter("/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"); check(ami == "ami-0123456789abcdef0");',
        'let subnets = cloud.subnets(); check(subnets.count("fleet", "true") == 1);',
        'let eips = cloud.addresses(); check(eips.at(0).get("idle") == "true");',
        'let credits = cloud.cpu_credits("' + FLEET_ID + '", 3); check(credits.len() == 5); check(cloud.ec2_instances("Project", "").len() == 1);',
        'let st = cloud.instance_status("' + FLEET_ID + '"); check(st.get("project") == "awsspot");']))
    execute("ssm-private", 'let cloud = aws.region("us-east-1"); let x = cloud.public_parameter("/myapp/secret");', 3)
    # Full lifecycle with capacity fallback, stop-means-terminate, DependencyViolation retry and verification.
    State.calls.clear()
    execute("spot-lifecycle", "\n".join([
        'let cloud = aws.region("us-east-1"); let spot = cloud.spot_run();',
        'let sg = spot.security_group("vpc-0fa4e00000000001"); check(sg.get("inbound_rules") == "0");',
        'let first = spot.launch("t4g.nano", "ami-00000000000ca9a", "subnet-0aa0000000000b", sg.get("id"), 0.0042); check(first.get("status") == "InsufficientInstanceCapacity");',
        'let inst = spot.launch("t3.nano", "ami-0123456789abcdef0", "subnet-0aa0000000000b", sg.get("id"), 0.0052); check(inst.get("status") == "launched");',
        'let up = spot.wait_state(inst.get("id"), "running", 60); check(up.get("state") == "running");',
        'let ok = spot.wait_status_ok(inst.get("id"), 60); check(ok.get("instance_status") == "ok");',
        'let st = spot.stop(inst.get("id")); check(st.get("status") == "UnsupportedOperation");',
        'let t = spot.terminate(inst.get("id")); let down = spot.wait_state(inst.get("id"), "terminated", 60); check(down.get("state") == "terminated");',
        'let g = spot.delete_security_group(sg.get("id")); let proof = spot.verify(); check(proof.count("clean", "false") == 0);',
        'check(spot.leftovers().len() == 0); check(spot.spot_price() > 0.0015); check(spot.estimated_cost() < 0.05);']))
    assert len(sent("RunInstances")) == 2 and not State.live() and not State.groups, "lifecycle left resources"
    # Refusals: non-nano type, foreign/fleet instance, fleet subnet, fleet-tagged instance. Each exits 3 and tears down.
    State.calls.clear()
    execute("refuse-type", 'let cloud = aws.region("us-east-1"); let spot = cloud.spot_run(); let sg = spot.security_group("vpc-0fa4e00000000001"); let i = spot.launch("t3.micro", "ami-0123456789abcdef0", "subnet-0aa0000000000b", sg.get("id"), 0.004);', 3)
    assert not sent("RunInstances") and not State.groups, "non-nano launch was sent or teardown skipped"
    execute("refuse-foreign", 'let cloud = aws.region("us-east-1"); let spot = cloud.spot_run(); let t = spot.terminate("' + FLEET_ID + '");', 3)
    execute("refuse-fleet-subnet", 'let cloud = aws.region("us-east-1"); let spot = cloud.spot_run(); let sg = spot.security_group("vpc-0fa4e00000000001"); let i = spot.launch("t4g.nano", "ami-0123456789abcdef0", "' + FLEET_SUBNET + '", sg.get("id"), 0.0042);', 3)
    execute("refuse-price", 'let cloud = aws.region("us-east-1"); let spot = cloud.spot_run(); let sg = spot.security_group("vpc-0fa4e00000000001"); let i = spot.launch("t4g.nano", "ami-0123456789abcdef0", "subnet-0aa0000000000b", sg.get("id"), 0.01);', 3)
    assert not sent("TerminateInstances") and not sent("RunInstances") and not State.groups, "refusal reached AWS"
    r = execute("refuse-fleet-tag", 'let cloud = aws.region("us-east-1"); let spot = cloud.spot_run(); let sg = spot.security_group("vpc-0fa4e00000000001"); let i = spot.launch("t4g.nano", "ami-000000000000f1ee7", "subnet-0aa0000000000b", sg.get("id"), 0.0042); let t = spot.terminate(i.get("id"));', 3)
    assert "Project=awsspot" in r.stdout and not sent("TerminateInstances"), "fleet-tagged instance was not refused"
    for i in State.live(): State.instances[i]["state"] = "terminated"   # the fake's own cleanup of the refused fixture
    State.groups.clear()
    # Bounded wait and teardown on a failure path: the instance never runs, the script fails, the host tears down.
    State.calls.clear()
    r = execute("bounded-teardown", 'let cloud = aws.region("us-east-1"); let spot = cloud.spot_run(); let sg = spot.security_group("vpc-0fa4e00000000001"); let i = spot.launch("t4g.nano", "ami-0123456789abcdef0", "subnet-0aa000000057c4", sg.get("id"), 0.0042); let w = spot.wait_state(i.get("id"), "running", 2); check(w.get("timed_out") == "false");', 3)
    assert sent("TerminateInstances") and not State.live() and not State.groups, "failure path did not tear down"
    # Profile guard: a live (non-fake) session on the default profile may not mutate EC2.
    r = execute("profile-guard", 'let cloud = aws.region("us-east-1"); let spot = cloud.spot_run();', 3,
                {"LMAWS_ENDPOINT": "", "LMAWS_LIVE": "1", "AWS_PROFILE": "default", "CI": "false"})
    assert "lmaws or lmaws-ec2" in r.stdout, r.stdout
    return dict(ec2_reads=8, spot_lifecycle=True, capacity_fallback=True, refusals=5, bounded_wait_teardown=True, profile_guard=True)
