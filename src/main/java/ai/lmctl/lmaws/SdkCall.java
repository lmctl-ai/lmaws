package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.SdkField;
import software.amazon.awssdk.core.SdkPojo;
import software.amazon.awssdk.core.protocol.MarshallingType;
import software.amazon.awssdk.core.traits.ListTrait;
import software.amazon.awssdk.core.traits.MapTrait;
import software.amazon.awssdk.utils.builder.SdkBuilder;

/**
 * Generic, guarded call of one AWS SDK operation: service + operation + JSON input -> JSON output.
 *
 * Reads (Describe/List/Get/Head) run under default, lmaws or admin. Everything else is a mutation: it must be on the
 * explicit allowlist below, needs AWS_PROFILE=admin, LMAWS_ADMIN_GRANT=1 and apply (plus LMAWS_APPLY=1 and LMAWS_LIVE=1),
 * and is a dry run by default. Creates must carry the tag poc=NAME in the request; updates and deletes touch only
 * resources that are recorded in the run's state file AND still carry that tag (Route 53 records, which cannot be tagged,
 * are matched by name, type and a content hash recorded in the state file).
 */
public final class SdkCall {
    private SdkCall() {}
    static final Pattern READ = Pattern.compile("^(Describe|List|Get|Head)[A-Z][A-Za-z0-9]*$");
    static final Pattern OP = Pattern.compile("^[A-Z][A-Za-z0-9]{2,80}$");
    static final Pattern POC = Pattern.compile("^[a-z0-9][a-z0-9-]{1,40}$");
    static final Pattern ENV = Pattern.compile("\\{\\{env:([A-Z][A-Z0-9_]{0,63})\\}\\}");
    static final Pattern SECRET_KEY = Pattern.compile("(?i).*(secret|password|passwd|token|credential|privatekey|headervalue|secretstring|accesskey).*");
    /** Reads that return secret material. */
    static final Set<String> READ_DENY = Set.of("secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "ssm:GetParameter",
            "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:GetParameterHistory", "ecr:GetAuthorizationToken", "sts:GetSessionToken",
            "sts:GetFederationToken", "iam:GetCredentialReport", "lambda:GetFunction");
    static final Map<String, Class<?>> CLIENTS = new LinkedHashMap<>();
    static {
        CLIENTS.put("s3", software.amazon.awssdk.services.s3.S3Client.class);
        CLIENTS.put("ecr", software.amazon.awssdk.services.ecr.EcrClient.class);
        CLIENTS.put("ecs", software.amazon.awssdk.services.ecs.EcsClient.class);
        CLIENTS.put("elbv2", software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2Client.class);
        CLIENTS.put("cloudfront", software.amazon.awssdk.services.cloudfront.CloudFrontClient.class);
        CLIENTS.put("acm", software.amazon.awssdk.services.acm.AcmClient.class);
        CLIENTS.put("route53", software.amazon.awssdk.services.route53.Route53Client.class);
        CLIENTS.put("iam", software.amazon.awssdk.services.iam.IamClient.class);
        CLIENTS.put("logs", software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient.class);
        CLIENTS.put("secretsmanager", software.amazon.awssdk.services.secretsmanager.SecretsManagerClient.class);
        CLIENTS.put("ec2", software.amazon.awssdk.services.ec2.Ec2Client.class);
        CLIENTS.put("ssm", software.amazon.awssdk.services.ssm.SsmClient.class);
        CLIENTS.put("sts", software.amazon.awssdk.services.sts.StsClient.class);
        CLIENTS.put("lambda", software.amazon.awssdk.services.lambda.LambdaClient.class);
        CLIENTS.put("sqs", software.amazon.awssdk.services.sqs.SqsClient.class);
        CLIENTS.put("sns", software.amazon.awssdk.services.sns.SnsClient.class);
        CLIENTS.put("dynamodb", software.amazon.awssdk.services.dynamodb.DynamoDbClient.class);
    }

    /** kind create: arn/name are output paths (prefix "in:" = input path, "synth:logs" = built log-group ARN); update/delete: id = input paths. */
    record Rule(String kind, String id, String arn, String name, String of) {}
    static final Map<String, Rule> RULES = new LinkedHashMap<>();
    private static void create(String op, String arn, String name) { RULES.put(op, new Rule("create", null, arn, name, null)); }
    private static void own(String kind, String id, String of, String... ops) { for (String op : ops) RULES.put(op, new Rule(kind, id, null, null, of)); }
    static {
        create("secretsmanager:CreateSecret", "ARN", "Name");
        RULES.put("s3:PutBucketPolicy", new Rule("bounded-policy", null, null, null, null));
        create("ecr:CreateRepository", "repository.repositoryArn", "repository.repositoryName");
        own("update", "repositoryName", "ecr:CreateRepository", "ecr:PutImageScanningConfiguration", "ecr:PutImageTagMutability", "ecr:PutLifecyclePolicy");
        own("delete", "repositoryName", "ecr:CreateRepository", "ecr:DeleteRepository");
        create("logs:CreateLogGroup", "synth:logs", "in:logGroupName");
        own("update", "logGroupName", "logs:CreateLogGroup", "logs:PutRetentionPolicy");
        own("delete", "logGroupName", "logs:CreateLogGroup", "logs:DeleteLogGroup");
        create("iam:CreateRole", "Role.Arn", "Role.RoleName");
        own("update", "RoleName", "iam:CreateRole", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:UpdateAssumeRolePolicy");
        own("delete", "RoleName", "iam:CreateRole", "iam:DeleteRole");
        create("ecs:CreateCluster", "cluster.clusterArn", "cluster.clusterName");
        own("delete", "cluster", "ecs:CreateCluster", "ecs:DeleteCluster");
        create("ecs:RegisterTaskDefinition", "taskDefinition.taskDefinitionArn", "taskDefinition.family");
        own("delete", "taskDefinition", "ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition");
        own("delete", "taskDefinitions", "ecs:RegisterTaskDefinition", "ecs:DeleteTaskDefinitions");
        create("ecs:CreateService", "service.serviceArn", "service.serviceName");
        own("update", "service", "ecs:CreateService", "ecs:UpdateService");
        own("delete", "service", "ecs:CreateService", "ecs:DeleteService");
        create("elbv2:CreateLoadBalancer", "LoadBalancers.0.LoadBalancerArn", "LoadBalancers.0.LoadBalancerName");
        create("elbv2:CreateTargetGroup", "TargetGroups.0.TargetGroupArn", "TargetGroups.0.TargetGroupName");
        create("elbv2:CreateListener", "Listeners.0.ListenerArn", "Listeners.0.ListenerArn");
        create("elbv2:CreateRule", "Rules.0.RuleArn", "Rules.0.RuleArn");
        own("update", "LoadBalancerArn", "elbv2:CreateLoadBalancer", "elbv2:ModifyLoadBalancerAttributes");
        own("update", "TargetGroupArn", "elbv2:CreateTargetGroup", "elbv2:ModifyTargetGroup", "elbv2:ModifyTargetGroupAttributes");
        own("update", "ListenerArn", "elbv2:CreateListener", "elbv2:ModifyListener", "elbv2:AddListenerCertificates");
        own("update", "RuleArn", "elbv2:CreateRule", "elbv2:ModifyRule");
        own("delete", "LoadBalancerArn", "elbv2:CreateLoadBalancer", "elbv2:DeleteLoadBalancer");
        own("delete", "TargetGroupArn", "elbv2:CreateTargetGroup", "elbv2:DeleteTargetGroup");
        own("delete", "ListenerArn", "elbv2:CreateListener", "elbv2:DeleteListener");
        own("delete", "RuleArn", "elbv2:CreateRule", "elbv2:DeleteRule");
        create("cloudfront:CreateDistributionWithTags", "Distribution.ARN", "Distribution.Id");
        own("update", "Id", "cloudfront:CreateDistributionWithTags", "cloudfront:UpdateDistribution");
        own("delete", "Id", "cloudfront:CreateDistributionWithTags", "cloudfront:DeleteDistribution");
        create("acm:RequestCertificate", "CertificateArn", "CertificateArn");
        own("delete", "CertificateArn", "acm:RequestCertificate", "acm:DeleteCertificate");
        create("ec2:CreateSecurityGroup", "in:GroupName", "GroupId");
        own("update", "GroupId", "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress");
        own("delete", "GroupId", "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup");
        RULES.put("route53:ChangeResourceRecordSets", new Rule("dns", null, null, null, null));
    }

    // ---------------------------------------------------------------- JSON <-> SDK pojo

    @SuppressWarnings({"unchecked", "rawtypes"})
    static SdkPojo toPojo(SdkPojo builder, Object json, String where) {
        if (!(json instanceof Map<?, ?> in)) throw new IllegalArgumentException(where + " must be a JSON object");
        for (var e : in.entrySet()) {
            String key = String.valueOf(e.getKey());
            SdkField field = null;
            for (SdkField<?> f : builder.sdkFields()) if (f.memberName().equalsIgnoreCase(key) || (f.locationName() != null && f.locationName().equalsIgnoreCase(key))) { field = f; break; }
            if (field == null) throw new IllegalArgumentException("unknown field " + where + "." + key);
            if (e.getValue() == null) continue;
            field.set(builder, convert(field, e.getValue(), where + "." + key));
        }
        return builder;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    static Object convert(SdkField f, Object v, String where) {
        MarshallingType t = f.marshallingType();
        if (t == MarshallingType.STRING) return v instanceof String || v instanceof Number || v instanceof Boolean ? String.valueOf(v) : bad(where, "string");
        if (t == MarshallingType.BOOLEAN) return v instanceof Boolean ? v : "true".equals(v) ? Boolean.TRUE : "false".equals(v) ? Boolean.FALSE : bad(where, "boolean");
        if (t == MarshallingType.INTEGER) return num(v, where).intValue();
        if (t == MarshallingType.LONG) return num(v, where).longValue();
        if (t == MarshallingType.SHORT) return num(v, where).shortValue();
        if (t == MarshallingType.BYTE) return num(v, where).byteValue();
        if (t == MarshallingType.FLOAT) return num(v, where).floatValue();
        if (t == MarshallingType.DOUBLE) return num(v, where).doubleValue();
        if (t == MarshallingType.BIG_DECIMAL) return new java.math.BigDecimal(String.valueOf(v));
        if (t == MarshallingType.INSTANT) return v instanceof Number n ? Instant.ofEpochSecond(n.longValue()) : Instant.parse(String.valueOf(v));
        if (t == MarshallingType.SDK_BYTES) return SdkBytes.fromByteArray(Base64.getDecoder().decode(String.valueOf(v)));
        if (t == MarshallingType.SDK_POJO) {
            SdkPojo b = (SdkPojo) f.constructor().get();
            toPojo(b, v, where);
            return ((SdkBuilder) b).build();
        }
        if (t == MarshallingType.LIST) {
            if (!(v instanceof List<?> l)) return bad(where, "array");
            SdkField member = ((ListTrait) f.getTrait(ListTrait.class)).memberFieldInfo();
            List<Object> out = new ArrayList<>();
            int i = 0;
            for (Object x : l) out.add(convert(member, x, where + "[" + i++ + "]"));
            return out;
        }
        if (t == MarshallingType.MAP) {
            if (!(v instanceof Map<?, ?> m)) return bad(where, "object");
            SdkField member = ((MapTrait) f.getTrait(MapTrait.class)).valueFieldInfo();
            Map<String, Object> out = new LinkedHashMap<>();
            for (var e : m.entrySet()) out.put(String.valueOf(e.getKey()), convert(member, e.getValue(), where + "." + e.getKey()));
            return out;
        }
        throw new IllegalArgumentException("unsupported field type at " + where);
    }
    private static Object bad(String where, String want) { throw new IllegalArgumentException(where + " must be a " + want); }
    private static Number num(Object v, String where) { if (v instanceof Number n) return n; try { return Double.valueOf(String.valueOf(v)); } catch (RuntimeException e) { bad(where, "number"); return 0; } }

    static Object fromPojo(Object o) {
        if (o == null) return null;
        if (o instanceof SdkPojo p) {
            Map<String, Object> m = new LinkedHashMap<>();
            for (SdkField<?> f : p.sdkFields()) {
                Object v = f.getValueOrDefault(p);
                if (v == null || (v instanceof Collection<?> c && c.isEmpty()) || (v instanceof Map<?, ?> mm && mm.isEmpty())) continue;
                m.put(f.memberName(), fromPojo(v));
            }
            return m;
        }
        if (o instanceof Collection<?> c) { List<Object> l = new ArrayList<>(); for (Object x : c) l.add(fromPojo(x)); return l; }
        if (o instanceof Map<?, ?> mm) { Map<String, Object> m = new LinkedHashMap<>(); mm.forEach((k, v) -> m.put(String.valueOf(k), fromPojo(v))); return m; }
        if (o instanceof String || o instanceof Number || o instanceof Boolean) return o;
        if (o instanceof SdkBytes b) return Base64.getEncoder().encodeToString(b.asByteArray());
        return String.valueOf(o);
    }

    // ---------------------------------------------------------------- helpers over parsed JSON

    @SuppressWarnings("unchecked")
    static List<Object> at(Object json, String path) {
        List<Object> cur = new ArrayList<>(); cur.add(json);
        for (String part : path.split("\\.")) {
            List<Object> next = new ArrayList<>();
            for (Object c : cur) {
                if (c instanceof Map<?, ?> m) { for (var e : m.entrySet()) if (String.valueOf(e.getKey()).equalsIgnoreCase(part)) next.add(e.getValue()); }
                else if (c instanceof List<?> l) {
                    if (part.matches("[0-9]+")) { int i = Integer.parseInt(part); if (i < l.size()) next.add(l.get(i)); }
                    else for (Object x : l) if (x instanceof Map<?, ?> m) for (var e : m.entrySet()) if (String.valueOf(e.getKey()).equalsIgnoreCase(part)) next.add(e.getValue());
                }
            }
            cur = next;
        }
        List<Object> out = new ArrayList<>();
        for (Object c : cur) { if (c instanceof List<?> l) out.addAll(l); else if (c != null) out.add(c); }
        return out;
    }
    static String first(Object json, String path) { var l = at(json, path); return l.isEmpty() ? "" : String.valueOf(l.get(0)); }

    /** True if the JSON holds a tag poc=NAME in any common shape: {Key,Value}/{key,value} pairs or a {"poc":"NAME"} map. */
    static boolean hasTag(Object json, String poc) {
        if (json instanceof Map<?, ?> m) {
            Object k = null, v = null;
            for (var e : m.entrySet()) { String n = String.valueOf(e.getKey()); if (n.equalsIgnoreCase("key")) k = e.getValue(); if (n.equalsIgnoreCase("value")) v = e.getValue(); }
            if ("poc".equals(k) && poc.equals(v)) return true;
            if (poc.equals(m.get("poc"))) return true;
            for (Object x : m.values()) if (hasTag(x, poc)) return true;
        } else if (json instanceof List<?> l) { for (Object x : l) if (hasTag(x, poc)) return true; }
        return false;
    }

    static Object resolveEnv(Object o, Set<String> secrets, boolean lenient) {
        return resolveEnv(o,secrets,lenient,Map.of());
    }
    static Object resolveEnv(Object o, Set<String> secrets, boolean lenient, Map<String,String> environment) {
        if (o instanceof String s) {
            var m = ENV.matcher(s);
            StringBuilder b = new StringBuilder();
            while (m.find()) {
                String val = environment.containsKey(m.group(1)) ? environment.get(m.group(1)) : System.getenv(m.group(1));
                if (val == null || val.isEmpty()) { if (lenient) { m.appendReplacement(b, java.util.regex.Matcher.quoteReplacement(m.group())); continue; } throw new IllegalArgumentException("environment variable " + m.group(1) + " is not set"); }
                secrets.add(val);
                m.appendReplacement(b, java.util.regex.Matcher.quoteReplacement(val));
            }
            m.appendTail(b);
            return b.toString();
        }
        if (o instanceof Map<?, ?> mm) { Map<String, Object> out = new LinkedHashMap<>(); mm.forEach((k, v) -> out.put(String.valueOf(k), resolveEnv(v, secrets, lenient, environment))); return out; }
        if (o instanceof List<?> l) { List<Object> out = new ArrayList<>(); for (Object x : l) out.add(resolveEnv(x, secrets, lenient, environment)); return out; }
        return o;
    }

    static Object redact(Object o, Set<String> secrets) {
        if (o instanceof String s) { for (String x : secrets) if (!x.isEmpty()) s = s.replace(x, "***"); return s; }
        if (o instanceof Map<?, ?> mm) {
            Map<String, Object> out = new LinkedHashMap<>();
            String nameVal = first(o,"name");
            boolean envPair = mm.keySet().stream().anyMatch(k -> String.valueOf(k).equalsIgnoreCase("value")) && SECRET_KEY.matcher(nameVal).matches();
            boolean httpHeader = mm.keySet().stream().anyMatch(k -> String.valueOf(k).equalsIgnoreCase("HttpHeaderName"));
            mm.forEach((k, v) -> {
                String key=String.valueOf(k);
                if (httpHeader && key.equalsIgnoreCase("Values")) out.put(key,List.of("***"));
                else out.put(key,v instanceof String && (SECRET_KEY.matcher(key).matches() || (envPair && key.equalsIgnoreCase("value"))) ? "***" : redact(v,secrets));
            });
            return out;
        }
        if (o instanceof List<?> l) { List<Object> out = new ArrayList<>(); for (Object x : l) out.add(redact(x, secrets)); return out; }
        return o;
    }

    // ---------------------------------------------------------------- execution

    static String lower(String op) { return Character.toLowerCase(op.charAt(0)) + op.substring(1); }

    /** Runs one operation on the SDK client; returns the response as JSON-shaped data. */
    static Object invoke(Object client, Class<?> iface, String op, Object input) {
        Method m = null;
        for (Method x : iface.getMethods()) if (x.getName().equals(lower(op)) && x.getParameterCount() == 1 && SdkPojo.class.isAssignableFrom(x.getParameterTypes()[0]) && !x.getParameterTypes()[0].isInterface()) { m = x; break; }
        if (m == null) throw new IllegalArgumentException("unknown operation " + op);
        try {
            Object builder = m.getParameterTypes()[0].getMethod("builder").invoke(null);
            Object request = ((SdkBuilder<?, ?>) toPojo((SdkPojo) builder, input, "input")).build();
            return fromPojo(m.invoke(client, request));
        } catch (InvocationTargetException e) {
            Throwable c = e.getCause() == null ? e : e.getCause();
            if (c instanceof RuntimeException r) throw r;
            throw new IllegalStateException(c);
        } catch (ReflectiveOperationException e) { throw new IllegalStateException("cannot call " + op, e); }
    }

    /** Operation names of one service client, for discovery. */
    static List<Map<String, String>> operations(String service) {
        Class<?> iface = CLIENTS.get(service);
        if (iface == null) throw new IllegalArgumentException("unknown service " + service + "; known: " + String.join(",", CLIENTS.keySet()));
        TreeSet<String> names = new TreeSet<>();
        for (Method x : iface.getMethods()) if (x.getParameterCount() == 1 && SdkPojo.class.isAssignableFrom(x.getParameterTypes()[0]) && !x.getParameterTypes()[0].isInterface() && x.getParameterTypes()[0].getSimpleName().endsWith("Request")) names.add(x.getParameterTypes()[0].getSimpleName().replaceAll("Request$", ""));
        List<Map<String, String>> out = new ArrayList<>();
        for (String n : names) {
            String key = service + ":" + n;
            String mode = READ.matcher(n).matches() ? (READ_DENY.contains(key) ? "denied" : "read") : RULES.containsKey(key) ? RULES.get(key).kind() : "denied";
            if (service.equals("s3") && !Set.of("GetBucketPolicy","PutBucketPolicy").contains(n)) mode="denied";
            Map<String, String> r = new LinkedHashMap<>(); r.put("service", service); r.put("operation", n); r.put("mode", mode); out.add(r);
        }
        return out;
    }

    // ---------------------------------------------------------------- state file

    static final class State {
        final Path path; final String poc; final List<Object> resources = new ArrayList<>(); final Map<String, Object> records = new LinkedHashMap<>();
        State(Path p, String poc) { this.path = p; this.poc = poc; }
        @SuppressWarnings("unchecked")
        static State load(String file, String poc, boolean mustExist) {
            Path p = Path.of(file).toAbsolutePath();
            State s = new State(p, poc);
            if (!Files.exists(p)) { if (mustExist) throw new SecurityException("state file " + file + " does not exist: nothing recorded there can be changed or deleted"); return s; }
            try {
                Map<String, Object> m = Json.object(Json.parse(Files.readString(p)));
                if (!poc.equals(m.get("poc"))) throw new SecurityException("state file belongs to poc=" + m.get("poc") + ", not " + poc);
                if (m.get("resources") instanceof List<?> l) s.resources.addAll(l);
                if (m.get("records") instanceof Map<?, ?> r) r.forEach((k, v) -> s.records.put(String.valueOf(k), v));
            } catch (java.io.IOException e) { throw new IllegalStateException("cannot read state file", e); }
            return s;
        }
        void save() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("poc", poc); m.put("tag", "poc=" + poc); m.put("resources", resources); m.put("records", records);
            try {
                Files.createDirectories(path.getParent());
                Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
                Files.deleteIfExists(tmp);
                Files.createFile(tmp, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                Files.writeString(tmp, Jsons.encodeRaw(m) + "\n", StandardCharsets.UTF_8);
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.io.IOException | UnsupportedOperationException e) { throw new IllegalStateException("cannot write state file", e); }
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> find(String service, String id, String of) {
            for (Object o : resources) { Map<String, Object> e = (Map<String, Object>) o; if (service.equals(e.get("service")) && of.equals(service + ":" + e.get("op")) && e.get("ids") instanceof List<?> ids && ids.contains(id)) return e; }
            return null;
        }
    }

    static List<String> idsOf(String... values) {
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        for (String v : values) {
            if (v == null || v.isEmpty()) continue;
            ids.add(v);
            int slash = v.lastIndexOf('/'); if (slash >= 0) { ids.add(v.substring(slash + 1)); String rest = v.substring(0, slash); int s2 = rest.lastIndexOf('/'); if (s2 >= 0 && v.contains(":service/")) ids.add(rest.substring(s2 + 1) + "/" + v.substring(slash + 1)); }
            int colon = v.lastIndexOf(':'); if (colon >= 0 && v.startsWith("arn:") == false) ids.add(v.substring(0, colon));
            if (v.contains("task-definition/") ) { String fam = v.substring(slash + 1); int c = fam.lastIndexOf(':'); if (c > 0) ids.add(fam.substring(0, c)); }
        }
        return new ArrayList<>(ids);
    }

    // ---------------------------------------------------------------- the call

    static Map<String, String> row(String... kv) { Map<String, String> m = new LinkedHashMap<>(); for (int i = 0; i + 1 < kv.length; i += 2) if (kv[i + 1] != null) m.put(kv[i], kv[i + 1]); return m; }

    /** Per-service live probe for the tags of one recorded resource. */
    static Object probeTags(AwsBackend b, String service, Map<String, Object> entry) {
        String arn = String.valueOf(entry.get("arn")), name = String.valueOf(entry.get("name"));
        Class<?> iface = CLIENTS.get(service); Object client = b.sdkClient(service);
        return switch (service) {
            case "ecr", "ecs", "logs" -> invoke(client, iface, "ListTagsForResource", Map.of("resourceArn", arn));
            case "elbv2" -> invoke(client, iface, "DescribeTags", Map.of("ResourceArns", List.of(arn)));
            case "cloudfront" -> invoke(client, iface, "ListTagsForResource", Map.of("Resource", arn));
            case "acm" -> invoke(client, iface, "ListTagsForCertificate", Map.of("CertificateArn", arn));
            case "iam" -> invoke(client, iface, "ListRoleTags", Map.of("RoleName", name));
            case "ec2" -> invoke(client, iface, "DescribeSecurityGroups", Map.of("GroupIds", List.of(name)));
            default -> throw new SecurityException("no tag probe for " + service);
        };
    }

    static void serviceChecks(String key, Object in, String poc) {
        switch (key) {
            case "iam:CreateRole" -> {
                String role = first(in, "RoleName");
                if (!role.startsWith("poc-" + poc + "-")) throw new SecurityException("IAM role names must start with poc-" + poc + "-");
                Object trust = Json.parse(first(in, "AssumeRolePolicyDocument"));
                List<Object> st = at(trust, "Statement");
                if (st.size() != 1 || !"Allow".equals(first(st.get(0), "Effect")) || !"sts:AssumeRole".equals(first(st.get(0), "Action"))
                        || at(st.get(0), "Principal").size() != 1 || !"ecs-tasks.amazonaws.com".equals(first(st.get(0), "Principal.Service")))
                    throw new SecurityException("trust policy must allow only sts:AssumeRole for ecs-tasks.amazonaws.com");
            }
            case "iam:UpdateAssumeRolePolicy" -> {
                Object trust = Json.parse(first(in, "PolicyDocument"));
                List<Object> st = at(trust, "Statement");
                if (st.size() != 1 || !"ecs-tasks.amazonaws.com".equals(first(st.get(0), "Principal.Service"))) throw new SecurityException("trust policy must name only ecs-tasks.amazonaws.com");
            }
            case "iam:AttachRolePolicy", "iam:DetachRolePolicy" -> {
                String arn = first(in, "PolicyArn");
                if (!arn.equals("arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy") && !arn.matches("arn:aws:iam::[0-9]{12}:policy/poc-" + Pattern.quote(poc) + "-[A-Za-z0-9_+=,.@-]+"))
                    throw new SecurityException("only AmazonECSTaskExecutionRolePolicy or a poc-" + poc + "- customer policy may be attached");
            }
            case "iam:PutRolePolicy" -> {
                for (Object a : at(Json.parse(first(in, "PolicyDocument")), "Statement.Action")) {
                    String s = String.valueOf(a);
                    if (s.equals("*") || s.startsWith("iam:") || s.startsWith("sts:") || s.endsWith(":*") && !s.startsWith("logs:") ) throw new SecurityException("inline role policy action " + s + " is too broad");
                }
            }
            case "ec2:CreateSecurityGroup" -> { if (!first(in, "GroupName").startsWith("poc-" + poc + "-")) throw new SecurityException("security group names must start with poc-" + poc + "-"); }
            default -> { }
        }
    }

    /** DNS: every change must be a record this run created (matched by name/type and content hash) or a record that does not exist yet. */
    @SuppressWarnings("unchecked")
    static List<String[]> dnsChecks(AwsBackend b, Object in, State st, boolean demo) {
        List<String[]> pending = new ArrayList<>();
        String zone = first(in, "HostedZoneId");
        if (zone.isEmpty()) throw new IllegalArgumentException("HostedZoneId is required");
        for (Object ch : at(in, "ChangeBatch.Changes")) {
            String action = first(ch, "Action");
            Object rr = at(ch, "ResourceRecordSet").get(0);
            String name = first(rr, "Name"), type = first(rr, "Type");
            String full = name.endsWith(".") ? name : name + ".";
            String key = zone + "|" + full + "|" + type;
            String sha = sha(Jsons.encodeRaw(normalizeRecord(rr)));
            if (!Set.of("CREATE", "UPSERT", "DELETE").contains(action)) throw new SecurityException("unknown Route 53 action " + action);
            Object live = demo ? null : liveRecord(b, zone, full, type);
            Object recorded = st.records.get(key);
            if (action.equals("DELETE")) {
                if (recorded == null) throw new SecurityException("record " + full + " " + type + " is not in the state file: refusing to delete");
                if (live == null || !String.valueOf(recorded).equals(sha(Jsons.encodeRaw(normalizeRecord(live)))))
                    throw new SecurityException("record " + full + " " + type + " changed since this run wrote it: refusing to delete");
                pending.add(new String[] {"remove", key, ""});
            } else {
                if (live != null && (recorded == null || !String.valueOf(recorded).equals(sha(Jsons.encodeRaw(normalizeRecord(live))))))
                    throw new SecurityException("record " + full + " " + type + " already exists and was not written by this run: refusing to change it");
                pending.add(new String[] {"put", key, sha});
            }
        }
        return pending;
    }
    static Object normalizeRecord(Object rr) {
        Map<String, Object> m = (Map<String, Object>) canonical(rr);
        m.put("Name", first(rr, "Name").endsWith(".") ? first(rr, "Name") : first(rr, "Name") + ".");
        return m;
    }
    static Object canonical(Object o) {
        if (o instanceof Map<?, ?> m) { Map<String, Object> out = new TreeMap<>(); m.forEach((k, v) -> out.put(String.valueOf(k), canonical(v))); return out; }
        if (o instanceof List<?> l) { List<Object> out = new ArrayList<>(); for (Object x : l) out.add(canonical(x)); return out; }
        if (o instanceof Number n) return n.doubleValue() == Math.rint(n.doubleValue()) ? (Object) n.longValue() : n;
        return o;
    }
    static Object liveRecord(AwsBackend b, String zone, String full, String type) {
        Object out = invoke(b.sdkClient("route53"), CLIENTS.get("route53"), "ListResourceRecordSets", Map.of("HostedZoneId", zone, "StartRecordName", full, "StartRecordType", type, "MaxItems", "1"));
        for (Object r : at(out, "ResourceRecordSets")) if (full.equalsIgnoreCase(first(r, "Name")) && type.equals(first(r, "Type"))) return r;
        return null;
    }
    static String sha(String s) {
        try { return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /** Read-only call returning the raw (secret-redacted, unmasked) JSON response, so recipes can chain ARNs. */
    static String read(AwsBackend b, String service, String op, String inputJson) {
        if (!READ.matcher(op).matches()) throw new SecurityException("sdk_read only runs Describe/List/Get/Head operations; use sdk_call for " + op);
        return call(b, service, op, inputJson, "", "", false).get("output");
    }

    /** Explicit local registration of a pre-existing tagged service/group. Never an AWS write.
     * Adopted entries grant only the narrow update operation, never deletion. */
    static Map<String, String> adoptExisting(AwsBackend b, String service, String id, String poc, String stateFile, boolean record) {
        if (b.isDemo()) throw new SecurityException("existing-resource adoption requires live read-only verification");
        if (!"admin".equals(AwsBackend.activeProfile()) || !"1".equals(System.getenv("LMAWS_ADMIN_GRANT")))
            throw new SecurityException("adoption requires admin and LMAWS_ADMIN_GRANT=1");
        if (!POC.matcher(poc).matches() || stateFile.isBlank()) throw new IllegalArgumentException("valid poc and state path required");
        String name, op;
        if (service.equals("ecs") && id.matches("arn:aws:ecs:us-east-1:[0-9]{12}:service/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+")) {
            name=id.substring(id.lastIndexOf('/')+1); op="CreateService";
            if (!id.split(":")[4].equals(b.accountIdForResize())) throw new SecurityException("cross-account adoption refused");
        } else if (service.equals("ec2") && id.matches("sg-[0-9a-f]{8,17}")) {
            name=id; op="CreateSecurityGroup";
        } else if (service.equals("iam") && SdkPrerequisites.ROLES.contains(id) && poc.equals("go-fargate")) {
            name=id; op="CreateRole";
            SdkPrerequisites.verifyRole(b,id,poc);
        } else throw new SecurityException("adoption supports exact ECS/SG identities and the two approved IAM roles only");
        Map<String,Object> entry=new LinkedHashMap<>();
        entry.put("service",service); entry.put("op",op); entry.put("arn",service.equals("ecs")?id:"");
        entry.put("name",name); entry.put("ids",List.of(id));
        entry.put("adopted",true); entry.put("adoptedAt",Instant.now().toString());
        entry.put("allowedOperation",service.equals("ecs")?"UpdateService":service.equals("iam")?"PutRolePolicy":"AuthorizeSecurityGroupIngress");
        if (!hasTag(probeTags(b,service,entry),poc)) throw new SecurityException("existing resource lacks expected poc tag");
        State state=State.load(stateFile,poc,false);
        Map<String,Object> prior=state.find(service,id,service+":"+op);
        if (service.equals("iam")) entry.put("previousInlinePolicies", SdkPrerequisites.inlinePolicies(b,name));
        if (record && prior==null) { state.resources.add(entry); state.save(); }
        return row("kind","sdk_adopt_existing","service",service,"id",id,"action",record?"recorded":"dry_run","awsWrites","0");
    }

    static Map<String, String> call(AwsBackend b, String service, String op, String inputJson, String poc, String stateFile, boolean apply) {
        return call(b,service,op,inputJson,poc,stateFile,apply,Map.of());
    }
    static Map<String, String> call(AwsBackend b, String service, String op, String inputJson, String poc, String stateFile, boolean apply, Map<String,String> environment) {
        Class<?> iface = CLIENTS.get(service);
        if (iface == null) throw new IllegalArgumentException("unknown service " + service + "; known: " + String.join(",", CLIENTS.keySet()));
        if (!OP.matcher(op).matches()) throw new IllegalArgumentException("invalid operation name");
        String key = service + ":" + op;
        Object parsed = inputJson == null || inputJson.isBlank() ? new LinkedHashMap<String, Object>() : Json.parse(inputJson);
        if (!(parsed instanceof Map)) throw new IllegalArgumentException("input must be a JSON object");
        Set<String> secrets = new LinkedHashSet<>();
        Object in = resolveEnv(parsed, secrets, b.isDemo() || !apply, environment);
        boolean demo = b.isDemo();
        String profile = AwsBackend.activeProfile();
        boolean read = READ.matcher(op).matches();
        if (read) {
            if (service.equals("s3") && !op.equals("GetBucketPolicy")) throw new SecurityException("generic S3 supports GetBucketPolicy only");
            if (service.equals("s3")) SdkPrerequisites.bucketInput(b,in);
            if (READ_DENY.contains(key)) throw new SecurityException(key + " returns secret material and is denied");
            if (!demo && !List.of("default", "lmaws", "admin").contains(profile)) throw new SecurityException("reads need AWS_PROFILE default, lmaws or admin (active: " + profile + ")");
            Object out = demo ? new LinkedHashMap<String, Object>() : invoke(b.sdkClient(service), iface, op, in);
            return row("kind", "sdk_call", "service", service, "operation", op, "mode", "read", "applied", "false", "action", "read", "demo", String.valueOf(demo),
                    "output", Jsons.encodeRaw(redact(out, secrets)));
        }
        Rule rule = RULES.get(key);
        if (rule == null) throw new SecurityException(key + " is not in the guarded mutation allowlist (see sdk_operations)");
        if (poc == null || !POC.matcher(poc).matches()) throw new IllegalArgumentException("poc must match [a-z0-9][a-z0-9-]{1,40}");
        if (stateFile == null || stateFile.isBlank()) throw new IllegalArgumentException("a state file path is required for mutations");
        if (!demo && (!"admin".equals(profile) || !"1".equals(System.getenv("LMAWS_ADMIN_GRANT")))) throw new SecurityException("mutating SDK calls require AWS_PROFILE=admin and LMAWS_ADMIN_GRANT=1");
        if (!demo && !b.endpointActive() && !AwsBackend.isLiveEnabled()) throw new SecurityException("mutating SDK calls require LMAWS_LIVE=1");
        if (!demo && !b.endpointActive() && !"us-east-1".equals(b.regionName())) throw new SecurityException("mutating SDK calls require us-east-1");
        String ci = System.getenv().getOrDefault("CI", "");
        if (!demo && !b.endpointActive() && (ci.equalsIgnoreCase("true") || ci.equals("1"))) throw new SecurityException("live mutations are forbidden in CI");
        serviceChecks(key, in, poc);
        State st = State.load(stateFile, poc, !demo && (rule.kind().equals("update") || rule.kind().equals("delete")) && !(key.equals("iam:PutRolePolicy") && !apply && SdkPrerequisites.ROLES.contains(first(in,"RoleName"))));
        Map<String, Object> entry = null;
        List<String[]> dns = List.of();
        switch (rule.kind()) {
            case "create" -> { if (!hasTag(in, poc)) throw new SecurityException(key + " must carry the tag poc=" + poc + " in its request"); }
            case "dns" -> dns = dnsChecks(b, in, st, demo);
            case "bounded-policy" -> { }
            default -> {
                var values = demo ? List.of() : at(in, rule.id());
                if (!demo && values.isEmpty()) throw new IllegalArgumentException(key + " needs " + rule.id() + " in its input");
                for (Object v : values) {
                    entry = st.find(service, String.valueOf(v), rule.of());
                    if (entry == null && key.equals("iam:PutRolePolicy") && !apply && SdkPrerequisites.ROLES.contains(String.valueOf(v))) {
                        SdkPrerequisites.verifyRole(b,String.valueOf(v),poc);
                        entry=new LinkedHashMap<>();entry.put("adopted",true);entry.put("allowedOperation","PutRolePolicy");entry.put("name",v);entry.put("arn","");
                        entry.put("previousInlinePolicies",SdkPrerequisites.inlinePolicies(b,String.valueOf(v)));
                    }
                    if (entry == null) throw new SecurityException(key + " target " + v + " is not recorded in the state file: refusing (never touch what this run did not create)");
                    if (Boolean.TRUE.equals(entry.get("adopted")) && (!rule.kind().equals("update") || !op.equals(entry.get("allowedOperation"))))
                        throw new SecurityException("adopted resource only permits its explicit update operation; deletion refused");
                    if (!demo && !hasTag(probeTags(b, service, entry), poc)) throw new SecurityException(key + " target " + v + " no longer carries the tag poc=" + poc + ": refusing");
                }
            }
        }
        Object rollback = SdkPrerequisites.check(b,key,parsed,in,poc,st,entry,demo);
        System.out.println("sdk call " + key + (apply ? " APPLY " : " DRY-RUN ") + "poc=" + poc + " input=" + Jsons.encodeRaw(redact(parsed, Set.of())));
        Map<String, String> r = row("kind", "sdk_call", "service", service, "operation", op, "mode", "mutate:" + rule.kind(), "poc", poc, "demo", String.valueOf(demo),
                "input", Jsons.encodeRaw(redact(parsed, Set.of())));
        if (!apply || demo) {
            r.put("applied", "false"); r.put("action", demo && apply ? "demo" : "dry_run");
            return r;
        }
        if (!AwsBackend.isApplyEnabled()) throw new SecurityException("applying requires --apply (LMAWS_APPLY=1)");
        if (rollback != null) { st.records.put("rollback:"+key+":"+first(in,service.equals("iam")?"RoleName":"Bucket"),rollback); st.save(); }
        SdkPrerequisites.recheck(b,key,in,rollback);
        Object out;
        try { out = invoke(b.sdkClient(service), iface, op, SdkPrerequisites.request(key,in)); }
        catch (RuntimeException ex) { if (key.equals("secretsmanager:CreateSecret")) throw new SecurityException("CreateSecret failed; secret-bearing service diagnostics suppressed"); throw ex; }
        switch (rule.kind()) {
            case "create" -> {
                String arn = rule.arn().equals("synth:logs") ? "arn:aws:logs:" + b.regionName() + ":" + b.accountIdForResize() + ":log-group:" + first(in, "logGroupName") : first(out, rule.arn());
                String name = rule.name().startsWith("in:") ? first(in, rule.name().substring(3)) : first(out, rule.name());
                if (rule.arn().startsWith("in:") || service.equals("ec2")) arn = "";
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("service", service); e.put("op", op); e.put("arn", arn); e.put("name", name); e.put("ids", idsOf(arn, name)); e.put("created", Instant.now().toString());
                st.resources.add(e);
                r.put("id", arn.isEmpty() ? name : arn);
            }
            case "delete" -> { for (Object v : at(in, rule.id())) { var e = st.find(service, String.valueOf(v), rule.of()); if (e != null) st.resources.remove(e); } }
            case "dns" -> { for (String[] p : dns) { if (p[0].equals("put")) st.records.put(p[1], p[2]); else st.records.remove(p[1]); } }
            default -> { }
        }
        st.save();
        r.put("applied", "true"); r.put("action", "called");
        r.put("output", Jsons.encodeRaw(redact(out, secrets)));
        return r;
    }
}
