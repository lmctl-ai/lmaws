package ai.lmctl.lmaws;

import java.lang.reflect.*;
import java.net.URI;
import java.util.*;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.acm.model.*;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;
import software.amazon.awssdk.services.cloudfront.model.*;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.route53.model.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

/**
 * Credential-free SDK request checks for the web adapter.  Dynamic proxies
 * implement the AWS client interfaces, so guards and request builders are
 * exercised without credentials, sockets, or a localhost protocol fixture.
 */
public final class WebTransportChecks {
    private static final String RUN = "a1b2c3d4";
    private static final String DOMAIN = "example.com";
    private WebTransportChecks() {}

    public static void main(String[] args) { run(); System.out.println("PASS web SDK transport checks"); }

    public static void run() {
        Map<String,Object> seen = new LinkedHashMap<>();
        Route53Client r53 = proxy(Route53Client.class, seen);
        CloudFrontClient cf = proxy(CloudFrontClient.class, seen);
        AcmClient acm = proxy(AcmClient.class, seen);
        S3Client s3 = proxy(S3Client.class, seen);
        // Ec2Client has hundreds of methods and exceeds the JVM proxy
        // class-initializer limit. It is never called by these checks; a
        // real SDK client pointed at an unroutable loopback port supplies the
        // constructor/close contract without credentials or network traffic.
        Ec2Client ec2 = Ec2Client.builder().region(Region.US_EAST_1)
                .endpointOverride(URI.create("http://127.0.0.1:1"))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"))).build();
        try (WebStackAws web = new WebStackAws(r53, cf, acm, s3, ec2, RUN, DOMAIN)) {
            expect(() -> web.changeAlias("zone", "lmaws-site-" + RUN + ".other.example", "d1234567890.cloudfront.net", false));
            expect(() -> web.recordA("zone", "lmaws-app-" + RUN + ".other.example", "192.0.2.10", false));
            expect(() -> web.requestCertificate("lmaws-site-" + RUN + ".other.example"));
            expect(() -> web.recordCname("zone", "_token.other.example", "value", false));

            Distribution d = web.createDistribution("lmaws-site-" + RUN,
                    "lmaws-site-" + RUN + "." + DOMAIN, "oac-" + RUN);
            if (!d.id().equals("EDFDVBD6EXAMPLE")) throw new AssertionError("distribution response was not consumed");
            Object create = seen.get("createDistributionWithTags");
            if (!(create instanceof CreateDistributionWithTagsRequest req)) throw new AssertionError("distribution request missing");
            if (req.distributionConfigWithTags().tags().items().stream().noneMatch(t -> "lmaws_test".equals(t.key()) && RUN.equals(t.value())))
                throw new AssertionError("distribution request missing ownership tag");
            if (req.distributionConfigWithTags().distributionConfig().defaultCacheBehavior().viewerProtocolPolicy() != ViewerProtocolPolicy.ALLOW_ALL)
                throw new AssertionError("phase one must allow HTTP before ACM");
            if (req.distributionConfigWithTags().distributionConfig().aliases() != null
                    && !req.distributionConfigWithTags().distributionConfig().aliases().items().isEmpty())
                throw new AssertionError("phase one distribution must not claim custom alias");

            web.createOac();
            Object oac = seen.get("createOriginAccessControl");
            if (!(oac instanceof CreateOriginAccessControlRequest oacReq)
                    || !oacReq.originAccessControlConfig().name().equals("lmaws-oac-" + RUN))
                throw new AssertionError("OAC request was not run-scoped");

            web.requestCertificate("lmaws-site-" + RUN + "." + DOMAIN);
            Object cert = seen.get("requestCertificate");
            if (!(cert instanceof RequestCertificateRequest certReq)
                    || certReq.tags().stream().noneMatch(t -> "lmaws_test".equals(t.key()) && RUN.equals(t.value())))
                throw new AssertionError("certificate request missing ownership tag");

            // Bucket mutations require the exact run tag and the policy must
            // bind reads to the tagged CloudFront distribution ARN.
            expect(() -> web.bucketPolicy("lmaws-site-" + RUN,
                    "arn:aws:cloudfront::000000000000:distribution/EDFDVBD6EXAMPLE"));
            seen.put("allowBucket", true);
            String sourceArn = "arn:aws:cloudfront::000000000000:distribution/EDFDVBD6EXAMPLE";
            web.bucketPolicy("lmaws-site-" + RUN, sourceArn);
            if (!(seen.get("putBucketPolicy") instanceof PutBucketPolicyRequest policy)
                    || !policy.policy().contains("\"AWS:SourceArn\":\"" + sourceArn + "\""))
                throw new AssertionError("bucket policy did not bind CloudFront source ARN");

            // Emptying uses paginated object-version listings and refuses a
            // partial DeleteObjects result rather than claiming success.
            seen.put("partialDelete", true);
            expect(() -> web.emptyBucket("lmaws-site-" + RUN));
            seen.put("partialDelete", false);
            seen.remove("listPage");
            web.emptyBucket("lmaws-site-" + RUN);
            if (!Integer.valueOf(2).equals(seen.get("listPage")))
                throw new AssertionError("version pagination was not followed");

            web.recordA("zone", "lmaws-app-" + RUN + "." + DOMAIN, "192.0.2.10", false);
            Object change = seen.get("changeResourceRecordSets");
            if (!(change instanceof ChangeResourceRecordSetsRequest recordReq)
                    || !recordReq.changeBatch().changes().getFirst().resourceRecordSet().name().startsWith("lmaws-app-"))
                throw new AssertionError("Route 53 A request missing scoped name");
        } finally {
            // Proxy clients have no resources and close() is deliberately a no-op.
        }
    }

    private static void expect(Runnable action) {
        try { action.run(); } catch (RuntimeException expected) { return; }
        throw new AssertionError("unsafe web request was accepted");
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Map<String,Object> seen) {
        InvocationHandler h = (obj, method, args) -> {
            String name = method.getName();
            if (args != null && args.length == 1 && args[0] != null && args[0].getClass().getName().endsWith("Request"))
                seen.put(name, args[0]);
            if (args != null && args.length == 1 && args[0] instanceof java.util.function.Consumer<?> consumer) {
                if (type == CloudFrontClient.class && name.equals("createDistributionWithTags")) {
                    var b = CreateDistributionWithTagsRequest.builder(); ((java.util.function.Consumer<CreateDistributionWithTagsRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == CloudFrontClient.class && name.equals("createOriginAccessControl")) {
                    var b = CreateOriginAccessControlRequest.builder(); ((java.util.function.Consumer<CreateOriginAccessControlRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == AcmClient.class && name.equals("requestCertificate")) {
                    var b = RequestCertificateRequest.builder(); ((java.util.function.Consumer<RequestCertificateRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == Route53Client.class && name.equals("changeResourceRecordSets")) {
                    var b = ChangeResourceRecordSetsRequest.builder(); ((java.util.function.Consumer<ChangeResourceRecordSetsRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == Route53Client.class && name.equals("getChange")) {
                    var b = GetChangeRequest.builder(); ((java.util.function.Consumer<GetChangeRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == Route53Client.class && name.equals("getHostedZone")) {
                    var b = GetHostedZoneRequest.builder(); ((java.util.function.Consumer<GetHostedZoneRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == S3Client.class && name.equals("putBucketPolicy")) {
                    var b = PutBucketPolicyRequest.builder(); ((java.util.function.Consumer<PutBucketPolicyRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                }
            }
            if (type == CloudFrontClient.class && name.equals("createDistributionWithTags"))
                return CreateDistributionWithTagsResponse.builder().distribution(Distribution.builder().id("EDFDVBD6EXAMPLE").arn("arn:aws:cloudfront::000000000000:distribution/EDFDVBD6EXAMPLE").domainName("d1234567890.cloudfront.net").build()).build();
            if (type == CloudFrontClient.class && name.equals("createOriginAccessControl"))
                return CreateOriginAccessControlResponse.builder().originAccessControl(OriginAccessControl.builder().id("oac").build()).build();
            if (type == AcmClient.class && name.equals("requestCertificate"))
                return RequestCertificateResponse.builder().certificateArn("arn:aws:acm:us-east-1:000000000000:certificate/synthetic").build();
            if (type == Route53Client.class && name.equals("getChange"))
                return GetChangeResponse.builder().changeInfo(ChangeInfo.builder().status(ChangeStatus.INSYNC).id("/change/C1").build()).build();
            if (type == Route53Client.class && name.equals("getHostedZone"))
                return GetHostedZoneResponse.builder().hostedZone(HostedZone.builder().id("/hostedzone/ZTEST").name(DOMAIN + ".").build()).build();
            if (type == S3Client.class && name.equals("getBucketTagging")) {
                if (Boolean.TRUE.equals(seen.get("allowBucket")))
                    return GetBucketTaggingResponse.builder().tagSet(software.amazon.awssdk.services.s3.model.Tag.builder().key("lmaws_test").value(RUN).build()).build();
                return GetBucketTaggingResponse.builder().tagSet(List.of()).build();
            }
            if (type == S3Client.class && name.equals("listObjectVersions")) {
                int page = ((Number) seen.getOrDefault("listPage", 0)).intValue() + 1; seen.put("listPage", page);
                ObjectVersion v = ObjectVersion.builder().key("index.html").versionId("v" + page).build();
                return page == 1
                        ? ListObjectVersionsResponse.builder().versions(v).isTruncated(true).nextKeyMarker("k2").nextVersionIdMarker("v2").build()
                        : ListObjectVersionsResponse.builder().versions(v).isTruncated(false).build();
            }
            if (type == S3Client.class && name.equals("deleteObjects")) {
                if (Boolean.TRUE.equals(seen.get("partialDelete")))
                    return DeleteObjectsResponse.builder().errors(S3Error.builder().key("index.html").versionId("v1").code("AccessDenied").build()).build();
                return DeleteObjectsResponse.builder().deleted(DeletedObject.builder().key("index.html").build()).build();
            }
            if (type == Route53Client.class && name.equals("changeResourceRecordSets"))
                return ChangeResourceRecordSetsResponse.builder().changeInfo(ChangeInfo.builder().status(ChangeStatus.PENDING).id("/change/C1").build()).build();
            if (method.getReturnType() == void.class) return null;
            if (method.getReturnType() == boolean.class) return false;
            if (method.getReturnType() == int.class) return 0;
            if (method.getReturnType() == long.class) return 0L;
            if (method.getReturnType() == double.class) return 0.0d;
            return null;
        };
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, h);
    }
}
