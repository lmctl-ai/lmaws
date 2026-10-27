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
    private static final String PROOF = "0123456789abcdef0123456789abcdef";
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
        try (WebStackAws web = new WebStackAws(r53, cf, acm, s3, ec2, RUN, DOMAIN, PROOF)) {
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
                    || !oacReq.originAccessControlConfig().name().equals("lmaws-oac-" + RUN)
                    || !oacReq.originAccessControlConfig().description().equals("lmweblab " + RUN + " owner:" + PROOF))
                throw new AssertionError("OAC request was not run-scoped");
            seen.remove("deleteOriginAccessControl");
            try (WebStackAws wrongProof = new WebStackAws(r53, cf, acm, s3, ec2, RUN, DOMAIN,
                    "fedcba9876543210fedcba9876543210")) {
                expect(() -> wrongProof.deleteOac("oac"));
            }
            try (WebStackAws missingProof = new WebStackAws(r53, cf, acm, s3, ec2, RUN, DOMAIN)) {
                expect(() -> missingProof.deleteOac("oac"));
            }
            if (seen.containsKey("deleteOriginAccessControl"))
                throw new AssertionError("unproven OAC deletion reached Delete API");
            web.deleteOac("oac");
            if (!(seen.get("deleteOriginAccessControl") instanceof DeleteOriginAccessControlRequest))
                throw new AssertionError("proven OAC deletion did not reach Delete API");

            web.requestCertificate("lmaws-site-" + RUN + "." + DOMAIN);
            Object cert = seen.get("requestCertificate");
            if (!(cert instanceof RequestCertificateRequest certReq)
                    || certReq.tags().stream().noneMatch(t -> "lmaws_test".equals(t.key()) && RUN.equals(t.value())))
                throw new AssertionError("certificate request missing ownership tag");
            String certArn = "arn:aws:acm:us-east-1:000000000000:certificate/synthetic";
            web.createDistribution("lmaws-site-" + RUN,
                    "lmaws-site-" + RUN + "." + DOMAIN, "oac-" + RUN, certArn);
            if (!(seen.get("createDistributionWithTags") instanceof CreateDistributionWithTagsRequest preparedReq))
                throw new AssertionError("prepared-certificate distribution request missing");
            DistributionConfig prepared = preparedReq.distributionConfigWithTags().distributionConfig();
            if (!prepared.aliases().items().equals(List.of("lmaws-site-" + RUN + "." + DOMAIN))
                    || !certArn.equals(prepared.viewerCertificate().acmCertificateArn())
                    || prepared.defaultCacheBehavior().viewerProtocolPolicy() != ViewerProtocolPolicy.ALLOW_ALL
                    || prepared.viewerCertificate().minimumProtocolVersion() != MinimumProtocolVersion.TLS_V1_2_2021)
                throw new AssertionError("prepared certificate distribution config is unsafe");

            // HTTPS phase must use the exact alias, an issued certificate, a
            // modern minimum protocol, and an explicit redirect policy.
            web.attachCertificate("EDFDVBD6EXAMPLE", "lmaws-site-" + RUN + "." + DOMAIN,
                    "arn:aws:acm:us-east-1:000000000000:certificate/synthetic", true);
            if (!(seen.get("updateDistribution") instanceof UpdateDistributionRequest httpsReq))
                throw new AssertionError("HTTPS update request missing");
            DistributionConfig httpsConfig = httpsReq.distributionConfig();
            if (!httpsConfig.aliases().items().equals(List.of("lmaws-site-" + RUN + "." + DOMAIN)))
                throw new AssertionError("HTTPS alias was not exact run/domain name");
            if (httpsConfig.defaultCacheBehavior().viewerProtocolPolicy() != ViewerProtocolPolicy.REDIRECT_TO_HTTPS)
                throw new AssertionError("HTTPS phase did not enable redirect");
            if (httpsConfig.viewerCertificate().minimumProtocolVersion() != MinimumProtocolVersion.TLS_V1_2_2021)
                throw new AssertionError("HTTPS phase did not enforce TLS 1.2");

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
            seen.remove("accepted");
            web.recordA("zone", "lmaws-app-" + RUN + "." + DOMAIN, "192.0.2.10", false,
                    () -> seen.put("accepted", true));
            if (!Boolean.TRUE.equals(seen.get("accepted")))
                throw new AssertionError("accepted callback did not run after Route 53 mutation response");
            seen.put("timeoutChange", true); seen.remove("accepted");
            expect(() -> web.recordA("zone", "lmaws-app-" + RUN + "." + DOMAIN, "192.0.2.10", false,
                    () -> seen.put("accepted", true)));
            if (!Boolean.TRUE.equals(seen.get("accepted")))
                throw new AssertionError("DNS state callback did not run before INSYNC timeout");
            seen.remove("timeoutChange");

            // Scenario 11 shifts the same run-scoped pair repeatedly. Each
            // call must emit two UPSERT records and preserve the callback
            // ordering used by durable state recovery.
            seen.remove("foreignWeighted");
            web.weightedSet("zone", "lmaws-weighted-" + RUN + "." + DOMAIN,
                    "d1234567890.cloudfront.net", "192.0.2.20", 90, 10, false,
                    () -> seen.put("weightedAccepted", true));
            assertWeighted(seen, 90, 10, ChangeAction.UPSERT);
            seen.put("sameWeighted", true);
            expect(() -> web.weightedSetOwned("zone", "lmaws-weighted-" + RUN + "." + DOMAIN,
                    "d1234567890.cloudfront.net", "192.0.2.20", 90, 10, false, false, null));
            seen.remove("sameWeighted");
            web.weightedSet("zone", "lmaws-weighted-" + RUN + "." + DOMAIN,
                    "d1234567890.cloudfront.net", "192.0.2.20", 50, 50, false, null);
            assertWeighted(seen, 50, 50, ChangeAction.UPSERT);
            web.weightedSet("zone", "lmaws-weighted-" + RUN + "." + DOMAIN,
                    "d1234567890.cloudfront.net", "192.0.2.20", 0, 100, true, null);
            assertWeighted(seen, 0, 100, ChangeAction.DELETE);
            if (!Boolean.TRUE.equals(seen.get("weightedAccepted"))) throw new AssertionError("weighted callback missing");
            seen.put("foreignWeighted", true);
            expect(() -> web.weightedSet("zone", "lmaws-weighted-" + RUN + "." + DOMAIN,
                    "d1234567890.cloudfront.net", "192.0.2.20", 90, 10, false, null));
        } finally {
            // Proxy clients have no resources and close() is deliberately a no-op.
        }
    }

    private static void expect(Runnable action) {
        try { action.run(); } catch (RuntimeException expected) { return; }
        throw new AssertionError("unsafe web request was accepted");
    }

    private static void assertWeighted(Map<String,Object> seen,long staticWeight,long dynamicWeight,ChangeAction action) {
        if (!(seen.get("changeResourceRecordSets") instanceof ChangeResourceRecordSetsRequest req)
                || req.changeBatch().changes().size()!=2
                || req.changeBatch().changes().stream().anyMatch(c -> c.action()!=action))
            throw new AssertionError("weighted Route 53 request missing expected actions");
        var a=req.changeBatch().changes().get(0).resourceRecordSet();
        var b=req.changeBatch().changes().get(1).resourceRecordSet();
        if(a.weight()!=staticWeight||b.weight()!=dynamicWeight||!a.setIdentifier().startsWith("static-")||!b.setIdentifier().startsWith("dynamic-"))
            throw new AssertionError("weighted Route 53 request has wrong weights or identifiers");
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
                } else if (type == Route53Client.class && name.equals("listResourceRecordSets")) {
                    var b = ListResourceRecordSetsRequest.builder(); ((java.util.function.Consumer<ListResourceRecordSetsRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == S3Client.class && name.equals("putBucketPolicy")) {
                    var b = PutBucketPolicyRequest.builder(); ((java.util.function.Consumer<PutBucketPolicyRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == CloudFrontClient.class && name.equals("updateDistribution")) {
                    var b = UpdateDistributionRequest.builder(); ((java.util.function.Consumer<UpdateDistributionRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                } else if (type == CloudFrontClient.class && name.equals("deleteOriginAccessControl")) {
                    var b = DeleteOriginAccessControlRequest.builder(); ((java.util.function.Consumer<DeleteOriginAccessControlRequest.Builder>) consumer).accept(b); seen.put(name, b.build());
                }
            }
            if (type == CloudFrontClient.class && name.equals("createDistributionWithTags"))
                return CreateDistributionWithTagsResponse.builder().distribution(Distribution.builder().id("EDFDVBD6EXAMPLE").arn("arn:aws:cloudfront::000000000000:distribution/EDFDVBD6EXAMPLE").domainName("d1234567890.cloudfront.net").build()).build();
            if (type == CloudFrontClient.class && name.equals("createOriginAccessControl"))
                return CreateOriginAccessControlResponse.builder().originAccessControl(OriginAccessControl.builder().id("oac").build()).build();
            if (type == CloudFrontClient.class && name.equals("getOriginAccessControl"))
                return GetOriginAccessControlResponse.builder().eTag("etag").originAccessControl(OriginAccessControl.builder().id("oac").originAccessControlConfig(OriginAccessControlConfig.builder().name("lmaws-oac-" + RUN).description("lmweblab " + RUN + " owner:" + PROOF).build()).build()).build();
            if (type == CloudFrontClient.class && name.equals("deleteOriginAccessControl"))
                return DeleteOriginAccessControlResponse.builder().build();
            if (type == CloudFrontClient.class && name.equals("getDistribution"))
                return GetDistributionResponse.builder().eTag("etag").distribution(Distribution.builder().id("EDFDVBD6EXAMPLE").arn("arn:aws:cloudfront::000000000000:distribution/EDFDVBD6EXAMPLE").domainName("d1234567890.cloudfront.net").status("Deployed").distributionConfig(DistributionConfig.builder().enabled(true).defaultCacheBehavior(DefaultCacheBehavior.builder().targetOriginId("s3-lmaws-site-a1b2c3d4").viewerProtocolPolicy(ViewerProtocolPolicy.ALLOW_ALL).build()).build()).build()).build();
            if (type == CloudFrontClient.class && name.equals("listTagsForResource"))
                return software.amazon.awssdk.services.cloudfront.model.ListTagsForResourceResponse.builder().tags(Tags.builder().items(software.amazon.awssdk.services.cloudfront.model.Tag.builder().key("lmaws_test").value(RUN).build()).build()).build();
            if (type == CloudFrontClient.class && name.equals("updateDistribution"))
                return UpdateDistributionResponse.builder().eTag("etag").distribution(Distribution.builder().id("EDFDVBD6EXAMPLE").status("Deployed").build()).build();
            if (type == AcmClient.class && name.equals("requestCertificate"))
                return RequestCertificateResponse.builder().certificateArn("arn:aws:acm:us-east-1:000000000000:certificate/synthetic").build();
            if (type == AcmClient.class && name.equals("describeCertificate"))
                return DescribeCertificateResponse.builder().certificate(CertificateDetail.builder().domainName("lmaws-site-" + RUN + "." + DOMAIN).status(CertificateStatus.ISSUED).build()).build();
            if (type == AcmClient.class && name.equals("listTagsForCertificate"))
                return software.amazon.awssdk.services.acm.model.ListTagsForCertificateResponse.builder().tags(software.amazon.awssdk.services.acm.model.Tag.builder().key("lmaws_test").value(RUN).build()).build();
            if (type == Route53Client.class && name.equals("getChange")) {
                if (Boolean.TRUE.equals(seen.get("timeoutChange"))) throw new IllegalStateException("synthetic Route 53 wait failure");
                return GetChangeResponse.builder().changeInfo(ChangeInfo.builder().status(ChangeStatus.INSYNC).id("/change/C1").build()).build();
            }
            if (type == Route53Client.class && name.equals("getHostedZone"))
                return GetHostedZoneResponse.builder().hostedZone(HostedZone.builder().id("/hostedzone/ZTEST").name(DOMAIN + ".").build()).build();
            if (type == Route53Client.class && name.equals("listResourceRecordSets")) {
                if (Boolean.TRUE.equals(seen.get("foreignWeighted")))
                    return ListResourceRecordSetsResponse.builder().resourceRecordSets(ResourceRecordSet.builder().name("lmaws-weighted-" + RUN + "." + DOMAIN + ".").type(RRType.A).setIdentifier("foreign").resourceRecords(software.amazon.awssdk.services.route53.model.ResourceRecord.builder().value("192.0.2.50").build()).build()).build();
                if (Boolean.TRUE.equals(seen.get("sameWeighted")))
                    return ListResourceRecordSetsResponse.builder().resourceRecordSets(ResourceRecordSet.builder().name("lmaws-weighted-" + RUN + "." + DOMAIN + ".").type(RRType.A).setIdentifier("static-" + RUN).resourceRecords(software.amazon.awssdk.services.route53.model.ResourceRecord.builder().value("192.0.2.50").build()).build()).build();
                return ListResourceRecordSetsResponse.builder().resourceRecordSets(List.of()).build();
            }
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
