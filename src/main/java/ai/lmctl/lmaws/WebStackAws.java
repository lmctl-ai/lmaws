package ai.lmctl.lmaws;

import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;
import java.nio.file.Path;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.route53.model.*;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;
import software.amazon.awssdk.services.cloudfront.model.*;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.acm.model.CertificateDetail;
import software.amazon.awssdk.services.acm.model.RequestCertificateRequest;
import software.amazon.awssdk.services.acm.model.ValidationMethod;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.Tagging;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import software.amazon.awssdk.services.ec2.model.IpPermission;
import software.amazon.awssdk.services.ec2.model.IpRange;

/** Guarded AWS lifecycle for the lmweblab stack. */
public final class WebStackAws implements AutoCloseable {
    private static final Pattern RUN=Pattern.compile("[0-9a-f]{4,32}");
    private final Route53Client route53; private final CloudFrontClient cloudfront; private final AcmClient acm; private final S3Client s3; private final Ec2Client ec2; private final String runId; private final String domain; private final String ownerProof;
    public WebStackAws(Route53Client r,CloudFrontClient c,AcmClient a,S3Client s,Ec2Client e,String id){this(r,c,a,s,e,id,null);}
    public WebStackAws(Route53Client r,CloudFrontClient c,AcmClient a,S3Client s,Ec2Client e,String id,String domain){this(r,c,a,s,e,id,domain,null);}
    public WebStackAws(Route53Client r,CloudFrontClient c,AcmClient a,S3Client s,Ec2Client e,String id,String domain,String proof){route53=Objects.requireNonNull(r);cloudfront=Objects.requireNonNull(c);acm=Objects.requireNonNull(a);s3=Objects.requireNonNull(s);ec2=Objects.requireNonNull(e);if(id==null||!RUN.matcher(id).matches())throw new IllegalArgumentException("invalid run id");runId=id;if(proof!=null&&!proof.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("invalid OAC ownership proof");ownerProof=proof;this.domain=domain==null?null:(domain.endsWith(".")?domain.substring(0,domain.length()-1):domain);}
    private void owned(String n){if(n==null||!n.startsWith("lmaws-")||!n.endsWith("-"+runId))throw new SecurityException("resource outside this run namespace");}
    public List<HostedZone> zones(){List<HostedZone> rows=new ArrayList<>();int pages=0;for(var page:route53.listHostedZonesPaginator()){if(++pages>100||rows.size()+page.hostedZones().size()>10000)throw new IllegalStateException("hosted-zone discovery limit");rows.addAll(page.hostedZones());}return rows;}
    public String zoneId(String domain){String d=domain.endsWith(".")?domain:domain+".";return zones().stream().filter(z->d.equals(z.name())).map(HostedZone::id).findFirst().orElseThrow(()->new IllegalArgumentException("hosted zone not found"));}
    public String changeAlias(String zone,String fqdn,String target,boolean delete){return changeAlias(zone,fqdn,target,delete,null);}
    public String changeAlias(String zone,String fqdn,String target,boolean delete,Runnable accepted){WebStack.requireAliasTarget(target);recordName(zone,fqdn,false);ResourceRecordSet rr=ResourceRecordSet.builder().name(fqdn.endsWith(".")?fqdn:fqdn+".").type(RRType.A).aliasTarget(AliasTarget.builder().dnsName(target).hostedZoneId("Z2FDTNDATAQYW2").evaluateTargetHealth(false).build()).build();ChangeInfo ci=route53.changeResourceRecordSets(x->x.hostedZoneId(zone).changeBatch(ChangeBatch.builder().changes(Change.builder().action(delete?ChangeAction.DELETE:ChangeAction.CREATE).resourceRecordSet(rr).build()).build()).build()).changeInfo();if(accepted!=null)accepted.run();waitChange(ci.id(),Duration.ofMinutes(5));return ci.id();}
    public String recordA(String zone,String fqdn,String ip,boolean delete){return recordA(zone,fqdn,ip,delete,null);}
    public String recordA(String zone,String fqdn,String ip,boolean delete,Runnable accepted){recordName(zone,fqdn,false);WebStack.requireHttpCidr(ip+"/32");return record(zone,fqdn,RRType.A,ip,delete,accepted);}
    public String recordCname(String zone,String fqdn,String value,boolean delete){return recordCname(zone,fqdn,value,delete,null);}
    public String recordCname(String zone,String fqdn,String value,boolean delete,Runnable accepted){recordName(zone,fqdn,true);if(value==null||value.length()>255)throw new IllegalArgumentException("invalid CNAME value");return record(zone,fqdn,RRType.CNAME,value,delete,accepted);}
    private String record(String zone,String fqdn,RRType type,String value,boolean delete,Runnable accepted){ResourceRecordSet rr=ResourceRecordSet.builder().name(fqdn.endsWith(".")?fqdn:fqdn+".").type(type).ttl(60L).resourceRecords(software.amazon.awssdk.services.route53.model.ResourceRecord.builder().value(value).build()).build();ChangeInfo ci=route53.changeResourceRecordSets(x->x.hostedZoneId(zone).changeBatch(ChangeBatch.builder().changes(Change.builder().action(delete?ChangeAction.DELETE:ChangeAction.CREATE).resourceRecordSet(rr).build()).build()).build()).changeInfo();if(accepted!=null)accepted.run();waitChange(ci.id(),Duration.ofMinutes(5));return ci.id();}
    /** Set the two owned weighted A records used by scenario 11. UPSERT is scoped to the exact run name and identifiers. */
    public String weightedSet(String zone,String fqdn,String staticTarget,String dynamicIp,long staticWeight,long dynamicWeight,boolean delete,Runnable accepted){return weightedSetOwned(zone,fqdn,staticTarget,dynamicIp,staticWeight,dynamicWeight,delete,true,accepted);}
    public String weightedSetOwned(String zone,String fqdn,String staticTarget,String dynamicIp,long staticWeight,long dynamicWeight,boolean delete,boolean allowExisting,Runnable accepted){
        weightedName(zone,fqdn); if(staticWeight<0||staticWeight>255||dynamicWeight<0||dynamicWeight>255)throw new IllegalArgumentException("weighted DNS weights must be 0..255");
        if(staticTarget==null||!staticTarget.matches("[a-z0-9-]+\\.cloudfront\\.net\\.?"))throw new SecurityException("invalid CloudFront weighted target");
        WebStack.requireHttpCidr(dynamicIp+"/32");
        String name=fqdn.endsWith(".")?fqdn:fqdn+".";
        // A run may shift only the two records it created. Refuse adoption of any
        // other record at this exact name before issuing an UPSERT.
        var existingPage=route53.listResourceRecordSets(x->x.hostedZoneId(zone).startRecordName(name).startRecordType(RRType.A).maxItems("100"));
        for(var existing:existingPage.resourceRecordSets()) if(stripDot(existing.name()).equals(stripDot(fqdn))) {
            boolean ours=("static-"+runId).equals(existing.setIdentifier())||("dynamic-"+runId).equals(existing.setIdentifier());
            if(!ours||(!allowExisting&&!delete)) throw new SecurityException("weighted DNS name already contains a record not established by this run");
        }
        ResourceRecordSet alias=ResourceRecordSet.builder().name(name).type(RRType.A).setIdentifier("static-"+runId).weight(staticWeight).aliasTarget(AliasTarget.builder().dnsName(staticTarget).hostedZoneId("Z2FDTNDATAQYW2").evaluateTargetHealth(false).build()).build();
        ResourceRecordSet ip=ResourceRecordSet.builder().name(name).type(RRType.A).setIdentifier("dynamic-"+runId).weight(dynamicWeight).ttl(60L).resourceRecords(software.amazon.awssdk.services.route53.model.ResourceRecord.builder().value(dynamicIp).build()).build();
        ChangeAction action=delete?ChangeAction.DELETE:ChangeAction.UPSERT;
        ChangeBatch batch=ChangeBatch.builder().changes(Change.builder().action(action).resourceRecordSet(alias).build(),Change.builder().action(action).resourceRecordSet(ip).build()).build();
        ChangeInfo ci=route53.changeResourceRecordSets(x->x.hostedZoneId(zone).changeBatch(batch).build()).changeInfo(); if(accepted!=null)accepted.run(); waitChange(ci.id(),Duration.ofMinutes(5)); return ci.id();
    }
    private void weightedName(String zone,String fqdn){
        String n=stripDot(fqdn), expected="lmaws-weighted-"+runId+"."+domain;
        if(!n.equals(expected))throw new SecurityException("weighted DNS name outside this run/domain");
        String zoneName=stripDot(route53.getHostedZone(x->x.id(zone)).hostedZone().name()); if(!domain.equals(zoneName))throw new SecurityException("hosted zone domain mismatch");
    }
    public void waitChange(String id,Duration timeout){long end=System.nanoTime()+timeout.toNanos();for(;;){if(route53.getChange(x->x.id(id)).changeInfo().status()==ChangeStatus.INSYNC)return;if(System.nanoTime()>end)throw new IllegalStateException("Route 53 change timeout");sleep(2000);}}
    private String oacDescription(){return "lmweblab "+runId+(ownerProof==null?"":" owner:"+ownerProof);}
    public String createOac(){return cloudfront.createOriginAccessControl(x->x.originAccessControlConfig(OriginAccessControlConfig.builder().name("lmaws-oac-"+runId).description(oacDescription()).originAccessControlOriginType("s3").signingBehavior("always").signingProtocol("sigv4").build())).originAccessControl().id();}
    public void deleteOac(String id){if(id==null||id.isBlank())throw new IllegalArgumentException("oac id required");var g=cloudfront.getOriginAccessControl(x->x.id(id));if(ownerProof==null||!("lmaws-oac-"+runId).equals(g.originAccessControl().originAccessControlConfig().name())||!oacDescription().equals(g.originAccessControl().originAccessControlConfig().description()))throw new SecurityException("origin access control is not owned by this run");cloudfront.deleteOriginAccessControl(x->x.id(id).ifMatch(g.eTag()));}
    public Distribution createDistribution(String bucket,String alias,String oac){return createDistribution(bucket,alias,oac,null);}
    public Distribution createDistribution(String bucket,String alias,String oac,String certArn){owned(bucket);if(!alias.equals("lmaws-site-"+runId+"."+domain))throw new SecurityException("alias outside this run namespace");Origin o=Origin.builder().id("s3-"+bucket).domainName(bucket+".s3.amazonaws.com").originAccessControlId(oac).s3OriginConfig(S3OriginConfig.builder().originAccessIdentity("").build()).build();AllowedMethods methods=AllowedMethods.builder().items(Method.GET,Method.HEAD).quantity(2).cachedMethods(CachedMethods.builder().items(Method.GET,Method.HEAD).quantity(2).build()).build();DefaultCacheBehavior cb=DefaultCacheBehavior.builder().targetOriginId(o.id()).viewerProtocolPolicy(ViewerProtocolPolicy.ALLOW_ALL).trustedSigners(TrustedSigners.builder().enabled(false).quantity(0).build()).allowedMethods(methods).forwardedValues(ForwardedValues.builder().queryString(false).cookies(CookiePreference.builder().forward(ItemSelection.NONE).build()).build()).compress(true).minTTL(0L).defaultTTL(30L).maxTTL(60L).build();DistributionConfig d=DistributionConfig.builder().callerReference(UUID.randomUUID().toString()).enabled(true).comment("lmweblab "+runId).origins(Origins.builder().items(o).quantity(1).build()).defaultCacheBehavior(cb).priceClass(PriceClass.PRICE_CLASS_100).viewerCertificate(ViewerCertificate.builder().cloudFrontDefaultCertificate(true).build())
.customErrorResponses(CustomErrorResponses.builder().quantity(2).items(CustomErrorResponse.builder().errorCode(403).responseCode("404").responsePagePath("/404.html").errorCachingMinTTL(0L).build(),CustomErrorResponse.builder().errorCode(404).responseCode("404").responsePagePath("/404.html").errorCachingMinTTL(0L).build()).build()).defaultRootObject("index.html").build();Tags tags=Tags.builder().items(software.amazon.awssdk.services.cloudfront.model.Tag.builder().key("lmaws_test").value(runId).build()).build();
        final DistributionConfig config=certArn==null?d:d.toBuilder().aliases(Aliases.builder().items(alias).quantity(1).build()).viewerCertificate(viewerCertificate(alias,certArn)).build();
        var request=CreateDistributionWithTagsRequest.builder().distributionConfigWithTags(DistributionConfigWithTags.builder().distributionConfig(config).tags(tags).build()).build();
        long deadline=System.nanoTime()+Duration.ofMinutes(5).toNanos();
        for(;;)try{return cloudfront.createDistributionWithTags(request).distribution();}
        catch(InvalidViewerCertificateException e){if(certArn==null||System.nanoTime()>deadline)throw e;sleep(15000);}
    }
    /** CloudFront distribution for Lambda URL scenarios 03 (API origin) and 05 (S3 + /api/*). */
    public Distribution createLambdaDistribution(String bucket,String alias,String lambdaUrl,String oac,String certArn,boolean mixed){
        if(!alias.equals("lmaws-site-"+runId+"."+domain))throw new SecurityException("alias outside this run namespace");
        if(lambdaUrl==null||!lambdaUrl.matches("https://[a-z0-9-]+\\.lambda-url\\.(?:[a-z0-9-]+\\.)?on\\.aws/?|https://[a-z0-9-]+\\.lambda-url\\.local/?"))throw new SecurityException("Lambda URL is not an allowed HTTPS origin");
        String host=lambdaUrl.substring("https://".length()).replaceFirst("/$","");
        Origin api=Origin.builder().id("lambda-api-"+runId).domainName(host).customOriginConfig(CustomOriginConfig.builder().originProtocolPolicy(OriginProtocolPolicy.HTTPS_ONLY).httpsPort(443).httpPort(80).originSslProtocols(OriginSslProtocols.builder().items(SslProtocol.TLS_V1_2).quantity(1).build()).build()).build();
        Origin s3origin=null; String defaultId=api.id();
        if(mixed){owned(bucket);s3origin=Origin.builder().id("s3-"+bucket).domainName(bucket+".s3.amazonaws.com").originAccessControlId(oac).s3OriginConfig(S3OriginConfig.builder().originAccessIdentity("").build()).build();defaultId=s3origin.id();}
        AllowedMethods apiMethods=AllowedMethods.builder().items(Method.GET,Method.HEAD,Method.OPTIONS,Method.PUT,Method.POST,Method.PATCH,Method.DELETE).quantity(7).cachedMethods(CachedMethods.builder().items(Method.GET,Method.HEAD).quantity(2).build()).build();
        DefaultCacheBehavior def=DefaultCacheBehavior.builder().trustedSigners(TrustedSigners.builder().enabled(false).quantity(0).build()).targetOriginId(defaultId).viewerProtocolPolicy(ViewerProtocolPolicy.ALLOW_ALL).allowedMethods(mixed?AllowedMethods.builder().items(Method.GET,Method.HEAD).quantity(2).cachedMethods(CachedMethods.builder().items(Method.GET,Method.HEAD).quantity(2).build()).build():apiMethods).forwardedValues(ForwardedValues.builder().queryString(!mixed).cookies(CookiePreference.builder().forward(ItemSelection.NONE).build()).build()).minTTL(0L).defaultTTL(mixed?30L:0L).maxTTL(mixed?60L:0L).compress(true).build();
        CacheBehavior apiPath=mixed?CacheBehavior.builder().pathPattern("/api/*").targetOriginId(api.id()).viewerProtocolPolicy(ViewerProtocolPolicy.ALLOW_ALL).allowedMethods(apiMethods).forwardedValues(ForwardedValues.builder().queryString(true).cookies(CookiePreference.builder().forward(ItemSelection.ALL).build()).build()).minTTL(0L).defaultTTL(0L).maxTTL(0L).build():null;
        Origins.Builder origins=Origins.builder().items(mixed?List.of(s3origin,api):List.of(api)).quantity(mixed?2:1);
        DistributionConfig.Builder cfg=DistributionConfig.builder().callerReference(UUID.randomUUID().toString()).enabled(true).comment("lmweblab "+runId).origins(origins.build()).defaultCacheBehavior(def).priceClass(PriceClass.PRICE_CLASS_100).viewerCertificate(ViewerCertificate.builder().cloudFrontDefaultCertificate(true).build());
        if(mixed)cfg.defaultRootObject("index.html");
        if(apiPath!=null)cfg.cacheBehaviors(CacheBehaviors.builder().items(apiPath).quantity(1).build());
        if(certArn!=null)cfg.aliases(Aliases.builder().items(alias).quantity(1).build()).viewerCertificate(viewerCertificate(alias,certArn));
        var req=CreateDistributionWithTagsRequest.builder().distributionConfigWithTags(DistributionConfigWithTags.builder().distributionConfig(cfg.build()).tags(Tags.builder().items(software.amazon.awssdk.services.cloudfront.model.Tag.builder().key("lmaws_test").value(runId).build()).build()).build()).build();
        long deadline=System.nanoTime()+Duration.ofMinutes(5).toNanos();
        for(;;)try{return cloudfront.createDistributionWithTags(req).distribution();}
        catch(InvalidViewerCertificateException pending){if(certArn==null||System.nanoTime()>deadline)throw pending;sleep(5000);}
    }
    /** Static cache TTLs are bounded; API behaviours always stay uncached. */
    public void configureCache(String id,long ttl,long maxTtl) {
        if(ttl<0||ttl>300||maxTtl<ttl||maxTtl>3600)throw new IllegalArgumentException("cache TTL must be 0..300, max TTL between default and 3600");
        tagged(id);var g=dist(id);var config=g.distribution().distributionConfig();
        var def=config.defaultCacheBehavior();
        if(def.targetOriginId().startsWith("lambda-api-")&&ttl!=0)throw new SecurityException("API responses must remain uncached");
        var updated=config.toBuilder().defaultCacheBehavior(def.toBuilder().minTTL(0L).defaultTTL(ttl).maxTTL(maxTtl).build()).build();
        cloudfront.updateDistribution(x->x.id(id).ifMatch(g.eTag()).distributionConfig(updated));
    }
    private ViewerCertificate viewerCertificate(String alias,String arn) {
        if(!alias.equals("lmaws-site-"+runId+"."+domain))throw new SecurityException("certificate alias outside this run");
        var detail=certificate(arn);
        if(!alias.equals(detail.domainName())||!"ISSUED".equals(detail.statusAsString()))throw new IllegalStateException("current run certificate is not issued for this alias");
        if(acm.listTagsForCertificate(x->x.certificateArn(arn)).tags().stream().noneMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value())))throw new SecurityException("certificate tag mismatch");
        return ViewerCertificate.builder().acmCertificateArn(arn).sslSupportMethod(SSLSupportMethod.SNI_ONLY).minimumProtocolVersion(MinimumProtocolVersion.TLS_V1_2_2021).build();
    }
    public void attachCertificate(String id,String alias,String certArn,boolean redirect){if(!alias.equals("lmaws-site-"+runId+"."+domain))throw new SecurityException("alias outside this run");if(!("lmaws-site-"+runId+"."+domain).equals(certificate(certArn).domainName())||!"ISSUED".equalsIgnoreCase(certificate(certArn).statusAsString()))throw new IllegalStateException("ACM certificate is not ISSUED");tagged(id);var g=dist(id);var d=g.distribution();var c=d.distributionConfig().toBuilder().aliases(Aliases.builder().items(alias).quantity(1).build()).viewerCertificate(viewerCertificate(alias,certArn)).defaultCacheBehavior(d.distributionConfig().defaultCacheBehavior().toBuilder().viewerProtocolPolicy(redirect?ViewerProtocolPolicy.REDIRECT_TO_HTTPS:ViewerProtocolPolicy.ALLOW_ALL).build()).build();long deadline=System.nanoTime()+Duration.ofMinutes(5).toNanos();
        for(;;)try{cloudfront.updateDistribution(x->x.id(id).ifMatch(g.eTag()).distributionConfig(c));break;}
        catch(InvalidViewerCertificateException retry){if(System.nanoTime()>deadline)throw retry;sleep(15000);}
        waitDeployed(id,Duration.ofMinutes(25));}
    private software.amazon.awssdk.services.cloudfront.model.GetDistributionResponse dist(String id){return cloudfront.getDistribution(x->x.id(id));}
    private void tagged(String id){Distribution d=dist(id).distribution();if(cloudfront.listTagsForResource(x->x.resource(d.arn())).tags().items().stream().noneMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value())))throw new SecurityException("distribution is not owned by this run");}
    public void disableDistribution(String id){tagged(id);var g=dist(id);Distribution d=g.distribution();cloudfront.updateDistribution(x->x.id(id).ifMatch(g.eTag()).distributionConfig(d.distributionConfig().toBuilder().enabled(false).build()));waitDeployed(id,Duration.ofMinutes(25));}
    public void waitDeployed(String id,Duration timeout){long end=System.nanoTime()+timeout.toNanos();for(;;){if("Deployed".equalsIgnoreCase(dist(id).distribution().status()))return;if(System.nanoTime()>end)throw new IllegalStateException("CloudFront deployment timeout");sleep(15000);}}
    public void deleteDistribution(String id){tagged(id);var g=dist(id);if(g.distribution().distributionConfig().enabled())throw new IllegalStateException("distribution must be disabled");cloudfront.deleteDistribution(x->x.id(id).ifMatch(g.eTag()));}
    public String invalidate(String id){tagged(id);return cloudfront.createInvalidation(x->x.distributionId(id).invalidationBatch(InvalidationBatch.builder().callerReference(UUID.randomUUID().toString()).paths(Paths.builder().items("/*").quantity(1).build()).build())).invalidation().id();}
    public String requestCertificate(String fqdn){if(!fqdn.equals("lmaws-site-"+runId+"."+domain))throw new SecurityException("certificate outside this run");return acm.requestCertificate(RequestCertificateRequest.builder().domainName(fqdn).validationMethod(ValidationMethod.DNS).idempotencyToken(runId).tags(software.amazon.awssdk.services.acm.model.Tag.builder().key("lmaws_test").value(runId).build()).build()).certificateArn();}
    public CertificateDetail certificate(String arn){return acm.describeCertificate(x->x.certificateArn(arn)).certificate();}
    public CertificateDetail waitIssued(String arn,Duration timeout){long end=System.nanoTime()+timeout.toNanos();for(;;){CertificateDetail c=certificate(arn);String s=c.statusAsString();if("ISSUED".equalsIgnoreCase(s))return c;if(Set.of("FAILED","REVOKED","EXPIRED" ).contains(s))throw new IllegalStateException("ACM certificate status "+s);if(System.nanoTime()>end)throw new IllegalStateException("ACM issuance timeout");sleep(10000);}}
    public void deleteCertificate(String arn){if(acm.listTagsForCertificate(x->x.certificateArn(arn)).tags().stream().noneMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value())))throw new SecurityException("certificate is not owned by this run");acm.deleteCertificate(x->x.certificateArn(arn));}
    public void blockPublic(String bucket){taggedBucket(bucket);s3.putPublicAccessBlock(x->x.bucket(bucket).publicAccessBlockConfiguration(software.amazon.awssdk.services.s3.model.PublicAccessBlockConfiguration.builder().blockPublicAcls(true).ignorePublicAcls(true).blockPublicPolicy(true).restrictPublicBuckets(true).build()));}
    public void bucketPolicy(String bucket,String distributionArn){taggedBucket(bucket);if(distributionArn==null||!distributionArn.matches("arn:aws:cloudfront::[0-9]{12}:distribution/[A-Z0-9]+"))throw new SecurityException("invalid distribution ARN");String policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowCloudFront\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudfront.amazonaws.com\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::"+bucket+"/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\""+distributionArn+"\"}}}]}";s3.putBucketPolicy(x->x.bucket(bucket).policy(policy));}
    private void taggedBucket(String bucket){owned(bucket);if(s3.getBucketTagging(x->x.bucket(bucket)).tagSet().stream().noneMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value())))throw new SecurityException("bucket is not owned by this run");}
    public void createBucket(String bucket){owned(bucket);
        try{s3.headBucket(x->x.bucket(bucket));throw new SecurityException("bucket name already exists; refusing adoption");}
        catch(software.amazon.awssdk.services.s3.model.S3Exception e){if(e.statusCode()!=404)throw e;}
        s3.createBucket(x->x.bucket(bucket));s3.putBucketTagging(x->x.bucket(bucket).tagging(Tagging.builder().tagSet(software.amazon.awssdk.services.s3.model.Tag.builder().key("lmaws_test").value(runId).build()).build()));blockPublic(bucket);}
    public void upload(String bucket,String key,Path file){taggedBucket(bucket);if(key==null||key.contains(".."))throw new IllegalArgumentException("unsafe object key");String type=key.endsWith(".html")?"text/html":key.endsWith(".css")?"text/css":key.endsWith(".png")?"image/png":"application/octet-stream";s3.putObject(PutObjectRequest.builder().bucket(bucket).key(key).contentType(type).cacheControl("public,max-age=30").build(),RequestBody.fromFile(file));}
    public void emptyBucket(String bucket) {
        taggedBucket(bucket); String keyMarker=null,versionMarker=null;
        for(int page=0;page<100;page++) {
            var result=s3.listObjectVersions(ListObjectVersionsRequest.builder().bucket(bucket).keyMarker(keyMarker).versionIdMarker(versionMarker).maxKeys(1000).build());
            List<ObjectIdentifier> objects=new ArrayList<>();
            result.versions().forEach(v->objects.add(ObjectIdentifier.builder().key(v.key()).versionId(v.versionId()).build()));
            result.deleteMarkers().forEach(v->objects.add(ObjectIdentifier.builder().key(v.key()).versionId(v.versionId()).build()));
            for(int i=0;i<objects.size();i+=1000) {
                var deleted=s3.deleteObjects(DeleteObjectsRequest.builder().bucket(bucket).delete(Delete.builder().objects(objects.subList(i,Math.min(i+1000,objects.size()))).quiet(true).build()).build());
                if(!deleted.errors().isEmpty())throw new IllegalStateException("S3 object/version deletion was incomplete");
            }
            if(!Boolean.TRUE.equals(result.isTruncated()))return;
            keyMarker=result.nextKeyMarker();versionMarker=result.nextVersionIdMarker();
            if(keyMarker==null)throw new IllegalStateException("S3 truncated version listing has no cursor");
        }
        throw new IllegalStateException("S3 version cleanup exceeded 100 pages");
    }
    public void deleteBucket(String bucket){taggedBucket(bucket);emptyBucket(bucket);s3.deleteBucket(x->x.bucket(bucket));}
    public void ingress(String groupId,String cidr){WebStack.requireHttpCidr(cidr);
        var groups=ec2.describeSecurityGroups(x->x.groupIds(groupId)).securityGroups();
        if(groups.size()!=1||groups.get(0).tags().stream().noneMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value())))throw new SecurityException("ingress group is not owned by this run");
        ec2.authorizeSecurityGroupIngress(AuthorizeSecurityGroupIngressRequest.builder().groupId(groupId).ipPermissions(IpPermission.builder().ipProtocol("tcp").fromPort(80).toPort(80).ipRanges(IpRange.builder().cidrIp(cidr).description("lmweblab "+runId).build()).build()).build());}
    /** Read-only discovery; errors propagate so denial can never prove absence. */
    public List<Map<String,String>> recoverOwned() {
        List<Map<String,String>> out=new ArrayList<>();String bucket="lmaws-site-"+runId;
        for(var page:s3.listBucketsPaginator())for(var b:page.buckets())if(bucket.equals(b.name())) {
            boolean own;
            try{own=s3.getBucketTagging(x->x.bucket(b.name())).tagSet().stream().anyMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value()));}
            catch(software.amazon.awssdk.services.s3.model.S3Exception e){if(e.awsErrorDetails()!=null&&"NoSuchTagSet".equals(e.awsErrorDetails().errorCode()))own=false;else throw e;}
            Map<String,String> row=row("s3","bucket",b.name(),b.name());row.put("owned",String.valueOf(own));out.add(row);
        }
        int pages=0;
        for(var page:cloudfront.listDistributionsPaginator()) {
            if(++pages>100)throw new IllegalStateException("CloudFront discovery page limit");
            for(var d:page.distributionList().items())if(("lmweblab "+runId).equals(d.comment())) {
                Map<String,String> row=row("cloudfront","distribution",d.id(),d.id());row.put("arn",d.arn());row.put("cf_domain",d.domainName());row.put("status",d.status());
                row.put("owned",String.valueOf(cloudfront.listTagsForResource(x->x.resource(d.arn())).tags().items().stream().anyMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value()))));out.add(row);
            }
        }
        pages=0;for(var page:cloudfront.listOriginAccessControlsPaginator(x->{})){
            if(++pages>100)throw new IllegalStateException("OAC discovery page limit");
            for(var o:page.originAccessControlList().items())if(("lmaws-oac-"+runId).equals(o.name())){var row=row("cloudfront","oac",o.name(),o.id());row.put("owned",ownerProof==null?"unknown":String.valueOf(oacDescription().equals(o.description())));out.add(row);}
        }
        pages=0;for(var page:acm.listCertificatesPaginator()){
            if(++pages>100)throw new IllegalStateException("ACM discovery page limit");
            for(var cert:page.certificateSummaryList())if(("lmaws-site-"+runId+"."+domain).equals(cert.domainName())) {
                var row=row("acm","certificate",cert.domainName(),cert.certificateArn());row.put("status",certificate(cert.certificateArn()).statusAsString());
                row.put("owned",String.valueOf(acm.listTagsForCertificate(x->x.certificateArn(cert.certificateArn())).tags().stream().anyMatch(t->"lmaws_test".equals(t.key())&&runId.equals(t.value()))));out.add(row);
            }
        }
        var matchingZone=zones().stream().filter(z->(domain+".").equals(z.name())).findFirst();
        if(matchingZone.isEmpty())return out;
        String zone=matchingZone.get().id();pages=0;
        for(var page:route53.listResourceRecordSetsPaginator(x->x.hostedZoneId(zone))){
            if(++pages>100)throw new IllegalStateException("DNS discovery page limit");
            for(var record:page.resourceRecordSets()) {
                String n=stripDot(record.name());String site="lmaws-site-"+runId+"."+domain,app="lmaws-app-"+runId+"."+domain;
                if(n.equals(site)||n.equals(app)||(n.startsWith("_")&&n.endsWith("."+site))){var row=row("route53",record.typeAsString(),n,n);row.put("owned","true");out.add(row);}
                String weighted="lmaws-weighted-"+runId+"."+domain;
                if(n.equals(weighted)){
                    boolean expected=(record.type()==RRType.A&&(("static-"+runId).equals(record.setIdentifier())||("dynamic-"+runId).equals(record.setIdentifier())));
                    var row=row("route53","weighted-A",n,record.setIdentifier()==null?"":record.setIdentifier());row.put("owned",expected?(ownerProof==null?"unknown":"true"):"false");row.put("identifier",record.setIdentifier()==null?"":record.setIdentifier());row.put("weight",String.valueOf(record.weight()));out.add(row);
                }
            }
        }
        if(out.size()>10000)throw new IllegalStateException("web discovery resource limit");return out;
    }
    private static String stripDot(String value){return value.endsWith(".")?value.substring(0,value.length()-1):value;}
    private void recordName(String zone,String name,boolean validation) {
        String n=stripDot(name),site="lmaws-site-"+runId+"."+domain,app="lmaws-app-"+runId+"."+domain;
        if(domain==null || !(validation?n.matches("_[a-zA-Z0-9_-]+\\."+Pattern.quote(site)):n.equals(site)||n.equals(app)))throw new SecurityException("DNS name outside this run/domain");
        String zoneName=stripDot(route53.getHostedZone(x->x.id(zone)).hostedZone().name());
        if(!domain.equals(zoneName))throw new SecurityException("hosted zone domain mismatch");
    }
    private static Map<String,String> row(String service,String kind,String name,String id){Map<String,String> m=new LinkedHashMap<>();m.put("service",service);m.put("kind",kind);m.put("name",name);m.put("id",id);return m;}
    private static void sleep(long ms){try{Thread.sleep(ms);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}}
    @Override public void close(){route53.close();cloudfront.close();acm.close();s3.close();}
}
