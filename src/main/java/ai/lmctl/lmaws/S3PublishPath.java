package ai.lmctl.lmaws;

import io.lmctl.lmcode.Json;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.kms.model.*;
import java.util.*;

/** Read-only metadata and explicitly scoped policy evidence, never a synthetic PUT verdict. */
final class S3PublishPath {
    private S3PublishPath() {}

    static List<Map<String,String>> inspect(AwsBackend backend,String bucket,String key,String inline) {
        if(bucket==null || !bucket.matches("[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")) throw new IllegalArgumentException("invalid bucket");
        if(key==null || key.isBlank() || key.length()>1024 || key.startsWith("/")) throw new IllegalArgumentException("invalid object key");
        if(inline==null || inline.length()>65536) throw new IllegalArgumentException("inline policy exceeds diagnostic bound");
        List<Map<String,String>> out=new ArrayList<>();
        if(backend.isDemo()) {
            for(String layer:List.of("session_policy","identity","bucket_policy","encryption","kms","ownership","public_access_block"))
                out.add(row("bucket",bucket,"layer",layer,"status","unknown: needs real read-only metadata","detail","Demo mode does not inspect a production bucket."));
            return out;
        }
        String account="", principal="";
        try {
            var caller=backend.publishPathIdentity();account=caller.account();principal=caller.arn().contains(":assumed-role/")?"":caller.arn();Jsons.knownAccount(account);
            out.add(row("bucket",bucket,"layer","identity","status","unknown: needs issuer identity-policy and SCP evaluation","caller",mask(caller.arn()),"principal_context",principal.isBlank()?"unknown: needs iam:GetRole to resolve the IAM role ARN":"known federated-user/IAM principal ARN","detail","sts:GetCallerIdentity succeeded. It establishes the caller, not effective PutObject permission. Reading issuer policies (for example iam:GetPolicyVersion) and organization policies is a separate prerequisite."));
        } catch(Exception e) {
            out.add(row("bucket",bucket,"layer","identity","status",unknown(e,"sts:GetCallerIdentity"),"detail","Caller account and principal context remain unknown."));
        }
        String expectedOwner=account.isBlank()?null:account;
        String object="arn:aws:s3:::"+bucket+"/"+key;
        boolean ownerVerified=false;
        try {
            String policy=backend.s3Client().getBucketPolicy(GetBucketPolicyRequest.builder().bucket(bucket).expectedBucketOwner(expectedOwner).build()).policy();
            ownerVerified=expectedOwner!=null;
            // S3 returns JSON, not a form-encoded IAM document: preserve literal '+' and '%'.
            out.addAll(S3PathPolicies.bucket(policy,object,principal,account));
        } catch(Exception e) {
            if(code(e).equals("NoSuchBucketPolicy")) {
                ownerVerified=expectedOwner!=null;
                out.add(row("layer","bucket_policy","status","allowed","detail","No bucket policy exists; this layer adds no resource-policy Deny. Identity/session/SCP permissions still apply."));
            } else out.add(row("layer","bucket_policy","status",unknown(e,"s3:GetBucketPolicy"),"detail","No inference from an unreadable policy; 403 may also indicate expected-owner mismatch."));
        }
        String algorithm="", kmsId="";boolean bucketKey=false;
        try {
            var encryption=backend.s3Client().getBucketEncryption(GetBucketEncryptionRequest.builder().bucket(bucket).expectedBucketOwner(expectedOwner).build());
            ownerVerified|=expectedOwner!=null;
            var rules=encryption.serverSideEncryptionConfiguration().rules();
            if(!rules.isEmpty() && rules.get(0).applyServerSideEncryptionByDefault()!=null) {
                var defaults=rules.get(0).applyServerSideEncryptionByDefault();algorithm=defaults.sseAlgorithmAsString();
                kmsId=Objects.toString(defaults.kmsMasterKeyID(),"");bucketKey=Boolean.TRUE.equals(rules.get(0).bucketKeyEnabled());
                out.add(row("layer","encryption","status",algorithm.equals("AES256")?"allowed":"unknown: needs KMS authorization evaluation","algorithm",algorithm,"kms_key",maskedKey(kmsId),"bucket_key_enabled",String.valueOf(bucketKey),"detail",algorithm.equals("AES256")?"SSE-S3 default; a plain PUT needs no KMS action. Explicit encryption headers can change the path.":"SSE-KMS default identified; metadata is not an authorization grant. Explicit encryption headers may select a different key."));
            } else out.add(row("layer","encryption","status","unknown: needs readable default encryption configuration","detail","The metadata response contained no encryption rule."));
        } catch(Exception e) {out.add(row("layer","encryption","status",unknown(e,"s3:GetEncryptionConfiguration")));}

        try {
            var controls=backend.s3Client().getBucketOwnershipControls(GetBucketOwnershipControlsRequest.builder().bucket(bucket).expectedBucketOwner(expectedOwner).build()).ownershipControls();
            ownerVerified|=expectedOwner!=null;
            String mode=controls.rules().isEmpty()?"unknown":controls.rules().get(0).objectOwnershipAsString();
            out.add(row("layer","ownership","status",mode.equals("unknown")?"unknown: needs ownership mode":"allowed","object_ownership",mode,"detail",mode.equals("BucketOwnerEnforced")?"ACLs are disabled. Omit ACL headers for a plain PUT. Unsupported ACLs fail; an uploader sending ACL headers may also require PutObjectAcl, which the supplied session may deny.":"ACLs may be enabled. A plain PUT does not automatically require PutObjectAcl. Bucket-owner-preferred cross-account ownership may need bucket-owner-full-control; inspect bucket-policy ACL conditions and the actual request."));
        } catch(Exception e) {
            if(code(e).equals("OwnershipControlsNotFoundError")) {
                ownerVerified|=expectedOwner!=null;
                out.add(row("layer","ownership","status","allowed","object_ownership","ObjectWriter (legacy, no ownership controls)","detail","ACL-enabled legacy mode; no ACL action is needed for an ACL-free PUT. Request and bucket-policy ACL requirements still matter."));
            } else out.add(row("layer","ownership","status",unknown(e,"s3:GetOwnershipControls")));
        }
        try {
            var flags=backend.s3Client().getPublicAccessBlock(GetPublicAccessBlockRequest.builder().bucket(bucket).expectedBucketOwner(expectedOwner).build()).publicAccessBlockConfiguration();
            ownerVerified|=expectedOwner!=null;
            out.add(row("layer","public_access_block","status","allowed","block_public_acls",String.valueOf(flags.blockPublicAcls()),"ignore_public_acls",String.valueOf(flags.ignorePublicAcls()),"block_public_policy",String.valueOf(flags.blockPublicPolicy()),"restrict_public_buckets",String.valueOf(flags.restrictPublicBuckets()),"detail","Bucket settings read. These flags do not by themselves grant or deny an ordinary same-account private, ACL-free PUT. Public ACLs/cross-account paths can be blocked. Account-level BPA is not evaluated."));
        } catch(Exception e) {
            if(code(e).equals("NoSuchPublicAccessBlockConfiguration")) {
                ownerVerified|=expectedOwner!=null;
                out.add(row("layer","public_access_block","status","allowed","detail","No bucket-level BPA configuration; account-level settings remain unevaluated."));
            } else out.add(row("layer","public_access_block","status",unknown(e,"s3:GetPublicAccessBlock")));
        }
        if(ownerVerified && !account.isBlank()) {
            out.add(row("layer","session_policy","status",S3PathPolicies.session(inline,"s3:PutObject",object,Map.of("s3:ResourceAccount",account,"aws:ResourceAccount",account,"aws:PrincipalAccount",account,"aws:PrincipalArn",principal,"aws:SecureTransport","true","aws:RequestedRegion",backend.region())),"detail","Supplied inline document only; expected-owner metadata read established bucket account. Attached managed session policies, issuer policies and SCPs are not evaluated."));
        } else out.add(row("layer","session_policy","status","unknown: needs verified s3:ResourceAccount bucket ownership context","detail","Caller identity alone does not establish bucket ownership. An unreadable metadata layer is not evidence of a successful production write."));

        if(algorithm.equals("AES256")) out.add(row("layer","kms","status","allowed","detail","SSE-S3 does not require KMS; caller-specified SSE-KMS headers would need a separate check."));
        else if(algorithm.equals("aws:kms") || algorithm.equals("aws:kms:dsse")) {
            inspectKms(backend,out,kmsId.isBlank()?"alias/aws/s3":kmsId,account,bucket,key,bucketKey,inline);
        } else out.add(row("layer","kms","status","unknown: needs s3:GetEncryptionConfiguration to determine KMS requirements"));
        out.add(row("layer","request_requirements","status","unknown: needs uploader flags and workflow","detail","Plain ACL-free, untagged PUT: s3:PutObject. ACL headers: s3:PutObjectAcl (check the session Deny); tags: s3:PutObjectTagging. Sync/listing: s3:ListBucket. List pending multipart uploads: s3:ListBucketMultipartUploads; list upload parts: s3:ListMultipartUploadParts; abort: s3:AbortMultipartUpload. Ownership mode alone does not require tagging/list actions. SSE-KMS PUT needs GenerateDataKey; multipart/read may also need Decrypt."));
        for(var row:out) {row.putIfAbsent("bucket",bucket);String status=row.getOrDefault("status","");if(status.startsWith("allowed:")){row.put("status","allowed");row.put("detail",row.getOrDefault("detail","")+" "+status.substring(8));}row.replaceAll((k,v)->mask(v));}
        return out;
    }

    private static void inspectKms(AwsBackend backend,List<Map<String,String>> out,String id,String account,String bucket,String key,boolean bucketKey,String inline) {
        String arn="",state="";boolean keyReadable=false;String missing="";
        try {
            var metadata=backend.kmsClient().describeKey(DescribeKeyRequest.builder().keyId(id).build()).keyMetadata();
            arn=Objects.toString(metadata.arn(),"");state=Objects.toString(metadata.keyStateAsString(),"");
            out.add(row("layer","kms_key","status",state.equals("Enabled")?"allowed":"denied: KMS key is "+state,"key",maskedKey(arn.isBlank()?id:arn),"key_state",state,"detail","DescribeKey readability and key state only; this does not prove permission to encrypt."));
        } catch(Exception e) {missing=unknown(e,"kms:DescribeKey");out.add(row("layer","kms_key","status",missing,"key",maskedKey(id)));}
        try {
            String policy=backend.kmsClient().getKeyPolicy(GetKeyPolicyRequest.builder().keyId(arn.isBlank()?id:arn).policyName("default").build()).policy();
            Json.parse(policy);keyReadable=true;
            out.add(row("layer","kms_key_policy","status","unknown: needs effective key-policy principal, identity and grant evaluation","policy_readable","true","detail","kms:GetKeyPolicy succeeded; a readable key policy does not prove this session can use the key. Key grants, IAM policies and SCPs remain unevaluated."));
        } catch(Exception e) {out.add(row("layer","kms_key_policy","status",unknown(e,"kms:GetKeyPolicy"),"policy_readable","false"));}
        String context=bucketKey?"arn:aws:s3:::"+bucket:"arn:aws:s3:::"+bucket+"/"+key;
        boolean explicitDeny=false;
        for(String action:List.of("kms:GenerateDataKey","kms:Decrypt")) {
            String status;
            if(account.isBlank()) status="unknown: needs sts:GetCallerIdentity for kms:CallerAccount";
            else if(!arn.startsWith("arn:")) status="unknown: needs kms:DescribeKey resolved key ARN";
            else status=S3PathPolicies.session(inline,action,arn,Map.of("aws:PrincipalAccount",account,"kms:CallerAccount",account,"kms:ViaService","s3."+backend.region()+".amazonaws.com","kms:EncryptionContext:aws:s3:arn",context));
            explicitDeny|=status.startsWith("denied:") && status.toLowerCase(Locale.ROOT).contains("explicit");
            out.add(row("layer","kms_session_policy","action",action,"status",status,"key",maskedKey(arn.isBlank()?id:arn),"encryption_context",context,"via_service","s3."+backend.region()+".amazonaws.com","caller_account",mask(account),"detail","Inline policy only. Context uses the bucket ARN with Bucket Keys, otherwise the object ARN; managed session policies are not evaluated."));
        }
        String verdict=explicitDeny?"denied: explicit inline session Deny for required KMS operation":!state.isBlank()&&!state.equals("Enabled")?"denied: KMS key is "+state:!missing.isBlank()?missing:!keyReadable?"unknown: needs kms:GetKeyPolicy":"unknown: needs effective KMS key-policy, grants, issuer and SCP evaluation";
        out.add(row("layer","kms","status",verdict,"key",maskedKey(arn.isBlank()?id:arn),"detail","GenerateDataKey is needed for SSE-KMS PUT; Decrypt is relevant to multipart/read workflows. No GenerateDataKey, Decrypt or encryption operation was called."));
    }
    static String unknown(Exception e,String action) {return "unknown: needs "+action+" ("+code(e)+")";}
    static String code(Exception e) {return e instanceof AwsServiceException aws && aws.awsErrorDetails()!=null?Objects.toString(aws.awsErrorDetails().errorCode(),aws.getClass().getSimpleName()):e.getClass().getSimpleName();}
    static String mask(String value) {return value==null?"":Jsons.mask(value).replaceAll("(?<![0-9])[0-9]{12}(?![0-9])","************").replaceAll("[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}","[masked-id]").replaceAll("alias/[A-Za-z0-9_./-]+","alias/[masked]");}
    static String maskedKey(String value) {return value==null||value.isBlank()?"":value.startsWith("arn:")?mask(value).replaceAll("(:(?:key|alias)/).*","$1[masked]"):"[masked-key]";}
    static Map<String,String> row(String... fields) {Map<String,String> row=new LinkedHashMap<>();for(int i=0;i+1<fields.length;i+=2)row.put(fields[i],fields[i+1]);return row;}
}
