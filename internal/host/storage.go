package host

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/lmctl-ai/lmaws/internal/membudget"
)

func (h *Host) BucketCreate(bucket string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateBucketName(bucket); cerr != nil {
		return false, h.finishErrorLocked("bucket_create", bucket, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return false, h.finishErrorLocked("bucket_create", bucket, cerr)
	}

	if h.storageEndpoint == "" {
		if _, exists := h.buckets[bucket]; exists {
			h.finishOKLocked()
			return false, nil
		}
		h.buckets[bucket] = &fakeBucket{objects: make(map[string]*fakeObject)}
		h.ledger.Record("bucket", bucket)
		h.finishOKLocked()
		return true, nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	// H3: S3 us-east-1 CreateBucket returns 200 OK when re-creating an owned bucket.
	// Probe with HeadBucket first so bucket_create returns false on existing buckets.
	// H2: If HeadBucket returns 403, fall through to CreateBucket (body-bearing PUT)
	// so InvalidAccessKeyId / SignatureDoesNotMatch (UNAUTHENTICATED) vs AccessDenied (PERMISSION_DENIED)
	// is classified from the XML error body.
	_, headErr := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if headErr == nil {
		h.finishOKLocked()
		return false, nil
	}
	headCerr := classifyAWSError(headErr)
	if headCerr.Code != CodeNotFound && headCerr.HTTPStatus != 404 && headCerr.HTTPStatus != 403 {
		return false, h.finishErrorLocked("bucket_create", bucket, headCerr)
	}

	_, createErr := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	if createErr != nil {
		cerr := classifyAWSError(createErr)
		if cerr.Code == CodeAlreadyExists {
			h.finishOKLocked()
			return false, nil
		}
		return false, h.finishErrorLocked("bucket_create", bucket, cerr)
	}

	h.ledger.Record("bucket", bucket)
	h.finishOKLocked()
	return true, nil
}

func (h *Host) BucketDelete(bucket string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateBucketName(bucket); cerr != nil {
		return false, h.finishErrorLocked("bucket_delete", bucket, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return false, h.finishErrorLocked("bucket_delete", bucket, cerr)
	}

	if h.storageEndpoint == "" {
		b, exists := h.buckets[bucket]
		if !exists {
			h.finishOKLocked()
			return false, nil
		}
		if len(b.objects) > 0 {
			return false, h.finishErrorLocked("bucket_delete", bucket,
				newCloudError(CodeConflict, 409, "BucketNotEmpty", fmt.Sprintf("bucket %q is not empty", bucket)))
		}
		delete(h.buckets, bucket)
		h.ledger.Remove("bucket", bucket)
		h.finishOKLocked()
		return true, nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	// Pre-flight non-empty check (and existence probe).
	listOut, listErr := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		MaxKeys: aws.Int32(1),
	})
	if listErr != nil {
		cerr := classifyAWSError(listErr)
		if cerr.Code == CodeNotFound {
			h.finishOKLocked()
			return false, nil
		}
		return false, h.finishErrorLocked("bucket_delete", bucket, cerr)
	}
	if len(listOut.Contents) > 0 {
		return false, h.finishErrorLocked("bucket_delete", bucket,
			newCloudError(CodeConflict, 409, "BucketNotEmpty", fmt.Sprintf("bucket %q is not empty", bucket)))
	}

	_, delErr := s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
	if delErr != nil {
		cerr := classifyAWSError(delErr)
		if cerr.Code == CodeNotFound {
			h.finishOKLocked()
			return false, nil
		}
		return false, h.finishErrorLocked("bucket_delete", bucket, cerr)
	}

	h.ledger.Remove("bucket", bucket)
	h.finishOKLocked()
	return true, nil
}

func (h *Host) BucketExists(bucket string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateBucketName(bucket); cerr != nil {
		return false, h.finishErrorLocked("bucket_exists", bucket, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return false, h.finishErrorLocked("bucket_exists", bucket, cerr)
	}

	if h.storageEndpoint == "" {
		_, exists := h.buckets[bucket]
		h.finishOKLocked()
		return exists, nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		cerr := classifyAWSError(err)
		if cerr.Code == CodeNotFound || cerr.HTTPStatus == 404 {
			h.finishOKLocked()
			return false, nil
		}
		return false, h.finishErrorLocked("bucket_exists", bucket, cerr)
	}

	h.finishOKLocked()
	return true, nil
}

func (h *Host) BucketList() ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return nil, h.finishErrorLocked("bucket_list", "", cerr)
	}

	if h.storageEndpoint == "" {
		names := make([]string, 0, len(h.buckets))
		for name := range h.buckets {
			names = append(names, name)
		}
		sort.Strings(names)
		h.finishOKLocked()
		return names, nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	out, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		cerr := classifyAWSError(err)
		return nil, h.finishErrorLocked("bucket_list", "", cerr)
	}

	names := make([]string, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.Name != nil {
			names = append(names, *b.Name)
		}
	}
	sort.Strings(names)
	h.finishOKLocked()
	return names, nil
}

func (h *Host) ObjectPut(bucket, key, body, contentType string, metadata map[string]string) (*ObjectMeta, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	target := bucket + "/" + key
	if cerr := ValidateBucketName(bucket); cerr != nil {
		return nil, h.finishErrorLocked("object_put", target, cerr)
	}
	if cerr := ValidateObjectKey(key); cerr != nil {
		return nil, h.finishErrorLocked("object_put", target, cerr)
	}
	if cerr := ValidateContentType(contentType); cerr != nil {
		return nil, h.finishErrorLocked("object_put", target, cerr)
	}
	if cerr := ValidateMetadata(metadata); cerr != nil {
		return nil, h.finishErrorLocked("object_put", target, cerr)
	}
	if len(body) > MaxObjectBodyBytes {
		return nil, h.finishErrorLocked("object_put", target,
			newCloudError(CodeInvalidArgument, 0, "EntityTooLarge",
				fmt.Sprintf("object body size %d exceeds 33554432 bytes (32 MiB)", len(body))))
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return nil, h.finishErrorLocked("object_put", target, cerr)
	}

	bodyBytes := []byte(body)
	if err := membudget.Charge(int64(len(bodyBytes))); err != nil {
		return nil, err
	}
	defer membudget.Release(int64(len(bodyBytes)))

	copiedMeta := make(map[string]string, len(metadata))
	for k, v := range metadata {
		copiedMeta[k] = v
	}

	if h.storageEndpoint == "" {
		b, exists := h.buckets[bucket]
		if !exists {
			return nil, h.finishErrorLocked("object_put", target,
				newCloudError(CodeNotFound, 404, "NoSuchBucket", fmt.Sprintf("bucket %q does not exist", bucket)))
		}
		etag := computeSHA256Hex(bodyBytes)
		b.objects[key] = &fakeObject{
			body:        bodyBytes,
			etag:        etag,
			contentType: contentType,
			metadata:    copiedMeta,
		}
		h.finishOKLocked()
		return &ObjectMeta{
			Exists:      true,
			Bucket:      bucket,
			Key:         key,
			Size:        int64(len(bodyBytes)),
			ETag:        etag,
			ContentType: contentType,
			Metadata:    copiedMeta,
		}, nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	out, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(bodyBytes),
		ContentLength: aws.Int64(int64(len(bodyBytes))),
		ContentType:   aws.String(contentType),
		Metadata:      copiedMeta,
	})
	if err != nil {
		cerr := classifyAWSError(err)
		return nil, h.finishErrorLocked("object_put", target, cerr)
	}

	etag := NormalizeETag(aws.ToString(out.ETag))
	if etag == "" {
		etag = computeSHA256Hex(bodyBytes)
	}

	h.finishOKLocked()
	return &ObjectMeta{
		Exists:      true,
		Bucket:      bucket,
		Key:         key,
		Size:        int64(len(bodyBytes)),
		ETag:        etag,
		ContentType: contentType,
		Metadata:    copiedMeta,
	}, nil
}

func (h *Host) ObjectGet(bucket, key string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	target := bucket + "/" + key
	if cerr := ValidateBucketName(bucket); cerr != nil {
		return "", h.finishErrorLocked("object_get", target, cerr)
	}
	if cerr := ValidateObjectKey(key); cerr != nil {
		return "", h.finishErrorLocked("object_get", target, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return "", h.finishErrorLocked("object_get", target, cerr)
	}

	if h.storageEndpoint == "" {
		b, exists := h.buckets[bucket]
		if !exists {
			return "", h.finishErrorLocked("object_get", target,
				newCloudError(CodeNotFound, 404, "NoSuchBucket", fmt.Sprintf("bucket %q does not exist", bucket)))
		}
		obj, ok := b.objects[key]
		if !ok {
			return "", h.finishErrorLocked("object_get", target,
				newCloudError(CodeNotFound, 404, "NoSuchKey", fmt.Sprintf("object %q does not exist in bucket %q", key, bucket)))
		}
		if err := membudget.Charge(int64(len(obj.body))); err != nil {
			return "", err
		}
		defer membudget.Release(int64(len(obj.body)))
		h.finishOKLocked()
		return string(obj.body), nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		cerr := classifyAWSError(err)
		return "", h.finishErrorLocked("object_get", target, cerr)
	}
	defer func() {
		if out.Body != nil {
			_ = out.Body.Close()
		}
	}()

	contentLen := aws.ToInt64(out.ContentLength)
	if contentLen > MaxObjectBodyBytes {
		return "", h.finishErrorLocked("object_get", target,
			newCloudError(CodeInvalidArgument, 0, "EntityTooLarge",
				fmt.Sprintf("object body size %d exceeds 33554432 bytes (32 MiB)", contentLen)))
	}
	if contentLen > 0 {
		if err := membudget.Require(contentLen); err != nil {
			return "", err
		}
	}

	data, readErr := io.ReadAll(io.LimitReader(out.Body, MaxObjectBodyBytes+1))
	if readErr != nil {
		return "", h.finishErrorLocked("object_get", target,
			newCloudError(CodeUnavailable, 0, "ReadError", readErr.Error()))
	}
	if len(data) > MaxObjectBodyBytes {
		return "", h.finishErrorLocked("object_get", target,
			newCloudError(CodeInvalidArgument, 0, "EntityTooLarge", "object body exceeds 32 MiB"))
	}
	if err := membudget.Charge(int64(len(data))); err != nil {
		return "", err
	}
	defer membudget.Release(int64(len(data)))

	h.finishOKLocked()
	return string(data), nil
}

func (h *Host) ObjectHead(bucket, key string) (*ObjectMeta, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	target := bucket + "/" + key
	if cerr := ValidateBucketName(bucket); cerr != nil {
		return nil, h.finishErrorLocked("object_head", target, cerr)
	}
	if cerr := ValidateObjectKey(key); cerr != nil {
		return nil, h.finishErrorLocked("object_head", target, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return nil, h.finishErrorLocked("object_head", target, cerr)
	}

	if h.storageEndpoint == "" {
		b, exists := h.buckets[bucket]
		if !exists {
			return notFoundObjectMeta(bucket, key), h.finishErrorLocked("object_head", target,
				newCloudError(CodeNotFound, 404, "NoSuchBucket", fmt.Sprintf("bucket %q does not exist", bucket)))
		}
		obj, ok := b.objects[key]
		if !ok {
			h.finishOKLocked()
			return notFoundObjectMeta(bucket, key), nil
		}
		copiedMeta := make(map[string]string, len(obj.metadata))
		for k, v := range obj.metadata {
			copiedMeta[k] = v
		}
		h.finishOKLocked()
		return &ObjectMeta{
			Exists:      true,
			Bucket:      bucket,
			Key:         key,
			Size:        int64(len(obj.body)),
			ETag:        obj.etag,
			ContentType: obj.contentType,
			Metadata:    copiedMeta,
		}, nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	out, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		cerr := classifyAWSError(err)
		if cerr.Code == CodeNotFound || cerr.HTTPStatus == 404 {
			// S3 HEAD 404 has no body; probe HeadBucket to distinguish missing key in existing bucket
			// (Exists: false, ErrorCode.OK) from missing bucket (ErrorCode.NOT_FOUND).
			_, hbErr := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
				Bucket: aws.String(bucket),
			})
			if hbErr == nil {
				h.finishOKLocked()
				return notFoundObjectMeta(bucket, key), nil
			}
			hbCerr := classifyAWSError(hbErr)
			if hbCerr.Code == CodeNotFound || hbCerr.HTTPStatus == 404 {
				return notFoundObjectMeta(bucket, key), h.finishErrorLocked("object_head", target,
					newCloudError(CodeNotFound, 404, "NoSuchBucket", fmt.Sprintf("bucket %q does not exist", bucket)))
			}
			return notFoundObjectMeta(bucket, key), h.finishErrorLocked("object_head", target, hbCerr)
		}
		return notFoundObjectMeta(bucket, key), h.finishErrorLocked("object_head", target, cerr)
	}

	metaMap := make(map[string]string, len(out.Metadata))
	for k, v := range out.Metadata {
		metaMap[strings.ToLower(k)] = v
	}
	ct := aws.ToString(out.ContentType)
	if ct == "" {
		ct = "application/octet-stream"
	}

	h.finishOKLocked()
	return &ObjectMeta{
		Exists:      true,
		Bucket:      bucket,
		Key:         key,
		Size:        aws.ToInt64(out.ContentLength),
		ETag:        NormalizeETag(aws.ToString(out.ETag)),
		ContentType: ct,
		Metadata:    metaMap,
	}, nil
}

func (h *Host) ObjectDelete(bucket, key string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	target := bucket + "/" + key
	if cerr := ValidateBucketName(bucket); cerr != nil {
		return h.finishErrorLocked("object_delete", target, cerr)
	}
	if cerr := ValidateObjectKey(key); cerr != nil {
		return h.finishErrorLocked("object_delete", target, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return h.finishErrorLocked("object_delete", target, cerr)
	}

	if h.storageEndpoint == "" {
		b, exists := h.buckets[bucket]
		if !exists {
			return h.finishErrorLocked("object_delete", target,
				newCloudError(CodeNotFound, 404, "NoSuchBucket", fmt.Sprintf("bucket %q does not exist", bucket)))
		}
		delete(b.objects, key)
		h.finishOKLocked()
		return nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	_, err := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		cerr := classifyAWSError(err)
		if cerr.ProviderCode == "NoSuchKey" {
			h.finishOKLocked()
			return nil
		}
		return h.finishErrorLocked("object_delete", target, cerr)
	}

	h.finishOKLocked()
	return nil
}

func (h *Host) ObjectList(bucket, prefix string, maxKeys int64, pageToken string) (*ObjectListPage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateBucketName(bucket); cerr != nil {
		return nil, h.finishErrorLocked("object_list", bucket, cerr)
	}
	if cerr := ValidateListPrefix(prefix); cerr != nil {
		return nil, h.finishErrorLocked("object_list", bucket, cerr)
	}
	if cerr := ValidateMaxKeys(maxKeys); cerr != nil {
		return nil, h.finishErrorLocked("object_list", bucket, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return nil, h.finishErrorLocked("object_list", bucket, cerr)
	}

	if maxKeys == 0 {
		h.finishOKLocked()
		return emptyObjectListPage(), nil
	}

	allItems, cerr := h.fetchAllMatchingObjectsLocked(bucket, prefix)
	if cerr != nil {
		return nil, h.finishErrorLocked("object_list", bucket, cerr)
	}

	startIdx := 0
	if pageToken != "" {
		startIdx = sort.Search(len(allItems), func(i int) bool {
			return allItems[i].Key > pageToken
		})
	}
	if startIdx >= len(allItems) {
		h.finishOKLocked()
		return emptyObjectListPage(), nil
	}

	endIdx := startIdx + int(maxKeys)
	hasMore := false
	nextToken := ""
	if endIdx < len(allItems) {
		hasMore = true
		nextToken = allItems[endIdx-1].Key
	} else {
		endIdx = len(allItems)
	}

	pageItems := allItems[startIdx:endIdx]
	h.finishOKLocked()
	return &ObjectListPage{
		Items:     pageItems,
		HasMore:   hasMore,
		NextToken: nextToken,
	}, nil
}

func (h *Host) ObjectListAll(bucket, prefix string) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateBucketName(bucket); cerr != nil {
		return nil, h.finishErrorLocked("object_list_all", bucket, cerr)
	}
	if cerr := ValidateListPrefix(prefix); cerr != nil {
		return nil, h.finishErrorLocked("object_list_all", bucket, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.storageEndpoint); cerr != nil {
		return nil, h.finishErrorLocked("object_list_all", bucket, cerr)
	}

	allItems, cerr := h.fetchAllMatchingObjectsLocked(bucket, prefix)
	if cerr != nil {
		return nil, h.finishErrorLocked("object_list_all", bucket, cerr)
	}

	keys := make([]string, len(allItems))
	for i, item := range allItems {
		keys[i] = item.Key
	}
	h.finishOKLocked()
	return keys, nil
}

func (h *Host) fetchAllMatchingObjectsLocked(bucket, prefix string) ([]*ObjectSummary, *CloudError) {
	if h.storageEndpoint == "" {
		b, exists := h.buckets[bucket]
		if !exists {
			return nil, newCloudError(CodeNotFound, 404, "NoSuchBucket", fmt.Sprintf("bucket %q does not exist", bucket))
		}
		var items []*ObjectSummary
		for k, obj := range b.objects {
			if prefix == "" || strings.HasPrefix(k, prefix) {
				items = append(items, &ObjectSummary{
					Key:  k,
					Size: int64(len(obj.body)),
					ETag: obj.etag,
				})
			}
		}
		sort.Slice(items, func(i, j int) bool {
			return items[i].Key < items[j].Key
		})
		return items, nil
	}

	ctx := context.Background()
	s3Client := h.newS3ClientLocked()

	var items []*ObjectSummary
	var contToken *string
	for {
		req := &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			MaxKeys:           aws.Int32(1000),
			ContinuationToken: contToken,
		}
		if prefix != "" {
			req.Prefix = aws.String(prefix)
		}
		out, err := s3Client.ListObjectsV2(ctx, req)
		if err != nil {
			return nil, classifyAWSError(err)
		}
		for _, o := range out.Contents {
			if o.Key == nil {
				continue
			}
			items = append(items, &ObjectSummary{
				Key:  *o.Key,
				Size: aws.ToInt64(o.Size),
				ETag: NormalizeETag(aws.ToString(o.ETag)),
			})
		}
		if !aws.ToBool(out.IsTruncated) || out.NextContinuationToken == nil || *out.NextContinuationToken == "" {
			break
		}
		contToken = out.NextContinuationToken
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Key < items[j].Key
	})
	return items, nil
}
