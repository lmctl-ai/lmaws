// SPDX-License-Identifier: MIT

package aws

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lmctl-ai/lmcloud/hostkit"
)

func (r *remote) CreateBucket(ctx context.Context, name string) (bool, error) {
	r.recordCall("CreateBucket", true)
	cli := r.s3Client(ctx)

	// H3: In us-east-1, S3 CreateBucket on an already-owned bucket returns 200 OK
	// instead of 409 BucketAlreadyOwnedByYou. Probe HeadBucket first so
	// bucket_create returns false when the bucket already exists.
	//
	// H2: If HeadBucket returns 403 or 404, fall through to CreateBucket (PUT,
	// body-bearing) unless HeadBucket failed with a non-403/404 error (such as
	// 503 after retries).
	headErr := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, err := cli.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(name)})
		return err
	})
	if headErr == nil {
		return false, nil
	}
	if status, _ := extractHTTPResponse(headErr); status != http.StatusNotFound && status != http.StatusForbidden {
		return false, classify(headErr, scopeBucket)
	}

	in := &s3.CreateBucketInput{Bucket: aws.String(name)}
	if region := r.simRegion(); region != "" && region != defaultSimRegion {
		in.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(region),
		}
	}
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, cErr := cli.CreateBucket(ctx, in)
		return cErr
	})
	if err == nil {
		return true, nil
	}
	ce := classify(err, scopeBucket)
	if ce.ProviderCode == "BucketAlreadyOwnedByYou" {
		return false, nil
	}
	return false, ce
}

func (r *remote) DeleteBucket(ctx context.Context, name string) error {
	r.recordCall("DeleteBucket", true)
	cli := r.s3Client(ctx)
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, dErr := cli.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(name)})
		return dErr
	})
	if err == nil {
		return nil
	}
	ce := classify(err, scopeBucket)
	if ce.Code == hostkit.NotFound {
		return ce.WithAbsent(hostkit.AbsentBucket)
	}
	return ce
}

func (r *remote) HeadBucket(ctx context.Context, name string) error {
	r.recordCall("HeadBucket", false)
	cli := r.s3Client(ctx)
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, hErr := cli.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(name)})
		return hErr
	})
	if err == nil {
		return nil
	}
	status, _ := extractHTTPResponse(err)
	// H2: S3 HEAD has no response body on the wire. If HEAD returns 403 without
	// an explicit X-Amzn-Errortype header, issue a body-bearing GetBucketLocation
	// probe so UNAUTHENTICATED vs PERMISSION_DENIED is classified from the XML body
	// (and never mapped to exists == false).
	if status == http.StatusForbidden && !hasExplicitHeadAuthHeader(err) {
		probeErr := r.doAWS(ctx, true, func(ctx context.Context) error {
			_, pErr := cli.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(name)})
			return pErr
		})
		if probeErr != nil {
			if pce := classify(probeErr, scopeBucket); pce.Code == hostkit.Unauthenticated || pce.Code == hostkit.PermissionDenied {
				return pce
			}
		}
	}
	ce := classify(err, scopeBucket)
	if ce.Code == hostkit.NotFound {
		return ce.WithAbsent(hostkit.AbsentBucket)
	}
	return ce
}

func (r *remote) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	r.recordCall("ListBuckets", false)
	if token != "" {
		return nil, "", nil
	}
	cli := r.s3Client(ctx)
	var out *s3.ListBucketsOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListBuckets(ctx, &s3.ListBucketsInput{})
		return lErr
	})
	if err != nil {
		return nil, "", classify(err, scopeNone)
	}
	names := make([]string, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.Name != nil && *b.Name != "" {
			names = append(names, *b.Name)
		}
	}
	return names, "", nil
}

func (r *remote) PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (hostkit.ObjectMeta, error) {
	r.recordCall("PutObject", true)
	cli := r.s3Client(ctx)
	var out *s3.PutObjectOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var pErr error
		out, pErr = cli.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String(key),
			Body:        bytes.NewReader(body),
			ContentType: aws.String(contentType),
			Metadata:    metadata,
		})
		return pErr
	})
	if err != nil {
		return hostkit.ObjectMeta{}, classify(err, scopeObject)
	}
	etag := cleanETag(aws.ToString(out.ETag))
	metaCopy := make(map[string]string, len(metadata))
	for k, v := range metadata {
		metaCopy[k] = v
	}
	return hostkit.ObjectMeta{
		Exists:      true,
		Bucket:      bucket,
		Key:         key,
		Size:        int64(len(body)),
		ETag:        etag,
		ContentType: contentType,
		Metadata:    metaCopy,
	}, nil
}

func (r *remote) GetObject(ctx context.Context, bucket, key string, limit int64) ([]byte, error) {
	r.recordCall("GetObject", false)
	cli := r.s3Client(ctx)
	var data []byte
	var sizeErr error
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		out, gErr := cli.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if gErr != nil {
			return gErr
		}
		defer out.Body.Close()
		if limit > 0 && out.ContentLength != nil && *out.ContentLength > limit {
			sizeErr = &hostkit.CloudError{
				Code:    hostkit.Internal,
				Message: fmt.Sprintf("object %q (%d bytes) exceeds maximum size (%d bytes)", key, *out.ContentLength, limit),
			}
			return nil
		}
		var rErr *hostkit.CloudError
		data, rErr = hostkit.ReadBounded(out.Body, limit)
		if rErr != nil {
			sizeErr = rErr
			return nil
		}
		return nil
	})
	if sizeErr != nil {
		return nil, sizeErr
	}
	if err != nil {
		return nil, classify(err, scopeObject)
	}
	return data, nil
}

func (r *remote) HeadObject(ctx context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	r.recordCall("HeadObject", false)
	cli := r.s3Client(ctx)
	var out *s3.HeadObjectOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var hErr error
		out, hErr = cli.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		return hErr
	})
	if err != nil {
		status, _ := extractHTTPResponse(err)
		// H2: S3 HEAD has no body on 403. When X-Amzn-Errortype is absent,
		// issue a ranged GetObject probe (bytes=0-0) to classify the XML error
		// body into UNAUTHENTICATED vs PERMISSION_DENIED.
		if status == http.StatusForbidden && !hasExplicitHeadAuthHeader(err) {
			probeErr := r.doAWS(ctx, true, func(ctx context.Context) error {
				gOut, pErr := cli.GetObject(ctx, &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
					Range:  aws.String("bytes=0-0"),
				})
				if gOut != nil && gOut.Body != nil {
					_ = gOut.Body.Close()
				}
				return pErr
			})
			if probeErr != nil {
				if pce := classify(probeErr, scopeObject); pce.Code == hostkit.Unauthenticated || pce.Code == hostkit.PermissionDenied {
					return hostkit.ObjectMeta{}, pce
				}
			}
		}
		ce := classify(err, scopeObject)
		if ce.Code == hostkit.NotFound {
			if ce.Absent == hostkit.AbsentBucket {
				return hostkit.ObjectMeta{}, ce
			}
			// S3 HeadObject 404 has no XML body, so disambiguate missing key vs
			// missing bucket via HeadBucket.
			bErr := r.HeadBucket(ctx, bucket)
			if bErr != nil {
				if bce := classify(bErr, scopeBucket); bce.Code == hostkit.NotFound {
					return hostkit.ObjectMeta{}, &hostkit.CloudError{
						Code:         hostkit.NotFound,
						Message:      fmt.Sprintf("The specified bucket %q does not exist", bucket),
						ProviderCode: "NoSuchBucket",
						HTTPStatus:   http.StatusNotFound,
						Absent:       hostkit.AbsentBucket,
					}
				}
				return hostkit.ObjectMeta{}, bErr
			}
			return hostkit.ObjectMeta{}, ce.WithAbsent(hostkit.AbsentObject)
		}
		return hostkit.ObjectMeta{}, ce
	}

	var size int64
	if out.ContentLength != nil {
		size = *out.ContentLength
	}
	ct := aws.ToString(out.ContentType)
	if ct == "" {
		ct = "application/octet-stream"
	}
	meta := make(map[string]string, len(out.Metadata))
	for k, v := range out.Metadata {
		meta[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return hostkit.ObjectMeta{
		Exists:      true,
		Bucket:      bucket,
		Key:         key,
		Size:        size,
		ETag:        cleanETag(aws.ToString(out.ETag)),
		ContentType: ct,
		Metadata:    meta,
	}, nil
}

func (r *remote) DeleteObject(ctx context.Context, bucket, key string) error {
	r.recordCall("DeleteObject", true)
	cli := r.s3Client(ctx)
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, dErr := cli.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		return dErr
	})
	if err != nil {
		return classify(err, scopeObject)
	}
	return nil
}

func (r *remote) ListObjects(ctx context.Context, bucket, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	r.recordCall("ListObjects", false)
	cli := r.s3Client(ctx)
	in := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		MaxKeys: aws.Int32(int32(max)),
	}
	if prefix != "" {
		in.Prefix = aws.String(prefix)
	}
	if token != "" {
		in.ContinuationToken = aws.String(token)
	}
	var out *s3.ListObjectsV2Output
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListObjectsV2(ctx, in)
		return lErr
	})
	if err != nil {
		return hostkit.ObjectPage{}, classify(err, scopeBucket)
	}
	items := make([]hostkit.ObjectSummary, 0, len(out.Contents))
	for _, obj := range out.Contents {
		if obj.Key == nil || obj.Size == nil {
			return hostkit.ObjectPage{}, &hostkit.CloudError{
				Code:    hostkit.Internal,
				Message: "s3 ListObjectsV2 item missing required Key or Size field",
			}
		}
		items = append(items, hostkit.ObjectSummary{
			Key:  *obj.Key,
			Size: *obj.Size,
			ETag: cleanETag(aws.ToString(obj.ETag)),
		})
	}
	var next string
	if aws.ToBool(out.IsTruncated) {
		next = aws.ToString(out.NextContinuationToken)
		if next == "" && len(items) > 0 {
			next = items[len(items)-1].Key
		}
	}
	return hostkit.ObjectPage{
		Items:     items,
		NextToken: next,
	}, nil
}

func cleanETag(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "W/")
	s = strings.Trim(s, `"`)
	return s
}
