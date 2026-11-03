// SPDX-License-Identifier: MIT

package aws

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/lmctl-ai/lmcloud/hostkit"
)

const (
	defaultSimRegion    = "us-east-1"
	defaultSimAccessKey = "test"
	defaultSimSecretKey = "test"
)

type remote struct {
	mu           sync.Mutex
	client       *http.Client
	retry        hostkit.RetryPolicy
	getenv       func(string) string
	stripS3XID   *bool
	calls        map[string]int
	mutatorCalls int
	tableLayouts map[string]bool
}

func (r *remote) recordCall(name string, mutator bool) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = make(map[string]int)
	}
	r.calls[name]++
	if mutator {
		r.mutatorCalls++
	}
	r.mu.Unlock()
}

func (r *remote) callsSnapshot() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.calls))
	for k, v := range r.calls {
		out[k] = v
	}
	return out
}

func (r *remote) mutatorCallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutatorCalls
}

// stripS3XIDEnabled reports whether the S3 `?x-id=` query-parameter stripping
// compatibility middleware is active.
//
// Default: true (unless Options.StripS3XID is explicitly false or
// LMAWS_COMPAT_STRIP_S3_XID is "0", "false", "no", or "off").
//
// Removal condition: delete stripS3XIDEnabled and stripS3XIDMiddleware once an
// awssim release containing commit dc7b063 (branch fix-sdk-compat, which adds
// "x-id" and "fetch-owner" to AuthFilter.S3_QUERY) is published and pinned by
// lmcloud/scripts/sims.lock.
func (r *remote) stripS3XIDEnabled() bool {
	if r.stripS3XID != nil {
		return *r.stripS3XID
	}
	switch strings.ToLower(strings.TrimSpace(r.getenv("LMAWS_COMPAT_STRIP_S3_XID"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// stripS3XIDMiddleware strips the Smithy `x-id` query parameter (e.g.,
// `?x-id=PutObject`, `?x-id=GetObject`, `?x-id=DeleteObject`, `?x-id=ListBuckets`)
// before SigV4 signing so older released awssim binaries in `--auth enforce`
// mode do not reject S3 operations with 403 AccessDenied.
//
// Removal condition: delete once an awssim release containing commit dc7b063
// is published and pinned by lmcloud/scripts/sims.lock.
var stripS3XIDMiddleware = middleware.BuildMiddlewareFunc(
	"lmaws.CompatStripS3XIDQueryParam",
	func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (
		middleware.BuildOutput, middleware.Metadata, error,
	) {
		if req, ok := in.Request.(*smithyhttp.Request); ok && req.URL != nil && req.URL.RawQuery != "" {
			parts := strings.Split(req.URL.RawQuery, "&")
			kept := parts[:0]
			for _, p := range parts {
				if p == "x-id" || strings.HasPrefix(p, "x-id=") {
					continue
				}
				kept = append(kept, p)
			}
			req.URL.RawQuery = strings.Join(kept, "&")
		}
		return next.HandleBuild(ctx, in)
	},
)

func addStripS3XIDMiddleware(stack *middleware.Stack) error {
	return stack.Build.Add(stripS3XIDMiddleware, middleware.After)
}

func (r *remote) simRegion() string {
	for _, k := range []string{"LMAWS_SIM_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := strings.TrimSpace(r.getenv(k)); v != "" {
			return v
		}
	}
	return defaultSimRegion
}

func (r *remote) simCredentials() (string, string, string) {
	ak := strings.TrimSpace(r.getenv("LMAWS_SIM_ACCESS_KEY_ID"))
	if ak == "" {
		ak = defaultSimAccessKey
	}
	sk := strings.TrimSpace(r.getenv("LMAWS_SIM_SECRET_ACCESS_KEY"))
	if sk == "" {
		sk = defaultSimSecretKey
	}
	tok := strings.TrimSpace(r.getenv("LMAWS_SIM_SESSION_TOKEN"))
	return ak, sk, tok
}

// newAWSConfig constructs a hermetically isolated aws.Config with SDK retries
// completely disabled (hostkit.RetryPolicy owns retries).
func (r *remote) newAWSConfig() aws.Config {
	ak, sk, tok := r.simCredentials()
	return aws.Config{
		Region:           r.simRegion(),
		Credentials:      credentials.NewStaticCredentialsProvider(ak, sk, tok),
		HTTPClient:       r.client,
		RetryMaxAttempts: 1,
		Retryer:          func() aws.Retryer { return aws.NopRetryer{} },
	}
}

func (r *remote) s3Client(ctx context.Context) *s3.Client {
	ep := hostkit.EndpointFrom(ctx)
	cfg := r.newAWSConfig()
	stripXID := r.stripS3XIDEnabled()
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ep)
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		if stripXID {
			o.APIOptions = append(o.APIOptions, addStripS3XIDMiddleware)
		}
	})
}

func (r *remote) sqsClient(ctx context.Context) *sqs.Client {
	ep := hostkit.EndpointFrom(ctx)
	cfg := r.newAWSConfig()
	return sqs.NewFromConfig(cfg, func(o *sqs.Options) {
		o.BaseEndpoint = aws.String(ep)
	})
}

func (r *remote) ddbClient(ctx context.Context) *dynamodb.Client {
	ep := hostkit.EndpointFrom(ctx)
	cfg := r.newAWSConfig()
	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(ep)
	})
}

// doAWS executes op under hostkit's RetryPolicy (with AWS SDK retries disabled).
func (r *remote) doAWS(ctx context.Context, idempotent bool, op func(ctx context.Context) error) error {
	var lastCallErr error
	r.retry.Do(ctx, idempotent, func(ctx context.Context, _ int) hostkit.Attempt {
		lastCallErr = op(ctx)
		if lastCallErr == nil {
			return hostkit.Attempt{Status: http.StatusOK}
		}
		status, hdr := extractHTTPResponse(lastCallErr)
		if status == 0 {
			// Transport error (no HTTP response received).
			return hostkit.Attempt{Err: lastCallErr, NotSent: hostkit.RequestNotSent(lastCallErr)}
		}
		var retryAfter string
		if hdr != nil {
			retryAfter = hdr.Get("Retry-After")
		}
		return hostkit.Attempt{Status: status, RetryAfter: retryAfter}
	})
	return lastCallErr
}
