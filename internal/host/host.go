package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/lmctl-ai/lmaws/internal/safety"
)

// Options configures a new AWS Host instance.
type Options struct {
	DefaultEndpoint string
	Region          string
	Ledger          *safety.RunLedger
}

type fakeObject struct {
	body        []byte
	etag        string
	contentType string
	metadata    map[string]string
}

type fakeBucket struct {
	objects map[string]*fakeObject
}

type fakeQueueMessage struct {
	id          string
	wireBody    string
	receipt     string
	visibleAt   time.Time
	delivered   bool
	receiptSeq  int64
	deleted     bool
	firstEnqSeq int64
}

type fakeQueue struct {
	name     string
	messages []*fakeQueueMessage
	nextSeq  int64
}

// Host implements the shared lmcloud Cloud context for AWS (S3 + SQS) in SIM/FAKE ONLY mode.
type Host struct {
	mu              sync.Mutex
	abortOnError    bool
	lastErr         *CloudError
	storageEndpoint string
	queueEndpoint   string
	region          string
	ledger          *safety.RunLedger
	httpClient      *http.Client

	// In-memory fallback state used only when no endpoint is configured in offline unit tests.
	buckets map[string]*fakeBucket
	queues  map[string]*fakeQueue
}

// New creates a new AWS Host instance.
func New(opts Options) *Host {
	ep := strings.TrimSpace(opts.DefaultEndpoint)
	if ep == "" {
		ep = strings.TrimSpace(os.Getenv("LMAWS_ENDPOINT"))
	}
	ep = strings.TrimRight(ep, "/")

	region := strings.TrimSpace(opts.Region)
	if region == "" {
		region = strings.TrimSpace(os.Getenv("LMAWS_REGION"))
	}
	if region == "" {
		region = "us-east-1"
	}

	ledger := opts.Ledger
	if ledger == nil {
		ledger = safety.NewRunLedger()
	}

	return &Host{
		abortOnError:    true,
		lastErr:         okCloudError(),
		storageEndpoint: ep,
		queueEndpoint:   ep,
		region:          region,
		ledger:          ledger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		buckets: make(map[string]*fakeBucket),
		queues:  make(map[string]*fakeQueue),
	}
}

func (h *Host) Provider() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastErr = okCloudError()
	return "aws"
}

func (h *Host) AbortOnError() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastErr = okCloudError()
	return h.abortOnError
}

func (h *Host) SetAbortOnError(abort bool) *Host {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.abortOnError = abort
	h.lastErr = okCloudError()
	return h
}

func (h *Host) LastError() *CloudError {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastErr == nil {
		return okCloudError()
	}
	cp := *h.lastErr
	return &cp
}

func (h *Host) Endpoint(service string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateServiceName(service); cerr != nil {
		return "", h.finishErrorLocked("endpoint", service, cerr)
	}
	h.finishOKLocked()
	switch service {
	case "sqs", "queue", "pubsub":
		return h.queueEndpoint, nil
	default:
		return h.storageEndpoint, nil
	}
}

func (h *Host) SetEndpoint(service, rawURL string) (*Host, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateServiceName(service); cerr != nil {
		return nil, h.finishErrorLocked("set_endpoint", service, cerr)
	}
	norm, cerr := ValidateEndpointURL(rawURL)
	if cerr != nil {
		return nil, h.finishErrorLocked("set_endpoint", rawURL, cerr)
	}

	switch service {
	case "":
		h.storageEndpoint = norm
		h.queueEndpoint = norm
	case "storage", "object-storage", "object_storage", "s3", "blob", "gcs", "objectstorage":
		h.storageEndpoint = norm
	case "sqs", "queue", "pubsub":
		h.queueEndpoint = norm
	}
	h.finishOKLocked()
	return h, nil
}

func (h *Host) finishOKLocked() {
	h.lastErr = okCloudError()
}

func (h *Host) finishErrorLocked(op, target string, cerr *CloudError) error {
	h.lastErr = cerr
	if h.abortOnError {
		return cerr.FormatAbortError(op, target)
	}
	return nil
}

// checkSimEndpointLocked enforces the SIM/FAKE ONLY policy: live AWS endpoints are never allowed.
func (h *Host) checkSimEndpointLocked(endpoint string) *CloudError {
	if endpoint == "" {
		return nil
	}
	if _, cerr := ValidateEndpointURL(endpoint); cerr != nil {
		return cerr
	}
	return nil
}

func (h *Host) resolveSimCredentialsLocked() (string, string) {
	accessKey := strings.TrimSpace(os.Getenv("LMAWS_SIM_ACCESS_KEY_ID"))
	secretKey := strings.TrimSpace(os.Getenv("LMAWS_SIM_SECRET_ACCESS_KEY"))
	if accessKey == "" && secretKey == "" {
		return "test", "test"
	}
	return accessKey, secretKey
}

func (h *Host) newAWSConfigLocked() aws.Config {
	accessKey, secretKey := h.resolveSimCredentialsLocked()
	region := h.region
	if region == "" {
		region = "us-east-1"
	}
	return aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		HTTPClient:  h.httpClient,
		RetryMaxAttempts: 1,
	}
}

// stripS3XIDMiddleware removes the Smithy `x-id` query parameter before signing
// so awssim's enforced-mode S3 query whitelist accepts PutObject/GetObject/DeleteObject/ListBuckets.
func stripS3XIDMiddleware(stack *middleware.Stack) error {
	return stack.Build.Add(middleware.BuildMiddlewareFunc(
		"LMAWSStripS3XID",
		func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
			if req, ok := in.Request.(*smithyhttp.Request); ok && req.Request != nil && req.Request.URL != nil {
				rawQ := req.Request.URL.RawQuery
				if strings.Contains(rawQ, "x-id=") {
					parts := strings.Split(rawQ, "&")
					kept := make([]string, 0, len(parts))
					for _, p := range parts {
						if p == "" || strings.HasPrefix(p, "x-id=") {
							continue
						}
						kept = append(kept, p)
					}
					req.Request.URL.RawQuery = strings.Join(kept, "&")
				}
			}
			return next.HandleBuild(ctx, in)
		},
	), middleware.Before)
}

func (h *Host) newS3ClientLocked() *s3.Client {
	cfg := h.newAWSConfigLocked()
	ep := h.storageEndpoint
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ep)
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		o.APIOptions = append(o.APIOptions, stripS3XIDMiddleware)
	})
}

func (h *Host) newSQSClientLocked() *sqs.Client {
	cfg := h.newAWSConfigLocked()
	ep := h.queueEndpoint
	return sqs.NewFromConfig(cfg, func(o *sqs.Options) {
		o.BaseEndpoint = aws.String(ep)
	})
}

// classifyAWSError maps an AWS SDK v2 error into a normalized CloudError.
func classifyAWSError(err error) *CloudError {
	if err == nil {
		return okCloudError()
	}

	httpStatus := 0
	headerCode := ""
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		httpStatus = respErr.HTTPStatusCode()
		if respErr.Response != nil && respErr.Response.Header != nil {
			headerCode = strings.TrimSpace(respErr.Response.Header.Get("X-Amzn-Errortype"))
			if idx := strings.IndexByte(headerCode, ':'); idx > 0 {
				headerCode = headerCode[:idx]
			}
			if idx := strings.LastIndexByte(headerCode, '#'); idx >= 0 && idx+1 < len(headerCode) {
				headerCode = headerCode[idx+1:]
			}
		}
	}

	pcode := ""
	msg := err.Error()
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		pcode = strings.TrimSpace(apiErr.ErrorCode())
		if idx := strings.LastIndexByte(pcode, '#'); idx >= 0 && idx+1 < len(pcode) {
			pcode = pcode[idx+1:]
		}
		if apiErr.ErrorMessage() != "" {
			msg = apiErr.ErrorMessage()
		}
	}

	if (pcode == "" || pcode == "UnknownError" || pcode == "Forbidden" || pcode == "NotFound" || pcode == "BadRequest") && headerCode != "" {
		pcode = headerCode
	}
	if pcode == "" {
		pcode = fmt.Sprintf("HTTP_%d", httpStatus)
	}

	code := mapStatusAndAWSCode(httpStatus, pcode)
	return newCloudError(code, httpStatus, pcode, msg)
}

func mapStatusAndAWSCode(status int, pcode string) string {
	lower := strings.ToLower(pcode)

	switch pcode {
	case "InvalidAccessKeyId", "SignatureDoesNotMatch", "UnrecognizedClientException",
		"MissingAuthenticationToken", "InvalidToken", "ExpiredToken", "ExpiredTokenException",
		"IncompleteSignature", "AuthFailure", "AuthorizationHeaderMalformed":
		return CodeUnauthenticated
	case "AccessDenied", "AccessDeniedException", "AllAccessDisabled", "AccountProblem":
		return CodePermissionDenied
	case "NoSuchBucket", "NoSuchKey", "NotFound", "QueueDoesNotExist",
		"AWS.SimpleQueueService.NonExistentQueue", "NonExistentQueue":
		return CodeNotFound
	case "BucketAlreadyExists", "BucketAlreadyOwnedByYou", "QueueNameExists":
		return CodeAlreadyExists
	case "BucketNotEmpty", "QueueDeletedRecently", "AWS.SimpleQueueService.QueueDeletedRecently":
		return CodeConflict
	case "PreconditionFailed":
		return CodePreconditionFailed
	case "SlowDown", "RequestThrottled", "Throttling", "ThrottlingException", "TooManyRequestsException":
		return CodeRateLimited
	case "ReceiptHandleIsInvalid", "MessageNotInflight", "InvalidParameterValue",
		"InvalidArgument", "MalformedXML", "InvalidRequest", "BatchEntryIdsNotDistinct",
		"EmptyBatchRequest", "InvalidBatchEntryId", "TooManyEntriesInBatchRequest":
		return CodeInvalidArgument
	}

	if strings.Contains(lower, "nonexistentqueue") || strings.Contains(lower, "queuedoesnotexist") {
		return CodeNotFound
	}
	if strings.Contains(lower, "queuedeletedrecently") || strings.Contains(lower, "bucketnotempty") {
		return CodeConflict
	}
	if strings.Contains(lower, "invalidaccesskeyid") || strings.Contains(lower, "signaturedoesnotmatch") || strings.Contains(lower, "unrecognizedclient") {
		return CodeUnauthenticated
	}
	if strings.Contains(lower, "accessdenied") {
		return CodePermissionDenied
	}
	if strings.Contains(lower, "receipthandleisinvalid") || strings.Contains(lower, "messagenotinflight") {
		return CodeInvalidArgument
	}

	switch status {
	case 400:
		return CodeInvalidArgument
	case 401:
		return CodeUnauthenticated
	case 403:
		return CodePermissionDenied
	case 404:
		return CodeNotFound
	case 409:
		return CodeConflict
	case 412:
		return CodePreconditionFailed
	case 429:
		return CodeRateLimited
	case 502, 503, 504:
		return CodeUnavailable
	default:
		if status >= 500 {
			return CodeInternal
		}
		if status == 0 {
			return CodeUnavailable
		}
		return CodeInternal
	}
}

func computeSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeQueueURLToEndpoint(rawQueueURL, configuredEndpoint string) string {
	if rawQueueURL == "" || configuredEndpoint == "" {
		return rawQueueURL
	}
	uQ, err1 := url.Parse(rawQueueURL)
	uE, err2 := url.Parse(configuredEndpoint)
	if err1 != nil || err2 != nil || uE.Host == "" {
		return rawQueueURL
	}
	uQ.Scheme = uE.Scheme
	uQ.Host = uE.Host
	return uQ.String()
}
