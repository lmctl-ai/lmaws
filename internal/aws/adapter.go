// SPDX-License-Identifier: MIT

// Package aws implements the provider-specific hostkit.ObjectStore and
// hostkit.Queue adapters for AWS S3 and SQS (via github.com/aws/aws-sdk-go-v2).
//
// Phase A-C enforces a strict SIM/FAKE ONLY boundary:
//   - When no endpoint override is active and LMAWS_LIVE != "1", operations
//     route to hostkit's in-process fakeadapter (offline mode).
//   - When a loopback endpoint is active (127.0.0.1, ::1, localhost), operations
//     route to the AWS SDK v2 remote adapter against awssim.
//   - When LMAWS_LIVE == "1" or a non-loopback HTTPS endpoint is configured,
//     operations fail immediately with UNAUTHENTICATED (LiveCredentialsNotImplemented)
//     before any network request is made.
package aws

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

// Options configures the AWS adapter. All fields are optional.
type Options struct {
	// Getenv reads environment variables; defaults to os.Getenv.
	Getenv func(string) string

	// StripS3XID controls whether the compatibility middleware strips the
	// aws-sdk-go-v2 `?x-id=<Operation>` query parameter from S3 requests before
	// SigV4 signing.
	//
	// If nil, defaults to true unless LMAWS_COMPAT_STRIP_S3_XID is "0" or "false".
	//
	// Removal condition: delete StripS3XID and stripS3XIDMiddleware once an
	// awssim release containing commit dc7b063 (branch fix-sdk-compat, which
	// adds "x-id" and "fetch-owner" to AuthFilter.S3_QUERY) is published and
	// pinned by lmcloud-sims.
	StripS3XID *bool

	// Retry overrides the default hostkit.RetryPolicy (3 attempts on 429/5xx).
	Retry *hostkit.RetryPolicy

	// HTTPClient overrides the underlying HTTP client; defaults to
	// hostkit.NewHTTPClient(60 * time.Second).
	HTTPClient *http.Client
}

// Adapter implements hostkit.ObjectStore and hostkit.Queue for AWS.
type Adapter struct {
	remote *remote
	fake   *fakeadapter.Fake
	getenv func(string) string
}

// New constructs an AWS Adapter.
func New(opts *Options) *Adapter {
	getenv := os.Getenv
	var stripXID *bool
	retry := hostkit.DefaultRetryPolicy()
	var client *http.Client
	if opts != nil {
		if opts.Getenv != nil {
			getenv = opts.Getenv
		}
		stripXID = opts.StripS3XID
		if opts.Retry != nil {
			retry = *opts.Retry
		}
		client = opts.HTTPClient
	}
	if client == nil {
		client = hostkit.NewHTTPClient(60 * time.Second)
	}
	return &Adapter{
		remote: &remote{
			client:     client,
			retry:      retry,
			getenv:     getenv,
			stripS3XID: stripXID,
			calls:      make(map[string]int),
		},
		fake:   fakeadapter.New(fakeadapter.Options{}),
		getenv: getenv,
	}
}

// Endpoints returns the AWS endpoint resolver for hostkit/cloudhost:
//   - provider prefix: LMAWS_STORAGE_ENDPOINT, LMAWS_QUEUE_ENDPOINT, LMAWS_ENDPOINT
//   - native SDK variables: AWS_ENDPOINT_URL_S3, AWS_ENDPOINT_URL_SQS, AWS_ENDPOINT_URL
func Endpoints() *hostkit.EndpointResolver {
	return &hostkit.EndpointResolver{
		Prefix: "LMAWS",
		Native: map[string][]hostkit.NativeEnv{
			"storage": {{Name: "AWS_ENDPOINT_URL_S3"}, {Name: "AWS_ENDPOINT_URL"}},
			"queue":   {{Name: "AWS_ENDPOINT_URL_SQS"}, {Name: "AWS_ENDPOINT_URL"}},
		},
	}
}

var errLiveNotImplemented = &hostkit.CloudError{
	Code:         hostkit.Unauthenticated,
	Message:      "lmaws: live AWS credentials are not implemented in Phase A-C; set LMAWS_ENDPOINT to a loopback awssim URL or unset LMAWS_LIVE for offline mode",
	ProviderCode: "LiveCredentialsNotImplemented",
}

func (a *Adapter) route(ctx context.Context) (hostkit.ObjectStore, hostkit.Queue, bool, error) {
	base := hostkit.EndpointFrom(ctx)
	if base == "" {
		if strings.TrimSpace(a.getenv("LMAWS_LIVE")) == "1" {
			return nil, nil, false, errLiveNotImplemented
		}
		return a.fake, a.fake, true, nil
	}
	u, err := url.Parse(base)
	if err != nil || !hostkit.IsLoopbackHost(u.Hostname()) {
		// Never send simulator credentials (test/test) to a non-loopback host.
		return nil, nil, false, errLiveNotImplemented
	}
	return a.remote, a.remote, false, nil
}

// Calls returns a snapshot of remote adapter operation counts (for testing).
func (a *Adapter) Calls() map[string]int {
	return a.remote.callsSnapshot()
}

// MutatorCalls returns the total number of remote mutator calls executed (for dry-run tests).
func (a *Adapter) MutatorCalls() int {
	return a.remote.mutatorCallCount()
}

// --- hostkit.ObjectStore ---

func (a *Adapter) CreateBucket(ctx context.Context, name string) (bool, error) {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return false, err
	}
	return s.CreateBucket(ctx, name)
}

func (a *Adapter) DeleteBucket(ctx context.Context, name string) error {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return err
	}
	return s.DeleteBucket(ctx, name)
}

func (a *Adapter) HeadBucket(ctx context.Context, name string) error {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return err
	}
	return s.HeadBucket(ctx, name)
}

func (a *Adapter) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return nil, "", err
	}
	return s.ListBuckets(ctx, token)
}

func (a *Adapter) PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (hostkit.ObjectMeta, error) {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return hostkit.ObjectMeta{}, err
	}
	return s.PutObject(ctx, bucket, key, body, contentType, metadata)
}

func (a *Adapter) GetObject(ctx context.Context, bucket, key string, limit int64) ([]byte, error) {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetObject(ctx, bucket, key, limit)
}

func (a *Adapter) HeadObject(ctx context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return hostkit.ObjectMeta{}, err
	}
	return s.HeadObject(ctx, bucket, key)
}

func (a *Adapter) DeleteObject(ctx context.Context, bucket, key string) error {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return err
	}
	return s.DeleteObject(ctx, bucket, key)
}

func (a *Adapter) ListObjects(ctx context.Context, bucket, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	s, _, _, err := a.route(ctx)
	if err != nil {
		return hostkit.ObjectPage{}, err
	}
	return s.ListObjects(ctx, bucket, prefix, max, token)
}

// --- hostkit.Queue ---

func (a *Adapter) QueueCaps() hostkit.QueueCaps {
	return hostkit.QueueCaps{LongPoll: true, TextOnlyWire: true}
}

func (a *Adapter) CreateQueue(ctx context.Context, name string) (bool, error) {
	_, q, _, err := a.route(ctx)
	if err != nil {
		return false, err
	}
	return q.CreateQueue(ctx, name)
}

func (a *Adapter) DeleteQueue(ctx context.Context, name string) error {
	_, q, _, err := a.route(ctx)
	if err != nil {
		return err
	}
	return q.DeleteQueue(ctx, name)
}

func (a *Adapter) LookupQueue(ctx context.Context, name string) error {
	_, q, _, err := a.route(ctx)
	if err != nil {
		return err
	}
	return q.LookupQueue(ctx, name)
}

func (a *Adapter) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	_, q, _, err := a.route(ctx)
	if err != nil {
		return nil, "", err
	}
	return q.ListQueues(ctx, token)
}

func (a *Adapter) Send(ctx context.Context, queue, wire string) (string, error) {
	_, q, _, err := a.route(ctx)
	if err != nil {
		return "", err
	}
	return q.Send(ctx, queue, wire)
}

func (a *Adapter) Receive(ctx context.Context, queue string, max, waitSeconds, visibility int) ([]hostkit.RawMessage, error) {
	_, q, isFake, err := a.route(ctx)
	if err != nil {
		return nil, err
	}
	if isFake {
		return q.Receive(ctx, queue, max, 0, visibility)
	}
	return q.Receive(ctx, queue, max, waitSeconds, visibility)
}

func (a *Adapter) Ack(ctx context.Context, queue, receipt string) error {
	_, q, _, err := a.route(ctx)
	if err != nil {
		return err
	}
	return q.Ack(ctx, queue, receipt)
}

func (a *Adapter) Nack(ctx context.Context, queue, receipt string, visibility int) (string, error) {
	_, q, _, err := a.route(ctx)
	if err != nil {
		return "", err
	}
	return q.Nack(ctx, queue, receipt, visibility)
}
