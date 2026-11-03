// SPDX-License-Identifier: MIT

// Package aws implements the provider-specific hostkit.ObjectStore and
// hostkit.Queue adapters for AWS S3 and SQS (via github.com/aws/aws-sdk-go-v2).
//
// Execution modes:
//   - Offline fake: when neither LMCLOUD_LIVE=1 nor LMAWS_LIVE=1 is set and no
//     endpoint override is active, operations route to hostkit/fakeadapter.
//   - Simulator: when neither LMCLOUD_LIVE=1 nor LMAWS_LIVE=1 is set and a
//     loopback endpoint is active (127.0.0.1, ::1, localhost), operations route
//     to the AWS SDK v2 simulator adapter against awssim.
//   - Live Stage 1 (read-only): when BOTH LMCLOUD_LIVE=1 and LMAWS_LIVE=1 are
//     set, operations route through hostkit/safety (Session + LiveGuard +
//     CostMeter + Journal) after STS GetCallerIdentity attestation against
//     LMAWS_LIVE_ACCOUNT (254332045686) and LMAWS_LIVE_REGION (us-east-1).
//     Only read-only metadata/list operations (bucket_list, bucket_exists,
//     object_list/object_list_all, object_head, queue_list, queue_exists) are
//     permitted in Stage 1; all mutating operations and arbitrary GetObject /
//     Receive calls return PERMISSION_DENIED (LiveMutationDisabled).
package aws

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
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
	// pinned by lmcloud/scripts/sims.lock.
	StripS3XID *bool

	// Retry overrides the default hostkit.RetryPolicy (3 attempts on 429/5xx).
	Retry *hostkit.RetryPolicy

	// HTTPClient overrides the underlying HTTP client; defaults to
	// hostkit.NewHTTPClient(60 * time.Second).
	HTTPClient *http.Client

	// LiveJournalDir overrides the journal directory in live mode (defaults to
	// LMAWS_LIVE_JOURNAL_DIR / LMCLOUD_LIVE_JOURNAL_DIR / private temp dir).
	LiveJournalDir string

	// LivePolicyPath overrides LMAWS_LIVE_POLICY / LMCLOUD_LIVE_POLICY.
	LivePolicyPath string

	// LiveCostCapUSD lowers the live cost cap below the $0.05 default.
	LiveCostCapUSD float64
}

// Adapter implements hostkit.ObjectStore, hostkit.Queue,
// hostkit.QueueCapsProvider, and hostkit.QueueCreateTokenReader for AWS by
// delegating through hostkit.Router.
// Note: Adapter intentionally does NOT implement hostkit.BucketCreateTokenReader
// because S3 CreateBucket has no atomic tag/metadata parameter (tagging requires
// a separate PutBucketTagging request); a conflict on an accessible S3 bucket
// therefore returns created=false with ErrorCode.OK (durable-memory/09-hostkit.md).
type Adapter struct {
	router hostkit.Router
	remote *remote
	live   *liveAdapter
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
	rem := &remote{
		client:     client,
		retry:      retry,
		getenv:     getenv,
		stripS3XID: stripXID,
		calls:      make(map[string]int),
	}
	fk := fakeadapter.New(fakeadapter.Options{})
	lv := newLiveAdapter(opts, getenv, retry, client)

	pick := func(ctx context.Context) (hostkit.Backend, error) {
		lmcloudLive := strings.TrimSpace(getenv("LMCLOUD_LIVE"))
		lmawsLive := strings.TrimSpace(getenv("LMAWS_LIVE"))
		if (lmcloudLive != "" && lmcloudLive != "0" && lmcloudLive != "1") ||
			(lmawsLive != "" && lmawsLive != "0" && lmawsLive != "1") {
			return nil, hostkit.ProviderError(
				hostkit.InvalidArgument,
				0,
				"LiveDoubleOptInRequired",
				fmt.Sprintf("LMCLOUD_LIVE and LMAWS_LIVE must be '1', '0', or unset (got LMCLOUD_LIVE=%q, LMAWS_LIVE=%q)", lmcloudLive, lmawsLive),
			)
		}
		globalOn := lmcloudLive == "1"
		hostOn := lmawsLive == "1"
		if globalOn != hostOn {
			return nil, hostkit.ProviderError(
				hostkit.InvalidArgument,
				0,
				"LiveDoubleOptInRequired",
				fmt.Sprintf("live mode requires both LMCLOUD_LIVE=1 and LMAWS_LIVE=1 (got LMCLOUD_LIVE=%q, LMAWS_LIVE=%q)", lmcloudLive, lmawsLive),
			)
		}
		if globalOn && hostOn {
			return lv, nil
		}

		ep := strings.TrimSpace(hostkit.EndpointFrom(ctx))
		if ep == "" {
			return fk, nil
		}
		u, err := url.Parse(ep)
		if err == nil && hostkit.IsLoopbackHost(u.Hostname()) {
			return rem, nil
		}
		return nil, errLiveOptInRequired
	}

	return &Adapter{
		router: hostkit.Router{Pick: pick},
		remote: rem,
		live:   lv,
	}
}

// Close releases any active live session and its journal flock lease.
func (a *Adapter) Close() error {
	if a == nil || a.live == nil {
		return nil
	}
	return a.live.Close()
}

// FinishAndSweep executes an active LIFO recovery sweep on the current live
// session (if open), compacts its journal, and closes the session.
func (a *Adapter) FinishAndSweep(ctx context.Context) (safety.SweepReport, error) {
	if a == nil || a.live == nil {
		return safety.SweepReport{}, nil
	}
	return a.live.FinishAndSweep(ctx)
}

// SweepCLI executes the `lmaws --sweep` command (dry-run by default unless
// --apply or --delete is passed).
func (a *Adapter) SweepCLI(ctx context.Context, args []string, out io.Writer) int {
	if a == nil || a.live == nil {
		_, _ = fmt.Fprintln(out, `{"ok":true,"swept":0,"mode":"sim-or-live-readonly-stage1"}`)
		return 0
	}
	return a.live.SweepCLI(ctx, args, out)
}

// LiveSession returns the active live safety.Session if live mode has been
// initialized on this Adapter, or nil otherwise.
func (a *Adapter) LiveSession() *safety.Session {
	if a == nil || a.live == nil {
		return nil
	}
	return a.live.session()
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

var errLiveOptInRequired = &hostkit.CloudError{
	Code:         hostkit.Unauthenticated,
	Message:      "lmaws: non-loopback AWS endpoints require live double opt-in (LMCLOUD_LIVE=1 and LMAWS_LIVE=1) without endpoint overrides",
	ProviderCode: "LiveOptInRequired",
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
	return a.router.CreateBucket(ctx, name)
}

func (a *Adapter) DeleteBucket(ctx context.Context, name string) error {
	return a.router.DeleteBucket(ctx, name)
}

func (a *Adapter) HeadBucket(ctx context.Context, name string) error {
	return a.router.HeadBucket(ctx, name)
}

func (a *Adapter) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	return a.router.ListBuckets(ctx, token)
}

func (a *Adapter) PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (hostkit.ObjectMeta, error) {
	return a.router.PutObject(ctx, bucket, key, body, contentType, metadata)
}

func (a *Adapter) GetObject(ctx context.Context, bucket, key string, limit int64) ([]byte, error) {
	return a.router.GetObject(ctx, bucket, key, limit)
}

func (a *Adapter) HeadObject(ctx context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	return a.router.HeadObject(ctx, bucket, key)
}

func (a *Adapter) DeleteObject(ctx context.Context, bucket, key string) error {
	return a.router.DeleteObject(ctx, bucket, key)
}

func (a *Adapter) ListObjects(ctx context.Context, bucket, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	return a.router.ListObjects(ctx, bucket, prefix, max, token)
}

// --- hostkit.Queue, hostkit.QueueCapsProvider & hostkit.QueueCreateTokenReader ---

func (a *Adapter) QueueCaps() hostkit.QueueCaps {
	return a.remote.QueueCaps()
}

// QueueCapsFor reports the queue capabilities of the backend selected by ctx
// (offline fake uses LongPoll: false so WaitLoop honours wait_seconds; loopback
// awssim uses LongPoll: true).
func (a *Adapter) QueueCapsFor(ctx context.Context, queue string) hostkit.QueueCaps {
	return a.router.QueueCapsFor(ctx, queue)
}

func (a *Adapter) QueueCreateToken(ctx context.Context, queue string) (string, error) {
	return a.router.QueueCreateToken(ctx, queue)
}

func (a *Adapter) CreateQueue(ctx context.Context, name string) (bool, error) {
	return a.router.CreateQueue(ctx, name)
}

func (a *Adapter) DeleteQueue(ctx context.Context, name string) error {
	return a.router.DeleteQueue(ctx, name)
}

func (a *Adapter) LookupQueue(ctx context.Context, name string) error {
	return a.router.LookupQueue(ctx, name)
}

func (a *Adapter) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	return a.router.ListQueues(ctx, token)
}

func (a *Adapter) Send(ctx context.Context, queue, wire string) (string, error) {
	return a.router.Send(ctx, queue, wire)
}

func (a *Adapter) Receive(ctx context.Context, queue string, max, waitSeconds, visibility int) ([]hostkit.RawMessage, error) {
	return a.router.Receive(ctx, queue, max, waitSeconds, visibility)
}

func (a *Adapter) Ack(ctx context.Context, queue, receipt string) error {
	return a.router.Ack(ctx, queue, receipt)
}

func (a *Adapter) Nack(ctx context.Context, queue, receipt string, visibility int) (string, error) {
	return a.router.Nack(ctx, queue, receipt, visibility)
}
