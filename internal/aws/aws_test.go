// SPDX-License-Identifier: MIT

package aws

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/cloudhost"
	"github.com/lmctl-ai/lmcloud/schema"
)

func synthAWSErr(status int, code, msg, headerErrType string) error {
	hdr := http.Header{}
	if headerErrType != "" {
		hdr.Set("X-Amzn-Errortype", headerErrType)
	}
	httpResp := &http.Response{
		StatusCode: status,
		Header:     hdr,
		Body:       io.NopCloser(strings.NewReader("")),
	}
	var inner error = errors.New(msg)
	if code != "" {
		inner = &smithy.GenericAPIError{
			Code:    code,
			Message: msg,
		}
	}
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: httpResp},
			Err:      inner,
		},
	}
}

func TestClassifyTable(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   string
		msg    string
		header string
		sc     scope
		want   hostkit.Code
		absent hostkit.Absence
	}{
		{"S3 InvalidAccessKeyId", 403, "InvalidAccessKeyId", "bad key", "", scopeBucket, hostkit.Unauthenticated, ""},
		{"S3 SignatureDoesNotMatch", 403, "SignatureDoesNotMatch", "bad sig", "", scopeObject, hostkit.Unauthenticated, ""},
		{"HEAD 403 header InvalidAccessKeyId", 403, "Forbidden", "Forbidden", "InvalidAccessKeyId", scopeBucket, hostkit.Unauthenticated, ""},
		{"SQS InvalidClientTokenId", 403, "InvalidClientTokenId", "bad token", "", scopeQueue, hostkit.Unauthenticated, ""},
		{"S3 AccessDenied", 403, "AccessDenied", "denied", "", scopeObject, hostkit.PermissionDenied, ""},
		{"HEAD 403 header AccessDenied", 403, "Forbidden", "Forbidden", "AccessDenied:sub", scopeBucket, hostkit.PermissionDenied, ""},
		{"HEAD 403 bare Forbidden", 403, "Forbidden", "Forbidden", "", scopeBucket, hostkit.PermissionDenied, ""},
		{"S3 NoSuchBucket", 404, "NoSuchBucket", "no bucket", "", scopeObject, hostkit.NotFound, hostkit.AbsentBucket},
		{"S3 NoSuchKey", 404, "NoSuchKey", "no key", "", scopeObject, hostkit.NotFound, hostkit.AbsentObject},
		{"HEAD 404 bucket scope", 404, "NotFound", "Not Found", "", scopeBucket, hostkit.NotFound, hostkit.AbsentBucket},
		{"HEAD 404 object scope", 404, "NotFound", "Not Found", "", scopeObject, hostkit.NotFound, hostkit.AbsentObject},
		{"SQS NonExistentQueue", 400, "AWS.SimpleQueueService.NonExistentQueue", "no queue", "", scopeQueue, hostkit.NotFound, hostkit.AbsentQueue},
		{"SQS QueueDoesNotExist namespace#", 400, "com.amazonaws.sqs#QueueDoesNotExist", "no queue", "", scopeQueue, hostkit.NotFound, hostkit.AbsentQueue},
		{"SQS MessageNotInflight", 400, "MessageNotInflight", "not inflight", "", scopeMessage, hostkit.NotFound, hostkit.AbsentMessage},
		{"S3 BucketAlreadyExists", 409, "BucketAlreadyExists", "exists", "", scopeBucket, hostkit.Conflict, ""},
		{"S3 BucketNotEmpty", 409, "BucketNotEmpty", "not empty", "", scopeBucket, hostkit.Conflict, ""},
		{"SQS QueueDeletedRecently", 400, "AWS.SimpleQueueService.QueueDeletedRecently", "wait 60s", "", scopeQueue, hostkit.Conflict, ""},
		{"S3 PreconditionFailed", 412, "PreconditionFailed", "etag mismatch", "", scopeObject, hostkit.PreconditionFailed, ""},
		{"SQS ReceiptHandleIsInvalid", 400, "ReceiptHandleIsInvalid", "bad receipt", "", scopeMessage, hostkit.InvalidArgument, ""},
		{"SQS InvalidParameterValue", 400, "InvalidParameterValue", "bad param", "", scopeQueue, hostkit.InvalidArgument, ""},
		{"S3 SlowDown 503", 503, "SlowDown", "slow down", "", scopeObject, hostkit.Internal, ""},
		{"S3 InternalError 500", 500, "InternalError", "boom", "", scopeObject, hostkit.Internal, ""},
		{"HTTP 429 Throttling", 429, "ThrottlingException", "throttled", "", scopeQueue, hostkit.Internal, ""},
	}
	for _, c := range cases {
		err := synthAWSErr(c.status, c.code, c.msg, c.header)
		ce := classify(err, c.sc)
		if ce.Code != c.want || ce.Absent != c.absent || ce.HTTPStatus != c.status || !ce.Code.Valid() {
			t.Errorf("%s: got code=%s absent=%q http=%d, want code=%s absent=%q http=%d",
				c.name, ce.Code, ce.Absent, ce.HTTPStatus, c.want, c.absent, c.status)
		}
	}
}

type mockAWS struct {
	t        *testing.T
	mu       sync.Mutex
	requests []string
	queries  []string
	handle   func(w http.ResponseWriter, r *http.Request) bool
}

func (m *mockAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var bodyStr string
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		bodyStr = string(b)
		r.Body = io.NopCloser(bytes.NewReader(b))
	}
	entry := r.Method + " " + r.URL.Path
	target := r.Header.Get("X-Amz-Target")
	if target != "" {
		entry += " (" + target + ")"
	} else if r.Method == http.MethodPost && strings.Contains(bodyStr, "Action=") {
		for _, part := range strings.Split(bodyStr, "&") {
			if strings.HasPrefix(part, "Action=") {
				entry += " (" + part + ")"
				break
			}
		}
	}
	m.mu.Lock()
	m.requests = append(m.requests, entry)
	m.queries = append(m.queries, r.URL.RawQuery)
	m.mu.Unlock()
	if m.handle != nil && m.handle(w, r) {
		return
	}
	if r.Method == http.MethodPost && (strings.Contains(target, "GetQueueUrl") || strings.Contains(bodyStr, "Action=GetQueueUrl")) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"__type":"com.amazonaws.sqs#QueueDoesNotExist","message":"mock: no queue"}`)
		return
	}
	writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "mock default 404")
}

func (m *mockAWS) count(prefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func (m *mockAWS) mutatingRequestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.requests {
		if strings.HasPrefix(r, "PUT ") || strings.HasPrefix(r, "DELETE ") {
			n++
		} else if strings.HasPrefix(r, "POST ") {
			if !strings.Contains(r, "GetQueueUrl") && !strings.Contains(r, "ListQueues") {
				n++
			}
		}
	}
	return n
}

func writeS3Error(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, msg)
}

func fastRetry() hostkit.RetryPolicy {
	p := hostkit.DefaultRetryPolicy()
	p.Jitter = func(time.Duration) time.Duration { return 0 }
	return p
}

func newTestHost(t *testing.T, opts *Options, handle func(w http.ResponseWriter, r *http.Request) bool) (*cloudhost.Host, *Adapter, *mockAWS) {
	t.Helper()
	m := &mockAWS{t: t, handle: handle}
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	t.Setenv("LMAWS_ENDPOINT", srv.URL)
	t.Setenv("LMAWS_LIVE", "")
	rPolicy := fastRetry()
	var aOpts Options
	if opts != nil {
		aOpts = *opts
	}
	aOpts.Retry = &rPolicy
	a := New(&aOpts)
	h := cloudhost.New(cloudhost.Config{
		Provider:  "aws",
		Store:     a,
		Queue:     a,
		Endpoints: Endpoints(),
	})
	h.SetAbortOnError(false)
	return h, a, m
}

// 503 SlowDown is retried 3 times by hostkit.RetryPolicy (with AWS SDK retries off), then INTERNAL.
func TestSlowDownRetriedThreeTimesThenInternal(t *testing.T) {
	h, _, m := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		writeS3Error(w, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.")
		return true
	})
	if buckets, _ := h.BucketList(false); buckets != nil || h.LastError().Code != hostkit.Internal || h.LastError().HTTPStatus != 503 || h.LastError().ProviderCode != "SlowDown" {
		t.Fatalf("unexpected result: buckets=%v last=%+v", buckets, h.LastError())
	}
	if n := m.count("GET /"); n != 3 {
		t.Fatalf("GET / attempts = %d, want 3 (SDK retries must be off; hostkit retries 3x)", n)
	}
}

// Oversize object response (> 32 MiB) is rejected with INTERNAL and never truncated.
func TestOversizeObjectRejected(t *testing.T) {
	h, _, _ := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/bkt/big.bin" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.CopyN(w, zeroReader{}, 33_562_624)
			return true
		}
		return false
	})
	if body, _ := h.ObjectGet(false, "bkt", "big.bin"); body != "" || h.LastError().Code != hostkit.Internal {
		t.Fatalf("len=%d last=%+v", len(body), h.LastError())
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// Pagination stalled continuation token fails with INTERNAL instead of looping forever.
func TestStalledContinuationTokenFails(t *testing.T) {
	h, _, _ := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/bkt" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bkt</Name>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>same-tok</NextContinuationToken>
  <Contents><Key>k1</Key><Size>4</Size><ETag>"e1"</ETag></Contents>
</ListBucketResult>`)
			return true
		}
		return false
	})
	if keys, _ := h.ObjectListAll(false, "bkt", ""); keys != nil || h.LastError().Code != hostkit.Internal {
		t.Fatalf("keys=%v last=%+v", keys, h.LastError())
	}
}

func TestBucketListAndQueueListPaginationStallAndLimit(t *testing.T) {
	// 1. Multi-page BucketList follows ContinuationToken across pages and sorts results.
	h1, _, m1 := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			if r.URL.Query().Get("continuation-token") == "tok-page-2" {
				_, _ = io.WriteString(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>alpha</Name></Bucket></Buckets></ListAllMyBucketsResult>`)
			} else {
				_, _ = io.WriteString(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>zeta</Name></Bucket></Buckets><ContinuationToken>tok-page-2</ContinuationToken></ListAllMyBucketsResult>`)
			}
			return true
		}
		return false
	})
	buckets, err := h1.BucketList(false)
	if err != nil || len(buckets) != 2 || buckets[0] != "alpha" || buckets[1] != "zeta" {
		t.Fatalf("multi-page BucketList: buckets=%v err=%v last=%+v", buckets, err, h1.LastError())
	}
	if m1.count("GET /") != 2 {
		t.Fatalf("expected 2 GET / requests for 2-page BucketList, got %d", m1.count("GET /"))
	}

	// 2. Stalled BucketList ContinuationToken fails after 2 requests with INTERNAL and returns no partial names.
	h2, _, m2 := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>one</Name></Bucket></Buckets><ContinuationToken>same</ContinuationToken></ListAllMyBucketsResult>`)
			return true
		}
		return false
	})
	if names, _ := h2.BucketList(false); names != nil || h2.LastError().Code != hostkit.Internal {
		t.Fatalf("stalled BucketList: names=%v last=%+v", names, h2.LastError())
	}
	if m2.count("GET /") != 2 {
		t.Fatalf("expected 2 GET / requests before stalled token abort, got %d", m2.count("GET /"))
	}

	// 3. BucketList exceeding MaxPages fails with INTERNAL and refuses partial results.
	var pageSeq atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := pageSeq.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>b-%d</Name></Bucket></Buckets><ContinuationToken>tok-%d</ContinuationToken></ListAllMyBucketsResult>`, n, n)
	}))
	defer srv.Close()
	t.Setenv("LMAWS_ENDPOINT", srv.URL)
	a3 := New(nil)
	h3 := cloudhost.New(cloudhost.Config{
		Provider:  "aws",
		Store:     a3,
		Queue:     a3,
		Endpoints: Endpoints(),
		MaxPages:  3,
	})
	h3.SetAbortOnError(false)
	if names, _ := h3.BucketList(false); names != nil || h3.LastError().Code != hostkit.Internal {
		t.Fatalf("page-limit BucketList: names=%v last=%+v", names, h3.LastError())
	}
	if pageSeq.Load() != 3 {
		t.Fatalf("expected 3 page fetches for MaxPages=3, got %d", pageSeq.Load())
	}

	// 4. Stalled QueueList NextToken fails with INTERNAL and returns no partial queue names.
	h4, _, _ := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.Header.Get("X-Amz-Target") == "AmazonSQS.ListQueues" {
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"QueueUrls":["http://127.0.0.1:4566/000000000000/q1"],"NextToken":"same-qtok"}`)
			return true
		}
		return false
	})
	if qnames, _ := h4.QueueList(false); qnames != nil || h4.LastError().Code != hostkit.Internal {
		t.Fatalf("stalled QueueList: qnames=%v last=%+v", qnames, h4.LastError())
	}
}

// H2: S3 HEAD 403 has no body; verify header classification and body-bearing probe fallback.
func TestHead403Classification(t *testing.T) {
	cases := []struct {
		name      string
		headHdr   string
		probeCode string
		want      hostkit.Code
	}{
		{"header says InvalidAccessKeyId", "InvalidAccessKeyId", "", hostkit.Unauthenticated},
		{"header says AccessDenied", "AccessDenied", "", hostkit.PermissionDenied},
		{"no header, probe says InvalidAccessKeyId", "", "InvalidAccessKeyId", hostkit.Unauthenticated},
		{"no header, probe says AccessDenied", "", "AccessDenied", hostkit.PermissionDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, _, m := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodHead {
					if c.headHdr != "" {
						w.Header().Set("X-Amzn-Errortype", c.headHdr)
					}
					w.WriteHeader(http.StatusForbidden)
					return true
				}
				if r.Method == http.MethodGet {
					writeS3Error(w, http.StatusForbidden, c.probeCode, "probe error")
					return true
				}
				return false
			})
			ex, _ := h.BucketExists(false, "bkt")
			if ex || h.LastError().Code != c.want {
				t.Fatalf("BucketExists: ex=%v last=%+v, want %s", ex, h.LastError(), c.want)
			}
			meta, _ := h.ObjectHead(false, "bkt", "secret.txt")
			if meta.Exists || h.LastError().Code != c.want {
				t.Fatalf("ObjectHead: exists=%v last=%+v, want %s", meta.Exists, h.LastError(), c.want)
			}
			if c.headHdr != "" && m.count("GET ") != 0 {
				t.Fatalf("expected 0 fallback GETs when X-Amzn-Errortype header is present, got %d", m.count("GET "))
			}
		})
	}
}

// HeadObject 404 disambiguates missing key (OK, exists=false) vs missing bucket (NOT_FOUND).
func TestHeadObject404Disambiguation(t *testing.T) {
	bucketExists := true
	h, _, _ := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodHead && r.URL.Path == "/bkt/missing.txt" {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		if r.Method == http.MethodHead && r.URL.Path == "/bkt" {
			if bucketExists {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return true
		}
		return false
	})

	meta, _ := h.ObjectHead(false, "bkt", "missing.txt")
	if meta.Exists || h.LastError().Code != hostkit.OK {
		t.Fatalf("missing object in existing bucket: exists=%v last=%+v", meta.Exists, h.LastError())
	}

	bucketExists = false
	meta, _ = h.ObjectHead(false, "bkt", "missing.txt")
	if meta.Exists || h.LastError().Code != hostkit.NotFound || h.LastError().ProviderCode != "NoSuchBucket" {
		t.Fatalf("missing bucket on ObjectHead: exists=%v last=%+v", meta.Exists, h.LastError())
	}
}

// H3: us-east-1 CreateBucket probes HeadBucket before PUT; when HEAD returns 403, PUT classifies auth.
func TestCreateBucketHeadBeforePutAndAuth(t *testing.T) {
	var created atomic.Bool
	h, _, m := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/owned-bkt" {
			if r.Method == http.MethodHead {
				if created.Load() {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
				return true
			}
			if r.Method == http.MethodPut {
				created.Store(true)
				w.WriteHeader(http.StatusOK)
				return true
			}
		}
		return false
	})
	if c, _ := h.BucketCreate(false, "owned-bkt"); !c || h.LastError().Code != hostkit.OK {
		t.Fatalf("first BucketCreate: c=%v last=%+v", c, h.LastError())
	}
	if c, _ := h.BucketCreate(false, "owned-bkt"); c || h.LastError().Code != hostkit.OK {
		t.Fatalf("second BucketCreate: c=%v last=%+v", c, h.LastError())
	}
	if m.count("PUT /owned-bkt") != 1 {
		t.Fatalf("expected 1 PUT /owned-bkt, got %d", m.count("PUT /owned-bkt"))
	}
}

// Dry-run proof: dry execution makes ZERO mutator calls on the adapter and ZERO mutating HTTP requests.
func TestDryRunZeroMutatorCalls(t *testing.T) {
	h, a, m := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodHead && r.URL.Path == "/dry-bkt" {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		return false
	})

	_, _ = h.BucketCreate(true, "dry-bkt")
	_, _ = h.ObjectPut(true, "dry-bkt", "k.txt", "hello", "text/plain", map[string]string{"env": "dev"})
	_ = h.ObjectDelete(true, "dry-bkt", "k.txt")
	_, _ = h.BucketDelete(true, "dry-bkt")
	_, _ = h.QueueCreate(true, "dry-q")
	_, _ = h.QueueSend(true, "dry-q", "msg")
	_, _ = h.QueueReceive(true, "dry-q", 1, 0, 30)
	_ = h.QueueAck(true, "dry-q", "r1")
	_, _ = h.QueueNack(true, "dry-q", "r1", 5)
	_, _ = h.QueueDelete(true, "dry-q")

	if got := a.MutatorCalls(); got != 0 {
		t.Fatalf("expected 0 adapter mutator calls in dry mode, got %d (calls=%v)", got, a.Calls())
	}
	if got := m.mutatingRequestCount(); got != 0 {
		t.Fatalf("expected 0 mutating HTTP requests in dry mode, got %d (requests=%v)", got, m.requests)
	}
}

// Endpoint validation from every source: unsafe endpoints rejected before any network traffic.
func TestEndpointRouting(t *testing.T) {
	h, _, m := newTestHost(t, nil, nil)

	t.Setenv("LMAWS_ENDPOINT", "http://0.0.0.0:4566")
	if _, _ = h.BucketExists(false, "bkt"); h.LastError().Code != hostkit.InvalidArgument || len(m.requests) != 0 {
		t.Fatalf("0.0.0.0: last=%+v requests=%v", h.LastError(), m.requests)
	}

	t.Setenv("LMAWS_ENDPOINT", "http://127.0.0.1.evil.example:4566")
	if _, _ = h.BucketExists(false, "bkt"); h.LastError().Code != hostkit.InvalidArgument || len(m.requests) != 0 {
		t.Fatalf("spoofed loopback: last=%+v requests=%v", h.LastError(), m.requests)
	}

	t.Setenv("LMAWS_ENDPOINT", "https://s3.us-east-1.amazonaws.com")
	if _, _ = h.BucketExists(false, "bkt"); h.LastError().Code != hostkit.Unauthenticated || h.LastError().ProviderCode != "LiveCredentialsNotImplemented" {
		t.Fatalf("live https endpoint: last=%+v", h.LastError())
	}

	t.Setenv("LMAWS_ENDPOINT", "")
	t.Setenv("LMAWS_LIVE", "1")
	if _, _ = h.BucketCreate(false, "bkt"); h.LastError().Code != hostkit.Unauthenticated || h.LastError().ProviderCode != "LiveCredentialsNotImplemented" {
		t.Fatalf("LMAWS_LIVE=1: last=%+v", h.LastError())
	}

	t.Setenv("LMAWS_LIVE", "")
	if c, _ := h.BucketCreate(false, "offline-bkt"); !c || h.LastError().Code != hostkit.OK {
		t.Fatalf("offline fake: c=%v last=%+v", c, h.LastError())
	}
	if len(m.requests) != 0 {
		t.Fatalf("expected 0 network requests during endpoint rejection / offline fake, got %v", m.requests)
	}
}

// Compatibility option LMAWS_COMPAT_STRIP_S3_XID toggles stripping of `?x-id=` on S3 requests.
func TestStripS3XIDCompatOption(t *testing.T) {
	handle := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && r.URL.Path == "/bkt/k.txt" {
			w.Header().Set("ETag", `"etag-1"`)
			w.WriteHeader(http.StatusOK)
			return true
		}
		return false
	}

	// Default (enabled): x-id is stripped.
	t.Setenv("LMAWS_COMPAT_STRIP_S3_XID", "")
	h1, _, m1 := newTestHost(t, nil, handle)
	if _, _ = h1.ObjectPut(false, "bkt", "k.txt", "v", "text/plain", nil); h1.LastError().Code != hostkit.OK {
		t.Fatalf("put with strip enabled: %+v", h1.LastError())
	}
	if len(m1.queries) != 1 || strings.Contains(m1.queries[0], "x-id=") {
		t.Fatalf("expected x-id to be stripped by default, got queries=%v", m1.queries)
	}

	// Disabled via LMAWS_COMPAT_STRIP_S3_XID=0: x-id=PutObject is preserved on the wire.
	t.Setenv("LMAWS_COMPAT_STRIP_S3_XID", "0")
	h2, _, m2 := newTestHost(t, nil, handle)
	if _, _ = h2.ObjectPut(false, "bkt", "k.txt", "v", "text/plain", nil); h2.LastError().Code != hostkit.OK {
		t.Fatalf("put with strip disabled: %+v", h2.LastError())
	}
	if len(m2.queries) != 1 || !strings.Contains(m2.queries[0], "x-id=PutObject") {
		t.Fatalf("expected x-id=PutObject to be preserved when LMAWS_COMPAT_STRIP_S3_XID=0, got queries=%v", m2.queries)
	}
}

func TestQueueURLNormalizationLongPollAckNack(t *testing.T) {
	var recvCalls atomic.Int32
	h, _, m := newTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			return false
		}
		target := r.Header.Get("X-Amz-Target")
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		switch target {
		case "AmazonSQS.GetQueueUrl":
			// Return a different host (e.g., localhost:4566) to verify normalization to active loopback endpoint.
			_, _ = io.WriteString(w, `{"QueueUrl":"http://localhost:4566/000000000000/q-norm"}`)
			return true
		case "AmazonSQS.SendMessage":
			_, _ = io.WriteString(w, `{"MessageId":"m-123"}`)
			return true
		case "AmazonSQS.ReceiveMessage":
			if recvCalls.Add(1) < 2 {
				// First poll returns empty early; Receive must keep polling until waitSeconds elapses or messages arrive.
				_, _ = io.WriteString(w, `{"Messages":[]}`)
				return true
			}
			_, _ = io.WriteString(w, `{"Messages":[{"MessageId":"m-123","ReceiptHandle":"rh-1","Body":"hello"}]}`)
			return true
		case "AmazonSQS.ChangeMessageVisibility":
			_, _ = io.WriteString(w, `{}`)
			return true
		case "AmazonSQS.DeleteMessage":
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "bad-rh") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"__type":"com.amazonaws.sqs#ReceiptHandleIsInvalid","message":"invalid receipt"}`)
				return true
			}
			_, _ = io.WriteString(w, `{}`)
			return true
		}
		return false
	})

	if id, _ := h.QueueSend(false, "q-norm", "hello"); id != "m-123" || h.LastError().Code != hostkit.OK {
		t.Fatalf("QueueSend: id=%q last=%+v", id, h.LastError())
	}
	msgs, _ := h.QueueReceive(false, "q-norm", 1, 1, 30)
	if len(msgs) != 1 || h.LastError().Code != hostkit.OK || recvCalls.Load() < 2 {
		t.Fatalf("QueueReceive: msgs=%v calls=%d last=%+v", msgs, recvCalls.Load(), h.LastError())
	}
	if next, _ := h.QueueNack(false, "q-norm", "rh-1", 5); next != "rh-1" || h.LastError().Code != hostkit.OK {
		t.Fatalf("QueueNack: next=%q last=%+v", next, h.LastError())
	}
	if _ = h.QueueAck(false, "q-norm", "rh-1"); h.LastError().Code != hostkit.OK {
		t.Fatalf("QueueAck: last=%+v", h.LastError())
	}
	if _ = h.QueueAck(false, "q-norm", "bad-rh"); h.LastError().Code != hostkit.InvalidArgument {
		t.Fatalf("QueueAck bad receipt: last=%+v", h.LastError())
	}
	if m.count("POST /000000000000/q-norm") == 0 && m.count("POST /") == 0 {
		t.Fatalf("expected normalized loopback SQS requests to reach mock server")
	}
}

func TestSchemaParity(t *testing.T) {
	disk, err := os.ReadFile("../../schema/lmcloud.dsl.json")
	if err != nil {
		t.Fatalf("read schema/lmcloud.dsl.json: %v", err)
	}
	if !bytes.Equal(disk, schema.Bytes) {
		t.Fatalf("schema/lmcloud.dsl.json differs from github.com/lmctl-ai/lmcloud/schema.Bytes")
	}
	var root struct {
		XMLName xml.Name
	}
	_ = root
}
