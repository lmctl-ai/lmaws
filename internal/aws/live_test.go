// SPDX-License-Identifier: MIT

package aws

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/cloudhost"
	"github.com/lmctl-ai/lmcloud/hostkit/httpguard"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

type recordedLiveWireReq struct {
	Scheme string
	Host   string
	Method string
	Path   string
	Query  string
	Target string
	Auth   string
}

// liveGuardForwardTransport records the outgoing request's real URL scheme and
// host (AFTER liveEndpointGuardTransport has verified https://*.amazonaws.com
// and SigV4 headers) and forwards the request over loopback to httpguard.Server
// so tests run completely offline without touching external network.
type liveGuardForwardTransport struct {
	srvURL string
	mu     sync.Mutex
	wire   []recordedLiveWireReq
}

func (f *liveGuardForwardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyCopy []byte
	if req.Body != nil {
		bodyCopy, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(strings.NewReader(string(bodyCopy)))
	}
	f.mu.Lock()
	f.wire = append(f.wire, recordedLiveWireReq{
		Scheme: req.URL.Scheme,
		Host:   req.URL.Host,
		Method: req.Method,
		Path:   req.URL.Path,
		Query:  req.URL.RawQuery,
		Target: req.Header.Get("X-Amz-Target"),
		Auth:   req.Header.Get("Authorization"),
	})
	f.mu.Unlock()

	targetURL, err := url.Parse(f.srvURL)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	if bodyCopy != nil {
		clone.Body = io.NopCloser(strings.NewReader(string(bodyCopy)))
	}
	clone.Host = req.URL.Host
	clone.Header = req.Header.Clone()
	clone.Header.Set("X-Orig-Host", req.URL.Host)
	clone.Header.Set("X-Orig-Scheme", req.URL.Scheme)
	clone.Header.Set("X-Orig-Body", string(bodyCopy))
	clone.URL.Scheme = targetURL.Scheme
	clone.URL.Host = targetURL.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func (f *liveGuardForwardTransport) records() []recordedLiveWireReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedLiveWireReq(nil), f.wire...)
}

func setValidLiveEnv(t *testing.T) {
	t.Helper()
	t.Setenv("LMCLOUD_LIVE", "1")
	t.Setenv("LMAWS_LIVE", "1")
	t.Setenv("LMAWS_LIVE_ACCOUNT", RequiredLiveAccount)
	t.Setenv("LMAWS_LIVE_REGION", RequiredLiveRegion)
	t.Setenv("AWS_REGION", RequiredLiveRegion)
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "AQoDYXdzEJr1EXAMPLE_SECRET_SESSION_TOKEN")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/nonexistent-creds")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/nonexistent-config")
	for _, k := range forbiddenLiveEndpointEnvs {
		t.Setenv(k, "")
	}
}

func newLiveTestHost(t *testing.T, extraOpts *Options, step httpguard.Step) (*cloudhost.Host, *Adapter, *httpguard.Server, *liveGuardForwardTransport) {
	t.Helper()
	setValidLiveEnv(t)

	srv := httpguard.New(t)
	if step != nil {
		srv.Script(step)
	}
	fwd := &liveGuardForwardTransport{srvURL: srv.URL}
	rp := fastRetry()
	opts := Options{
		Retry:          &rp,
		HTTPClient:     &http.Client{Transport: fwd},
		LiveJournalDir: t.TempDir() + "/journal",
	}
	if extraOpts != nil {
		if extraOpts.LiveCostCapUSD > 0 {
			opts.LiveCostCapUSD = extraOpts.LiveCostCapUSD
		}
		if extraOpts.LiveJournalDir != "" {
			opts.LiveJournalDir = extraOpts.LiveJournalDir
		}
		if extraOpts.LivePolicyPath != "" {
			opts.LivePolicyPath = extraOpts.LivePolicyPath
		}
	}
	a := New(&opts)
	t.Cleanup(func() { _ = a.Close() })
	h := cloudhost.New(cloudhost.Config{
		Provider:  "aws",
		Store:     a,
		Queue:     a,
		Endpoints: Endpoints(),
	})
	h.SetAbortOnError(false)
	return h, a, srv, fwd
}

func stsCallerIdentityXML(account, arn string) string {
	return fmt.Sprintf(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>%s</Arn>
    <UserId>AROAEXAMPLE:session</UserId>
    <Account>%s</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>req-sts-1</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`, arn, account)
}

func TestLiveDoubleOptInAndDefaultSim(t *testing.T) {
	h, _, srv, _ := newLiveTestHost(t, nil, nil)

	// 1. Default (neither set) -> offline fake (0 HTTP calls).
	t.Setenv("LMCLOUD_LIVE", "")
	t.Setenv("LMAWS_LIVE", "")
	if c, _ := h.BucketCreate(false, "fake-bkt"); !c || h.LastError().Code != hostkit.OK {
		t.Fatalf("offline fake BucketCreate: c=%v last=%+v", c, h.LastError())
	}
	if got := len(srv.Requests()); got != 0 {
		t.Fatalf("expected 0 HTTP requests in offline fake mode, got %d", got)
	}

	// 2. Partial opt-in: only LMAWS_LIVE=1 -> InvalidArgument (LiveDoubleOptInRequired).
	t.Setenv("LMCLOUD_LIVE", "")
	t.Setenv("LMAWS_LIVE", "1")
	if _, _ = h.BucketList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveDoubleOptInRequired" {
		t.Fatalf("only LMAWS_LIVE=1: got last=%+v", h.LastError())
	}

	// 3. Partial opt-in: only LMCLOUD_LIVE=1 -> InvalidArgument (LiveDoubleOptInRequired).
	t.Setenv("LMCLOUD_LIVE", "1")
	t.Setenv("LMAWS_LIVE", "")
	if _, _ = h.BucketList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveDoubleOptInRequired" {
		t.Fatalf("only LMCLOUD_LIVE=1: got last=%+v", h.LastError())
	}

	// 4. Invalid non-boolean value -> InvalidArgument (LiveDoubleOptInRequired).
	t.Setenv("LMCLOUD_LIVE", "true")
	t.Setenv("LMAWS_LIVE", "1")
	if _, _ = h.BucketList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveDoubleOptInRequired" {
		t.Fatalf("LMCLOUD_LIVE=true: got last=%+v", h.LastError())
	}

	if got := len(srv.Requests()); got != 0 {
		t.Fatalf("expected 0 HTTP requests during double opt-in failures, got %d", got)
	}
}

func TestLiveEndpointOverridesForbidden(t *testing.T) {
	h, _, srv, _ := newLiveTestHost(t, nil, nil)

	for _, envVar := range []string{
		"LMCLOUD_ENDPOINT",
		"LMCLOUD_STORAGE_ENDPOINT",
		"LMCLOUD_QUEUE_ENDPOINT",
		"LMAWS_ENDPOINT",
		"LMAWS_STORAGE_ENDPOINT",
		"LMAWS_QUEUE_ENDPOINT",
		"AWS_ENDPOINT_URL",
		"AWS_ENDPOINT_URL_S3",
		"AWS_ENDPOINT_URL_SQS",
		"AWS_ENDPOINT_URL_STS",
	} {
		t.Run(envVar, func(t *testing.T) {
			setValidLiveEnv(t)
			t.Setenv(envVar, "https://s3.us-east-1.amazonaws.com")
			if _, _ = h.BucketList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveEndpointOverrideForbidden" {
				t.Fatalf("%s override in live mode: got last=%+v", envVar, h.LastError())
			}
			if _, _ = h.QueueList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveEndpointOverrideForbidden" {
				t.Fatalf("%s override on QueueList in live mode: got last=%+v", envVar, h.LastError())
			}
		})
	}

	// Script-level set_endpoint override in live mode is also forbidden.
	setValidLiveEnv(t)
	if err := h.SetEndpoint("storage", "https://s3.us-east-1.amazonaws.com"); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}
	if _, _ = h.BucketList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveEndpointOverrideForbidden" {
		t.Fatalf("set_endpoint override in live mode: got last=%+v", h.LastError())
	}
	if got := len(srv.Requests()); got != 0 {
		t.Fatalf("expected 0 HTTP requests when endpoint overrides are rejected, got %d", got)
	}
}

func TestLiveAccountRegionAndSTSAttestation(t *testing.T) {
	// 1. Missing LMAWS_LIVE_ACCOUNT (no default fallback).
	t.Run("missing_account_env", func(t *testing.T) {
		h, _, srv, _ := newLiveTestHost(t, nil, nil)
		t.Setenv("LMAWS_LIVE_ACCOUNT", "")
		if _, _ = h.BucketList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveAccountRequired" {
			t.Fatalf("missing LMAWS_LIVE_ACCOUNT: got %+v", h.LastError())
		}
		if len(srv.Requests()) != 0 {
			t.Fatalf("expected 0 requests, got %d", len(srv.Requests()))
		}
	})

	// 2. Wrong LMAWS_LIVE_ACCOUNT env value.
	t.Run("wrong_account_env", func(t *testing.T) {
		h, _, srv, _ := newLiveTestHost(t, nil, nil)
		t.Setenv("LMAWS_LIVE_ACCOUNT", "111122223333")
		if _, _ = h.BucketList(false); h.LastError().Code != hostkit.PermissionDenied || h.LastError().ProviderCode != "LiveAccountNotAllowed" {
			t.Fatalf("wrong LMAWS_LIVE_ACCOUNT: got %+v", h.LastError())
		}
		if len(srv.Requests()) != 0 {
			t.Fatalf("expected 0 requests, got %d", len(srv.Requests()))
		}
	})

	// 3. Missing LMAWS_LIVE_REGION (no default fallback).
	t.Run("missing_region_env", func(t *testing.T) {
		h, _, srv, _ := newLiveTestHost(t, nil, nil)
		t.Setenv("LMAWS_LIVE_REGION", "")
		if _, _ = h.BucketList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveRegionRequired" {
			t.Fatalf("missing LMAWS_LIVE_REGION: got %+v", h.LastError())
		}
		if len(srv.Requests()) != 0 {
			t.Fatalf("expected 0 requests, got %d", len(srv.Requests()))
		}
	})

	// 4. Wrong LMAWS_LIVE_REGION env value.
	t.Run("wrong_region_env", func(t *testing.T) {
		h, _, srv, _ := newLiveTestHost(t, nil, nil)
		t.Setenv("LMAWS_LIVE_REGION", "us-west-2")
		if _, _ = h.BucketList(false); h.LastError().Code != hostkit.PermissionDenied || h.LastError().ProviderCode != "LiveRegionNotAllowed" {
			t.Fatalf("wrong LMAWS_LIVE_REGION: got %+v", h.LastError())
		}
		if len(srv.Requests()) != 0 {
			t.Fatalf("expected 0 requests, got %d", len(srv.Requests()))
		}
	})

	// 5. Conflicting AWS_REGION env value.
	t.Run("conflicting_aws_region", func(t *testing.T) {
		h, _, srv, _ := newLiveTestHost(t, nil, nil)
		t.Setenv("AWS_REGION", "eu-west-1")
		if _, _ = h.BucketList(false); h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "LiveRegionConflict" {
			t.Fatalf("conflicting AWS_REGION: got %+v", h.LastError())
		}
		if len(srv.Requests()) != 0 {
			t.Fatalf("expected 0 requests, got %d", len(srv.Requests()))
		}
	})

	// 6. Simulator dummy credentials ("test"/"test") are rejected before STS call.
	t.Run("sim_dummy_creds_rejected", func(t *testing.T) {
		h, _, srv, _ := newLiveTestHost(t, nil, nil)
		t.Setenv("AWS_ACCESS_KEY_ID", "test")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
		if _, _ = h.BucketList(false); h.LastError().Code != hostkit.Unauthenticated || h.LastError().ProviderCode != "SimCredentialsInLiveForbidden" {
			t.Fatalf("sim dummy creds in live mode: got %+v", h.LastError())
		}
		if len(srv.Requests()) != 0 {
			t.Fatalf("expected 0 requests, got %d", len(srv.Requests()))
		}
	})

	// 7. STS GetCallerIdentity returns a different AWS account -> PermissionDenied (LiveAccountMismatch), 0 S3 calls.
	t.Run("sts_account_mismatch", func(t *testing.T) {
		h, _, srv, _ := newLiveTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Orig-Host") == "sts.us-east-1.amazonaws.com" {
				httpguard.Status(
					http.StatusOK,
					stsCallerIdentityXML("999999999999", "arn:aws:sts::999999999999:assumed-role/awsspot-admin/i-123"),
					"Content-Type: text/xml",
				)(w, r)
				return
			}
			t.Fatalf("unexpected non-STS call to %s", r.Header.Get("X-Orig-Host"))
		})
		if _, _ = h.BucketList(false); h.LastError().Code != hostkit.PermissionDenied || h.LastError().ProviderCode != "LiveAccountMismatch" {
			t.Fatalf("STS account mismatch: got %+v", h.LastError())
		}
		httpguard.AssertCount(t, srv, "POST", 1)
	})

	// 8. STS GetCallerIdentity returns 403 InvalidClientTokenId echoing secrets -> Unauthenticated, secrets scrubbed.
	t.Run("sts_auth_failure_redacts_secrets", func(t *testing.T) {
		secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		sessionTok := "AQoDYXdzEJr1EXAMPLE_SECRET_SESSION_TOKEN"
		accessKey := "AKIAIOSFODNN7EXAMPLE"
		h, _, srv, _ := newLiveTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) {
			httpguard.Status(
				http.StatusForbidden,
				fmt.Sprintf(`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>Token %s key %s secret %s invalid</Message></Error></ErrorResponse>`,
					sessionTok, accessKey, secretKey),
				"Content-Type: text/xml",
			)(w, r)
		})
		if _, _ = h.BucketList(false); h.LastError().Code != hostkit.Unauthenticated {
			t.Fatalf("STS 403 InvalidClientTokenId: got %+v", h.LastError())
		}
		msg := h.LastError().Message
		if strings.Contains(msg, secretKey) || strings.Contains(msg, sessionTok) || strings.Contains(msg, accessKey) {
			t.Fatalf("credential values leaked in error message: %q", msg)
		}
		httpguard.AssertCount(t, srv, "POST", 1)
	})
}

func TestLiveReadOnlyOperationsAndCostMetering(t *testing.T) {
	h, a, _, fwd := newLiveTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) {
		origHost := r.Header.Get("X-Orig-Host")
		switch {
		case origHost == "sts.us-east-1.amazonaws.com":
			httpguard.Status(
				http.StatusOK,
				stsCallerIdentityXML(RequiredLiveAccount, "arn:aws:sts::254332045686:assumed-role/awsspot-admin/i-0abcdef1234567890"),
				"Content-Type: text/xml",
			)(w, r)

		case origHost == "s3.us-east-1.amazonaws.com" && r.Method == http.MethodGet && r.URL.Path == "/":
			httpguard.Status(
				http.StatusOK,
				`<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult><Buckets><Bucket><Name>live-bkt-b</Name></Bucket><Bucket><Name>live-bkt-a</Name></Bucket></Buckets></ListAllMyBucketsResult>`,
				"Content-Type: application/xml",
			)(w, r)

		case origHost == "live-bkt-a.s3.us-east-1.amazonaws.com" && r.Method == http.MethodHead && (r.URL.Path == "" || r.URL.Path == "/"):
			httpguard.Status(http.StatusOK, "")(w, r)

		case origHost == "missing-bkt.s3.us-east-1.amazonaws.com" && r.Method == http.MethodHead && (r.URL.Path == "" || r.URL.Path == "/"):
			httpguard.Status(http.StatusNotFound, "")(w, r)

		case origHost == "live-bkt-a.s3.us-east-1.amazonaws.com" && r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
			httpguard.Status(
				http.StatusOK,
				`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>live-bkt-a</Name><IsTruncated>false</IsTruncated><Contents><Key>docs/readme.txt</Key><Size>42</Size><ETag>"etag-readme"</ETag></Contents></ListBucketResult>`,
				"Content-Type: application/xml",
			)(w, r)

		case origHost == "live-bkt-a.s3.us-east-1.amazonaws.com" && r.Method == http.MethodHead && r.URL.Path == "/docs/readme.txt":
			httpguard.Status(
				http.StatusOK,
				"",
				"Content-Length: 42",
				"Content-Type: text/plain",
				`ETag: "etag-readme"`,
				"X-Amz-Meta-Env: prod",
			)(w, r)

		case origHost == "live-bkt-a.s3.us-east-1.amazonaws.com" && r.Method == http.MethodHead && r.URL.Path == "/docs/absent.txt":
			httpguard.Status(http.StatusNotFound, "")(w, r)

		case origHost == "live-bkt-a.s3.us-east-1.amazonaws.com" && r.Method == http.MethodHead && r.URL.Path == "/docs/forbidden.txt":
			httpguard.Status(http.StatusForbidden, "")(w, r)

		case origHost == "sqs.us-east-1.amazonaws.com" && r.Method == http.MethodPost:
			target := r.Header.Get("X-Amz-Target")
			bodyStr := r.Header.Get("X-Orig-Body")
			switch target {
			case "AmazonSQS.ListQueues":
				httpguard.Status(
					http.StatusOK,
					`{"QueueUrls":["https://sqs.us-east-1.amazonaws.com/254332045686/live-q-2","https://sqs.us-east-1.amazonaws.com/254332045686/live-q-1"]}`,
					"Content-Type: application/x-amz-json-1.0",
				)(w, r)
			case "AmazonSQS.GetQueueUrl":
				if strings.Contains(bodyStr, `"live-q-1"`) {
					httpguard.Status(
						http.StatusOK,
						`{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/254332045686/live-q-1"}`,
						"Content-Type: application/x-amz-json-1.0",
					)(w, r)
				} else {
					httpguard.Status(
						http.StatusBadRequest,
						`{"__type":"com.amazonaws.sqs#QueueDoesNotExist","message":"The specified queue does not exist."}`,
						"Content-Type: application/x-amz-json-1.0",
					)(w, r)
				}
			default:
				t.Fatalf("unexpected SQS target %q", target)
			}

		default:
			t.Fatalf("unexpected live request: %s https://%s%s?%s", r.Method, origHost, r.URL.Path, r.URL.RawQuery)
		}
	})

	// 1. bucket_list -> 5000 nano-USD
	buckets, err := h.BucketList(false)
	if err != nil || h.LastError().Code != hostkit.OK || len(buckets) != 2 || buckets[0] != "live-bkt-a" || buckets[1] != "live-bkt-b" {
		t.Fatalf("BucketList: buckets=%v err=%v last=%+v", buckets, err, h.LastError())
	}

	// 2. bucket_exists (hit + miss) -> 400 + 400 = 800 nano-USD
	if ex, _ := h.BucketExists(false, "live-bkt-a"); !ex || h.LastError().Code != hostkit.OK {
		t.Fatalf("BucketExists(live-bkt-a): ex=%v last=%+v", ex, h.LastError())
	}
	if ex, _ := h.BucketExists(false, "missing-bkt"); ex || h.LastError().Code != hostkit.OK {
		t.Fatalf("BucketExists(missing-bkt): ex=%v last=%+v", ex, h.LastError())
	}

	// 3. object_list & object_list_all -> 5000 + 5000 = 10000 nano-USD
	page, err := h.ObjectList(false, "live-bkt-a", "docs/", 10, "")
	if err != nil || h.LastError().Code != hostkit.OK || len(page.Items) != 1 || page.Items[0].Key != "docs/readme.txt" {
		t.Fatalf("ObjectList: page=%+v err=%v last=%+v", page, err, h.LastError())
	}
	keys, err := h.ObjectListAll(false, "live-bkt-a", "docs/")
	if err != nil || h.LastError().Code != hostkit.OK || len(keys) != 1 || keys[0] != "docs/readme.txt" {
		t.Fatalf("ObjectListAll: keys=%v err=%v last=%+v", keys, err, h.LastError())
	}

	// 4. object_head (hit: 400 nano-USD; miss in existing bucket: 400 HeadObject + 400 HeadBucket = 800 nano-USD; 403: 400 nano-USD and NO GetObject)
	meta, err := h.ObjectHead(false, "live-bkt-a", "docs/readme.txt")
	if err != nil || h.LastError().Code != hostkit.OK || !meta.Exists || meta.Size != 42 || meta.ETag != "etag-readme" || meta.Metadata["env"] != "prod" {
		t.Fatalf("ObjectHead hit: meta=%+v err=%v last=%+v", meta, err, h.LastError())
	}
	metaMiss, err := h.ObjectHead(false, "live-bkt-a", "docs/absent.txt")
	if err != nil || h.LastError().Code != hostkit.OK || metaMiss.Exists {
		t.Fatalf("ObjectHead miss: meta=%+v err=%v last=%+v", metaMiss, err, h.LastError())
	}
	metaForbid, _ := h.ObjectHead(false, "live-bkt-a", "docs/forbidden.txt")
	if metaForbid.Exists || h.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("ObjectHead 403: meta=%+v last=%+v", metaForbid, h.LastError())
	}

	// 5. queue_list -> 400 nano-USD
	queues, err := h.QueueList(false)
	if err != nil || h.LastError().Code != hostkit.OK || len(queues) != 2 || queues[0] != "live-q-1" || queues[1] != "live-q-2" {
		t.Fatalf("QueueList: queues=%v err=%v last=%+v", queues, err, h.LastError())
	}

	// 6. queue_exists (hit + miss) -> 400 + 400 = 800 nano-USD
	if qex, _ := h.QueueExists(false, "live-q-1"); !qex || h.LastError().Code != hostkit.OK {
		t.Fatalf("QueueExists(live-q-1): qex=%v last=%+v", qex, h.LastError())
	}
	if qex, _ := h.QueueExists(false, "missing-q"); qex || h.LastError().Code != hostkit.OK {
		t.Fatalf("QueueExists(missing-q): qex=%v last=%+v", qex, h.LastError())
	}

	// Verify every wire request used https:// and carried AWS4-HMAC-SHA256 signature.
	wireReqs := fwd.records()
	if len(wireReqs) == 0 {
		t.Fatal("expected recorded wire requests")
	}
	for i, wr := range wireReqs {
		if wr.Scheme != "https" {
			t.Fatalf("wire request %d used scheme %q, want https", i, wr.Scheme)
		}
		if !strings.HasPrefix(wr.Auth, "AWS4-HMAC-SHA256 ") {
			t.Fatalf("wire request %d missing SigV4 Authorization header: %q", i, wr.Auth)
		}
	}

	// Verify hostkit/safety CostMeter and Journal state:
	// Expected nano-USD:
	//   bucket_list:   5000
	//   bucket_exists: 400 * 2 = 800
	//   object_list:   5000 * 2 = 10000
	//   object_head:   400 (hit) + (400 + 400) (miss + HeadBucket) + 400 (403) = 1600
	//   queue_list:    400
	//   queue_exists:  400 * 2 = 800
	// Total = 18600 nano-USD.
	sess := a.LiveSession()
	if sess == nil {
		t.Fatal("expected non-nil LiveSession")
	}
	snap := sess.Meter().Snapshot()
	if snap.CapNanoUSD != safety.USDToNano(0.05) {
		t.Fatalf("default cap = %d nano-USD, want %d ($0.05)", snap.CapNanoUSD, safety.USDToNano(0.05))
	}
	const wantCharged int64 = 18600
	if snap.ChargedNanoUSD != wantCharged || snap.InFlightNanoUSD != 0 {
		t.Fatalf("meter snapshot: charged=%d inFlight=%d, want charged=%d inFlight=0",
			snap.ChargedNanoUSD, snap.InFlightNanoUSD, wantCharged)
	}
	jState := sess.Journal().State()
	if jState.ChargedNanoUSD != wantCharged || len(jState.PendingAttempts) != 0 {
		t.Fatalf("journal state: charged=%d pendingAttempts=%d, want charged=%d pending=0",
			jState.ChargedNanoUSD, len(jState.PendingAttempts), wantCharged)
	}
}

func TestLiveCostCapEnforcedOnReadOps(t *testing.T) {
	// Cap = 0.00001 USD (10,000 nano-USD). With 20% cleanup reserve (2,000 nano-USD),
	// work ceiling is 8,000 nano-USD: enough for 1 bucket_list (5,000 nano-USD),
	// but the 2nd bucket_list (projected 10,000 > 8,000) must fail closed before dispatch.
	var s3ListCount int
	h, _, _, _ := newLiveTestHost(t, &Options{LiveCostCapUSD: 0.00001}, func(w http.ResponseWriter, r *http.Request) {
		origHost := r.Header.Get("X-Orig-Host")
		if origHost == "sts.us-east-1.amazonaws.com" {
			httpguard.Status(
				http.StatusOK,
				stsCallerIdentityXML(RequiredLiveAccount, "arn:aws:iam::254332045686:role/awsspot-admin"),
				"Content-Type: text/xml",
			)(w, r)
			return
		}
		if origHost == "s3.us-east-1.amazonaws.com" {
			s3ListCount++
			httpguard.Status(
				http.StatusOK,
				`<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult><Buckets><Bucket><Name>b1</Name></Bucket></Buckets></ListAllMyBucketsResult>`,
				"Content-Type: application/xml",
			)(w, r)
			return
		}
		t.Fatalf("unexpected request to %s", origHost)
	})

	if b, _ := h.BucketList(false); len(b) != 1 || h.LastError().Code != hostkit.OK {
		t.Fatalf("first BucketList: b=%v last=%+v", b, h.LastError())
	}
	if b, _ := h.BucketList(false); b != nil || h.LastError().Code != hostkit.PermissionDenied || h.LastError().ProviderCode != "LiveCostCapExceeded" {
		t.Fatalf("second BucketList should exceed cost cap: b=%v last=%+v", b, h.LastError())
	}
	if s3ListCount != 1 {
		t.Fatalf("expected exactly 1 S3 ListBuckets HTTP call before cost cap abort, got %d", s3ListCount)
	}
}

func TestLiveMutatingOpsAndGetObjectRefusedStage1(t *testing.T) {
	h, _, srv, _ := newLiveTestHost(t, nil, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected HTTP request during stage 1 mutating/disallowed op: %s %s", r.Method, r.URL.Path)
	})

	assertRefused := func(name string, fn func()) {
		t.Helper()
		fn()
		last := h.LastError()
		if last.Code != hostkit.PermissionDenied || last.ProviderCode != "LiveMutationDisabled" {
			t.Fatalf("%s: got code=%s provider_code=%q msg=%q, want PERMISSION_DENIED / LiveMutationDisabled",
				name, last.Code, last.ProviderCode, last.Message)
		}
	}

	assertRefused("bucket_create", func() { _, _ = h.BucketCreate(false, "lmcloud-conf-0123456789ab-bkt-1") })
	assertRefused("bucket_delete", func() { _, _ = h.BucketDelete(false, "lmcloud-conf-0123456789ab-bkt-1") })
	assertRefused("object_put", func() {
		_, _ = h.ObjectPut(false, "lmcloud-conf-0123456789ab-bkt-1", "k.txt", "hello", "text/plain", nil)
	})
	assertRefused("object_delete", func() { _ = h.ObjectDelete(false, "lmcloud-conf-0123456789ab-bkt-1", "k.txt") })
	assertRefused("object_get", func() { _, _ = h.ObjectGet(false, "lmcloud-conf-0123456789ab-bkt-1", "k.txt") })
	assertRefused("queue_create", func() { _, _ = h.QueueCreate(false, "lmcloud-conf-0123456789ab-q-1") })
	assertRefused("queue_delete", func() { _, _ = h.QueueDelete(false, "lmcloud-conf-0123456789ab-q-1") })
	assertRefused("queue_send", func() { _, _ = h.QueueSend(false, "lmcloud-conf-0123456789ab-q-1", "msg") })
	assertRefused("queue_receive", func() { _, _ = h.QueueReceive(false, "lmcloud-conf-0123456789ab-q-1", 1, 0, 30) })
	assertRefused("queue_ack", func() { _ = h.QueueAck(false, "lmcloud-conf-0123456789ab-q-1", "rh-1") })
	assertRefused("queue_nack", func() { _, _ = h.QueueNack(false, "lmcloud-conf-0123456789ab-q-1", "rh-1", 10) })

	if got := len(srv.Requests()); got != 0 {
		t.Fatalf("expected 0 HTTP requests for refused stage 1 ops, got %d", got)
	}
}

func TestLiveTransportGuardBlocksDisallowedWireRequests(t *testing.T) {
	tr := &liveEndpointGuardTransport{
		region: "us-east-1",
		base: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	}
	sigHeader := "AWS4-HMAC-SHA256 Credential=AKIA/20261103/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abcd"

	cases := []struct {
		name   string
		method string
		rawURL string
		auth   string
		target string
		body   string
	}{
		{"plain http", http.MethodGet, "http://s3.us-east-1.amazonaws.com/", sigHeader, "", ""},
		{"loopback https", http.MethodGet, "https://127.0.0.1:4566/", sigHeader, "", ""},
		{"unsigned request", http.MethodGet, "https://s3.us-east-1.amazonaws.com/", "", "", ""},
		{"wrong region host", http.MethodGet, "https://s3.us-west-2.amazonaws.com/", sigHeader, "", ""},
		{"S3 PUT bucket", http.MethodPut, "https://bkt.s3.us-east-1.amazonaws.com/", sigHeader, "", ""},
		{"S3 DELETE object", http.MethodDelete, "https://bkt.s3.us-east-1.amazonaws.com/key.txt", sigHeader, "", ""},
		{"S3 GetObject", http.MethodGet, "https://bkt.s3.us-east-1.amazonaws.com/key.txt", sigHeader, "", ""},
		{"S3 ranged GetObject", http.MethodGet, "https://bkt.s3.us-east-1.amazonaws.com/key.txt?x-id=GetObject", sigHeader, "", ""},
		{"SQS CreateQueue", http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", sigHeader, "AmazonSQS.CreateQueue", `{}`},
		{"SQS ReceiveMessage", http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", sigHeader, "AmazonSQS.ReceiveMessage", `{}`},
		{"STS AssumeRole", http.MethodPost, "https://sts.us-east-1.amazonaws.com/", sigHeader, "", "Action=AssumeRole&Version=2011-06-15"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.rawURL, strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			if tc.target != "" {
				req.Header.Set("X-Amz-Target", tc.target)
			}
			if _, err := tr.RoundTrip(req); err == nil {
				t.Fatalf("expected liveEndpointGuardTransport to block %s (%s %s), but it succeeded", tc.name, tc.method, tc.rawURL)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
