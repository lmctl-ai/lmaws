// SPDX-License-Identifier: MIT

package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

const (
	// RequiredLiveAccount is the operator-approved AWS account ID for Stage 1/2 live mode.
	RequiredLiveAccount = "254332045686"
	// RequiredLiveRegion is the operator-approved AWS region for Stage 1/2 live mode.
	RequiredLiveRegion = "us-east-1"
	// liveConformancePrefix is the mandatory prefix for Stage 2 live conformance resources.
	liveConformancePrefix = "lmcloud-conf-"

	// Conservative internet egress rate ($0.09 / GiB = 90,000,000 nano-USD / GiB).
	liveEgressGiBNanoUSD int64 = 90_000_000
	liveBytesPerGiB      int64 = 1024 * 1024 * 1024

	// Escaped-XML worst-case sizing for S3 ListObjectsV2:
	// A 1024-byte S3 key with every character XML-escaped (e.g. &quot; / &apos; = 6x)
	// is 6144 bytes, plus ~512 bytes of <Contents> metadata = 6656 bytes per item,
	// plus 32 KiB for the XML envelope and escaped Prefix/ContinuationToken.
	liveWorstCaseItemXMLBytes     int64 = 6656
	liveWorstCaseEnvelopeXMLBytes int64 = 32 * 1024

	// Hard response body and page bounds for live operations.
	maxLiveObjectListPageSize   int   = 100
	maxLiveBucketListPageSize   int32 = 100
	maxLiveQueueListPageSize    int32 = 100
	maxLiveSmallRespBodyBytes   int64 = 64 * 1024   // 64 KiB bound for GetBucketLocation / GetQueueUrl / Tagging
	maxLiveListRespBodyBytes    int64 = 512 * 1024  // 512 KiB bound for ListBuckets / ListQueues
	maxLiveReceiveRespBodyBytes int64 = 1024 * 1024 // 1 MiB bound for SQS ReceiveMessage
	maxLiveResponseBodyBytes    int64 = int64(maxLiveObjectListPageSize)*liveWorstCaseItemXMLBytes + liveWorstCaseEnvelopeXMLBytes
)

// ErrLiveResponseTooLarge is returned when an HTTP response body exceeds the reserved byte bound.
var ErrLiveResponseTooLarge = errors.New("live response body exceeded maximum allowed byte bound")

var forbiddenLiveEndpointEnvs = []string{
	"LMCLOUD_ENDPOINT",
	"LMCLOUD_STORAGE_ENDPOINT",
	"LMCLOUD_QUEUE_ENDPOINT",
	"LMCLOUD_TABLES_ENDPOINT",
	"LMAWS_ENDPOINT",
	"LMAWS_STORAGE_ENDPOINT",
	"LMAWS_QUEUE_ENDPOINT",
	"LMAWS_TABLES_ENDPOINT",
	"AWS_ENDPOINT_URL",
	"AWS_ENDPOINT_URL_S3",
	"AWS_ENDPOINT_URL_SQS",
	"AWS_ENDPOINT_DYNAMODB",
	"AWS_ENDPOINT_URL_DYNAMODB",
	"AWS_ENDPOINT_URL_STS",
	"AWS_ENDPOINT_URL_IAM",
	"AWS_ENDPOINT_URL_SSO",
	"AWS_ENDPOINT_URL_SSOOIDC",
	"AWS_EC2_METADATA_SERVICE_ENDPOINT",
	"STORAGE_EMULATOR_HOST",
	"PUBSUB_EMULATOR_HOST",
	"FIRESTORE_EMULATOR_HOST",
}

var (
	awsAccessKeyPattern = regexp.MustCompile(`\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`)
	jsonSecretPattern   = regexp.MustCompile(`(?i)"(SecretAccessKey|SessionToken|SecurityToken|AccessToken|RefreshToken|ClientSecret|IdToken|Authorization)"\s*:\s*"([^"]+)"`)
	iniSecretPattern    = regexp.MustCompile(`(?im)^\s*(aws_secret_access_key|aws_session_token|aws_security_token)\s*=\s*(\S+)`)
)

type liveEnvConfig struct {
	account    string
	region     string
	runID      string
	journalDir string
	policyPath string
	policyHash string
	principal  string
	costCapUSD float64
	mutate     bool
	maxBuckets int
	maxQueues  int
}

func isForbiddenLiveEndpointEnvKey(k string) bool {
	if slices.Contains(forbiddenLiveEndpointEnvs, k) {
		return true
	}
	if strings.HasPrefix(k, "AWS_ENDPOINT_URL") || strings.HasPrefix(k, "AWS_ENDPOINT_") {
		return true
	}
	if (strings.HasPrefix(k, "LMCLOUD_") || strings.HasPrefix(k, "LMAWS_")) && strings.Contains(k, "ENDPOINT") {
		return true
	}
	return false
}

// isFixedLinkLocalCredHost returns true only for the fixed IPv4 link-local addresses
// permitted for Stage 1 live credential resolution:
//   - EC2 IMDSv2: 169.254.169.254
//   - ECS task container credentials: 169.254.170.2
func isFixedLinkLocalCredHost(host string, allowIMDS bool) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if allowIMDS && v4.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	return v4.Equal(net.IPv4(169, 254, 170, 2))
}

func validateContainerFullURI(rawURI string) *hostkit.CloudError {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return nil
	}
	u, err := url.Parse(rawURI)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"LiveCredentialEndpointForbidden",
			"AWS_CONTAINER_CREDENTIALS_FULL_URI must be an http:// URI to fixed link-local 169.254.170.2 without userinfo, query, or fragment",
		)
	}
	if port := u.Port(); port != "" && port != "80" {
		return hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"LiveCredentialEndpointForbidden",
			fmt.Sprintf("AWS_CONTAINER_CREDENTIALS_FULL_URI port %q is not permitted in live mode", port),
		)
	}
	host := u.Hostname()
	if !isFixedLinkLocalCredHost(host, false) {
		return hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"LiveCredentialEndpointForbidden",
			fmt.Sprintf("AWS_CONTAINER_CREDENTIALS_FULL_URI host %q is forbidden in live mode (only fixed link-local 169.254.170.2 is allowed)", host),
		)
	}
	return nil
}

func validateLiveGates(ctx context.Context, getenv func(string) string, opts *Options) (liveEnvConfig, *hostkit.CloudError) {
	if ep := strings.TrimSpace(hostkit.EndpointFrom(ctx)); ep != "" {
		return liveEnvConfig{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"LiveEndpointOverrideForbidden",
			"endpoint overrides are forbidden in live mode",
		)
	}
	for _, k := range forbiddenLiveEndpointEnvs {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return liveEnvConfig{}, hostkit.ProviderError(
				hostkit.InvalidArgument,
				0,
				"LiveEndpointOverrideForbidden",
				fmt.Sprintf("endpoint override via %s is forbidden in live mode", k),
			)
		}
	}
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		if isForbiddenLiveEndpointEnvKey(k) && strings.TrimSpace(getenv(k)) != "" {
			return liveEnvConfig{}, hostkit.ProviderError(
				hostkit.InvalidArgument,
				0,
				"LiveEndpointOverrideForbidden",
				fmt.Sprintf("endpoint override via %s is forbidden in live mode", k),
			)
		}
	}

	if strings.TrimSpace(getenv("LMAWS_LIVE_ALLOW_CREDENTIAL_PROCESS")) != "" {
		return liveEnvConfig{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveCredentialProcessForbidden",
			"credential_process and SSO are not supported in live mode",
		)
	}

	if cerr := validateContainerFullURI(getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")); cerr != nil {
		return liveEnvConfig{}, cerr
	}

	acct := strings.TrimSpace(getenv("LMAWS_LIVE_ACCOUNT"))
	if acct == "" {
		return liveEnvConfig{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"LiveAccountRequired",
			"live mode requires LMAWS_LIVE_ACCOUNT to be set explicitly (no default fallback)",
		)
	}
	if acct != RequiredLiveAccount {
		return liveEnvConfig{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveAccountNotAllowed",
			fmt.Sprintf("LMAWS_LIVE_ACCOUNT %q is not permitted (required: %q)", acct, RequiredLiveAccount),
		)
	}

	reg := strings.TrimSpace(getenv("LMAWS_LIVE_REGION"))
	if reg == "" {
		return liveEnvConfig{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"LiveRegionRequired",
			"live mode requires LMAWS_LIVE_REGION to be set explicitly (no default fallback)",
		)
	}
	if reg != RequiredLiveRegion {
		return liveEnvConfig{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveRegionNotAllowed",
			fmt.Sprintf("LMAWS_LIVE_REGION %q is not permitted (required: %q)", reg, RequiredLiveRegion),
		)
	}

	for _, regVar := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := strings.TrimSpace(getenv(regVar)); v != "" && v != reg {
			return liveEnvConfig{}, hostkit.ProviderError(
				hostkit.InvalidArgument,
				0,
				"LiveRegionConflict",
				fmt.Sprintf("%s=%q conflicts with LMAWS_LIVE_REGION=%q", regVar, v, reg),
			)
		}
	}

	rawMutate := strings.TrimSpace(getenv("LMAWS_LIVE_MUTATE"))
	if rawMutate != "" && rawMutate != "0" && rawMutate != "1" {
		return liveEnvConfig{}, hostkit.ProviderError(
			hostkit.InvalidArgument,
			0,
			"InvalidLiveOptIn",
			fmt.Sprintf("LMAWS_LIVE_MUTATE must be '1', '0', or unset (got %q)", rawMutate),
		)
	}
	mutate := rawMutate == "1"

	var costCap float64
	if opts != nil && opts.LiveCostCapUSD > 0 {
		costCap = opts.LiveCostCapUSD
	}
	for _, capVar := range []string{"LMAWS_LIVE_COST_CAP_USD", "LMCLOUD_LIVE_COST_CAP_USD"} {
		if raw := strings.TrimSpace(getenv(capVar)); raw != "" {
			parsed, err := strconv.ParseFloat(raw, 64)
			if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed <= 0 {
				return liveEnvConfig{}, hostkit.ProviderError(
					hostkit.InvalidArgument,
					0,
					"InvalidLiveCostCap",
					fmt.Sprintf("invalid %s=%q: must be a positive USD number", capVar, raw),
				)
			}
			maxAllowedCap := safety.DefaultCostCapUSD
			if mutate {
				maxAllowedCap = safety.HardCostCeilingUSD
			}
			if parsed > maxAllowedCap {
				pcode := "LiveCostCapExceedsDefault"
				if mutate {
					pcode = "LiveCostCapExceedsCeiling"
				}
				return liveEnvConfig{}, hostkit.ProviderError(
					hostkit.PermissionDenied,
					0,
					pcode,
					fmt.Sprintf("%s=%.6f exceeds maximum allowed live cap ($%.2f)", capVar, parsed, maxAllowedCap),
				)
			}
			if costCap == 0 || parsed < costCap {
				costCap = parsed
			}
		}
	}

	var maxBuckets, maxQueues int
	if mutate {
		if raw := strings.TrimSpace(getenv("LMAWS_LIVE_MAX_BUCKETS")); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 4 {
				return liveEnvConfig{}, hostkit.ProviderError(
					hostkit.InvalidArgument,
					0,
					"InvalidLiveResourceLimit",
					fmt.Sprintf("invalid LMAWS_LIVE_MAX_BUCKETS=%q (must be 1..4)", raw),
				)
			}
			maxBuckets = n
		}
		if raw := strings.TrimSpace(getenv("LMAWS_LIVE_MAX_QUEUES")); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 4 {
				return liveEnvConfig{}, hostkit.ProviderError(
					hostkit.InvalidArgument,
					0,
					"InvalidLiveResourceLimit",
					fmt.Sprintf("invalid LMAWS_LIVE_MAX_QUEUES=%q (must be 1..4)", raw),
				)
			}
			maxQueues = n
		}
	}

	jDir := ""
	if opts != nil && strings.TrimSpace(opts.LiveJournalDir) != "" {
		jDir = strings.TrimSpace(opts.LiveJournalDir)
	}
	if jDir == "" {
		jDir = strings.TrimSpace(getenv("LMAWS_LIVE_JOURNAL_DIR"))
	}
	if jDir == "" {
		jDir = strings.TrimSpace(getenv("LMCLOUD_LIVE_JOURNAL_DIR"))
	}

	polPath := ""
	if opts != nil && strings.TrimSpace(opts.LivePolicyPath) != "" {
		polPath = strings.TrimSpace(opts.LivePolicyPath)
	}
	if polPath == "" {
		polPath = strings.TrimSpace(getenv("LMAWS_LIVE_POLICY"))
	}
	if polPath == "" {
		polPath = strings.TrimSpace(getenv("LMCLOUD_LIVE_POLICY"))
	}

	runID := strings.TrimSpace(getenv("LMAWS_RUN_ID"))
	if runID == "" {
		runID = strings.TrimSpace(getenv("LMCLOUD_RUN_ID"))
	}

	return liveEnvConfig{
		account:    acct,
		region:     reg,
		runID:      runID,
		journalDir: jDir,
		policyPath: polPath,
		policyHash: strings.TrimSpace(getenv("LMCLOUD_POLICY_SHA256")),
		principal:  strings.TrimSpace(getenv("LMAWS_LIVE_PRINCIPAL")),
		costCapUSD: costCap,
		mutate:     mutate,
		maxBuckets: maxBuckets,
		maxQueues:  maxQueues,
	}, nil
}

func stage1MutationDisabledErr(op string) *hostkit.CloudError {
	return hostkit.ProviderError(
		hostkit.PermissionDenied,
		0,
		"LiveMutationDisabled",
		fmt.Sprintf("%s is disabled in stage 1 live read-only mode", op),
	)
}

func liveEgressNanoUSD(nBytes int64) int64 {
	if nBytes <= 0 {
		return 0
	}
	num := float64(nBytes) * float64(liveEgressGiBNanoUSD)
	nano := int64(math.Ceil(num / float64(liveBytesPerGiB)))
	if nano < 1 {
		nano = 1
	}
	return nano
}

func objectListWorstCaseBytes(maxKeys int) int64 {
	if maxKeys <= 0 || maxKeys > maxLiveObjectListPageSize {
		maxKeys = maxLiveObjectListPageSize
	}
	return int64(maxKeys)*liveWorstCaseItemXMLBytes + liveWorstCaseEnvelopeXMLBytes
}

func parseStrictQuery(rawQuery string) (url.Values, error) {
	if rawQuery == "" {
		return url.Values{}, nil
	}
	if strings.Contains(rawQuery, ";") {
		return nil, errors.New("semicolon query separator is forbidden")
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	for k, v := range vals {
		if k == "" || len(v) != 1 {
			return nil, fmt.Errorf("duplicate or empty query parameter %q", k)
		}
	}
	return vals, nil
}

func hasOnlyAllowedKeys(vals url.Values, allowed ...string) bool {
	for k := range vals {
		if !slices.Contains(allowed, k) {
			return false
		}
	}
	return true
}

func validateHostAuthority(req *http.Request) (string, error) {
	if req == nil || req.URL == nil {
		return "", errors.New("nil request or URL")
	}
	if req.URL.User != nil || req.URL.Fragment != "" || req.URL.Opaque != "" {
		return "", errors.New("refused URL with userinfo, opaque part, or fragment")
	}
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		return "", errors.New("refused empty URL host")
	}
	if req.Host != "" {
		reqHost := strings.ToLower(req.Host)
		urlHost := strings.ToLower(req.URL.Host)
		if reqHost != urlHost && reqHost != host {
			return "", fmt.Errorf("refused conflicting Host header %q vs URL host %q", req.Host, req.URL.Host)
		}
	}
	return host, nil
}

// liveCredGuardTransport enforces the Stage 1 endpoint allowlist on all HTTP
// traffic performed by the explicit AWS credential chain:
//  1. Fixed link-local HTTP addresses only for EC2 IMDSv2 (169.254.169.254)
//     and ECS task container metadata (169.254.170.2).
//  2. HTTPS only to approved STS endpoints (sts.<region>.amazonaws.com / sts.amazonaws.com)
//     for AssumeRoleWithWebIdentity.
//  3. Bounded response bodies (<= 64 KiB) to prevent memory exhaustion.
type liveCredGuardTransport struct {
	region string
	base   http.RoundTripper
}

func isAllowedCredSTSHost(host, region string) bool {
	return host == "sts.amazonaws.com" || host == "sts."+region+".amazonaws.com"
}

func (t *liveCredGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host, err := validateHostAuthority(req)
	if err != nil {
		return nil, fmt.Errorf("live credential transport: %w", err)
	}
	scheme := strings.ToLower(req.URL.Scheme)
	port := req.URL.Port()

	switch scheme {
	case "http":
		if port != "" && port != "80" {
			return nil, fmt.Errorf("live credential transport refused HTTP port %q", port)
		}
		if !isFixedLinkLocalCredHost(host, true) {
			return nil, fmt.Errorf("live credential transport refused non-link-local HTTP host %q", host)
		}
		ip := net.ParseIP(strings.Trim(host, "[]")).To4()
		isIMDS := ip != nil && ip.Equal(net.IPv4(169, 254, 169, 254))
		if isIMDS {
			if req.Method == http.MethodPut {
				if req.URL.Path != "/latest/api/token" || req.URL.RawQuery != "" {
					return nil, fmt.Errorf("live credential transport refused IMDS PUT path %q", req.URL.Path)
				}
			} else if req.Method == http.MethodGet {
				if !strings.HasPrefix(req.URL.Path, "/latest/meta-data/iam/security-credentials") || req.URL.RawQuery != "" {
					return nil, fmt.Errorf("live credential transport refused IMDS GET path %q", req.URL.Path)
				}
			} else {
				return nil, fmt.Errorf("live credential transport refused IMDS method %s", req.Method)
			}
		} else {
			if req.Method != http.MethodGet {
				return nil, fmt.Errorf("live credential transport refused container metadata method %s", req.Method)
			}
		}

	case "https":
		if port != "" && port != "443" {
			return nil, fmt.Errorf("live credential transport refused HTTPS port %q", port)
		}
		if hostkit.IsLoopbackHost(host) || net.ParseIP(host) != nil {
			return nil, fmt.Errorf("live credential transport refused loopback or IP host %q", host)
		}
		if !isAllowedCredSTSHost(host, t.region) {
			return nil, fmt.Errorf("live credential transport refused unapproved HTTPS host %q", host)
		}
		if req.Method != http.MethodPost || (req.URL.Path != "" && req.URL.Path != "/") || req.URL.RawQuery != "" {
			return nil, errors.New("live credential transport refused malformed STS credential request")
		}
		if req.Body == nil {
			return nil, errors.New("live credential transport refused empty STS credential request body")
		}
		b, rerr := io.ReadAll(io.LimitReader(req.Body, 16*1024+1))
		if rerr != nil {
			return nil, rerr
		}
		if len(b) > 16*1024 {
			return nil, errors.New("live credential transport refused oversized STS request body")
		}
		req.Body = io.NopCloser(bytes.NewReader(b))
		vals, perr := parseStrictQuery(string(b))
		if perr != nil {
			return nil, fmt.Errorf("live credential transport refused invalid STS form body: %w", perr)
		}
		act := vals.Get("Action")
		if act != "AssumeRoleWithWebIdentity" {
			return nil, fmt.Errorf("live credential transport refused STS action %q", act)
		}

	default:
		return nil, fmt.Errorf("live credential transport refused scheme %q", req.URL.Scheme)
	}

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		resp.Body = &boundedResponseBody{
			rc:       resp.Body,
			maxBytes: maxLiveSmallRespBodyBytes,
		}
	}
	return resp, nil
}

type respBytesTrackerKey struct{}

type respBytesTracker struct {
	mu           sync.Mutex
	maxBytes     int64
	bytesRead    int64
	completedEOF bool
	tooLarge     bool
	readErr      error
}

func (tr *respBytesTracker) record(n int64, eof, tooLarge bool, rerr error) {
	if tr == nil {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.bytesRead += n
	if eof {
		tr.completedEOF = true
	}
	if tooLarge {
		tr.tooLarge = true
	}
	if rerr != nil && !errors.Is(rerr, io.EOF) && tr.readErr == nil {
		tr.readErr = rerr
	}
}

func (tr *respBytesTracker) snapshot() (int64, bool, bool, error) {
	if tr == nil {
		return 0, true, false, nil
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.bytesRead, tr.completedEOF, tr.tooLarge, tr.readErr
}

type boundedResponseBody struct {
	rc        io.ReadCloser
	maxBytes  int64
	readSoFar int64
	tracker   *respBytesTracker
	done      bool
	tooLarge  bool
	stickyErr error
}

func (b *boundedResponseBody) Read(p []byte) (int, error) {
	if b.tooLarge {
		return 0, ErrLiveResponseTooLarge
	}
	if b.stickyErr != nil {
		return 0, b.stickyErr
	}
	if b.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.maxBytes >= 0 {
		// Allow reading at most (maxBytes - readSoFar) + 1 bytes so we detect overflow
		// at maxBytes+1 without ever reading unbounded data into caller buffers.
		rem := (b.maxBytes - b.readSoFar) + 1
		if rem <= 0 {
			b.tooLarge = true
			b.done = true
			b.tracker.record(0, false, true, ErrLiveResponseTooLarge)
			return 0, ErrLiveResponseTooLarge
		}
		if int64(len(p)) > rem {
			p = p[:rem]
		}
	}

	n, err := b.rc.Read(p)
	if n > 0 {
		b.readSoFar += int64(n)
		if b.maxBytes >= 0 && b.readSoFar > b.maxBytes {
			b.tooLarge = true
			b.done = true
			allowed := int(b.maxBytes - (b.readSoFar - int64(n)))
			if allowed < 0 {
				allowed = 0
			}
			b.tracker.record(int64(n), false, true, ErrLiveResponseTooLarge)
			return allowed, ErrLiveResponseTooLarge
		}
		b.tracker.record(int64(n), false, false, nil)
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			b.done = true
			b.tracker.record(0, true, false, nil)
		} else {
			b.stickyErr = err
			b.tracker.record(0, false, false, err)
		}
	}
	return n, err
}

func (b *boundedResponseBody) Close() error {
	return b.rc.Close()
}

// liveEndpointGuardTransport enforces at the HTTP transport boundary that every
// outgoing business request in Stage 1 live mode:
//  1. Uses https:// on standard port 443 with no userinfo, fragment, or Host mismatch.
//  2. Targets only the canonical AWS endpoints in the approved region (sts, s3, sqs).
//  3. Carries a single non-empty SigV4 Authorization header (AWS4-HMAC-SHA256).
//  4. Parses query/form/JSON strictly (no duplicates, no unknown params, no trailing data, no object-path GETs).
//  5. Requires X-Amz-Expected-Bucket-Owner=<account> on all bucket-scoped S3 calls.
//  6. Bounds response body size to the exact pre-dispatch reservation and tracks response egress bytes.
type liveEndpointGuardTransport struct {
	region         string
	account        string
	allowMutations bool
	base           http.RoundTripper
}

func extractLiveS3BucketFromHost(host, region string) (string, bool) {
	s3Regional := "s3." + region + ".amazonaws.com"
	if host == s3Regional || host == "s3.amazonaws.com" {
		return "", true
	}
	for _, suffix := range []string{"." + s3Regional, ".s3.amazonaws.com"} {
		if strings.HasSuffix(host, suffix) {
			prefix := strings.TrimSuffix(host, suffix)
			if prefix != "" && !strings.Contains(prefix, ".") {
				return prefix, false
			}
		}
	}
	return "", false
}

func isAllowedLiveS3Host(host, region string) bool {
	bkt, isRoot := extractLiveS3BucketFromHost(host, region)
	return isRoot || bkt != ""
}

func parseFlatJSONStringMap(dec *json.Decoder) (map[string]string, error) {
	seen := make(map[string]bool)
	out := make(map[string]string)
	for dec.More() {
		kTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, ok := kTok.(string)
		if !ok || k == "" {
			return nil, errors.New("map key must be a non-empty string")
		}
		if seen[k] {
			return nil, fmt.Errorf("duplicate map key %q", k)
		}
		seen[k] = true
		vTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		v, ok := vTok.(string)
		if !ok {
			return nil, fmt.Errorf("map value for %q must be a string", k)
		}
		out[k] = v
	}
	endTok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := endTok.(json.Delim); !ok || delim != '}' {
		return nil, errors.New("expected closing brace for string map")
	}
	return out, nil
}

func parseFlatJSONStringSlice(dec *json.Decoder) ([]string, error) {
	var out []string
	for dec.More() {
		vTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		s, ok := vTok.(string)
		if !ok {
			return nil, errors.New("array element must be a string")
		}
		out = append(out, s)
	}
	endTok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := endTok.(json.Delim); !ok || delim != ']' {
		return nil, errors.New("expected closing bracket for string array")
	}
	return out, nil
}

// validateSQSJSONBody strictly validates an SQS JSON protocol request body:
//   - Must be valid JSON (json.Valid).
//   - Top-level value must be a JSON object `{ ... }` (not null, array, or primitive).
//   - No duplicate keys are allowed.
//   - Only fields allowed for the target operation are permitted.
//   - No trailing tokens or closing delimiters after the top-level object are allowed.
func validateSQSJSONBody(target string, body []byte) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return errors.New("empty SQS JSON body")
	}
	if !json.Valid(trimmed) {
		return errors.New("malformed SQS JSON body")
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()

	firstTok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid SQS JSON start token: %w", err)
	}
	if delim, ok := firstTok.(json.Delim); !ok || delim != '{' {
		return errors.New("SQS JSON body must be a top-level JSON object")
	}

	seen := make(map[string]bool)
	fields := make(map[string]any)
	for dec.More() {
		kTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid SQS JSON member key: %w", err)
		}
		key, ok := kTok.(string)
		if !ok || key == "" {
			return errors.New("SQS JSON member key must be a non-empty string")
		}
		if seen[key] {
			return fmt.Errorf("duplicate JSON key %q in SQS payload", key)
		}
		seen[key] = true

		vTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid SQS JSON value for %q: %w", key, err)
		}
		if delim, isDelim := vTok.(json.Delim); isDelim {
			if delim == '{' && (target == "AmazonSQS.CreateQueue" || target == "AmazonSQS.TagQueue") && (key == "tags" || key == "Tags" || key == "Attributes") {
				m, merr := parseFlatJSONStringMap(dec)
				if merr != nil {
					return fmt.Errorf("invalid %s map in %s: %w", key, target, merr)
				}
				fields[key] = m
				continue
			}
			if delim == '[' && (target == "AmazonSQS.ReceiveMessage" || target == "AmazonSQS.GetQueueAttributes") &&
				(key == "AttributeNames" || key == "MessageSystemAttributeNames" || key == "MessageAttributeNames") {
				arr, aerr := parseFlatJSONStringSlice(dec)
				if aerr != nil {
					return fmt.Errorf("invalid %s array in %s: %w", key, target, aerr)
				}
				fields[key] = arr
				continue
			}
			return fmt.Errorf("non-scalar value for %q in SQS payload", key)
		}
		if vTok == nil {
			return fmt.Errorf("null value for %q in SQS payload", key)
		}
		fields[key] = vTok
	}

	endTok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("missing closing brace in SQS JSON payload: %w", err)
	}
	if delim, ok := endTok.(json.Delim); !ok || delim != '}' {
		return errors.New("expected closing brace in SQS JSON payload")
	}
	if extraTok, err := dec.Token(); !errors.Is(err, io.EOF) || extraTok != nil {
		return errors.New("trailing data after SQS JSON object")
	}

	switch target {
	case "AmazonSQS.ListQueues":
		for k, v := range fields {
			switch k {
			case "MaxResults":
				num, ok := v.(json.Number)
				if !ok {
					return errors.New("MaxResults must be a JSON number")
				}
				n, err := num.Int64()
				if err != nil || n < 1 || n > 1000 {
					return errors.New("MaxResults must be an integer in [1, 1000]")
				}
			case "NextToken", "QueueNamePrefix":
				if _, ok := v.(string); !ok {
					return fmt.Errorf("%s must be a JSON string", k)
				}
			default:
				return fmt.Errorf("unexpected field %q in ListQueues payload", k)
			}
		}
	case "AmazonSQS.GetQueueUrl":
		qName, ok := fields["QueueName"].(string)
		if !ok || strings.TrimSpace(qName) == "" {
			return errors.New("missing or non-string QueueName in GetQueueUrl payload")
		}
		for k, v := range fields {
			switch k {
			case "QueueName", "QueueOwnerAWSAccountId":
				if s, ok := v.(string); !ok || strings.TrimSpace(s) == "" {
					return fmt.Errorf("%s must be a non-empty JSON string", k)
				}
			default:
				return fmt.Errorf("unexpected field %q in GetQueueUrl payload", k)
			}
		}
	case "AmazonSQS.CreateQueue":
		qName, ok := fields["QueueName"].(string)
		if !ok || !strings.HasPrefix(strings.TrimSpace(qName), liveConformancePrefix) {
			return fmt.Errorf("CreateQueue QueueName %q must start with %q", qName, liveConformancePrefix)
		}
		for k := range fields {
			if k != "QueueName" && k != "tags" && k != "Tags" && k != "Attributes" {
				return fmt.Errorf("unexpected field %q in CreateQueue payload", k)
			}
		}
	case "AmazonSQS.DeleteQueue", "AmazonSQS.ListQueueTags":
		qURL, ok := fields["QueueUrl"].(string)
		if !ok || strings.TrimSpace(qURL) == "" {
			return fmt.Errorf("missing QueueUrl in %s payload", target)
		}
		if len(fields) != 1 {
			return fmt.Errorf("unexpected extra fields in %s payload", target)
		}
	case "AmazonSQS.TagQueue":
		qURL, ok := fields["QueueUrl"].(string)
		if !ok || strings.TrimSpace(qURL) == "" {
			return errors.New("missing QueueUrl in TagQueue payload")
		}
		for k := range fields {
			if k != "QueueUrl" && k != "Tags" && k != "tags" {
				return fmt.Errorf("unexpected field %q in TagQueue payload", k)
			}
		}
	case "AmazonSQS.GetQueueAttributes":
		qURL, ok := fields["QueueUrl"].(string)
		if !ok || strings.TrimSpace(qURL) == "" {
			return errors.New("missing QueueUrl in GetQueueAttributes payload")
		}
		for k := range fields {
			if k != "QueueUrl" && k != "AttributeNames" {
				return fmt.Errorf("unexpected field %q in GetQueueAttributes payload", k)
			}
		}
	case "AmazonSQS.SendMessage":
		qURL, ok := fields["QueueUrl"].(string)
		if !ok || strings.TrimSpace(qURL) == "" {
			return errors.New("missing QueueUrl in SendMessage payload")
		}
		if _, ok := fields["MessageBody"].(string); !ok {
			return errors.New("missing or non-string MessageBody in SendMessage payload")
		}
		for k := range fields {
			if k != "QueueUrl" && k != "MessageBody" && k != "DelaySeconds" {
				return fmt.Errorf("unexpected field %q in SendMessage payload", k)
			}
		}
	case "AmazonSQS.ReceiveMessage":
		qURL, ok := fields["QueueUrl"].(string)
		if !ok || strings.TrimSpace(qURL) == "" {
			return errors.New("missing QueueUrl in ReceiveMessage payload")
		}
		for k := range fields {
			switch k {
			case "QueueUrl", "MaxNumberOfMessages", "VisibilityTimeout", "WaitTimeSeconds",
				"AttributeNames", "MessageSystemAttributeNames", "MessageAttributeNames":
			default:
				return fmt.Errorf("unexpected field %q in ReceiveMessage payload", k)
			}
		}
	case "AmazonSQS.DeleteMessage":
		qURL, ok := fields["QueueUrl"].(string)
		if !ok || strings.TrimSpace(qURL) == "" {
			return errors.New("missing QueueUrl in DeleteMessage payload")
		}
		if rh, ok := fields["ReceiptHandle"].(string); !ok || strings.TrimSpace(rh) == "" {
			return errors.New("missing ReceiptHandle in DeleteMessage payload")
		}
		if len(fields) != 2 {
			return errors.New("unexpected extra fields in DeleteMessage payload")
		}
	case "AmazonSQS.ChangeMessageVisibility":
		qURL, ok := fields["QueueUrl"].(string)
		if !ok || strings.TrimSpace(qURL) == "" {
			return errors.New("missing QueueUrl in ChangeMessageVisibility payload")
		}
		if rh, ok := fields["ReceiptHandle"].(string); !ok || strings.TrimSpace(rh) == "" {
			return errors.New("missing ReceiptHandle in ChangeMessageVisibility payload")
		}
		if _, ok := fields["VisibilityTimeout"].(json.Number); !ok {
			return errors.New("missing VisibilityTimeout in ChangeMessageVisibility payload")
		}
		if len(fields) != 3 {
			return errors.New("unexpected extra fields in ChangeMessageVisibility payload")
		}
	default:
		return fmt.Errorf("unapproved SQS target %q", target)
	}
	return nil
}

func (t *liveEndpointGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host, err := validateHostAuthority(req)
	if err != nil {
		return nil, fmt.Errorf("live transport: %w", err)
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return nil, fmt.Errorf("live transport refused non-HTTPS scheme %q", req.URL.Scheme)
	}
	if port := req.URL.Port(); port != "" && port != "443" {
		return nil, fmt.Errorf("live transport refused unexpected port %q", port)
	}
	if hostkit.IsLoopbackHost(host) {
		return nil, fmt.Errorf("live transport refused loopback host %q", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil, fmt.Errorf("live transport refused raw IP literal %q", host)
	}

	authHeaders := req.Header.Values("Authorization")
	if len(authHeaders) != 1 {
		return nil, errors.New("live transport refused request without a single Authorization header")
	}
	auth := strings.TrimSpace(authHeaders[0])
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") ||
		!strings.Contains(auth, "Credential=") ||
		!strings.Contains(auth, "Signature=") {
		return nil, errors.New("live transport refused unsigned request (missing AWS4-HMAC-SHA256 Authorization)")
	}

	stsHost := "sts." + t.region + ".amazonaws.com"
	sqsHost := "sqs." + t.region + ".amazonaws.com"
	maxRespBytes := maxLiveResponseBodyBytes

	switch {
	case host == stsHost || host == "sts.amazonaws.com":
		if req.Method != http.MethodPost {
			return nil, fmt.Errorf("live transport refused STS method %s", req.Method)
		}
		if (req.URL.Path != "" && req.URL.Path != "/") || (req.URL.RawPath != "" && req.URL.RawPath != "/") {
			return nil, fmt.Errorf("live transport refused STS path %q", req.URL.Path)
		}
		if req.URL.RawQuery != "" {
			return nil, errors.New("live transport refused STS query parameters")
		}
		if req.Body == nil {
			return nil, errors.New("live transport refused empty STS body")
		}
		b, err := io.ReadAll(io.LimitReader(req.Body, 16*1024+1))
		if err != nil {
			return nil, err
		}
		if len(b) > 16*1024 {
			return nil, errors.New("live transport refused oversized STS body")
		}
		req.Body = io.NopCloser(bytes.NewReader(b))
		vals, perr := parseStrictQuery(string(b))
		if perr != nil {
			return nil, fmt.Errorf("live transport refused malformed STS body: %w", perr)
		}
		if vals.Get("Action") != "GetCallerIdentity" || !hasOnlyAllowedKeys(vals, "Action", "Version") {
			return nil, errors.New("live transport refused STS action other than exact GetCallerIdentity")
		}
		maxRespBytes = maxLiveSmallRespBodyBytes

	case isAllowedLiveS3Host(host, t.region):
		bucketName, isRootServiceHost := extractLiveS3BucketFromHost(host, t.region)
		if strings.Contains(req.URL.Path, "..") || strings.Contains(req.URL.RawPath, "..") || strings.Contains(req.URL.Path, "\\") {
			return nil, errors.New("live transport refused S3 path traversal segment")
		}
		vals, perr := parseStrictQuery(req.URL.RawQuery)
		if perr != nil {
			return nil, fmt.Errorf("live transport refused malformed S3 query: %w", perr)
		}
		xid := vals.Get("x-id")
		isCreateBucket := req.Method == http.MethodPut && !isRootServiceHost &&
			(req.URL.Path == "" || req.URL.Path == "/") && !vals.Has("tagging") &&
			(xid == "" || xid == "CreateBucket")
		if !isRootServiceHost && !isCreateBucket && t.account != "" {
			ownerHdr := strings.TrimSpace(req.Header.Get("X-Amz-Expected-Bucket-Owner"))
			if ownerHdr != t.account {
				return nil, fmt.Errorf("live transport refused S3 bucket request without X-Amz-Expected-Bucket-Owner=%s", t.account)
			}
		}
		isBucketRootPath := (req.URL.Path == "" || req.URL.Path == "/") && (req.URL.RawPath == "" || req.URL.RawPath == "/")

		switch req.Method {
		case http.MethodHead:
			if isRootServiceHost {
				return nil, errors.New("live transport refused S3 HEAD on service root host")
			}
			if !hasOnlyAllowedKeys(vals, "x-id") {
				return nil, errors.New("live transport refused unexpected query parameters on S3 HEAD")
			}
			if xid != "" && xid != "HeadBucket" && xid != "HeadObject" {
				return nil, fmt.Errorf("live transport refused S3 HEAD x-id=%q", xid)
			}
			maxRespBytes = 0

		case http.MethodGet:
			if !isBucketRootPath {
				if isRootServiceHost {
					return nil, fmt.Errorf("live transport refused S3 object-path GET %q on service root host", req.URL.Path)
				}
				if !strings.HasPrefix(bucketName, liveConformancePrefix) {
					return nil, fmt.Errorf("live transport refused S3 object-path GET %q in stage 1 read-only mode", req.URL.Path)
				}
				isGetObjectTagging := vals.Has("tagging") && vals.Get("tagging") == "" &&
					hasOnlyAllowedKeys(vals, "tagging", "x-id") &&
					(xid == "" || xid == "GetObjectTagging")
				isGetObject := t.allowMutations && !vals.Has("tagging") && hasOnlyAllowedKeys(vals, "x-id") &&
					(xid == "" || xid == "GetObject")
				if !isGetObjectTagging && !isGetObject {
					return nil, fmt.Errorf("live transport refused S3 object-path GET %q in stage 1 read-only mode", req.URL.Path)
				}
				if isGetObjectTagging {
					maxRespBytes = maxLiveSmallRespBodyBytes
				} else {
					maxRespBytes = safety.DefaultMaxObjectBytes + 4096
				}
			} else if isRootServiceHost {
				// ListBuckets only
				if !hasOnlyAllowedKeys(vals, "x-id", "continuation-token", "max-buckets", "bucket-region", "prefix") {
					return nil, errors.New("live transport refused unapproved query parameters on S3 ListBuckets")
				}
				if xid != "" && xid != "ListBuckets" {
					return nil, fmt.Errorf("live transport refused S3 root GET with x-id=%q", xid)
				}
				maxRespBytes = maxLiveListRespBodyBytes
			} else {
				isListObjects := vals.Get("list-type") == "2" &&
					!vals.Has("location") && !vals.Has("tagging") &&
					hasOnlyAllowedKeys(vals, "list-type", "x-id", "prefix", "max-keys", "continuation-token", "delimiter", "encoding-type", "fetch-owner", "start-after") &&
					(xid == "" || xid == "ListObjectsV2")
				isGetLocation := vals.Has("location") &&
					vals.Get("location") == "" &&
					hasOnlyAllowedKeys(vals, "location", "x-id") &&
					(xid == "" || xid == "GetBucketLocation")
				isGetBucketTagging := strings.HasPrefix(bucketName, liveConformancePrefix) &&
					vals.Has("tagging") && vals.Get("tagging") == "" &&
					hasOnlyAllowedKeys(vals, "tagging", "x-id") &&
					(xid == "" || xid == "GetBucketTagging")
				if !isListObjects && !isGetLocation && !isGetBucketTagging {
					return nil, errors.New("live transport refused S3 GET in stage 1 read-only mode")
				}
				if isGetLocation || isGetBucketTagging {
					maxRespBytes = maxLiveSmallRespBodyBytes
				} else {
					maxKeys := maxLiveObjectListPageSize
					if mkStr := vals.Get("max-keys"); mkStr != "" {
						if mk, err := strconv.Atoi(mkStr); err == nil && mk > 0 && mk <= maxLiveObjectListPageSize {
							maxKeys = mk
						}
					}
					maxRespBytes = objectListWorstCaseBytes(maxKeys)
				}
			}

		case http.MethodPut:
			if !t.allowMutations {
				return nil, fmt.Errorf("live transport refused S3 mutating method %s in stage 1 read-only mode", req.Method)
			}
			if isRootServiceHost || !strings.HasPrefix(bucketName, liveConformancePrefix) {
				return nil, fmt.Errorf("live transport refused S3 PUT on non-conformance bucket %q", bucketName)
			}
			if isBucketRootPath {
				isCreate := !vals.Has("tagging") && hasOnlyAllowedKeys(vals, "x-id") && (xid == "" || xid == "CreateBucket")
				isPutTag := vals.Has("tagging") && vals.Get("tagging") == "" && hasOnlyAllowedKeys(vals, "tagging", "x-id") && (xid == "" || xid == "PutBucketTagging")
				if !isCreate && !isPutTag {
					return nil, fmt.Errorf("live transport refused S3 bucket PUT query %q", req.URL.RawQuery)
				}
			} else {
				isPutObj := !vals.Has("tagging") && hasOnlyAllowedKeys(vals, "x-id") && (xid == "" || xid == "PutObject")
				isPutObjTag := vals.Has("tagging") && vals.Get("tagging") == "" && hasOnlyAllowedKeys(vals, "tagging", "x-id") && (xid == "" || xid == "PutObjectTagging")
				if !isPutObj && !isPutObjTag {
					return nil, fmt.Errorf("live transport refused S3 object PUT query %q", req.URL.RawQuery)
				}
			}
			maxRespBytes = maxLiveSmallRespBodyBytes

		case http.MethodDelete:
			if !t.allowMutations {
				return nil, fmt.Errorf("live transport refused S3 mutating method %s in stage 1 read-only mode", req.Method)
			}
			if isRootServiceHost || !strings.HasPrefix(bucketName, liveConformancePrefix) {
				return nil, fmt.Errorf("live transport refused S3 DELETE on non-conformance bucket %q", bucketName)
			}
			if isBucketRootPath {
				if !hasOnlyAllowedKeys(vals, "x-id") || (xid != "" && xid != "DeleteBucket") {
					return nil, fmt.Errorf("live transport refused S3 bucket DELETE query %q", req.URL.RawQuery)
				}
			} else {
				if !hasOnlyAllowedKeys(vals, "x-id") || (xid != "" && xid != "DeleteObject") {
					return nil, fmt.Errorf("live transport refused S3 object DELETE query %q", req.URL.RawQuery)
				}
			}
			maxRespBytes = maxLiveSmallRespBodyBytes

		default:
			return nil, fmt.Errorf("live transport refused S3 mutating method %s in stage 1 read-only mode", req.Method)
		}

	case host == sqsHost:
		if req.Method != http.MethodPost {
			return nil, fmt.Errorf("live transport refused SQS method %s", req.Method)
		}
		if (req.URL.Path != "" && req.URL.Path != "/") || (req.URL.RawPath != "" && req.URL.RawPath != "/") {
			return nil, fmt.Errorf("live transport refused SQS path %q", req.URL.Path)
		}
		if req.URL.RawQuery != "" {
			return nil, errors.New("live transport refused SQS query parameters")
		}
		targets := req.Header.Values("X-Amz-Target")
		if len(targets) > 1 {
			return nil, errors.New("live transport refused multiple X-Amz-Target headers")
		}
		if req.Body == nil {
			return nil, errors.New("live transport refused empty SQS request body")
		}
		maxReqBody := int64(64 * 1024)
		if t.allowMutations {
			maxReqBody = 256 * 1024
		}
		b, err := io.ReadAll(io.LimitReader(req.Body, maxReqBody+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > maxReqBody {
			return nil, errors.New("live transport refused oversized SQS request body")
		}
		req.Body = io.NopCloser(bytes.NewReader(b))

		target := ""
		if len(targets) == 1 {
			target = strings.TrimSpace(targets[0])
		}
		if target != "" {
			if !t.allowMutations {
				if target != "AmazonSQS.ListQueues" && target != "AmazonSQS.GetQueueUrl" {
					return nil, fmt.Errorf("live transport refused SQS target %q in stage 1 read-only mode", target)
				}
			}
			if err := validateSQSJSONBody(target, b); err != nil {
				return nil, fmt.Errorf("live transport refused SQS body: %w", err)
			}
			switch target {
			case "AmazonSQS.ListQueues":
				maxRespBytes = maxLiveListRespBodyBytes
			case "AmazonSQS.ReceiveMessage":
				maxRespBytes = maxLiveReceiveRespBodyBytes
			default:
				maxRespBytes = maxLiveSmallRespBodyBytes
			}
		} else {
			vals, perr := parseStrictQuery(string(b))
			if perr != nil {
				return nil, fmt.Errorf("live transport refused malformed SQS form body: %w", perr)
			}
			act := vals.Get("Action")
			switch act {
			case "ListQueues":
				if !hasOnlyAllowedKeys(vals, "Action", "Version", "MaxResults", "NextToken", "QueueNamePrefix") {
					return nil, errors.New("live transport refused unexpected SQS ListQueues form parameters")
				}
				maxRespBytes = maxLiveListRespBodyBytes
			case "GetQueueUrl":
				if vals.Get("QueueName") == "" || !hasOnlyAllowedKeys(vals, "Action", "Version", "QueueName", "QueueOwnerAWSAccountId") {
					return nil, errors.New("live transport refused invalid SQS GetQueueUrl form parameters")
				}
				maxRespBytes = maxLiveSmallRespBodyBytes
			default:
				return nil, fmt.Errorf("live transport refused SQS action %q in stage 1 read-only mode", act)
			}
		}

	default:
		return nil, fmt.Errorf("live transport refused unapproved endpoint host %q", host)
	}

	var tracker *respBytesTracker
	if req.Context() != nil {
		tracker, _ = req.Context().Value(respBytesTrackerKey{}).(*respBytesTracker)
	}
	if tracker != nil && tracker.maxBytes > 0 && tracker.maxBytes < maxRespBytes {
		maxRespBytes = tracker.maxBytes
	}

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		if req.Method == http.MethodHead {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			resp.Body = http.NoBody
			tracker.record(0, true, false, nil)
		} else {
			resp.Body = &boundedResponseBody{
				rc:       resp.Body,
				maxBytes: maxRespBytes,
				tracker:  tracker,
			}
		}
	} else {
		tracker.record(0, true, false, nil)
	}
	return resp, nil
}

func isProcessLiveEnvActive(getenv func(string) string) bool {
	for _, fn := range []func(string) string{os.Getenv, getenv} {
		if fn == nil {
			continue
		}
		for _, k := range []string{"LMCLOUD_LIVE", "LMAWS_LIVE", "LMAZURE_LIVE", "LMGCP_LIVE", "LMOCI_LIVE"} {
			v := strings.TrimSpace(fn(k))
			if v == "1" || strings.EqualFold(v, "true") {
				return true
			}
		}
	}
	return false
}

type liveAdapter struct {
	mu      sync.Mutex
	opts    *Options
	getenv  func(string) string
	retry   hostkit.RetryPolicy
	baseCli *http.Client

	sessKey string
	sess    *safety.Session
	raw     *liveRawBackend
	store   *safety.GuardStore
	queue   *safety.GuardQueue

	bootDir     string
	bootJournal *safety.Journal
	bootGuard   *safety.LiveGuard
}

func newLiveAdapter(opts *Options, getenv func(string) string, retry hostkit.RetryPolicy, baseCli *http.Client) *liveAdapter {
	return &liveAdapter{
		opts:    opts,
		getenv:  getenv,
		retry:   retry,
		baseCli: baseCli,
	}
}

func (l *liveAdapter) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bootJournal != nil {
		_ = l.bootJournal.Close()
		l.bootJournal = nil
	}
	if l.bootDir != "" {
		_ = os.RemoveAll(l.bootDir)
		l.bootDir = ""
	}
	l.bootGuard = nil
	if l.sess != nil {
		err := l.sess.Close()
		l.sess = nil
		l.store = nil
		l.queue = nil
		l.raw = nil
		l.sessKey = ""
		return err
	}
	return nil
}

func (l *liveAdapter) session() *safety.Session {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sess
}

func (l *liveAdapter) liveGuard() *safety.LiveGuard {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sess != nil {
		return l.sess.Guard()
	}
	if !isProcessLiveEnvActive(l.getenv) {
		return nil
	}
	if l.bootGuard != nil {
		return l.bootGuard
	}
	bDir, err := os.MkdirTemp("", "lmaws-boot-guard-*")
	if err != nil {
		return nil
	}
	_ = os.Chmod(bDir, 0o700)
	pol := safety.DefaultAWSLivePolicy(bDir, false)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pt, err := safety.LoadEmbeddedPriceTable("aws", RequiredLiveRegion, now)
	if err != nil {
		_ = os.RemoveAll(bDir)
		return nil
	}
	meter, err := safety.NewCostMeter(pol.Cost, pt, nil)
	if err != nil {
		_ = os.RemoveAll(bDir)
		return nil
	}
	j, err := safety.OpenJournal(bDir, safety.JournalMeta{
		RunID:      safety.NewRunID(now),
		PolicyHash: pol.Hash(),
		Provider:   "aws",
		Account:    RequiredLiveAccount,
		Scope:      RequiredLiveAccount,
		Region:     RequiredLiveRegion,
	})
	if err != nil {
		_ = os.RemoveAll(bDir)
		return nil
	}
	g, err := safety.NewLiveGuard(safety.GuardConfig{
		Policy:   pol,
		Journal:  j,
		Meter:    meter,
		Recovery: &liveRawBackend{},
		Now:      func() time.Time { return now },
	})
	if err != nil {
		_ = j.Close()
		_ = os.RemoveAll(bDir)
		return nil
	}
	l.bootDir = bDir
	l.bootJournal = j
	l.bootGuard = g
	return g
}

func (l *liveAdapter) buildLivePolicy(envCfg liveEnvConfig, absJDir string) (safety.Policy, error) {
	var pol safety.Policy
	if envCfg.policyPath != "" {
		loaded, lerr := safety.LoadPolicy(envCfg.policyPath, envCfg.policyHash)
		if lerr != nil {
			return safety.Policy{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "InvalidLivePolicy", lerr.Error())
		}
		if !slices.Contains(loaded.AllowedAccounts, envCfg.account) {
			return safety.Policy{}, hostkit.ProviderError(
				hostkit.PermissionDenied,
				0,
				"LiveAccountNotAllowed",
				fmt.Sprintf("LMAWS_LIVE_ACCOUNT %q is not in policy allowed_accounts", envCfg.account),
			)
		}
		if !slices.Contains(loaded.AllowedRegions, envCfg.region) {
			return safety.Policy{}, hostkit.ProviderError(
				hostkit.PermissionDenied,
				0,
				"LiveRegionNotAllowed",
				fmt.Sprintf("LMAWS_LIVE_REGION %q is not in policy allowed_regions", envCfg.region),
			)
		}
		loaded.AllowMutations = loaded.AllowMutations && envCfg.mutate
		pol = loaded
	} else {
		pol = safety.DefaultAWSLivePolicy(absJDir, envCfg.mutate)
		pol.AllowedAccounts = []string{envCfg.account}
		pol.AllowedRegions = []string{envCfg.region}
		if envCfg.principal != "" {
			pol.AllowedScopes = []string{envCfg.principal}
		} else {
			pol.AllowedScopes = []string{
				"arn:aws:iam::" + envCfg.account + ":role/lmcloud-conformance-ci",
				"arn:aws:sts::" + envCfg.account + ":assumed-role/lmcloud-conformance-ci/",
				"arn:aws:iam::" + envCfg.account + ":role/awsspot-admin",
				"arn:aws:sts::" + envCfg.account + ":assumed-role/awsspot-admin/",
				"arn:aws:iam::" + envCfg.account + ":role/",
				"arn:aws:sts::" + envCfg.account + ":assumed-role/",
				"arn:aws:iam::" + envCfg.account + ":user/",
				"arn:aws:sts::" + envCfg.account + ":federated-user/",
				"arn:aws:iam::" + envCfg.account + ":root",
			}
		}
	}

	if envCfg.maxBuckets > 0 {
		pol.Limits.MaxBuckets = envCfg.maxBuckets
	}
	if envCfg.maxQueues > 0 {
		pol.Limits.MaxQueues = envCfg.maxQueues
	}

	if envCfg.costCapUSD > 0 {
		maxPolicyCap := pol.Cost.CapUSD
		if envCfg.mutate && envCfg.policyPath == "" {
			maxPolicyCap = safety.HardCostCeilingUSD
		}
		if envCfg.costCapUSD > maxPolicyCap {
			return safety.Policy{}, hostkit.ProviderError(
				hostkit.PermissionDenied,
				0,
				"LiveCostCapExceedsPolicy",
				fmt.Sprintf("requested cost cap $%.6f exceeds policy cap $%.6f", envCfg.costCapUSD, maxPolicyCap),
			)
		}
		pol.Cost.CapUSD = envCfg.costCapUSD
		if pol.Cost.CleanupReserveUSD >= pol.Cost.CapUSD {
			pol.Cost.CleanupReserveUSD = pol.Cost.CapUSD * 0.2
		}
	}
	if err := pol.Validate(); err != nil {
		return safety.Policy{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "InvalidLivePolicy", err.Error())
	}
	return pol, nil
}

func (l *liveAdapter) ensureSession(ctx context.Context, envCfg liveEnvConfig) (*safety.Session, *safety.GuardStore, *safety.GuardQueue, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%.9f|%t|%d|%d",
		envCfg.account, envCfg.region, envCfg.runID, envCfg.journalDir, envCfg.policyPath, envCfg.principal,
		envCfg.costCapUSD, envCfg.mutate, envCfg.maxBuckets, envCfg.maxQueues)
	if l.sess != nil && l.sessKey == key {
		return l.sess, l.store, l.queue, nil
	}
	if l.sess != nil {
		_ = l.sess.Close()
		l.sess = nil
		l.store = nil
		l.queue = nil
		l.raw = nil
		l.sessKey = ""
	}

	jDir := envCfg.journalDir
	if jDir == "" {
		jDir = filepath.Join(os.TempDir(), fmt.Sprintf("lmaws-live-%d", os.Getuid()))
	}
	absJDir, err := safety.EnsureStateDir(jDir)
	if err != nil {
		return nil, nil, nil, hostkit.ProviderError(hostkit.Internal, 0, "LiveJournalDirInvalid", err.Error())
	}

	pol, err := l.buildLivePolicy(envCfg, absJDir)
	if err != nil {
		return nil, nil, nil, err
	}

	raw, err := newLiveRawBackend(ctx, envCfg, l.opts, l.retry, l.baseCli, l.getenv)
	if err != nil {
		return nil, nil, nil, err
	}
	raw.maxTotalBytes = pol.Limits.MaxTotalBytes

	sess, err := safety.OpenSession(ctx, safety.SessionConfig{
		Policy:   pol,
		RunID:    envCfg.runID,
		Recovery: raw,
	})
	if err != nil {
		var ce *hostkit.CloudError
		if errors.As(err, &ce) && ce != nil {
			return nil, nil, nil, raw.sanitizeCloudError(ce)
		}
		return nil, nil, nil, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveSessionOpenFailed",
			raw.sanitizeString(err.Error()),
		)
	}

	raw.sess = sess
	l.sess = sess
	l.sessKey = key
	l.raw = raw
	l.store = sess.WrapStore(raw)
	l.queue = sess.WrapQueue(raw)
	return l.sess, l.store, l.queue, nil
}

type prePutObjStateKey struct{}

type prePutObjState struct {
	entry           safety.LedgerEntry
	existsInJournal bool
}

type expectedObjectProofKey struct{}

type expectedObjectProof struct {
	etag      string
	versionID string
	entry     safety.LedgerEntry
}

type expectedDeleteObjectETagKey struct{}

type ownSweepPhysicalAttemptKey struct{}

func withOwnSweepPhysicalAttempt(ctx context.Context) context.Context {
	return context.WithValue(ctx, ownSweepPhysicalAttemptKey{}, true)
}

func isOwnSweepPhysicalAttempt(ctx context.Context) bool {
	v, _ := ctx.Value(ownSweepPhysicalAttemptKey{}).(bool)
	return v
}

type preReservedBucketListKey struct{}

type sweepPreReservesBucketListKey struct{}

type liveCleanupCtxKey struct{}

func withLiveCleanup(ctx context.Context) context.Context {
	return context.WithValue(ctx, liveCleanupCtxKey{}, true)
}

func isLiveCleanupCtx(ctx context.Context) bool {
	v, _ := ctx.Value(liveCleanupCtxKey{}).(bool)
	return v
}

// verifyLiveOwnedBucketAndObject enforces that in Stage 2 live mutation mode,
// object reads (GetObject, HeadObject, ListObjects) only read from a bucket
// (and, when checkObject is true, an object) that is confirmed in our run
// journal AND verified via remote AWS ownership tags. If the bucket or object
// is genuinely absent on AWS and not confirmed in the journal, it returns
// NotFound (AbsentBucket / AbsentObject) so missing-resource conformance tests pass.
func (l *liveAdapter) verifyLiveOwnedBucketAndObject(
	ctx context.Context,
	sess *safety.Session,
	raw *liveRawBackend,
	bucket, key string,
	checkObject bool,
) (expectedObjectProof, *hostkit.CloudError) {
	if nerr := safety.ValidateLiveResourceName(sess.RunID(), bucket); nerr != nil {
		return expectedObjectProof{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"UnownedParentResource",
			fmt.Sprintf("refusing operation on unowned bucket %q: %v", bucket, nerr),
		)
	}
	bEntry, hasBkt := sess.Journal().Lookup(safety.KindBucket, "", bucket)
	if hasBkt && (bEntry.Retain || bEntry.State == safety.StateRetained) {
		return expectedObjectProof{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"ForeignResourceCollision",
			bEntry.Reason,
		)
	}

	bRO, bErr, bCerr := raw.readOwnershipMetered(ctx, safety.ResourceRef{
		Kind:     safety.KindBucket,
		Location: raw.region,
		Name:     bucket,
	}, false, "verify_read_bucket_ownership")
	if bCerr != nil {
		return expectedObjectProof{}, bCerr
	}
	if (bErr == nil && !bRO.Exists) || (bErr != nil && raw.ClassifyAbsent(bErr) == safety.AbsenceDefinitive) {
		if hasBkt && bEntry.State == safety.StateConfirmed {
			_ = sess.Journal().Retain(safety.KindBucket, "", bucket, "confirmed bucket disappeared remotely")
			return expectedObjectProof{}, hostkit.ProviderError(
				hostkit.PermissionDenied,
				http.StatusForbidden,
				"ParentOwnershipMismatch",
				fmt.Sprintf("confirmed bucket %q disappeared remotely", bucket),
			)
		}
		return expectedObjectProof{}, (&hostkit.CloudError{
			Code:         hostkit.NotFound,
			Message:      fmt.Sprintf("The specified bucket %q does not exist", bucket),
			ProviderCode: "NoSuchBucket",
			HTTPStatus:   http.StatusNotFound,
		}).WithAbsent(hostkit.AbsentBucket)
	}
	if bErr != nil {
		if raw.ClassifyAbsent(bErr) == safety.AbsenceAmbiguous && hasBkt {
			_ = sess.Journal().Retain(safety.KindBucket, "", bucket, "ambiguous bucket ownership read: "+bErr.Error())
		}
		return expectedObjectProof{}, hostkit.AsCloudError(bErr)
	}
	if !hasBkt || bEntry.State != safety.StateConfirmed || bEntry.Retain {
		_ = sess.Journal().Retain(safety.KindBucket, "", bucket, "unowned bucket encountered on read")
		return expectedObjectProof{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"UnownedParentResource",
			fmt.Sprintf("bucket %q is not a confirmed resource of run %s", bucket, sess.RunID()),
		)
	}
	if verr := bRO.VerifyMatchesEntry(bEntry, sess.Journal().Meta()); verr != nil {
		_ = sess.Journal().Retain(safety.KindBucket, "", bucket, "bucket ownership mismatch on read: "+verr.Error())
		return expectedObjectProof{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"ParentOwnershipMismatch",
			verr.Error(),
		)
	}

	if !checkObject {
		return expectedObjectProof{}, nil
	}

	oEntry, hasObj := sess.Journal().Lookup(safety.KindObject, bucket, key)
	if hasObj && (oEntry.Retain || oEntry.State == safety.StateRetained) {
		return expectedObjectProof{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"ForeignResourceCollision",
			oEntry.Reason,
		)
	}

	oRO, oErr, oCerr := raw.readOwnershipMetered(ctx, safety.ResourceRef{
		Kind:     safety.KindObject,
		Parent:   bucket,
		Location: raw.region,
		Name:     key,
	}, false, "verify_read_object_ownership")
	if oCerr != nil {
		return expectedObjectProof{}, oCerr
	}
	if (oErr == nil && !oRO.Exists) || (oErr != nil && raw.ClassifyAbsent(oErr) == safety.AbsenceDefinitive) {
		return expectedObjectProof{}, (&hostkit.CloudError{
			Code:         hostkit.NotFound,
			Message:      fmt.Sprintf("The specified key %q does not exist", key),
			ProviderCode: "NoSuchKey",
			HTTPStatus:   http.StatusNotFound,
		}).WithAbsent(hostkit.AbsentObject)
	}
	if oErr != nil {
		return expectedObjectProof{}, hostkit.AsCloudError(oErr)
	}
	if !hasObj || oEntry.State != safety.StateConfirmed || oEntry.Retain {
		_ = sess.Journal().Retain(safety.KindObject, bucket, key, "unowned object encountered on read")
		return expectedObjectProof{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"UnownedResourceReadRefused",
			fmt.Sprintf("object %s/%s is not a confirmed resource of run %s", bucket, key, sess.RunID()),
		)
	}
	if verr := oRO.VerifyMatchesEntry(oEntry, sess.Journal().Meta()); verr != nil {
		_ = sess.Journal().Retain(safety.KindObject, bucket, key, "object ownership mismatch on read: "+verr.Error())
		return expectedObjectProof{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"UnownedResourceReadRefused",
			verr.Error(),
		)
	}
	provenETag := cleanETag(oRO.ETag)
	if provenETag == "" {
		_ = sess.Journal().Retain(safety.KindObject, bucket, key, "object ownership proof missing ETag")
		return expectedObjectProof{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"UnownedResourceReadRefused",
			fmt.Sprintf("object %s/%s ownership proof returned an empty ETag", bucket, key),
		)
	}
	return expectedObjectProof{
		etag:      provenETag,
		versionID: strings.TrimSpace(oRO.Generation),
		entry:     oEntry,
	}, nil
}

// --- hostkit.ObjectStore & hostkit.Queue on liveAdapter ---

func (l *liveAdapter) CreateBucket(ctx context.Context, name string) (bool, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return false, cerr
	}
	if !envCfg.mutate {
		return false, stage1MutationDisabledErr("bucket_create")
	}
	_, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return false, err
	}
	return store.CreateBucket(ctx, name)
}

func (l *liveAdapter) DeleteBucket(ctx context.Context, name string) error {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return cerr
	}
	if !envCfg.mutate {
		return stage1MutationDisabledErr("bucket_delete")
	}
	_, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return err
	}
	ctx = withLiveCleanup(ctx)
	ctx = context.WithValue(ctx, preReservedBucketListKey{}, new(bool))
	return store.DeleteBucket(ctx, name)
}

func (l *liveAdapter) PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (hostkit.ObjectMeta, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}
	if !envCfg.mutate {
		return hostkit.ObjectMeta{}, stage1MutationDisabledErr("object_put")
	}
	sess, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return hostkit.ObjectMeta{}, err
	}
	existingObj, hasObj := sess.Journal().Lookup(safety.KindObject, bucket, key)
	if hasObj && (existingObj.Retain || existingObj.State == safety.StateRetained) {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(
			hostkit.Conflict,
			http.StatusConflict,
			"ForeignResourceCollision",
			existingObj.Reason,
		)
	}
	ctx = context.WithValue(ctx, prePutObjStateKey{}, prePutObjState{
		entry:           existingObj,
		existsInJournal: hasObj,
	})
	return store.PutObject(ctx, bucket, key, body, contentType, metadata)
}

func (l *liveAdapter) DeleteObject(ctx context.Context, bucket, key string) error {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return cerr
	}
	if !envCfg.mutate {
		return stage1MutationDisabledErr("object_delete")
	}
	sess, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return err
	}
	if existingObj, hasObj := sess.Journal().Lookup(safety.KindObject, bucket, key); hasObj && existingObj.ETag != "" {
		ctx = context.WithValue(ctx, expectedDeleteObjectETagKey{}, cleanETag(existingObj.ETag))
	}
	return store.DeleteObject(withLiveCleanup(ctx), bucket, key)
}

func (l *liveAdapter) GetObject(ctx context.Context, bucket, key string, limit int64) ([]byte, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return nil, cerr
	}
	if !envCfg.mutate {
		return nil, stage1MutationDisabledErr("object_get")
	}
	sess, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	raw := l.raw
	l.mu.Unlock()
	proof, vcerr := l.verifyLiveOwnedBucketAndObject(ctx, sess, raw, bucket, key, true)
	if vcerr != nil {
		return nil, vcerr
	}
	ctx = context.WithValue(ctx, expectedObjectProofKey{}, proof)
	return store.GetObject(ctx, bucket, key, limit)
}

func (l *liveAdapter) CreateQueue(ctx context.Context, name string) (bool, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return false, cerr
	}
	if !envCfg.mutate {
		return false, stage1MutationDisabledErr("queue_create")
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return false, err
	}
	return queue.CreateQueue(ctx, name)
}

func (l *liveAdapter) DeleteQueue(ctx context.Context, name string) error {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return cerr
	}
	if !envCfg.mutate {
		return stage1MutationDisabledErr("queue_delete")
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return err
	}
	return queue.DeleteQueue(withLiveCleanup(ctx), name)
}

func (l *liveAdapter) Send(ctx context.Context, qName, wire string) (string, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return "", cerr
	}
	if !envCfg.mutate {
		return "", stage1MutationDisabledErr("queue_send")
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return "", err
	}
	return queue.Send(ctx, qName, wire)
}

func (l *liveAdapter) Receive(ctx context.Context, qName string, max, waitSeconds, visibility int) ([]hostkit.RawMessage, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return nil, cerr
	}
	if !envCfg.mutate {
		return nil, stage1MutationDisabledErr("queue_receive")
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return nil, err
	}
	return queue.Receive(ctx, qName, max, waitSeconds, visibility)
}

func (l *liveAdapter) Ack(ctx context.Context, qName, receipt string) error {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return cerr
	}
	if !envCfg.mutate {
		return stage1MutationDisabledErr("queue_ack")
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return err
	}
	return queue.Ack(ctx, qName, receipt)
}

func (l *liveAdapter) Nack(ctx context.Context, qName, receipt string, visibility int) (string, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return "", cerr
	}
	if !envCfg.mutate {
		return "", stage1MutationDisabledErr("queue_nack")
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return "", err
	}
	return queue.Nack(ctx, qName, receipt, visibility)
}

func (l *liveAdapter) QueueCreateToken(ctx context.Context, qName string) (string, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return "", cerr
	}
	if !envCfg.mutate {
		return "", stage1MutationDisabledErr("queue_create_token")
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return "", err
	}
	return queue.QueueCreateToken(ctx, qName)
}

func (l *liveAdapter) HeadBucket(ctx context.Context, name string) error {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return cerr
	}
	sess, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return err
	}
	if envCfg.mutate {
		if entry, ok := sess.Journal().Lookup(safety.KindBucket, "", name); ok && (entry.Retain || entry.State == safety.StateRetained) {
			return hostkit.ProviderError(hostkit.PermissionDenied, http.StatusForbidden, "ForeignResourceCollision", entry.Reason)
		}
	}
	return store.HeadBucket(ctx, name)
}

func (l *liveAdapter) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return nil, "", cerr
	}
	_, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return nil, "", err
	}
	return store.ListBuckets(ctx, token)
}

func (l *liveAdapter) HeadObject(ctx context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}
	sess, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return hostkit.ObjectMeta{}, err
	}
	if envCfg.mutate {
		l.mu.Lock()
		raw := l.raw
		l.mu.Unlock()
		proof, vcerr := l.verifyLiveOwnedBucketAndObject(ctx, sess, raw, bucket, key, true)
		if vcerr != nil {
			return hostkit.ObjectMeta{}, vcerr
		}
		ctx = context.WithValue(ctx, expectedObjectProofKey{}, proof)
	}
	return store.HeadObject(ctx, bucket, key)
}

func (l *liveAdapter) ListObjects(ctx context.Context, bucket, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return hostkit.ObjectPage{}, cerr
	}
	sess, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return hostkit.ObjectPage{}, err
	}
	if envCfg.mutate {
		l.mu.Lock()
		raw := l.raw
		l.mu.Unlock()
		if _, vcerr := l.verifyLiveOwnedBucketAndObject(ctx, sess, raw, bucket, "", false); vcerr != nil {
			return hostkit.ObjectPage{}, vcerr
		}
	}
	page, lerr := store.ListObjects(ctx, bucket, prefix, max, token)
	if lerr != nil || !envCfg.mutate {
		return page, lerr
	}
	for _, item := range page.Items {
		oEntry, hasObj := sess.Journal().Lookup(safety.KindObject, bucket, item.Key)
		if !hasObj || oEntry.State != safety.StateConfirmed || oEntry.Retain ||
			(oEntry.ETag != "" && item.ETag != "" && cleanETag(oEntry.ETag) != cleanETag(item.ETag)) {
			_ = sess.Journal().Retain(safety.KindObject, bucket, item.Key, "unjournaled, retained, or ETag-mismatched object encountered in ListObjects")
			return hostkit.ObjectPage{}, hostkit.ProviderError(
				hostkit.PermissionDenied,
				http.StatusForbidden,
				"UnownedResourceReadRefused",
				fmt.Sprintf("bucket %q contains unowned or modified object %q", bucket, item.Key),
			)
		}
	}
	return page, nil
}

func (l *liveAdapter) QueueCaps() hostkit.QueueCaps {
	return hostkit.QueueCaps{LongPoll: true, TextOnlyWire: true}
}

func (l *liveAdapter) LookupQueue(ctx context.Context, name string) error {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return cerr
	}
	sess, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return err
	}
	if envCfg.mutate {
		if entry, ok := sess.Journal().Lookup(safety.KindQueue, "", name); ok && (entry.Retain || entry.State == safety.StateRetained) {
			return hostkit.ProviderError(hostkit.PermissionDenied, http.StatusForbidden, "ForeignResourceCollision", entry.Reason)
		}
	}
	return queue.LookupQueue(ctx, name)
}

func (l *liveAdapter) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return nil, "", cerr
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return nil, "", err
	}
	return queue.ListQueues(ctx, token)
}

func liveTablesUnsupportedErr(op string) *hostkit.CloudError {
	return hostkit.ProviderError(
		hostkit.PermissionDenied,
		0,
		"LiveTablesUnsupported",
		fmt.Sprintf("tables operation %s is refused in live mode (tables live mode is disabled)", op),
	)
}

func (l *liveAdapter) failClosedTables(ctx context.Context, op string) *hostkit.CloudError {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return cerr
	}
	return liveTablesUnsupportedErr(op)
}

func (l *liveAdapter) TableCreateToken(ctx context.Context, _ string) (string, error) {
	return "", l.failClosedTables(ctx, "table_create_token")
}

func (l *liveAdapter) DescribeTable(ctx context.Context, _ string) (hostkit.TableInfo, error) {
	return hostkit.TableInfo{}, l.failClosedTables(ctx, "table_describe")
}

func (l *liveAdapter) CreateTable(ctx context.Context, _ string, _ bool) (bool, error) {
	return false, l.failClosedTables(ctx, "table_create")
}

func (l *liveAdapter) DeleteTable(ctx context.Context, _ string) error {
	return l.failClosedTables(ctx, "table_delete")
}

func (l *liveAdapter) HeadTable(ctx context.Context, _ string) error {
	return l.failClosedTables(ctx, "table_exists")
}

func (l *liveAdapter) ListTables(ctx context.Context, _ string) ([]string, string, error) {
	return nil, "", l.failClosedTables(ctx, "table_list")
}

func (l *liveAdapter) PutItem(ctx context.Context, _ string, _ hostkit.Item, _ hostkit.PutMode, _ string) (hostkit.Item, error) {
	return hostkit.Item{}, l.failClosedTables(ctx, "item_put")
}

func (l *liveAdapter) GetItem(ctx context.Context, _, _, _ string) (hostkit.Item, error) {
	return hostkit.Item{}, l.failClosedTables(ctx, "item_get")
}

func (l *liveAdapter) DeleteItem(ctx context.Context, _, _, _ string) error {
	return l.failClosedTables(ctx, "item_delete")
}

func (l *liveAdapter) UpdateItem(ctx context.Context, _, _, _ string, _ hostkit.Item) (hostkit.Item, error) {
	return hostkit.Item{}, l.failClosedTables(ctx, "item_update")
}

func (l *liveAdapter) Query(ctx context.Context, _, _, _, _ string, _ int, _ string) (hostkit.TablePage, error) {
	return hostkit.TablePage{}, l.failClosedTables(ctx, "item_query")
}

func (l *liveAdapter) Scan(ctx context.Context, _ string, _ int, _ string) (hostkit.TablePage, error) {
	return hostkit.TablePage{}, l.failClosedTables(ctx, "item_scan")
}

// liveCredentialsProvider wraps an aws.CredentialsProvider so that:
//  1. Every retrieved credential (initial or refreshed) is registered for redaction before returning.
//  2. Any provider failure returns a stable sanitized error that never includes raw provider output
//     or authorization tokens.
type liveCredentialsProvider struct {
	inner aws.CredentialsProvider
	raw   *liveRawBackend
}

func (p *liveCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if p == nil || p.inner == nil {
		return aws.Credentials{}, errors.New("live credential provider unavailable")
	}
	creds, err := p.inner.Retrieve(ctx)
	if p.raw != nil {
		p.raw.registerSecret(creds.SecretAccessKey)
		p.raw.registerSecret(creds.SessionToken)
		p.raw.registerSecret(creds.AccessKeyID)
	}
	if err != nil {
		return aws.Credentials{}, errors.New("AWS credential provider failed to retrieve credentials")
	}
	return creds, nil
}

// liveRawBackend implements hostkit.ObjectStore, hostkit.Queue, and
// safety.RecoveryAdapter against real AWS HTTPS endpoints in us-east-1.
type liveRawBackend struct {
	account        string
	region         string
	awsCfg         aws.Config
	businessClient *http.Client
	retry          hostkit.RetryPolicy
	sess           *safety.Session
	sweepMeter     *safety.CostMeter
	sweepJournal   *safety.Journal
	maxTotalBytes  int64

	mu                sync.Mutex
	redactedSecrets   []string
	attestedAccount   string
	attestedARN       string
	authMode          string
	bucketCreatedUnix map[string]int64
}

// buildExplicitLiveCredentialsProvider constructs the Stage 1 live credential
// provider explicitly without ever loading shared configuration or shared
// credentials files (~/.aws/config, ~/.aws/credentials, AWS_CONFIG_FILE,
// AWS_SHARED_CREDENTIALS_FILE, AWS_PROFILE).
//
// Only four credential sources are permitted:
//  1. Static environment variables (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY [+ AWS_SESSION_TOKEN]).
//  2. Web identity token file (AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN).
//  3. ECS container credentials at fixed http://169.254.170.2 via AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
//     (or AWS_CONTAINER_CREDENTIALS_FULL_URI when pointing to http://169.254.170.2/...).
//  4. EC2 Instance Metadata Service (IMDSv2) at fixed http://169.254.169.254.
func (r *liveRawBackend) buildExplicitLiveCredentialsProvider(envCfg liveEnvConfig, credHTTPCli *http.Client, getenv func(string) string) (aws.CredentialsProvider, *hostkit.CloudError) {
	for _, envSecret := range []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_SECURITY_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN",
	} {
		if v := strings.TrimSpace(getenv(envSecret)); v != "" {
			r.registerSecret(v)
		}
		if v := strings.TrimSpace(os.Getenv(envSecret)); v != "" {
			r.registerSecret(v)
		}
	}
	for _, tokenFileEnv := range []string{"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
		for _, p := range []string{strings.TrimSpace(getenv(tokenFileEnv)), strings.TrimSpace(os.Getenv(tokenFileEnv))} {
			if p != "" {
				if data, err := os.ReadFile(p); err == nil {
					r.registerSecret(strings.TrimSpace(string(data)))
				}
			}
		}
	}

	// 1. Static environment variables.
	akid := strings.TrimSpace(getenv("AWS_ACCESS_KEY_ID"))
	secret := strings.TrimSpace(getenv("AWS_SECRET_ACCESS_KEY"))
	sessionTok := strings.TrimSpace(getenv("AWS_SESSION_TOKEN"))
	if sessionTok == "" {
		sessionTok = strings.TrimSpace(getenv("AWS_SECURITY_TOKEN"))
	}
	if akid != "" || secret != "" {
		if akid == "" || secret == "" {
			return nil, hostkit.ProviderError(
				hostkit.Unauthenticated,
				0,
				"LiveCredentialsUnavailable",
				"both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set when using static environment credentials",
			)
		}
		r.authMode = "env_static"
		staticProv := credentials.NewStaticCredentialsProvider(akid, secret, sessionTok)
		return aws.NewCredentialsCache(&liveCredentialsProvider{inner: staticProv, raw: r}), nil
	}

	// 2. Web identity (AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN).
	webTokenFile := strings.TrimSpace(getenv("AWS_WEB_IDENTITY_TOKEN_FILE"))
	roleARN := strings.TrimSpace(getenv("AWS_ROLE_ARN"))
	if webTokenFile != "" || roleARN != "" {
		if webTokenFile == "" || roleARN == "" {
			return nil, hostkit.ProviderError(
				hostkit.Unauthenticated,
				0,
				"LiveCredentialsUnavailable",
				"both AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN must be set when using web identity credentials",
			)
		}
		sessionName := strings.TrimSpace(getenv("AWS_ROLE_SESSION_NAME"))
		stsCli := sts.New(sts.Options{
			Region:       envCfg.region,
			BaseEndpoint: aws.String("https://sts." + envCfg.region + ".amazonaws.com"),
			HTTPClient:   credHTTPCli,
			Retryer:      aws.NopRetryer{},
		})
		webProv := stscreds.NewWebIdentityRoleProvider(
			stsCli,
			roleARN,
			stscreds.IdentityTokenFile(webTokenFile),
			func(o *stscreds.WebIdentityRoleOptions) {
				o.RoleSessionName = sessionName
			},
		)
		r.authMode = "oidc_web_identity"
		return aws.NewCredentialsCache(&liveCredentialsProvider{inner: webProv, raw: r}), nil
	}

	// 3. ECS container credentials at fixed http://169.254.170.2.
	relURI := strings.TrimSpace(getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"))
	fullURI := strings.TrimSpace(getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"))
	if relURI != "" || fullURI != "" {
		targetEndpoint := fullURI
		if relURI != "" {
			if !strings.HasPrefix(relURI, "/") || strings.Contains(relURI, "..") || strings.ContainsAny(relURI, "?#\\") {
				return nil, hostkit.ProviderError(
					hostkit.InvalidArgument,
					0,
					"LiveCredentialEndpointForbidden",
					"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be a clean relative path starting with '/'",
				)
			}
			targetEndpoint = "http://169.254.170.2" + relURI
		}
		if cerr := validateContainerFullURI(targetEndpoint); cerr != nil {
			return nil, cerr
		}
		authToken := strings.TrimSpace(getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"))
		authTokenFile := strings.TrimSpace(getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"))
		ecsProv := endpointcreds.New(targetEndpoint, func(o *endpointcreds.Options) {
			o.HTTPClient = credHTTPCli
			o.Retryer = aws.NopRetryer{}
			if authToken != "" {
				o.AuthorizationToken = authToken
			}
			if authTokenFile != "" {
				o.AuthorizationTokenProvider = endpointcreds.TokenProviderFunc(func() (string, error) {
					b, err := os.ReadFile(authTokenFile)
					if err != nil {
						return "", errors.New("failed to read container authorization token file")
					}
					tok := strings.TrimSpace(string(b))
					r.registerSecret(tok)
					return tok, nil
				})
			}
		})
		r.authMode = "imds_role"
		return aws.NewCredentialsCache(&liveCredentialsProvider{inner: ecsProv, raw: r}), nil
	}

	// 4. EC2 IMDSv2 at fixed http://169.254.169.254 (unless disabled).
	if strings.EqualFold(strings.TrimSpace(getenv("AWS_EC2_METADATA_DISABLED")), "true") {
		return nil, hostkit.ProviderError(
			hostkit.Unauthenticated,
			0,
			"LiveCredentialsUnavailable",
			"no approved live AWS credentials configured (shared profile/credential_process/SSO are disabled in live mode)",
		)
	}
	imdsCli := imds.New(imds.Options{
		Endpoint:          "http://169.254.169.254",
		ClientEnableState: imds.ClientEnabled,
		EnableFallback:    aws.FalseTernary, // IMDSv2 only; never fall back to tokenless v1
		HTTPClient:        credHTTPCli,
		Retryer:           aws.NopRetryer{},
	})
	ec2Prov := ec2rolecreds.New(func(o *ec2rolecreds.Options) {
		o.Client = imdsCli
	})
	r.authMode = "imds_role"
	return aws.NewCredentialsCache(&liveCredentialsProvider{inner: ec2Prov, raw: r}), nil
}

func newLiveRawBackend(ctx context.Context, envCfg liveEnvConfig, opts *Options, retry hostkit.RetryPolicy, baseCli *http.Client, getenv func(string) string) (*liveRawBackend, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	enforcedBase := hostkit.EnforceClient(baseCli)
	businessCli := &http.Client{
		Timeout:       enforcedBase.Timeout,
		CheckRedirect: enforcedBase.CheckRedirect,
		Transport: &liveEndpointGuardTransport{
			region:         envCfg.region,
			account:        envCfg.account,
			allowMutations: envCfg.mutate,
			base:           enforcedBase.Transport,
		},
	}
	credHTTPCli := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: enforcedBase.CheckRedirect,
		Transport: &liveCredGuardTransport{
			region: envCfg.region,
			base:   enforcedBase.Transport,
		},
	}

	raw := &liveRawBackend{
		account:        envCfg.account,
		region:         envCfg.region,
		businessClient: businessCli,
		retry:          retry,
		authMode:       "imds_role",
	}

	credProv, cerr := raw.buildExplicitLiveCredentialsProvider(envCfg, credHTTPCli, getenv)
	if cerr != nil {
		return nil, raw.sanitizeCloudError(cerr)
	}

	loadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Explicitly pass empty slices for SharedConfigFiles and SharedCredentialsFiles
	// and our explicit CredentialsProvider so the SDK never opens ~/.aws/config,
	// ~/.aws/credentials, AWS_CONFIG_FILE, or AWS_SHARED_CREDENTIALS_FILE.
	awsCfg, err := config.LoadDefaultConfig(
		loadCtx,
		config.WithRegion(envCfg.region),
		config.WithSharedConfigFiles([]string{}),
		config.WithSharedCredentialsFiles([]string{}),
		config.WithCredentialsProvider(credProv),
		config.WithRetryMaxAttempts(1),
		config.WithClientLogMode(0),
		config.WithHTTPClient(credHTTPCli),
	)
	if err != nil {
		// If AWS_PROFILE was set in the environment, LoadDefaultConfig returns
		// SharedConfigProfileNotExistError because SharedConfigFiles is empty;
		// ignore AWS_PROFILE completely and construct aws.Config from the explicit provider.
		var profErr config.SharedConfigProfileNotExistError
		if !errors.As(err, &profErr) {
			return nil, hostkit.ProviderError(
				hostkit.Unauthenticated,
				0,
				"LiveConfigLoadFailed",
				"failed to initialize live AWS configuration",
			)
		}
		awsCfg = aws.Config{
			Region:           envCfg.region,
			Credentials:      credProv,
			HTTPClient:       credHTTPCli,
			RetryMaxAttempts: 1,
			ClientLogMode:    0,
		}
	}
	awsCfg.Region = envCfg.region
	awsCfg.Credentials = credProv
	awsCfg.ClientLogMode = 0
	awsCfg.RetryMaxAttempts = 1
	awsCfg.Retryer = func() aws.Retryer { return aws.NopRetryer{} }
	raw.awsCfg = awsCfg
	return raw, nil
}

func (r *liveRawBackend) ownerAccount() string {
	r.mu.Lock()
	acct := r.attestedAccount
	r.mu.Unlock()
	if acct != "" {
		return acct
	}
	return r.account
}

func (r *liveRawBackend) registerSecret(s string) {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return
	}
	r.mu.Lock()
	if !slices.Contains(r.redactedSecrets, s) {
		r.redactedSecrets = append(r.redactedSecrets, s)
	}
	r.mu.Unlock()
}

func sanitizeStaticSecrets(msg string) string {
	for _, envKey := range []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_SECURITY_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN",
	} {
		if v := strings.TrimSpace(os.Getenv(envKey)); len(v) >= 4 {
			msg = strings.ReplaceAll(msg, v, "[redacted]")
		}
	}
	msg = jsonSecretPattern.ReplaceAllString(msg, `"$1":"[redacted]"`)
	msg = iniSecretPattern.ReplaceAllString(msg, `$1 = [redacted]`)
	msg = awsAccessKeyPattern.ReplaceAllString(msg, "[redacted-key-id]")
	return msg
}

func (r *liveRawBackend) sanitizeString(msg string) string {
	if r != nil {
		r.mu.Lock()
		secrets := slices.Clone(r.redactedSecrets)
		r.mu.Unlock()
		for _, s := range secrets {
			if s != "" {
				msg = strings.ReplaceAll(msg, s, "[redacted]")
			}
		}
	}
	return sanitizeStaticSecrets(msg)
}

func (r *liveRawBackend) sanitizeCloudError(ce *hostkit.CloudError) *hostkit.CloudError {
	if ce == nil {
		return nil
	}
	cp := *ce
	cp.Message = r.sanitizeString(cp.Message)
	cp.ProviderCode = r.sanitizeString(cp.ProviderCode)
	return &cp
}

func (r *liveRawBackend) classifyLive(err error, sc scope) *hostkit.CloudError {
	if errors.Is(err, ErrLiveResponseTooLarge) {
		return hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveResponseTooLarge",
			fmt.Sprintf("live response body exceeded maximum bound (%d bytes)", maxLiveResponseBodyBytes),
		)
	}
	return r.sanitizeCloudError(classify(err, sc))
}

func (r *liveRawBackend) stsClient() *sts.Client {
	return sts.NewFromConfig(r.awsCfg, func(o *sts.Options) {
		o.Region = r.region
		o.BaseEndpoint = aws.String("https://sts." + r.region + ".amazonaws.com")
		o.HTTPClient = r.businessClient
		o.Retryer = aws.NopRetryer{}
	})
}

func (r *liveRawBackend) s3Client() *s3.Client {
	return s3.NewFromConfig(r.awsCfg, func(o *s3.Options) {
		o.Region = r.region
		o.BaseEndpoint = aws.String("https://s3." + r.region + ".amazonaws.com")
		o.UsePathStyle = false
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		o.HTTPClient = r.businessClient
		o.Retryer = aws.NopRetryer{}
	})
}

func (r *liveRawBackend) sqsClient() *sqs.Client {
	return sqs.NewFromConfig(r.awsCfg, func(o *sqs.Options) {
		o.Region = r.region
		o.BaseEndpoint = aws.String("https://sqs." + r.region + ".amazonaws.com")
		o.HTTPClient = r.businessClient
		o.Retryer = aws.NopRetryer{}
	})
}

func (r *liveRawBackend) activeMeter() *safety.CostMeter {
	if r.sess != nil {
		return r.sess.Meter()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sweepMeter
}

func (r *liveRawBackend) activeJournal() *safety.Journal {
	if r.sess != nil {
		return r.sess.Journal()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sweepJournal
}

func (r *liveRawBackend) recordBucketCreatedUnix(name string, ts int64) {
	if ts <= 0 || name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bucketCreatedUnix == nil {
		r.bucketCreatedUnix = make(map[string]int64)
	}
	r.bucketCreatedUnix[name] = ts
}

func (r *liveRawBackend) getBucketCreatedUnix(name string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bucketCreatedUnix[name]
}

// doLiveAWS executes an AWS operation whose primary attempt==0 request fee was
// already reserved by GuardStore/GuardQueue/Sweep, while reserving worst-case
// response egress bounds on attempt==0 (when maxRespBytes > 0) and full request +
// egress fees on any retry (attempt > 0).
func (r *liveRawBackend) doLiveAWS(ctx context.Context, opName, kind, parent, name string, maxRespBytes int64, idempotent bool, op func(ctx context.Context) error) error {
	return r.doLiveAWSWithMode(ctx, opName, kind, parent, name, "", maxRespBytes, idempotent, isOwnSweepPhysicalAttempt(ctx), op)
}

// doExtraPhysicalAWS executes a secondary physical AWS request (such as
// GetBucketTagging, GetObjectTagging, ListQueueTags, ListObjectsV2 child check
// pages, PutBucketTagging, GetQueueUrl resolution, or polling iterations) with
// its own pre-dispatch CostMeter reservation and durable journal attempt on
// every attempt (including attempt==0).
func (r *liveRawBackend) doExtraPhysicalAWS(ctx context.Context, opName, kind, parent, name, reason string, maxRespBytes int64, idempotent bool, op func(ctx context.Context) error) error {
	return r.doLiveAWSWithMode(ctx, opName, kind, parent, name, reason, maxRespBytes, idempotent, true, op)
}

func (r *liveRawBackend) doLiveAWSWithMode(
	ctx context.Context,
	opName, kind, parent, name, reason string,
	maxRespBytes int64,
	idempotent, ownAttempt bool,
	op func(ctx context.Context) error,
) error {
	var lastCallErr error
	r.retry.Do(hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{}), idempotent, func(ctx context.Context, attempt int) hostkit.Attempt {
		var (
			res       *safety.AttemptReservation
			attemptID string
			baseFee   int64
		)
		meter := r.activeMeter()
		journal := r.activeJournal()
		isCleanup := isLiveCleanupCtx(ctx) || (r.sess == nil && meter != nil)

		if meter != nil && (ownAttempt || attempt > 0 || maxRespBytes > 0) {
			if maxRespBytes > 0 && journal != nil {
				maxTotal := r.maxTotalBytes
				if maxTotal > 0 && journal.State().TotalPayloadBytes+maxRespBytes > maxTotal {
					lastCallErr = hostkit.ProviderError(
						hostkit.PermissionDenied,
						0,
						"LiveLimitExceeded",
						fmt.Sprintf("projected response bytes (%d + %d) exceed max_total_bytes (%d)",
							journal.State().TotalPayloadBytes, maxRespBytes, maxTotal),
					)
					return hostkit.Attempt{Status: http.StatusForbidden}
				}
			}
			// When ownAttempt == false and attempt == 0, GuardStore/GuardQueue/Sweep already
			// reserved the base request fee and wrote the primary journal attempt, so reserve
			// only the conservative response-egress bound (via object_delete which has a 0 base
			// request fee). When ownAttempt == true or attempt > 0, reserve both the request fee
			// and the response-egress bound and record a durable journal attempt for this physical
			// HTTP dispatch.
			pricingOp := "object_delete"
			if ownAttempt || attempt > 0 {
				pricingOp = opName
				if baseQuote, qerr := meter.QuoteAttempt(safety.AttemptPricingInput{
					Operation: opName,
					IsCleanup: isCleanup,
				}); qerr == nil {
					baseFee = baseQuote.AttemptNanoUSD
				}
			}
			var rerr error
			res, rerr = meter.ReserveAttempt(safety.AttemptPricingInput{
				Operation:   pricingOp,
				EgressBytes: maxRespBytes,
				IsCleanup:   isCleanup,
			})
			if rerr != nil {
				code := hostkit.PermissionDenied
				pcode := "LiveCostCapExceeded"
				if !errors.Is(rerr, safety.ErrCostCapExceeded) {
					code = hostkit.Internal
					pcode = "LivePricingFailure"
				}
				lastCallErr = hostkit.ProviderError(code, 0, pcode, r.sanitizeString(rerr.Error()))
				return hostkit.Attempt{Status: http.StatusForbidden}
			}
			if journal != nil && (ownAttempt || attempt > 0) {
				reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD
				attReason := reason
				if attReason == "" {
					if attempt > 0 {
						attReason = opName + "_retry"
					} else {
						attReason = opName
					}
				} else if attempt > 0 {
					attReason = fmt.Sprintf("%s_retry_%d", reason, attempt)
				}
				var jerr error
				attemptID, jerr = journal.BeginAttempt(kind, parent, name, attReason, reservedNano, maxRespBytes)
				if jerr != nil {
					res.Commit(0, false)
					lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(jerr.Error()))
					return hostkit.Attempt{Status: http.StatusInternalServerError}
				}
			}
		}

		tracker := &respBytesTracker{maxBytes: maxRespBytes}
		callCtx := context.WithValue(ctx, respBytesTrackerKey{}, tracker)
		lastCallErr = op(callCtx)
		actualBytes, completedEOF, tooLarge, readErr := tracker.snapshot()
		if maxRespBytes > 0 && actualBytes > maxRespBytes {
			tooLarge = true
		}
		if tooLarge {
			lastCallErr = ErrLiveResponseTooLarge
		} else if lastCallErr == nil && readErr != nil {
			lastCallErr = readErr
		}

		if res != nil {
			// Settle at actual egress cost only when the response stream completed cleanly
			// to EOF within bounds; otherwise (transport error, timeout, or oversized body)
			// settle at the full pre-dispatch reservation.
			if maxRespBytes > 0 && completedEOF && !tooLarge && readErr == nil {
				actualNano := baseFee + liveEgressNanoUSD(actualBytes)
				if maxQuote := res.Quote().AttemptNanoUSD; actualNano > maxQuote {
					actualNano = maxQuote
				}
				charged := res.Commit(actualNano, false)
				if journal != nil {
					if attemptID != "" {
						if serr := journal.SettleAttempt(attemptID, charged, true); serr != nil {
							lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(serr.Error()))
							return hostkit.Attempt{Status: http.StatusInternalServerError}
						}
						if actualBytes > 0 {
							_ = journal.RecordCostWithBytes(kind, parent, name, opName+"_bytes", 0, actualBytes)
						}
					} else if charged > 0 || actualBytes > 0 {
						if cerr := journal.RecordCostWithBytes(kind, parent, name, opName+"_bytes", charged, actualBytes); cerr != nil {
							lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(cerr.Error()))
							return hostkit.Attempt{Status: http.StatusInternalServerError}
						}
					}
				}
			} else {
				charged := res.Commit(-1, false)
				if journal != nil {
					if attemptID != "" {
						if serr := journal.SettleAttempt(attemptID, charged, false); serr != nil && lastCallErr == nil {
							lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(serr.Error()))
							return hostkit.Attempt{Status: http.StatusInternalServerError}
						}
					} else if charged > 0 {
						if cerr := journal.RecordCostWithBytes(kind, parent, name, opName+"_egress", charged, actualBytes); cerr != nil && lastCallErr == nil {
							lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(cerr.Error()))
							return hostkit.Attempt{Status: http.StatusInternalServerError}
						}
					}
				}
			}
		}

		if lastCallErr == nil {
			return hostkit.Attempt{Status: http.StatusOK}
		}
		if errors.Is(lastCallErr, ErrLiveResponseTooLarge) {
			return hostkit.Attempt{Status: http.StatusForbidden}
		}
		status, hdr := extractHTTPResponse(lastCallErr)
		if status == 0 {
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

func (r *liveRawBackend) runExtraMeteredRead(ctx context.Context, opName, kind, parent, name, reason string, fn func(ctx context.Context) error) error {
	meter := r.activeMeter()
	journal := r.activeJournal()
	if meter == nil {
		return fn(ctx)
	}
	isCleanup := isLiveCleanupCtx(ctx) || r.sess == nil
	res, rerr := meter.ReserveAttempt(safety.AttemptPricingInput{
		Operation: opName,
		IsCleanup: isCleanup,
	})
	if rerr != nil {
		code := hostkit.PermissionDenied
		pcode := "LiveCostCapExceeded"
		if !errors.Is(rerr, safety.ErrCostCapExceeded) {
			code = hostkit.Internal
			pcode = "LivePricingFailure"
		}
		return hostkit.ProviderError(code, 0, pcode, r.sanitizeString(rerr.Error()))
	}
	var attemptID string
	if journal != nil {
		reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD
		var jerr error
		attemptID, jerr = journal.BeginAttempt(kind, parent, name, reason, reservedNano, 0)
		if jerr != nil {
			res.Commit(0, false)
			return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(jerr.Error()))
		}
	}
	callErr := fn(ctx)
	charged := res.Commit(-1, false)
	if journal != nil {
		if serr := journal.SettleAttempt(attemptID, charged, false); serr != nil && callErr == nil {
			return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(serr.Error()))
		}
	}
	return callErr
}

func (r *liveRawBackend) readOwnershipMetered(ctx context.Context, ref safety.ResourceRef, isCleanup bool, reason string) (safety.RemoteOwnership, error, *hostkit.CloudError) {
	if isCleanup {
		ctx = withLiveCleanup(ctx)
	}
	op := "bucket_read_ownership"
	switch ref.Kind {
	case safety.KindQueue:
		op = "queue_read_ownership"
	case safety.KindObject:
		op = "object_head"
	}
	var (
		ro      safety.RemoteOwnership
		readErr error
	)
	mErr := r.runExtraMeteredRead(ctx, op, ref.Kind, ref.Parent, ref.Name, reason, func(ctx context.Context) error {
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		ro, readErr = r.ReadOwnership(reqCtx, ref)
		return nil
	})
	if mErr != nil {
		return safety.RemoteOwnership{}, nil, hostkit.AsCloudError(mErr)
	}
	return ro, readErr, nil
}

// --- safety.RecoveryAdapter ---

func (r *liveRawBackend) AttestIdentity(ctx context.Context) (safety.AttestedIdentity, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if r.awsCfg.Credentials == nil {
		return safety.AttestedIdentity{}, hostkit.ProviderError(
			hostkit.Unauthenticated,
			0,
			"LiveCredentialsUnavailable",
			"no AWS credential provider available in live chain",
		)
	}
	creds, err := r.awsCfg.Credentials.Retrieve(reqCtx)
	if err != nil {
		return safety.AttestedIdentity{}, hostkit.ProviderError(
			hostkit.Unauthenticated,
			0,
			"LiveCredentialsUnavailable",
			"AWS credential chain failed to retrieve credentials",
		)
	}
	r.registerSecret(creds.SecretAccessKey)
	r.registerSecret(creds.SessionToken)
	r.registerSecret(creds.AccessKeyID)

	if strings.TrimSpace(creds.AccessKeyID) == "" || strings.TrimSpace(creds.SecretAccessKey) == "" {
		return safety.AttestedIdentity{}, hostkit.ProviderError(
			hostkit.Unauthenticated,
			0,
			"LiveCredentialsUnavailable",
			"AWS credential chain returned empty access key or secret key",
		)
	}
	if creds.AccessKeyID == defaultSimAccessKey || creds.SecretAccessKey == defaultSimSecretKey {
		return safety.AttestedIdentity{}, hostkit.ProviderError(
			hostkit.Unauthenticated,
			0,
			"SimCredentialsInLiveForbidden",
			"simulator dummy credentials cannot be used in live mode",
		)
	}

	out, err := r.stsClient().GetCallerIdentity(reqCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		ce := r.classifyLive(err, scopeNone)
		if ce.Code != hostkit.PermissionDenied {
			ce.Code = hostkit.Unauthenticated
		}
		if ce.ProviderCode == "" {
			ce.ProviderCode = "STSGetCallerIdentityFailed"
		}
		return safety.AttestedIdentity{}, ce
	}

	gotAccount := strings.TrimSpace(aws.ToString(out.Account))
	gotARN := strings.TrimSpace(aws.ToString(out.Arn))
	if gotAccount == "" || gotARN == "" {
		return safety.AttestedIdentity{}, hostkit.ProviderError(
			hostkit.Unauthenticated,
			0,
			"InvalidCallerIdentity",
			"STS GetCallerIdentity returned an empty Account or Arn",
		)
	}
	if gotAccount != r.account {
		return safety.AttestedIdentity{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"LiveAccountMismatch",
			fmt.Sprintf("STS GetCallerIdentity account %q does not match required LMAWS_LIVE_ACCOUNT %q", gotAccount, r.account),
		)
	}
	iamPrefix := "arn:aws:iam::" + r.account + ":"
	stsPrefix := "arn:aws:sts::" + r.account + ":"
	if !strings.HasPrefix(gotARN, iamPrefix) && !strings.HasPrefix(gotARN, stsPrefix) {
		return safety.AttestedIdentity{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"LiveScopeMismatch",
			fmt.Sprintf("STS GetCallerIdentity ARN %q does not belong to required account %q", r.sanitizeString(gotARN), r.account),
		)
	}

	r.mu.Lock()
	r.attestedAccount = gotAccount
	r.attestedARN = gotARN
	r.mu.Unlock()

	return safety.AttestedIdentity{
		Provider:  "aws",
		Account:   gotAccount,
		Principal: gotARN,
		AuthMode:  r.authMode,
	}, nil
}

func (r *liveRawBackend) ResolveScope(_ context.Context, service string) (safety.ResolvedScope, error) {
	r.mu.Lock()
	acct := r.attestedAccount
	arn := r.attestedARN
	r.mu.Unlock()
	if acct == "" {
		acct = r.account
	}
	var ep string
	switch service {
	case "storage":
		ep = "https://s3." + r.region + ".amazonaws.com"
	case "queue":
		ep = "https://sqs." + r.region + ".amazonaws.com"
	default:
		return safety.ResolvedScope{}, fmt.Errorf("unsupported live service %q", service)
	}
	return safety.ResolvedScope{
		Provider: "aws",
		Account:  acct,
		Scope:    arn,
		Region:   r.region,
		Endpoint: ep,
	}, nil
}

func (r *liveRawBackend) attestedARNValue() string {
	r.mu.Lock()
	arn := r.attestedARN
	r.mu.Unlock()
	return arn
}

func (r *liveRawBackend) doRecoveryAWS(ctx context.Context, idempotent bool, op func(ctx context.Context) error) error {
	var lastCallErr error
	r.retry.Do(ctx, idempotent, func(ctx context.Context, _ int) hostkit.Attempt {
		lastCallErr = op(ctx)
		if lastCallErr == nil {
			return hostkit.Attempt{Status: http.StatusOK}
		}
		if errors.Is(lastCallErr, ErrLiveResponseTooLarge) {
			return hostkit.Attempt{Status: http.StatusForbidden}
		}
		status, hdr := extractHTTPResponse(lastCallErr)
		if status == 0 {
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

const (
	liveOwnerTagKey   = "lmcloud-owner"
	liveOwnerTagValue = "conformance"
	liveRunTagKey     = "lmcloud-run"
)

func isInternalOwnershipMetaKey(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case safety.TagKeyRunID, safety.TagKeyOwnerNonce, safety.TagKeyCreateToken, safety.TagKeyCreatedAt,
		liveOwnerTagKey, liveRunTagKey, createTokenTagKey:
		return true
	default:
		return false
	}
}

func liveOwnershipTagMap(ctx context.Context) (safety.OwnershipTags, map[string]string, error) {
	tags, ok := safety.OwnershipTagsFrom(ctx)
	if !ok || strings.TrimSpace(tags.RunID) == "" || strings.TrimSpace(tags.OwnerNonce) == "" || strings.TrimSpace(tags.CreateToken) == "" {
		return safety.OwnershipTags{}, nil, hostkit.ProviderError(
			hostkit.Internal,
			0,
			"MissingOwnershipTags",
			"live create requires safety.OwnershipTags in context",
		)
	}
	m := tags.Map()
	m[liveOwnerTagKey] = liveOwnerTagValue
	m[liveRunTagKey] = tags.RunID
	return tags, m, nil
}

func buildS3TagSet(tags map[string]string) []s3types.Tag {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]s3types.Tag, 0, len(keys))
	for _, k := range keys {
		out = append(out, s3types.Tag{
			Key:   aws.String(k),
			Value: aws.String(tags[k]),
		})
	}
	return out
}

func encodeS3TaggingHeader(tags map[string]string) string {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	vals := url.Values{}
	for _, k := range keys {
		vals.Set(k, tags[k])
	}
	return vals.Encode()
}

func s3TagSetToMap(tags []s3types.Tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		k := strings.TrimSpace(aws.ToString(t.Key))
		if k != "" {
			m[k] = strings.TrimSpace(aws.ToString(t.Value))
		}
	}
	return m
}

func applyRemoteOwnershipTags(tagMap map[string]string, ro *safety.RemoteOwnership) {
	if len(tagMap) == 0 || ro == nil {
		return
	}
	ownerVal := strings.TrimSpace(tagMap[liveOwnerTagKey])
	runVal := strings.TrimSpace(tagMap[liveRunTagKey])
	safetyRunVal := strings.TrimSpace(tagMap[safety.TagKeyRunID])
	if safetyRunVal == "" {
		safetyRunVal = runVal
	}
	// Require both lmcloud-owner=conformance and matching lmcloud-run / lmcloud_run_id.
	if ownerVal != liveOwnerTagValue || runVal == "" || safetyRunVal != runVal {
		return
	}
	ro.RunID = safetyRunVal
	ro.OwnerNonce = strings.TrimSpace(tagMap[safety.TagKeyOwnerNonce])
	ro.CreateToken = strings.TrimSpace(tagMap[safety.TagKeyCreateToken])
	if ro.CreateToken == "" {
		ro.CreateToken = strings.TrimSpace(tagMap[createTokenTagKey])
	}
	if tsStr := strings.TrimSpace(tagMap[safety.TagKeyCreatedAt]); tsStr != "" {
		if ts, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
			ro.CreatedAtUnix = ts
		}
	}
}

func (r *liveRawBackend) ReadOwnership(ctx context.Context, ref safety.ResourceRef) (safety.RemoteOwnership, error) {
	owner := r.ownerAccount()
	scopeARN := r.attestedARNValue()

	switch ref.Kind {
	case safety.KindBucket:
		cli := r.s3Client()
		headErr := r.doLiveAWS(ctx, "bucket_read_ownership", safety.KindBucket, "", ref.Name, 0, true, func(ctx context.Context) error {
			_, err := cli.HeadBucket(ctx, &s3.HeadBucketInput{
				Bucket:              aws.String(ref.Name),
				ExpectedBucketOwner: aws.String(owner),
			})
			return err
		})
		if headErr != nil {
			status, _ := extractHTTPResponse(headErr)
			if status == http.StatusForbidden && !hasExplicitHeadAuthHeader(headErr) {
				probeErr := r.doExtraPhysicalAWS(ctx, "bucket_exists", safety.KindBucket, "", ref.Name, "read_ownership_bucket_403_probe", maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
					_, pErr := cli.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
						Bucket:              aws.String(ref.Name),
						ExpectedBucketOwner: aws.String(owner),
					})
					return pErr
				})
				if probeErr != nil {
					var pce *hostkit.CloudError
					if errors.As(probeErr, &pce) && pce != nil && pce.ProviderCode == "LiveCostCapExceeded" {
						return safety.RemoteOwnership{}, pce
					}
					if classified := r.classifyLive(probeErr, scopeBucket); classified.Code == hostkit.Unauthenticated || classified.Code == hostkit.PermissionDenied {
						return safety.RemoteOwnership{}, classified
					}
				}
			}
			ce := r.classifyLive(headErr, scopeBucket)
			if ce.Code == hostkit.NotFound {
				return safety.RemoteOwnership{Exists: false}, nil
			}
			return safety.RemoteOwnership{}, ce
		}

		ro := safety.RemoteOwnership{
			Exists:              true,
			ProviderID:          "arn:aws:s3:::" + ref.Name,
			Account:             owner,
			Scope:               scopeARN,
			Location:            r.region,
			ServerCreatedAtUnix: r.getBucketCreatedUnix(ref.Name),
		}

		var tagOut *s3.GetBucketTaggingOutput
		tagErr := r.doExtraPhysicalAWS(ctx, "bucket_read_ownership", safety.KindBucket, "", ref.Name, "read_ownership_bucket_tags", maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
			var tErr error
			tagOut, tErr = cli.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
				Bucket:              aws.String(ref.Name),
				ExpectedBucketOwner: aws.String(owner),
			})
			return tErr
		})
		if tagErr == nil && tagOut != nil {
			applyRemoteOwnershipTags(s3TagSetToMap(tagOut.TagSet), &ro)
		} else if tagErr != nil {
			ce := r.classifyLive(tagErr, scopeBucket)
			if ce.ProviderCode != "NoSuchTagSet" {
				if ce.Code == hostkit.NotFound && ce.Absent == hostkit.AbsentBucket {
					return safety.RemoteOwnership{Exists: false}, nil
				}
				return safety.RemoteOwnership{}, ce
			}
		}

		var childKeys []string
		var token string
		preReservedList, _ := ctx.Value(preReservedBucketListKey{}).(*bool)
		sweepPreReserved, _ := ctx.Value(sweepPreReservesBucketListKey{}).(bool)
		for page := 0; page < 32; page++ {
			in := &s3.ListObjectsV2Input{
				Bucket:              aws.String(ref.Name),
				MaxKeys:             aws.Int32(int32(maxLiveObjectListPageSize)),
				ExpectedBucketOwner: aws.String(owner),
			}
			if token != "" {
				in.ContinuationToken = aws.String(token)
			}
			var listOut *s3.ListObjectsV2Output
			ownListAttempt := true
			if page == 0 {
				if preReservedList != nil && !*preReservedList {
					*preReservedList = true
					ownListAttempt = false
				} else if sweepPreReserved {
					ownListAttempt = false
				}
			}
			lErr := r.doLiveAWSWithMode(
				ctx,
				"object_list",
				safety.KindBucket,
				"",
				ref.Name,
				fmt.Sprintf("read_ownership_bucket_children_p%d", page),
				objectListWorstCaseBytes(maxLiveObjectListPageSize),
				true,
				ownListAttempt,
				func(ctx context.Context) error {
					var err error
					listOut, err = cli.ListObjectsV2(ctx, in)
					return err
				},
			)
			if lErr != nil {
				return safety.RemoteOwnership{}, r.classifyLive(lErr, scopeBucket)
			}
			for _, obj := range listOut.Contents {
				if obj.Key != nil {
					childKeys = append(childKeys, *obj.Key)
				}
			}
			next := strings.TrimSpace(aws.ToString(listOut.NextContinuationToken))
			if !aws.ToBool(listOut.IsTruncated) || next == "" || next == token {
				ro.ChildrenVerified = !aws.ToBool(listOut.IsTruncated)
				break
			}
			token = next
		}
		ro.ChildKeys = childKeys
		return ro, nil

	case safety.KindObject:
		cli := r.s3Client()
		var headOut *s3.HeadObjectOutput
		headErr := r.doLiveAWS(ctx, "object_head", safety.KindObject, ref.Parent, ref.Name, 0, true, func(ctx context.Context) error {
			var err error
			headOut, err = cli.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:              aws.String(ref.Parent),
				Key:                 aws.String(ref.Name),
				ExpectedBucketOwner: aws.String(owner),
			})
			return err
		})
		if headErr != nil {
			ce := r.classifyLive(headErr, scopeObject)
			if ce.Code == hostkit.NotFound {
				return safety.RemoteOwnership{Exists: false}, nil
			}
			return safety.RemoteOwnership{}, ce
		}

		ro := safety.RemoteOwnership{
			Exists:     true,
			ProviderID: "arn:aws:s3:::" + ref.Parent + "/" + ref.Name,
			Account:    owner,
			Scope:      scopeARN,
			Location:   r.region,
			ETag:       cleanETag(aws.ToString(headOut.ETag)),
			Generation: strings.TrimSpace(aws.ToString(headOut.VersionId)),
		}
		var tagOut *s3.GetObjectTaggingOutput
		tagErr := r.doExtraPhysicalAWS(ctx, "object_head", safety.KindObject, ref.Parent, ref.Name, "read_ownership_object_tags", maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
			var tErr error
			tagOut, tErr = cli.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket:              aws.String(ref.Parent),
				Key:                 aws.String(ref.Name),
				ExpectedBucketOwner: aws.String(owner),
			})
			return tErr
		})
		if tagErr == nil && tagOut != nil {
			applyRemoteOwnershipTags(s3TagSetToMap(tagOut.TagSet), &ro)
		} else if tagErr != nil {
			ce := r.classifyLive(tagErr, scopeObject)
			if ce.ProviderCode != "NoSuchTagSet" {
				if ce.Code == hostkit.NotFound {
					return safety.RemoteOwnership{Exists: false}, nil
				}
				return safety.RemoteOwnership{}, ce
			}
		}
		return ro, nil

	case safety.KindQueue:
		cli := r.sqsClient()
		var urlOut *sqs.GetQueueUrlOutput
		urlErr := r.doLiveAWS(ctx, "queue_read_ownership", safety.KindQueue, "", ref.Name, maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
			var gErr error
			urlOut, gErr = cli.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
				QueueName:              aws.String(ref.Name),
				QueueOwnerAWSAccountId: aws.String(owner),
			})
			return gErr
		})
		if urlErr != nil {
			ce := r.classifyLive(urlErr, scopeQueue)
			if ce.Code == hostkit.NotFound {
				return safety.RemoteOwnership{Exists: false}, nil
			}
			return safety.RemoteOwnership{}, ce
		}
		rawURL := strings.TrimSpace(aws.ToString(urlOut.QueueUrl))
		qName, verr := validateLiveQueueURL(rawURL, r.region, owner)
		if verr != nil {
			return safety.RemoteOwnership{}, hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", r.sanitizeString(verr.Error()))
		}
		if qName != ref.Name {
			return safety.RemoteOwnership{}, hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", fmt.Sprintf("sqs GetQueueUrl returned queue %q, wanted %q", qName, ref.Name))
		}

		ro := safety.RemoteOwnership{
			Exists:     true,
			ProviderID: rawURL,
			Account:    owner,
			Scope:      scopeARN,
			Location:   r.region,
		}
		var tagOut *sqs.ListQueueTagsOutput
		tagErr := r.doExtraPhysicalAWS(ctx, "queue_read_ownership", safety.KindQueue, "", ref.Name, "read_ownership_queue_tags", maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
			var tErr error
			tagOut, tErr = cli.ListQueueTags(ctx, &sqs.ListQueueTagsInput{
				QueueUrl: aws.String(rawURL),
			})
			return tErr
		})
		if tagErr != nil {
			ce := r.classifyLive(tagErr, scopeQueue)
			if ce.Code == hostkit.NotFound {
				return safety.RemoteOwnership{Exists: false}, nil
			}
			return safety.RemoteOwnership{}, ce
		}
		if tagOut != nil {
			applyRemoteOwnershipTags(tagOut.Tags, &ro)
		}
		return ro, nil

	case safety.KindQueueMessage:
		return safety.RemoteOwnership{Exists: false}, nil

	default:
		return safety.RemoteOwnership{}, fmt.Errorf("unsupported resource kind %q for ReadOwnership", ref.Kind)
	}
}

func (r *liveRawBackend) FindOwned(ctx context.Context, prefix string) ([]safety.ResourceRef, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil, nil
	}
	ctx = withLiveCleanup(ctx)
	var refs []safety.ResourceRef

	// 1. Enumerate S3 buckets matching prefix.
	s3Cli := r.s3Client()
	var bToken string
	for page := 0; page < 16; page++ {
		in := &s3.ListBucketsInput{
			MaxBuckets:   aws.Int32(maxLiveBucketListPageSize),
			BucketRegion: aws.String(r.region),
		}
		if bToken != "" {
			in.ContinuationToken = aws.String(bToken)
		}
		var out *s3.ListBucketsOutput
		err := r.doExtraPhysicalAWS(ctx, "bucket_list", safety.KindBucket, "", prefix, fmt.Sprintf("find_owned_buckets_p%d", page), maxLiveListRespBodyBytes, true, func(ctx context.Context) error {
			var lErr error
			out, lErr = s3Cli.ListBuckets(ctx, in)
			return lErr
		})
		if err != nil {
			return nil, r.classifyLive(err, scopeNone)
		}
		for _, b := range out.Buckets {
			name := strings.TrimSpace(aws.ToString(b.Name))
			if b.CreationDate != nil && !b.CreationDate.IsZero() {
				r.recordBucketCreatedUnix(name, b.CreationDate.UTC().Unix())
			}
			if strings.HasPrefix(name, prefix) {
				refs = append(refs, safety.ResourceRef{
					Kind:       safety.KindBucket,
					Location:   r.region,
					Name:       name,
					ProviderID: "arn:aws:s3:::" + name,
				})
			}
		}
		next := strings.TrimSpace(aws.ToString(out.ContinuationToken))
		if next == "" || next == bToken {
			break
		}
		bToken = next
	}

	// 2. Enumerate SQS queues matching prefix.
	sqsCli := r.sqsClient()
	owner := r.ownerAccount()
	var qToken string
	for page := 0; page < 16; page++ {
		in := &sqs.ListQueuesInput{
			MaxResults:      aws.Int32(maxLiveQueueListPageSize),
			QueueNamePrefix: aws.String(prefix),
		}
		if qToken != "" {
			in.NextToken = aws.String(qToken)
		}
		var out *sqs.ListQueuesOutput
		err := r.doExtraPhysicalAWS(ctx, "queue_list", safety.KindQueue, "", prefix, fmt.Sprintf("find_owned_queues_p%d", page), maxLiveListRespBodyBytes, true, func(ctx context.Context) error {
			var lErr error
			out, lErr = sqsCli.ListQueues(ctx, in)
			return lErr
		})
		if err != nil {
			return nil, r.classifyLive(err, scopeQueue)
		}
		for _, u := range out.QueueUrls {
			qName, verr := validateLiveQueueURL(u, r.region, owner)
			if verr != nil {
				return nil, hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", r.sanitizeString(verr.Error()))
			}
			if strings.HasPrefix(qName, prefix) {
				refs = append(refs, safety.ResourceRef{
					Kind:       safety.KindQueue,
					Location:   r.region,
					Name:       qName,
					ProviderID: strings.TrimSpace(u),
				})
			}
		}
		next := strings.TrimSpace(aws.ToString(out.NextToken))
		if next == "" || next == qToken {
			break
		}
		qToken = next
	}

	return refs, nil
}

func (r *liveRawBackend) DeleteOwned(ctx context.Context, ref safety.ResourceRef, ro safety.RemoteOwnership) error {
	ctx = withLiveCleanup(ctx)
	switch ref.Kind {
	case safety.KindObject:
		if ro.ETag != "" {
			ctx = context.WithValue(ctx, expectedDeleteObjectETagKey{}, cleanETag(ro.ETag))
		}
		return r.DeleteObject(ctx, ref.Parent, ref.Name)
	case safety.KindBucket:
		return r.DeleteBucket(ctx, ref.Name)
	case safety.KindQueue:
		return r.DeleteQueue(ctx, ref.Name)
	case safety.KindQueueMessage:
		return nil
	default:
		return fmt.Errorf("unsupported resource kind %q for DeleteOwned", ref.Kind)
	}
}

func (r *liveRawBackend) PollDelete(ctx context.Context, ref safety.ResourceRef) (bool, error) {
	ctx = withLiveCleanup(ctx)
	owner := r.ownerAccount()
	switch ref.Kind {
	case safety.KindObject:
		cli := r.s3Client()
		err := r.doLiveAWS(ctx, "object_head", safety.KindObject, ref.Parent, ref.Name, 0, true, func(ctx context.Context) error {
			_, hErr := cli.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:              aws.String(ref.Parent),
				Key:                 aws.String(ref.Name),
				ExpectedBucketOwner: aws.String(owner),
			})
			return hErr
		})
		if err == nil {
			return false, nil
		}
		if r.ClassifyAbsent(err) == safety.AbsenceDefinitive {
			return true, nil
		}
		return false, r.classifyLive(err, scopeObject)

	case safety.KindBucket:
		cli := r.s3Client()
		err := r.doLiveAWS(ctx, "bucket_exists", safety.KindBucket, "", ref.Name, 0, true, func(ctx context.Context) error {
			_, hErr := cli.HeadBucket(ctx, &s3.HeadBucketInput{
				Bucket:              aws.String(ref.Name),
				ExpectedBucketOwner: aws.String(owner),
			})
			return hErr
		})
		if err == nil {
			return false, nil
		}
		if r.ClassifyAbsent(err) == safety.AbsenceDefinitive {
			return true, nil
		}
		return false, r.classifyLive(err, scopeBucket)

	case safety.KindQueue:
		cli := r.sqsClient()
		err := r.doLiveAWS(ctx, "queue_exists", safety.KindQueue, "", ref.Name, maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
			_, gErr := cli.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
				QueueName:              aws.String(ref.Name),
				QueueOwnerAWSAccountId: aws.String(owner),
			})
			return gErr
		})
		if err == nil {
			return false, nil
		}
		if r.ClassifyAbsent(err) == safety.AbsenceDefinitive {
			return true, nil
		}
		return false, r.classifyLive(err, scopeQueue)

	case safety.KindQueueMessage:
		return true, nil

	default:
		return false, fmt.Errorf("unsupported resource kind %q for PollDelete", ref.Kind)
	}
}

func (r *liveRawBackend) ClassifyAbsent(err error) safety.AbsenceClass {
	if err == nil {
		return safety.AbsencePresentOrError
	}
	ce := r.classifyLive(err, scopeNone)
	switch ce.Code {
	case hostkit.NotFound:
		return safety.AbsenceDefinitive
	case hostkit.PermissionDenied, hostkit.Unauthenticated, hostkit.Conflict, hostkit.PreconditionFailed:
		return safety.AbsenceAmbiguous
	default:
		return safety.AbsencePresentOrError
	}
}

func (r *liveRawBackend) QuoteAttempt(in safety.AttemptPricingInput, base safety.AttemptQuote) (safety.AttemptQuote, error) {
	q := base
	if in.EgressBytes > 0 && in.Operation != "object_get" {
		q.AttemptNanoUSD += liveEgressNanoUSD(in.EgressBytes)
	}
	return q, nil
}

// --- S3 & SQS Implementations on liveRawBackend ---

func (r *liveRawBackend) CreateBucket(ctx context.Context, name string) (bool, error) {
	wantTags, tagMap, terr := liveOwnershipTagMap(ctx)
	if terr != nil {
		return false, terr
	}
	cli := r.s3Client()
	owner := r.ownerAccount()

	in := &s3.CreateBucketInput{Bucket: aws.String(name)}
	if r.region != "" && r.region != defaultSimRegion {
		in.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(r.region),
		}
	}
	err := r.doLiveAWS(ctx, "bucket_create", safety.KindBucket, "", name, 0, true, func(ctx context.Context) error {
		_, cErr := cli.CreateBucket(ctx, in)
		return cErr
	})
	if err != nil {
		ce := r.classifyLive(err, scopeBucket)
		if ce.ProviderCode != "BucketAlreadyOwnedByYou" {
			return false, ce
		}
	}

	// S3 CreateBucket in us-east-1 with omitted LocationConstraint returns 200 OK
	// on an already-owned same-account bucket (BucketAlreadyOwnedByYou semantics).
	// Before calling PutBucketTagging, verify via metered GetBucketTagging and
	// ListObjectsV2(MaxKeys: 1) that the bucket does NOT already carry foreign tags
	// and is completely empty, so a concurrent or pre-existing bucket can NEVER
	// have its tags overwritten and be adopted by this run.
	var preTagOut *s3.GetBucketTaggingOutput
	preTagErr := r.doExtraPhysicalAWS(
		ctx,
		"bucket_read_ownership",
		safety.KindBucket,
		"",
		name,
		"bucket_create_pre_tag_check",
		maxLiveSmallRespBodyBytes,
		true,
		func(ctx context.Context) error {
			var gErr error
			preTagOut, gErr = cli.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
				Bucket:              aws.String(name),
				ExpectedBucketOwner: aws.String(owner),
			})
			return gErr
		},
	)
	if preTagErr == nil && preTagOut != nil && len(preTagOut.TagSet) > 0 {
		existingMap := s3TagSetToMap(preTagOut.TagSet)
		var existingRO safety.RemoteOwnership
		applyRemoteOwnershipTags(existingMap, &existingRO)
		if existingRO.RunID != wantTags.RunID ||
			existingRO.OwnerNonce != wantTags.OwnerNonce ||
			existingRO.CreateToken != wantTags.CreateToken {
			return false, hostkit.ProviderError(
				hostkit.Conflict,
				http.StatusConflict,
				"ForeignResourceCollision",
				fmt.Sprintf("bucket %q already has non-matching tags immediately after CreateBucket; refusing to overwrite tags", name),
			)
		}
	} else if preTagErr != nil {
		ce := r.classifyLive(preTagErr, scopeBucket)
		if ce.ProviderCode != "NoSuchTagSet" {
			return false, ce
		}
	}

	var preListOut *s3.ListObjectsV2Output
	preListErr := r.doExtraPhysicalAWS(
		ctx,
		"object_list",
		safety.KindBucket,
		"",
		name,
		"bucket_create_empty_check",
		objectListWorstCaseBytes(1),
		true,
		func(ctx context.Context) error {
			var lErr error
			preListOut, lErr = cli.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket:              aws.String(name),
				MaxKeys:             aws.Int32(1),
				ExpectedBucketOwner: aws.String(owner),
			})
			return lErr
		},
	)
	if preListErr != nil {
		return false, r.classifyLive(preListErr, scopeBucket)
	}
	if preListOut != nil && len(preListOut.Contents) > 0 {
		return false, hostkit.ProviderError(
			hostkit.Conflict,
			http.StatusConflict,
			"ForeignResourceCollision",
			fmt.Sprintf("bucket %q is non-empty immediately after CreateBucket; refusing to tag pre-existing bucket", name),
		)
	}

	// Attach the mandatory conformance + safety ownership tags via PutBucketTagging.
	// GuardStore.CreateBucket always calls ReadOwnership afterwards and marks
	// the bucket StateRetained if tagging failed or mismatched.
	tagSet := buildS3TagSet(tagMap)
	tagErr := r.doExtraPhysicalAWS(
		ctx,
		"bucket_list",
		safety.KindBucket,
		"",
		name,
		"bucket_create_put_tagging",
		0,
		true,
		func(ctx context.Context) error {
			_, pErr := cli.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
				Bucket:              aws.String(name),
				ExpectedBucketOwner: aws.String(owner),
				Tagging:             &s3types.Tagging{TagSet: tagSet},
			})
			return pErr
		},
	)
	if tagErr != nil {
		return false, r.classifyLive(tagErr, scopeBucket)
	}
	return true, nil
}

func (r *liveRawBackend) DeleteBucket(ctx context.Context, name string) error {
	cli := r.s3Client()
	owner := r.ownerAccount()
	err := r.doLiveAWS(ctx, "bucket_delete", safety.KindBucket, "", name, 0, true, func(ctx context.Context) error {
		_, dErr := cli.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket:              aws.String(name),
			ExpectedBucketOwner: aws.String(owner),
		})
		return dErr
	})
	if err == nil {
		return nil
	}
	ce := r.classifyLive(err, scopeBucket)
	if ce.Code == hostkit.NotFound {
		return ce.WithAbsent(hostkit.AbsentBucket)
	}
	return ce
}

func (r *liveRawBackend) PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (hostkit.ObjectMeta, error) {
	_, tagMap, terr := liveOwnershipTagMap(ctx)
	if terr != nil {
		return hostkit.ObjectMeta{}, terr
	}

	// Verify whether an object with this key already exists in the bucket.
	// If it exists remotely, it MUST have been tracked as an owned resource in
	// our run journal BEFORE this PutObject and carry matching remote ownership
	// tags; otherwise mark it StateRetained and refuse the overwrite.
	preState, hasPreState := ctx.Value(prePutObjStateKey{}).(prePutObjState)
	ro, rerr, rcerr := r.readOwnershipMetered(ctx, safety.ResourceRef{
		Kind:     safety.KindObject,
		Parent:   bucket,
		Location: r.region,
		Name:     key,
	}, false, "pre_put_object_ownership_check")
	if rcerr != nil {
		return hostkit.ObjectMeta{}, rcerr
	}
	if rerr != nil && r.ClassifyAbsent(rerr) != safety.AbsenceDefinitive {
		if j := r.activeJournal(); j != nil {
			_ = j.Retain(safety.KindObject, bucket, key, "ambiguous pre-put object ownership probe: "+rerr.Error())
		}
		return hostkit.ObjectMeta{}, r.classifyLive(rerr, scopeObject)
	}
	var (
		condIfNoneMatch *string
		condIfMatch     *string
	)
	if rerr == nil && ro.Exists {
		j := r.activeJournal()
		provenETag := cleanETag(ro.ETag)
		allowedOverwrite := hasPreState &&
			preState.existsInJournal &&
			preState.entry.State == safety.StateConfirmed &&
			!preState.entry.Retain &&
			provenETag != "" &&
			j != nil &&
			ro.VerifyMatchesEntry(preState.entry, j.Meta()) == nil
		if !allowedOverwrite {
			if j != nil {
				_ = j.Retain(safety.KindObject, bucket, key, "foreign or untagged existing object in owned bucket")
			}
			return hostkit.ObjectMeta{}, hostkit.ProviderError(
				hostkit.Conflict,
				http.StatusConflict,
				"ForeignResourceCollision",
				fmt.Sprintf("refusing to overwrite existing unowned or untagged object %s/%s", bucket, key),
			)
		}
		condIfMatch = aws.String(`"` + provenETag + `"`)
	} else {
		if hasPreState && preState.existsInJournal && preState.entry.State == safety.StateConfirmed {
			if j := r.activeJournal(); j != nil {
				_ = j.Retain(safety.KindObject, bucket, key, "confirmed object disappeared remotely before overwrite")
			}
			return hostkit.ObjectMeta{}, hostkit.ProviderError(
				hostkit.Conflict,
				http.StatusConflict,
				"ForeignResourceCollision",
				fmt.Sprintf("confirmed object %s/%s disappeared remotely before overwrite", bucket, key),
			)
		}
		condIfNoneMatch = aws.String("*")
	}

	cli := r.s3Client()
	owner := r.ownerAccount()
	taggingHeader := encodeS3TaggingHeader(tagMap)

	userMeta := make(map[string]string, len(metadata))
	for k, v := range metadata {
		if !isInternalOwnershipMetaKey(k) {
			userMeta[k] = v
		}
	}

	var out *s3.PutObjectOutput
	err := r.doLiveAWS(ctx, "object_put", safety.KindObject, bucket, key, 0, true, func(ctx context.Context) error {
		var pErr error
		out, pErr = cli.PutObject(ctx, &s3.PutObjectInput{
			Bucket:              aws.String(bucket),
			Key:                 aws.String(key),
			Body:                bytes.NewReader(body),
			ContentType:         aws.String(contentType),
			Metadata:            userMeta,
			Tagging:             aws.String(taggingHeader),
			ExpectedBucketOwner: aws.String(owner),
			IfNoneMatch:         condIfNoneMatch,
			IfMatch:             condIfMatch,
		})
		return pErr
	})
	if err != nil {
		ce := r.classifyLive(err, scopeObject)
		if ce.Code == hostkit.PreconditionFailed || ce.Code == hostkit.Conflict ||
			ce.HTTPStatus == http.StatusPreconditionFailed || ce.HTTPStatus == http.StatusConflict ||
			ce.ProviderCode == "PreconditionFailed" || ce.ProviderCode == "ConditionalRequestConflict" {
			if j := r.activeJournal(); j != nil {
				_ = j.Retain(safety.KindObject, bucket, key, "conditional PutObject precondition failed: "+ce.Error())
			}
			return hostkit.ObjectMeta{}, hostkit.ProviderError(
				hostkit.Conflict,
				http.StatusConflict,
				"ForeignResourceCollision",
				fmt.Sprintf("conditional PutObject failed precondition for %s/%s: refusing concurrent overwrite", bucket, key),
			)
		}
		return hostkit.ObjectMeta{}, ce
	}
	etag := cleanETag(aws.ToString(out.ETag))
	metaCopy := make(map[string]string, len(userMeta))
	for k, v := range userMeta {
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

func (r *liveRawBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	cli := r.s3Client()
	owner := r.ownerAccount()
	expectedETag, _ := ctx.Value(expectedDeleteObjectETagKey{}).(string)
	if expectedETag == "" {
		if j := r.activeJournal(); j != nil {
			if entry, ok := j.Lookup(safety.KindObject, bucket, key); ok && entry.ETag != "" {
				expectedETag = cleanETag(entry.ETag)
			}
		}
	}
	err := r.doLiveAWS(ctx, "object_delete", safety.KindObject, bucket, key, 0, true, func(ctx context.Context) error {
		in := &s3.DeleteObjectInput{
			Bucket:              aws.String(bucket),
			Key:                 aws.String(key),
			ExpectedBucketOwner: aws.String(owner),
		}
		if expectedETag != "" {
			in.IfMatch = aws.String(`"` + expectedETag + `"`)
		}
		_, dErr := cli.DeleteObject(ctx, in)
		return dErr
	})
	if err != nil {
		ce := r.classifyLive(err, scopeObject)
		if ce.Code == hostkit.PreconditionFailed || ce.Code == hostkit.Conflict ||
			ce.HTTPStatus == http.StatusPreconditionFailed || ce.HTTPStatus == http.StatusConflict ||
			ce.ProviderCode == "PreconditionFailed" || ce.ProviderCode == "ConditionalRequestConflict" {
			if j := r.activeJournal(); j != nil {
				_ = j.Retain(safety.KindObject, bucket, key, "conditional DeleteObject precondition failed: "+ce.Error())
			}
			return hostkit.ProviderError(
				hostkit.Conflict,
				http.StatusConflict,
				"ForeignResourceCollision",
				fmt.Sprintf("conditional DeleteObject failed precondition for %s/%s: refusing delete", bucket, key),
			)
		}
		return ce
	}
	return nil
}

func (r *liveRawBackend) GetObject(ctx context.Context, bucket, key string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > safety.DefaultMaxObjectBytes {
		limit = safety.DefaultMaxObjectBytes
	}
	proof, hasProof := ctx.Value(expectedObjectProofKey{}).(expectedObjectProof)
	cli := r.s3Client()
	owner := r.ownerAccount()
	var (
		data         []byte
		sizeErr      error
		etagMismatch bool
	)
	err := r.doLiveAWS(ctx, "object_get", safety.KindObject, bucket, key, 0, true, func(ctx context.Context) error {
		in := &s3.GetObjectInput{
			Bucket:              aws.String(bucket),
			Key:                 aws.String(key),
			ExpectedBucketOwner: aws.String(owner),
		}
		if hasProof {
			if proof.etag != "" {
				in.IfMatch = aws.String(`"` + proof.etag + `"`)
			}
			if proof.versionID != "" {
				in.VersionId = aws.String(proof.versionID)
			}
		}
		out, gErr := cli.GetObject(ctx, in)
		if gErr != nil {
			return gErr
		}
		defer out.Body.Close()
		if hasProof && proof.etag != "" && cleanETag(aws.ToString(out.ETag)) != proof.etag {
			etagMismatch = true
			return nil
		}
		if limit > 0 && out.ContentLength != nil && *out.ContentLength > limit {
			sizeErr = &hostkit.CloudError{
				Code:    hostkit.Internal,
				Message: fmt.Sprintf("object %q (%d bytes) exceeds maximum size (%d bytes)", key, *out.ContentLength, limit),
			}
			return nil
		}
		var rErr error
		data, rErr = hostkit.ReadBoundedErr(out.Body, limit)
		if rErr != nil {
			sizeErr = rErr
			return nil
		}
		return nil
	})
	if sizeErr != nil {
		return nil, r.classifyLive(sizeErr, scopeObject)
	}
	if err != nil {
		ce := r.classifyLive(err, scopeObject)
		if hasProof && (ce.Code == hostkit.PreconditionFailed || ce.Code == hostkit.Conflict ||
			ce.HTTPStatus == http.StatusPreconditionFailed || ce.HTTPStatus == http.StatusConflict ||
			ce.ProviderCode == "PreconditionFailed" || ce.ProviderCode == "ConditionalRequestConflict") {
			if j := r.activeJournal(); j != nil {
				_ = j.Retain(safety.KindObject, bucket, key, "GetObject conditional If-Match failed: "+ce.Error())
			}
			return nil, hostkit.ProviderError(
				hostkit.PermissionDenied,
				http.StatusForbidden,
				"UnownedResourceReadRefused",
				fmt.Sprintf("object %s/%s changed after ownership proof (conditional GET failed)", bucket, key),
			)
		}
		return nil, ce
	}
	if etagMismatch {
		if j := r.activeJournal(); j != nil {
			_ = j.Retain(safety.KindObject, bucket, key, "GetObject response ETag mismatched proven ownership ETag")
		}
		return nil, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"UnownedResourceReadRefused",
			fmt.Sprintf("object %s/%s response ETag did not match proven ownership ETag", bucket, key),
		)
	}
	if hasProof {
		var postTagOut *s3.GetObjectTaggingOutput
		postTagErr := r.doExtraPhysicalAWS(ctx, "object_head", safety.KindObject, bucket, key, "verify_post_get_object_tags", maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
			var tErr error
			postTagOut, tErr = cli.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket:              aws.String(bucket),
				Key:                 aws.String(key),
				ExpectedBucketOwner: aws.String(owner),
			})
			return tErr
		})
		postRO := safety.RemoteOwnership{
			Exists:     true,
			ProviderID: "arn:aws:s3:::" + bucket + "/" + key,
			Account:    owner,
			Scope:      r.attestedARNValue(),
			Location:   r.region,
			ETag:       proof.etag,
			Generation: proof.versionID,
		}
		if postTagErr == nil && postTagOut != nil {
			applyRemoteOwnershipTags(s3TagSetToMap(postTagOut.TagSet), &postRO)
		}
		j := r.activeJournal()
		if postTagErr != nil || j == nil || postRO.VerifyMatchesEntry(proof.entry, j.Meta()) != nil {
			if j != nil {
				_ = j.Retain(safety.KindObject, bucket, key, "post-GET object tag verification failed")
			}
			if postTagErr != nil {
				var pce *hostkit.CloudError
				if errors.As(postTagErr, &pce) && pce != nil && pce.ProviderCode == "LiveCostCapExceeded" {
					return nil, pce
				}
			}
			return nil, hostkit.ProviderError(
				hostkit.PermissionDenied,
				http.StatusForbidden,
				"UnownedResourceReadRefused",
				fmt.Sprintf("object %s/%s failed post-GET ownership tag verification", bucket, key),
			)
		}
	}
	return data, nil
}

func (r *liveRawBackend) HeadBucket(ctx context.Context, name string) error {
	cli := r.s3Client()
	owner := r.ownerAccount()
	err := r.doLiveAWS(ctx, "bucket_exists", safety.KindBucket, "", name, 0, true, func(ctx context.Context) error {
		_, hErr := cli.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket:              aws.String(name),
			ExpectedBucketOwner: aws.String(owner),
		})
		return hErr
	})
	if err == nil {
		return nil
	}
	status, _ := extractHTTPResponse(err)
	// On a body-less 403 without X-Amzn-Errortype, issue a metered GetBucketLocation
	// metadata probe so UNAUTHENTICATED vs PERMISSION_DENIED is classified from XML.
	if status == http.StatusForbidden && !hasExplicitHeadAuthHeader(err) {
		probeErr := r.runExtraMeteredRead(ctx, "bucket_exists", safety.KindBucket, "", name, "head_bucket_403_probe", func(ctx context.Context) error {
			return r.doLiveAWS(ctx, "bucket_exists", safety.KindBucket, "", name, maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
				_, pErr := cli.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
					Bucket:              aws.String(name),
					ExpectedBucketOwner: aws.String(owner),
				})
				return pErr
			})
		})
		if probeErr != nil {
			var pce *hostkit.CloudError
			if errors.As(probeErr, &pce) && pce != nil && pce.ProviderCode == "LiveCostCapExceeded" {
				return pce
			}
			if classified := r.classifyLive(probeErr, scopeBucket); classified.Code == hostkit.Unauthenticated || classified.Code == hostkit.PermissionDenied {
				return classified
			}
		}
	}
	ce := r.classifyLive(err, scopeBucket)
	if ce.Code == hostkit.NotFound {
		return ce.WithAbsent(hostkit.AbsentBucket)
	}
	return ce
}

func (r *liveRawBackend) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	cli := r.s3Client()
	in := &s3.ListBucketsInput{
		MaxBuckets:   aws.Int32(maxLiveBucketListPageSize),
		BucketRegion: aws.String(r.region),
	}
	if token != "" {
		in.ContinuationToken = aws.String(token)
	}
	var out *s3.ListBucketsOutput
	err := r.doLiveAWS(ctx, "bucket_list", safety.KindBucket, "", "", maxLiveListRespBodyBytes, true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListBuckets(ctx, in)
		return lErr
	})
	if err != nil {
		return nil, "", r.classifyLive(err, scopeNone)
	}
	names := make([]string, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.Name != nil && *b.Name != "" {
			names = append(names, *b.Name)
		}
	}
	next := strings.TrimSpace(aws.ToString(out.ContinuationToken))
	if token != "" && next == token {
		return nil, "", hostkit.ProviderError(hostkit.Internal, 0, "StalledPagination", "pagination stalled: continuation token repeated")
	}
	return names, next, nil
}

func (r *liveRawBackend) HeadObject(ctx context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	proof, hasProof := ctx.Value(expectedObjectProofKey{}).(expectedObjectProof)
	cli := r.s3Client()
	owner := r.ownerAccount()
	var out *s3.HeadObjectOutput
	err := r.doLiveAWS(ctx, "object_head", safety.KindObject, bucket, key, 0, true, func(ctx context.Context) error {
		in := &s3.HeadObjectInput{
			Bucket:              aws.String(bucket),
			Key:                 aws.String(key),
			ExpectedBucketOwner: aws.String(owner),
		}
		if hasProof {
			if proof.etag != "" {
				in.IfMatch = aws.String(`"` + proof.etag + `"`)
			}
			if proof.versionID != "" {
				in.VersionId = aws.String(proof.versionID)
			}
		}
		var hErr error
		out, hErr = cli.HeadObject(ctx, in)
		return hErr
	})
	if err != nil {
		// Stage 1 invariant: NEVER call GetObject (not even ranged bytes=0-0) on 403.
		ce := r.classifyLive(err, scopeObject)
		if hasProof && (ce.Code == hostkit.PreconditionFailed || ce.Code == hostkit.Conflict ||
			ce.HTTPStatus == http.StatusPreconditionFailed || ce.HTTPStatus == http.StatusConflict ||
			ce.ProviderCode == "PreconditionFailed" || ce.ProviderCode == "ConditionalRequestConflict") {
			if j := r.activeJournal(); j != nil {
				_ = j.Retain(safety.KindObject, bucket, key, "HeadObject conditional If-Match failed: "+ce.Error())
			}
			return hostkit.ObjectMeta{}, hostkit.ProviderError(
				hostkit.PermissionDenied,
				http.StatusForbidden,
				"UnownedResourceReadRefused",
				fmt.Sprintf("object %s/%s changed after ownership proof (conditional HEAD failed)", bucket, key),
			)
		}
		if ce.Code == hostkit.NotFound {
			if ce.Absent == hostkit.AbsentBucket {
				return hostkit.ObjectMeta{}, ce
			}
			// Disambiguate missing key vs missing bucket via a metered HeadBucket call.
			bErr := r.runExtraMeteredRead(ctx, "bucket_exists", safety.KindBucket, "", bucket, "head_object_404_bucket_probe", func(ctx context.Context) error {
				return r.HeadBucket(ctx, bucket)
			})
			if bErr != nil {
				if bce := r.classifyLive(bErr, scopeBucket); bce.Code == hostkit.NotFound {
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
		lk := strings.ToLower(strings.TrimSpace(k))
		if !isInternalOwnershipMetaKey(lk) {
			meta[lk] = v
		}
	}
	gotETag := cleanETag(aws.ToString(out.ETag))
	if hasProof && proof.etag != "" && gotETag != proof.etag {
		if j := r.activeJournal(); j != nil {
			_ = j.Retain(safety.KindObject, bucket, key, "HeadObject response ETag mismatched proven ownership ETag")
		}
		return hostkit.ObjectMeta{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			http.StatusForbidden,
			"UnownedResourceReadRefused",
			fmt.Sprintf("object %s/%s response ETag did not match proven ownership ETag", bucket, key),
		)
	}
	return hostkit.ObjectMeta{
		Exists:      true,
		Bucket:      bucket,
		Key:         key,
		Size:        size,
		ETag:        gotETag,
		ContentType: ct,
		Metadata:    meta,
	}, nil
}

func (r *liveRawBackend) ListObjects(ctx context.Context, bucket, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	if max <= 0 || max > maxLiveObjectListPageSize {
		max = maxLiveObjectListPageSize
	}
	cli := r.s3Client()
	in := &s3.ListObjectsV2Input{
		Bucket:              aws.String(bucket),
		MaxKeys:             aws.Int32(int32(max)),
		ExpectedBucketOwner: aws.String(r.ownerAccount()),
	}
	if prefix != "" {
		in.Prefix = aws.String(prefix)
	}
	if token != "" {
		in.ContinuationToken = aws.String(token)
	}
	worstCaseBytes := objectListWorstCaseBytes(max)
	var out *s3.ListObjectsV2Output
	err := r.doLiveAWS(ctx, "object_list", safety.KindObject, bucket, prefix, worstCaseBytes, true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListObjectsV2(ctx, in)
		return lErr
	})
	if err != nil {
		return hostkit.ObjectPage{}, r.classifyLive(err, scopeBucket)
	}
	if len(out.Contents) > max {
		return hostkit.ObjectPage{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveListPageOverflow",
			fmt.Sprintf("s3 ListObjectsV2 returned %d items exceeding requested max %d", len(out.Contents), max),
		)
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
	next := strings.TrimSpace(aws.ToString(out.NextContinuationToken))
	if aws.ToBool(out.IsTruncated) && next == "" && len(items) > 0 {
		next = items[len(items)-1].Key
	}
	if token != "" && next == token {
		return hostkit.ObjectPage{}, hostkit.ProviderError(hostkit.Internal, 0, "StalledPagination", "pagination stalled: continuation token repeated")
	}
	return hostkit.ObjectPage{
		Items:     items,
		NextToken: next,
	}, nil
}

func (r *liveRawBackend) QueueCaps() hostkit.QueueCaps {
	return hostkit.QueueCaps{LongPoll: true, TextOnlyWire: true}
}

func (r *liveRawBackend) resolveLiveQueueURL(ctx context.Context, name string) (string, error) {
	cli := r.sqsClient()
	owner := r.ownerAccount()
	var out *sqs.GetQueueUrlOutput
	err := r.doExtraPhysicalAWS(ctx, "queue_exists", safety.KindQueue, "", name, "resolve_queue_url", maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
		var gErr error
		out, gErr = cli.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
			QueueName:              aws.String(name),
			QueueOwnerAWSAccountId: aws.String(owner),
		})
		return gErr
	})
	if err != nil {
		ce := r.classifyLive(err, scopeQueue)
		if ce.Code == hostkit.NotFound {
			return "", ce.WithAbsent(hostkit.AbsentQueue)
		}
		return "", ce
	}
	rawURL := strings.TrimSpace(aws.ToString(out.QueueUrl))
	qName, verr := validateLiveQueueURL(rawURL, r.region, owner)
	if verr != nil {
		return "", hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", r.sanitizeString(verr.Error()))
	}
	if qName != name {
		return "", hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", fmt.Sprintf("sqs GetQueueUrl returned queue %q, wanted %q", qName, name))
	}
	return rawURL, nil
}

func (r *liveRawBackend) CreateQueue(ctx context.Context, name string) (bool, error) {
	_, tagMap, terr := liveOwnershipTagMap(ctx)
	if terr != nil {
		return false, terr
	}
	cli := r.sqsClient()
	in := &sqs.CreateQueueInput{
		QueueName: aws.String(name),
		Tags:      tagMap,
	}
	var out *sqs.CreateQueueOutput
	err := r.doLiveAWS(ctx, "queue_create", safety.KindQueue, "", name, maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
		var cErr error
		out, cErr = cli.CreateQueue(ctx, in)
		return cErr
	})
	if err != nil {
		return false, r.classifyLive(err, scopeQueue)
	}
	rawURL := strings.TrimSpace(aws.ToString(out.QueueUrl))
	qName, verr := validateLiveQueueURL(rawURL, r.region, r.ownerAccount())
	if verr != nil {
		return false, hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", r.sanitizeString(verr.Error()))
	}
	if qName != name {
		return false, hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", fmt.Sprintf("sqs CreateQueue returned queue %q, wanted %q", qName, name))
	}
	return true, nil
}

func (r *liveRawBackend) QueueCreateToken(ctx context.Context, name string) (string, error) {
	qURL, err := r.resolveLiveQueueURL(ctx, name)
	if err != nil {
		return "", err
	}
	cli := r.sqsClient()
	var out *sqs.ListQueueTagsOutput
	tErr := r.doExtraPhysicalAWS(ctx, "queue_exists", safety.KindQueue, "", name, "queue_create_token_tags", maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
		var callErr error
		out, callErr = cli.ListQueueTags(ctx, &sqs.ListQueueTagsInput{
			QueueUrl: aws.String(qURL),
		})
		return callErr
	})
	if tErr != nil {
		return "", r.classifyLive(tErr, scopeQueue)
	}
	if out == nil || len(out.Tags) == 0 {
		return "", nil
	}
	if tok := strings.TrimSpace(out.Tags[safety.TagKeyCreateToken]); tok != "" {
		return tok, nil
	}
	return strings.TrimSpace(out.Tags[createTokenTagKey]), nil
}

func (r *liveRawBackend) DeleteQueue(ctx context.Context, name string) error {
	ctx = withLiveCleanup(ctx)
	qURL, err := r.resolveLiveQueueURL(ctx, name)
	if err != nil {
		return err
	}
	cli := r.sqsClient()
	dErr := r.doLiveAWS(ctx, "queue_delete", safety.KindQueue, "", name, 0, true, func(ctx context.Context) error {
		_, callErr := cli.DeleteQueue(ctx, &sqs.DeleteQueueInput{
			QueueUrl: aws.String(qURL),
		})
		return callErr
	})
	if dErr != nil {
		ce := r.classifyLive(dErr, scopeQueue)
		if ce.Code == hostkit.NotFound {
			return ce.WithAbsent(hostkit.AbsentQueue)
		}
		return ce
	}
	return nil
}

func (r *liveRawBackend) Send(ctx context.Context, queue, wire string) (string, error) {
	qURL, err := r.resolveLiveQueueURL(ctx, queue)
	if err != nil {
		return "", err
	}
	cli := r.sqsClient()
	var out *sqs.SendMessageOutput
	sErr := r.doLiveAWS(ctx, "queue_send", safety.KindQueueMessage, queue, "", maxLiveSmallRespBodyBytes, false, func(ctx context.Context) error {
		var callErr error
		out, callErr = cli.SendMessage(ctx, &sqs.SendMessageInput{
			QueueUrl:    aws.String(qURL),
			MessageBody: aws.String(wire),
		})
		return callErr
	})
	if sErr != nil {
		return "", r.classifyLive(sErr, scopeQueue)
	}
	id := strings.TrimSpace(aws.ToString(out.MessageId))
	if id == "" {
		return "", &hostkit.CloudError{
			Code:    hostkit.Internal,
			Message: "sqs SendMessage returned an empty MessageId",
		}
	}
	return id, nil
}

func (r *liveRawBackend) Receive(ctx context.Context, queue string, max, waitSeconds, visibility int) ([]hostkit.RawMessage, error) {
	qURL, err := r.resolveLiveQueueURL(ctx, queue)
	if err != nil {
		return nil, err
	}
	if max <= 0 {
		max = 1
	}
	if max > 10 {
		max = 10
	}
	if waitSeconds < 0 {
		waitSeconds = 0
	}
	if waitSeconds > 8 {
		waitSeconds = 8
	}
	cli := r.sqsClient()

	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	for iter := 0; ; iter++ {
		waitParam := int32(0)
		if waitSeconds > 0 {
			rem := time.Until(deadline)
			if rem > 0 {
				sec := int32((rem + 999*time.Millisecond) / time.Second)
				if sec > int32(waitSeconds) {
					sec = int32(waitSeconds)
				}
				if sec < 1 {
					sec = 1
				}
				waitParam = sec
			}
		}

		var out *sqs.ReceiveMessageOutput
		rErr := r.doLiveAWSWithMode(
			ctx,
			"queue_receive",
			safety.KindQueue,
			"",
			queue,
			fmt.Sprintf("queue_receive_poll_%d", iter),
			maxLiveReceiveRespBodyBytes,
			false,
			iter > 0,
			func(ctx context.Context) error {
				var callErr error
				out, callErr = cli.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
					QueueUrl:            aws.String(qURL),
					MaxNumberOfMessages: int32(max),
					VisibilityTimeout:   int32(visibility),
					WaitTimeSeconds:     waitParam,
				})
				return callErr
			},
		)
		if rErr != nil {
			return nil, r.classifyLive(rErr, scopeQueue)
		}

		if len(out.Messages) > 0 {
			msgs := make([]hostkit.RawMessage, 0, len(out.Messages))
			for _, m := range out.Messages {
				id := aws.ToString(m.MessageId)
				rh := aws.ToString(m.ReceiptHandle)
				if id == "" || rh == "" {
					return nil, &hostkit.CloudError{
						Code:    hostkit.Internal,
						Message: "sqs ReceiveMessage entry missing MessageId or ReceiptHandle",
					}
				}
				msgs = append(msgs, hostkit.RawMessage{
					ID:      id,
					Wire:    aws.ToString(m.Body),
					Receipt: rh,
				})
			}
			return msgs, nil
		}

		if waitSeconds <= 0 || !time.Now().Before(deadline) {
			return []hostkit.RawMessage{}, nil
		}
		sleepDur := 50 * time.Millisecond
		if rem := time.Until(deadline); rem < sleepDur {
			sleepDur = rem
		}
		if sleepDur > 0 {
			select {
			case <-ctx.Done():
				return nil, r.classifyLive(ctx.Err(), scopeQueue)
			case <-time.After(sleepDur):
			}
		}
	}
}

func (r *liveRawBackend) Ack(ctx context.Context, queue, receipt string) error {
	qURL, err := r.resolveLiveQueueURL(ctx, queue)
	if err != nil {
		return err
	}
	cli := r.sqsClient()
	dErr := r.doLiveAWS(ctx, "queue_ack", safety.KindQueueMessage, queue, "", 0, true, func(ctx context.Context) error {
		_, callErr := cli.DeleteMessage(ctx, &sqs.DeleteMessageInput{
			QueueUrl:      aws.String(qURL),
			ReceiptHandle: aws.String(receipt),
		})
		return callErr
	})
	if dErr != nil {
		return r.classifyLive(dErr, scopeMessage)
	}
	return nil
}

func (r *liveRawBackend) Nack(ctx context.Context, queue, receipt string, visibility int) (string, error) {
	qURL, err := r.resolveLiveQueueURL(ctx, queue)
	if err != nil {
		return "", err
	}
	cli := r.sqsClient()
	cErr := r.doLiveAWS(ctx, "queue_nack", safety.KindQueueMessage, queue, "", 0, true, func(ctx context.Context) error {
		_, callErr := cli.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
			QueueUrl:          aws.String(qURL),
			ReceiptHandle:     aws.String(receipt),
			VisibilityTimeout: int32(visibility),
		})
		return callErr
	})
	if cErr != nil {
		return "", r.classifyLive(cErr, scopeMessage)
	}
	return receipt, nil
}

func validateLiveQueueURL(rawURL, region, account string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", errors.New("sqs returned an empty QueueUrl")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.New("sqs returned a malformed QueueUrl")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("sqs QueueUrl must use https:// (got %q)", u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("sqs QueueUrl must not contain userinfo, query, or fragment")
	}
	host := strings.ToLower(u.Hostname())
	wantHost := "sqs." + strings.ToLower(region) + ".amazonaws.com"
	if host != wantHost && !(region == "us-east-1" && host == "queue.amazonaws.com") {
		return "", fmt.Errorf("sqs QueueUrl host %q does not match expected %q", host, wantHost)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != account || parts[1] == "" {
		return "", fmt.Errorf("sqs QueueUrl path %q does not match account %q", u.Path, account)
	}
	return parts[1], nil
}

func (r *liveRawBackend) LookupQueue(ctx context.Context, name string) error {
	cli := r.sqsClient()
	var out *sqs.GetQueueUrlOutput
	err := r.doLiveAWS(ctx, "queue_exists", safety.KindQueue, "", name, maxLiveSmallRespBodyBytes, true, func(ctx context.Context) error {
		var gErr error
		out, gErr = cli.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
			QueueName:              aws.String(name),
			QueueOwnerAWSAccountId: aws.String(r.ownerAccount()),
		})
		return gErr
	})
	if err != nil {
		ce := r.classifyLive(err, scopeQueue)
		if ce.Code == hostkit.NotFound {
			return ce.WithAbsent(hostkit.AbsentQueue)
		}
		return ce
	}
	qName, verr := validateLiveQueueURL(aws.ToString(out.QueueUrl), r.region, r.ownerAccount())
	if verr != nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", r.sanitizeString(verr.Error()))
	}
	if qName != name {
		return hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", fmt.Sprintf("sqs GetQueueUrl returned queue %q, wanted %q", qName, name))
	}
	return nil
}

func (r *liveRawBackend) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	cli := r.sqsClient()
	in := &sqs.ListQueuesInput{
		MaxResults: aws.Int32(maxLiveQueueListPageSize),
	}
	if token != "" {
		in.NextToken = aws.String(token)
	}
	var out *sqs.ListQueuesOutput
	err := r.doLiveAWS(ctx, "queue_list", safety.KindQueue, "", "", maxLiveListRespBodyBytes, true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListQueues(ctx, in)
		return lErr
	})
	if err != nil {
		return nil, "", r.classifyLive(err, scopeQueue)
	}
	if int32(len(out.QueueUrls)) > maxLiveQueueListPageSize {
		return nil, "", hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveListPageOverflow",
			fmt.Sprintf("sqs ListQueues returned %d items exceeding MaxResults %d", len(out.QueueUrls), maxLiveQueueListPageSize),
		)
	}
	names := make([]string, 0, len(out.QueueUrls))
	for _, u := range out.QueueUrls {
		qName, verr := validateLiveQueueURL(u, r.region, r.ownerAccount())
		if verr != nil {
			return nil, "", hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", r.sanitizeString(verr.Error()))
		}
		names = append(names, qName)
	}
	next := strings.TrimSpace(aws.ToString(out.NextToken))
	if token != "" && next == token {
		return nil, "", hostkit.ProviderError(hostkit.Internal, 0, "StalledPagination", "pagination stalled: next token repeated")
	}
	return names, next, nil
}

// FinishAndSweep executes an active LIFO recovery sweep on the current live
// session (if open), compacts its journal, and closes the session.
func (l *liveAdapter) FinishAndSweep(ctx context.Context) (safety.SweepReport, error) {
	l.mu.Lock()
	sess := l.sess
	l.sess = nil
	l.store = nil
	l.queue = nil
	l.raw = nil
	l.sessKey = ""
	l.mu.Unlock()
	if sess == nil {
		return safety.SweepReport{}, nil
	}
	ctx = withLiveCleanup(context.WithValue(ctx, sweepPreReservesBucketListKey{}, true))
	return sess.FinishAndSweep(ctx)
}

func parseRunStartEpoch(runID string) (int64, error) {
	runID = strings.TrimSpace(runID)
	if err := safety.ValidateRunID(runID); err != nil {
		return 0, err
	}
	parts := strings.Split(runID, "-")
	if len(parts) != 3 || parts[0] != "run" {
		return 0, fmt.Errorf("invalid run ID %q", runID)
	}
	epoch, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || epoch <= 0 {
		return 0, fmt.Errorf("invalid epoch in run ID %q", runID)
	}
	return epoch, nil
}

func isTagProvenOwnedByRun(ro safety.RemoteOwnership, runID string, runStartEpoch int64) bool {
	if !ro.Exists ||
		ro.RunID != runID ||
		ro.OwnerNonce == "" ||
		ro.CreateToken == "" ||
		runStartEpoch <= 0 ||
		ro.CreatedAtUnix < runStartEpoch {
		return false
	}
	if ro.ServerCreatedAtUnix > 0 && ro.ServerCreatedAtUnix < runStartEpoch {
		return false
	}
	return true
}

func sweepItemKey(kind, parent, name string) string {
	return kind + "|" + parent + "|" + name
}

func (r *liveRawBackend) reserveCleanupOp(op string) error {
	meter := r.activeMeter()
	if meter == nil || op == "" {
		return nil
	}
	res, err := meter.ReserveAttempt(safety.AttemptPricingInput{
		Operation: op,
		IsCleanup: true,
	})
	if err != nil {
		return err
	}
	res.Commit(-1, false)
	return nil
}

func (r *liveRawBackend) deleteAndPollProven(
	ctx context.Context,
	ref safety.ResourceRef,
	ro safety.RemoteOwnership,
	_, _ string,
	rep *safety.SweepReport,
) bool {
	ctx = withOwnSweepPhysicalAttempt(withLiveCleanup(ctx))
	delCtx, delCancel := context.WithTimeout(ctx, time.Duration(safety.DefaultMaxRequestTimeoutSeconds)*time.Second)
	delErr := r.DeleteOwned(delCtx, ref, ro)
	delCancel()
	if delErr != nil && r.ClassifyAbsent(delErr) != safety.AbsenceDefinitive {
		var ce *hostkit.CloudError
		if errors.As(delErr, &ce) && ce != nil && (ce.ProviderCode == "LiveCostCapExceeded" || ce.ProviderCode == "JournalWriteFailed") {
			rep.Failed = append(rep.Failed, safety.SweepItem{
				Kind:       ref.Kind,
				Parent:     ref.Parent,
				Name:       ref.Name,
				ProviderID: ro.ProviderID,
				Reason:     "cleanup cost/journal admission failed: " + delErr.Error(),
			})
			return false
		}
		if r.ClassifyAbsent(delErr) == safety.AbsenceAmbiguous {
			rep.Retained = append(rep.Retained, safety.SweepItem{
				Kind:       ref.Kind,
				Parent:     ref.Parent,
				Name:       ref.Name,
				ProviderID: ro.ProviderID,
				Reason:     "ambiguous delete response: " + delErr.Error(),
			})
			return false
		}
		rep.Failed = append(rep.Failed, safety.SweepItem{
			Kind:       ref.Kind,
			Parent:     ref.Parent,
			Name:       ref.Name,
			ProviderID: ro.ProviderID,
			Reason:     "delete failed: " + delErr.Error(),
		})
		return false
	}

	confirmed := false
	for attempt := 0; attempt < 5; attempt++ {
		pollCtx, pollCancel := context.WithTimeout(ctx, time.Duration(safety.DefaultMaxRequestTimeoutSeconds)*time.Second)
		done, pollErr := r.PollDelete(pollCtx, ref)
		pollCancel()
		if (pollErr == nil && done) || (pollErr != nil && r.ClassifyAbsent(pollErr) == safety.AbsenceDefinitive) {
			confirmed = true
			break
		}
		if pollErr != nil {
			var ce *hostkit.CloudError
			if errors.As(pollErr, &ce) && ce != nil && (ce.ProviderCode == "LiveCostCapExceeded" || ce.ProviderCode == "JournalWriteFailed") {
				rep.Failed = append(rep.Failed, safety.SweepItem{
					Kind:       ref.Kind,
					Parent:     ref.Parent,
					Name:       ref.Name,
					ProviderID: ro.ProviderID,
					Reason:     "poll-delete cost/journal admission failed: " + pollErr.Error(),
				})
				return false
			}
			if r.ClassifyAbsent(pollErr) == safety.AbsenceAmbiguous {
				rep.Retained = append(rep.Retained, safety.SweepItem{
					Kind:       ref.Kind,
					Parent:     ref.Parent,
					Name:       ref.Name,
					ProviderID: ro.ProviderID,
					Reason:     "ambiguous poll-delete response: " + pollErr.Error(),
				})
				return false
			}
		}
	}
	if !confirmed {
		rep.Failed = append(rep.Failed, safety.SweepItem{
			Kind:       ref.Kind,
			Parent:     ref.Parent,
			Name:       ref.Name,
			ProviderID: ro.ProviderID,
			Reason:     "delete not yet converged after 5 poll attempts",
		})
		return false
	}
	if j := r.activeJournal(); j != nil {
		_ = j.Deleted(ref.Kind, ref.Parent, ref.Name, 0)
	}
	rep.Deleted = append(rep.Deleted, safety.SweepItem{
		Kind:       ref.Kind,
		Parent:     ref.Parent,
		Name:       ref.Name,
		ProviderID: ro.ProviderID,
		Reason:     "deleted and verified absent via prefix+tag sweep",
	})
	return true
}

// sweepPrefixByTags scans AWS for any remaining S3 buckets or SQS queues matching
// `lmcloud-conf-<run12>-`. Any resource not already handled by journal sweep is
// inspected via remote tags: if proven owned by runID (matching lmcloud-owner=conformance,
// lmcloud-run=<runID>, lmcloud_run_id=<runID>, non-empty nonce & create token,
// and CreatedAtUnix >= runStartEpoch), it is swept (or recorded in WouldDelete);
// otherwise (untagged or foreign-tagged) it is recorded in rep.Retained and NEVER deleted.
func (r *liveRawBackend) sweepPrefixByTags(
	ctx context.Context,
	runID string,
	apply bool,
	rep *safety.SweepReport,
) {
	ctx = withLiveCleanup(ctx)
	runStartEpoch, err := parseRunStartEpoch(runID)
	if err != nil {
		rep.Failed = append(rep.Failed, safety.SweepItem{
			Kind:   "prefix_scan",
			Name:   runID,
			Reason: "parse run start epoch failed: " + err.Error(),
		})
		return
	}
	pfx, err := safety.ExpectedLivePrefix(runID)
	if err != nil {
		rep.Failed = append(rep.Failed, safety.SweepItem{
			Kind:   "prefix_scan",
			Name:   runID,
			Reason: "compute expected live prefix failed: " + err.Error(),
		})
		return
	}

	handled := make(map[string]bool)
	for _, list := range [][]safety.SweepItem{
		rep.Deleted,
		rep.WouldDelete,
		rep.Absent,
		rep.Retained,
		rep.Failed,
		rep.Pending,
	} {
		for _, it := range list {
			handled[sweepItemKey(it.Kind, it.Parent, it.Name)] = true
		}
	}

	findCtx, findCancel := context.WithTimeout(ctx, time.Duration(safety.DefaultMaxRequestTimeoutSeconds)*time.Second)
	found, ferr := r.FindOwned(findCtx, pfx)
	findCancel()
	if ferr != nil {
		rep.Failed = append(rep.Failed, safety.SweepItem{
			Kind:   "prefix_scan",
			Name:   pfx,
			Reason: "FindOwned failed: " + ferr.Error(),
		})
		return
	}

	for _, ref := range found {
		key := sweepItemKey(ref.Kind, ref.Parent, ref.Name)
		if handled[key] {
			continue
		}
		ro, rErr, rCerr := r.readOwnershipMetered(ctx, ref, true, "sweep_prefix_read_ownership")
		if rCerr != nil {
			rep.Failed = append(rep.Failed, safety.SweepItem{
				Kind:       ref.Kind,
				Parent:     ref.Parent,
				Name:       ref.Name,
				ProviderID: ref.ProviderID,
				Reason:     "read ownership reservation failed: " + rCerr.Error(),
			})
			continue
		}
		if (rErr == nil && !ro.Exists) || (rErr != nil && r.ClassifyAbsent(rErr) == safety.AbsenceDefinitive) {
			rep.Absent = append(rep.Absent, safety.SweepItem{
				Kind:       ref.Kind,
				Parent:     ref.Parent,
				Name:       ref.Name,
				ProviderID: ref.ProviderID,
				Reason:     "definitively absent during prefix scan",
			})
			handled[key] = true
			continue
		}
		if rErr != nil {
			if r.ClassifyAbsent(rErr) == safety.AbsenceAmbiguous {
				rep.Retained = append(rep.Retained, safety.SweepItem{
					Kind:       ref.Kind,
					Parent:     ref.Parent,
					Name:       ref.Name,
					ProviderID: ref.ProviderID,
					Reason:     "ambiguous ownership read during prefix scan: " + rErr.Error(),
				})
			} else {
				rep.Failed = append(rep.Failed, safety.SweepItem{
					Kind:       ref.Kind,
					Parent:     ref.Parent,
					Name:       ref.Name,
					ProviderID: ref.ProviderID,
					Reason:     "read ownership failed during prefix scan: " + rErr.Error(),
				})
			}
			handled[key] = true
			continue
		}

		if !isTagProvenOwnedByRun(ro, runID, runStartEpoch) {
			rep.Retained = append(rep.Retained, safety.SweepItem{
				Kind:       ref.Kind,
				Parent:     ref.Parent,
				Name:       ref.Name,
				ProviderID: ro.ProviderID,
				Reason:     fmt.Sprintf("prefix-matching resource lacks valid ownership tags for run %s; retaining", runID),
			})
			handled[key] = true
			continue
		}

		if ref.Kind == safety.KindBucket {
			if !ro.ChildrenVerified {
				rep.Retained = append(rep.Retained, safety.SweepItem{
					Kind:       safety.KindBucket,
					Name:       ref.Name,
					ProviderID: ro.ProviderID,
					Reason:     fmt.Sprintf("bucket %q child object listing was not verified", ref.Name),
				})
				handled[key] = true
				continue
			}
			childrenClean := true
			for _, childKey := range ro.ChildKeys {
				cKey := sweepItemKey(safety.KindObject, ref.Name, childKey)
				if handled[cKey] {
					continue
				}
				childRef := safety.ResourceRef{
					Kind:     safety.KindObject,
					Parent:   ref.Name,
					Location: r.region,
					Name:     childKey,
				}
				cRO, cErr, cCerr := r.readOwnershipMetered(ctx, childRef, true, "sweep_prefix_read_child_ownership")
				if cCerr != nil {
					rep.Failed = append(rep.Failed, safety.SweepItem{
						Kind:   safety.KindObject,
						Parent: ref.Name,
						Name:   childKey,
						Reason: "child ownership reservation failed: " + cCerr.Error(),
					})
					childrenClean = false
					break
				}
				if (cErr == nil && !cRO.Exists) || (cErr != nil && r.ClassifyAbsent(cErr) == safety.AbsenceDefinitive) {
					handled[cKey] = true
					continue
				}
				if cErr != nil || !isTagProvenOwnedByRun(cRO, runID, runStartEpoch) {
					rep.Retained = append(rep.Retained, safety.SweepItem{
						Kind:       safety.KindObject,
						Parent:     ref.Name,
						Name:       childKey,
						ProviderID: cRO.ProviderID,
						Reason:     fmt.Sprintf("child object %s/%s lacks valid ownership tags for run %s; retaining", ref.Name, childKey, runID),
					})
					childrenClean = false
					break
				}
				if !apply {
					rep.WouldDelete = append(rep.WouldDelete, safety.SweepItem{
						Kind:       safety.KindObject,
						Parent:     ref.Name,
						Name:       childKey,
						ProviderID: cRO.ProviderID,
						Reason:     "tag-verified ownership via prefix scan",
					})
					handled[cKey] = true
					continue
				}
				if !r.deleteAndPollProven(ctx, childRef, cRO, "object_delete", "object_head", rep) {
					childrenClean = false
					break
				}
				handled[cKey] = true
			}
			if !childrenClean {
				rep.Retained = append(rep.Retained, safety.SweepItem{
					Kind:       safety.KindBucket,
					Name:       ref.Name,
					ProviderID: ro.ProviderID,
					Reason:     fmt.Sprintf("bucket %q contains retained or unswept child objects", ref.Name),
				})
				handled[key] = true
				continue
			}
		}

		if !apply {
			rep.WouldDelete = append(rep.WouldDelete, safety.SweepItem{
				Kind:       ref.Kind,
				Parent:     ref.Parent,
				Name:       ref.Name,
				ProviderID: ro.ProviderID,
				Reason:     "tag-verified ownership via prefix scan",
			})
			handled[key] = true
			continue
		}

		delOp := "bucket_delete"
		pollOp := "bucket_exists"
		if ref.Kind == safety.KindQueue {
			delOp = "queue_delete"
			pollOp = "queue_exists"
		}
		r.deleteAndPollProven(ctx, ref, ro, delOp, pollOp, rep)
		handled[key] = true
	}
}

func (r *liveRawBackend) sweepRunWithoutJournal(
	ctx context.Context,
	absJDir, runID string,
	pol *safety.Policy,
	apply bool,
) (safety.SweepReport, error) {
	ctx = withLiveCleanup(ctx)
	rep := safety.SweepReport{
		RunID:  runID,
		DryRun: !apply,
	}
	var attestRes *safety.AttemptReservation
	if meter := r.activeMeter(); meter != nil {
		var rerr error
		attestRes, rerr = meter.ReserveAttempt(safety.AttemptPricingInput{
			Operation: "bucket_exists",
			IsCleanup: true,
		})
		if rerr != nil {
			return rep, fmt.Errorf("sweep attestation reservation failed: %w", rerr)
		}
	}
	ident, err := r.AttestIdentity(ctx)
	if err != nil {
		if attestRes != nil {
			attestRes.Commit(-1, false)
		}
		return rep, fmt.Errorf("sweep identity attestation failed: %w", err)
	}
	scope, err := r.ResolveScope(ctx, "storage")
	if err != nil {
		if attestRes != nil {
			attestRes.Commit(-1, false)
		}
		return rep, fmt.Errorf("sweep scope resolution failed: %w", err)
	}
	if pol != nil {
		if err := pol.CheckScope(ident.Provider, ident.Account, scope.Scope, scope.Region); err != nil {
			if attestRes != nil {
				attestRes.Commit(-1, false)
			}
			return rep, fmt.Errorf("sweep policy scope check failed: %w", err)
		}
	}
	var attestCharged int64
	if attestRes != nil {
		attestCharged = attestRes.Commit(-1, false)
	}
	if apply && absJDir != "" && pol != nil {
		startUnix, _ := parseRunStartEpoch(runID)
		if startUnix <= 0 {
			startUnix = time.Now().UTC().Unix()
		}
		recMeta := safety.JournalMeta{
			RunID:         runID,
			SessionID:     "sweep-" + safety.NewToken128()[:12],
			PolicyHash:    pol.Hash(),
			Provider:      ident.Provider,
			Account:       ident.Account,
			Scope:         scope.Scope,
			Region:        scope.Region,
			Endpoint:      scope.Endpoint,
			StartedAtUnix: startUnix,
		}
		recJ, oerr := safety.OpenJournal(absJDir, recMeta)
		if oerr != nil {
			return rep, fmt.Errorf("open recovery journal for %s: %w", runID, oerr)
		}
		defer func() {
			r.mu.Lock()
			r.sweepJournal = nil
			r.mu.Unlock()
			_ = recJ.Close()
		}()
		if attestCharged > 0 {
			if attID, berr := recJ.BeginAttempt(safety.KindBucket, "", "", "sweep_attest_identity", attestCharged, 0); berr == nil {
				_ = recJ.SettleAttempt(attID, attestCharged, true)
			}
		}
		r.mu.Lock()
		r.sweepJournal = recJ
		r.mu.Unlock()
	}
	// Ensure ReadOwnership(KindBucket) during journal-less sweep owns its page-0 ListObjectsV2 attempt.
	noPreReserveCtx := context.WithValue(ctx, sweepPreReservesBucketListKey{}, false)
	r.sweepPrefixByTags(noPreReserveCtx, runID, apply, &rep)
	return rep, nil
}

type sweepCLIOutput struct {
	OK             bool                 `json:"ok"`
	DryRun         bool                 `json:"dry_run"`
	Swept          int                  `json:"swept"`
	Deleted        int                  `json:"deleted"`
	WouldDelete    int                  `json:"would_delete"`
	Absent         int                  `json:"absent"`
	Retained       int                  `json:"retained"`
	Failed         int                  `json:"failed"`
	Pending        int                  `json:"pending"`
	UnownedSkipped int                  `json:"unowned_skipped"`
	ChargedNanoUSD int64                `json:"charged_nano_usd"`
	Reports        []safety.SweepReport `json:"reports,omitempty"`
	Error          string               `json:"error,omitempty"`
}

// SweepCLI implements `lmaws --sweep [--apply|--delete|--dry-run] [--all-stale] [--journal-dir DIR] [RUN_ID...]`.
// By default (without --apply or --delete), SweepCLI runs in dry-run mode.
func (l *liveAdapter) SweepCLI(ctx context.Context, args []string, out io.Writer) int {
	getenv := l.getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if strings.TrimSpace(getenv("LMCLOUD_LIVE")) != "1" || strings.TrimSpace(getenv("LMAWS_LIVE")) != "1" {
		_, _ = fmt.Fprintln(out, `{"ok":true,"swept":0,"mode":"sim-or-live-readonly-stage1"}`)
		return 0
	}

	if len(args) > 0 && strings.TrimSpace(args[0]) == "--sweep" {
		args = args[1:] // the host dispatcher passes the command token through
	}
	apply := false
	allStale := false
	var flagJournalDir string
	var runIDs []string
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case arg == "--apply" || arg == "--delete":
			apply = true
		case arg == "--dry-run":
			apply = false
		case arg == "--all-stale":
			allStale = true
		case arg == "--journal-dir" && i+1 < len(args):
			i++
			flagJournalDir = strings.TrimSpace(args[i])
		case strings.HasPrefix(arg, "--journal-dir="):
			flagJournalDir = strings.TrimSpace(strings.TrimPrefix(arg, "--journal-dir="))
		case strings.HasPrefix(arg, "-"):
			res := sweepCLIOutput{OK: false, DryRun: !apply, Error: fmt.Sprintf("unknown --sweep flag %q", arg)}
			_ = json.NewEncoder(out).Encode(res)
			return 1
		case arg != "":
			runIDs = append(runIDs, arg)
		}
	}

	for _, rid := range runIDs {
		if err := safety.ValidateRunID(rid); err != nil {
			res := sweepCLIOutput{OK: false, DryRun: !apply, Error: sanitizeStaticSecrets(err.Error())}
			_ = json.NewEncoder(out).Encode(res)
			return 1
		}
	}

	envCfg, cerr := validateLiveGates(ctx, getenv, l.opts)
	if cerr != nil {
		res := sweepCLIOutput{OK: false, DryRun: !apply, Error: sanitizeStaticSecrets(cerr.Error())}
		_ = json.NewEncoder(out).Encode(res)
		return 1
	}
	if apply {
		envCfg.mutate = true
	}

	jDir := flagJournalDir
	if jDir == "" {
		jDir = envCfg.journalDir
	}
	if jDir == "" {
		jDir = filepath.Join(os.TempDir(), fmt.Sprintf("lmaws-live-%d", os.Getuid()))
	}
	absJDir, err := safety.EnsureStateDir(jDir)
	if err != nil {
		res := sweepCLIOutput{OK: false, DryRun: !apply, Error: sanitizeStaticSecrets(err.Error())}
		_ = json.NewEncoder(out).Encode(res)
		return 1
	}

	// Strict run selection:
	// - If explicit RUN_ID positional arguments were passed, sweep only those runs.
	// - Else if --all-stale was explicitly passed, enumerate *.jsonl in absJDir.
	// - Else if LMAWS_RUN_ID / LMCLOUD_RUN_ID is set in the environment, sweep ONLY
	//   that run (using journal + prefix/tag scan if the journal exists, or
	//   journal-independent prefix/tag scan if the journal is missing; NEVER fall
	//   back to enumerating other runs' journals in absJDir).
	// - Else if --apply is set without any RUN_ID or --all-stale, fail closed.
	// - Else (dry-run with no RUN_ID and no env runID), enumerate *.jsonl in absJDir.
	if len(runIDs) == 0 {
		if allStale {
			entries, derr := os.ReadDir(absJDir)
			if derr == nil {
				for _, e := range entries {
					name := e.Name()
					if !e.IsDir() && strings.HasSuffix(name, ".jsonl") {
						rid := strings.TrimSuffix(name, ".jsonl")
						if safety.ValidateRunID(rid) == nil {
							runIDs = append(runIDs, rid)
						}
					}
				}
				sort.Strings(runIDs)
			}
		} else if envCfg.runID != "" {
			if err := safety.ValidateRunID(envCfg.runID); err != nil {
				res := sweepCLIOutput{OK: false, DryRun: !apply, Error: sanitizeStaticSecrets(err.Error())}
				_ = json.NewEncoder(out).Encode(res)
				return 1
			}
			runIDs = []string{envCfg.runID}
		} else if apply {
			res := sweepCLIOutput{
				OK:     false,
				DryRun: false,
				Error:  "--sweep --apply requires an explicit RUN_ID (or LMAWS_RUN_ID) or --all-stale",
			}
			_ = json.NewEncoder(out).Encode(res)
			return 1
		} else {
			entries, derr := os.ReadDir(absJDir)
			if derr == nil {
				for _, e := range entries {
					name := e.Name()
					if !e.IsDir() && strings.HasSuffix(name, ".jsonl") {
						rid := strings.TrimSuffix(name, ".jsonl")
						if safety.ValidateRunID(rid) == nil {
							runIDs = append(runIDs, rid)
						}
					}
				}
				sort.Strings(runIDs)
			}
		}
	}

	if len(runIDs) == 0 {
		res := sweepCLIOutput{OK: true, DryRun: !apply, Swept: 0}
		_ = json.NewEncoder(out).Encode(res)
		return 0
	}

	pol, perr := l.buildLivePolicy(envCfg, absJDir)
	if perr != nil {
		res := sweepCLIOutput{OK: false, DryRun: !apply, Error: sanitizeStaticSecrets(perr.Error())}
		_ = json.NewEncoder(out).Encode(res)
		return 1
	}
	raw, rerr := newLiveRawBackend(ctx, envCfg, l.opts, l.retry, l.baseCli, getenv)
	if rerr != nil {
		res := sweepCLIOutput{OK: false, DryRun: !apply, Error: sanitizeStaticSecrets(rerr.Error())}
		_ = json.NewEncoder(out).Encode(res)
		return 1
	}

	pt, pterr := safety.LoadEmbeddedPriceTable("aws", raw.region, time.Now().UTC())
	if pterr != nil {
		res := sweepCLIOutput{OK: false, DryRun: !apply, Error: sanitizeStaticSecrets(pterr.Error())}
		_ = json.NewEncoder(out).Encode(res)
		return 1
	}

	outSummary := sweepCLIOutput{
		OK:     true,
		DryRun: !apply,
	}
	var errMsgs []string
	sweepCtx := withLiveCleanup(context.WithValue(ctx, sweepPreReservesBucketListKey{}, true))
	prefixScanCtx := withLiveCleanup(context.WithValue(ctx, sweepPreReservesBucketListKey{}, false))
	hardCeilingNano := int64(safety.HardCostCeilingUSD * 1e9)
	for _, rid := range runIDs {
		var (
			rep  safety.SweepReport
			serr error
		)
		runMeter, merr := safety.NewCostMeter(pol.Cost, pt, raw)
		if merr != nil {
			outSummary.OK = false
			errMsgs = append(errMsgs, raw.sanitizeString(merr.Error()))
			continue
		}
		jPath, jperr := safety.JournalPath(absJDir, rid)
		if jperr != nil {
			outSummary.OK = false
			errMsgs = append(errMsgs, raw.sanitizeString(jperr.Error()))
			continue
		}
		_, statErr := os.Stat(jPath)
		if statErr == nil {
			loaded, lerr := safety.LoadJournal(jPath)
			if lerr != nil {
				rep = safety.SweepReport{RunID: rid, DryRun: !apply}
				serr = fmt.Errorf("corrupt or unreadable journal for %s: %w", rid, lerr)
			} else {
				safety.RestoreMeterFromState(runMeter, pt, *loaded)
				snap := runMeter.Snapshot()
				if loaded.ChargedNanoUSD >= hardCeilingNano || snap.ChargedNanoUSD >= snap.CapNanoUSD {
					rep = safety.SweepReport{RunID: rid, DryRun: !apply}
					serr = fmt.Errorf("sweep refused for %s: recorded campaign spend (%d nano-USD) meets or exceeds cost ceiling (%d nano-USD)",
						rid, snap.ChargedNanoUSD, snap.CapNanoUSD)
				} else {
					raw.mu.Lock()
					raw.sweepMeter = runMeter
					raw.sweepJournal = nil
					raw.mu.Unlock()
					if apply {
						openedJ, oerr := safety.OpenJournal(absJDir, loaded.Meta)
						if oerr != nil {
							rep = safety.SweepReport{RunID: rid, DryRun: false}
							serr = oerr
						} else {
							raw.mu.Lock()
							raw.sweepJournal = openedJ
							raw.mu.Unlock()
							rep, serr = safety.Sweep(sweepCtx, raw, safety.SweepOptions{
								Journal:    openedJ,
								Policy:     &pol,
								Meter:      runMeter,
								Apply:      true,
								ScanPrefix: false,
							})
							if serr == nil {
								raw.sweepPrefixByTags(prefixScanCtx, rid, true, &rep)
							}
							raw.mu.Lock()
							raw.sweepJournal = nil
							raw.mu.Unlock()
							if cerr := openedJ.Close(); cerr != nil && serr == nil {
								serr = cerr
							}
						}
					} else {
						rep, serr = safety.Sweep(sweepCtx, raw, safety.SweepOptions{
							JournalDir: absJDir,
							RunID:      rid,
							Policy:     &pol,
							Meter:      runMeter,
							Apply:      false,
							ScanPrefix: false,
						})
						if serr == nil {
							raw.sweepPrefixByTags(prefixScanCtx, rid, false, &rep)
						}
					}
				}
			}
		} else if !os.IsNotExist(statErr) {
			rep = safety.SweepReport{RunID: rid, DryRun: !apply}
			serr = fmt.Errorf("stat journal for %s: %w", rid, statErr)
		} else {
			raw.mu.Lock()
			raw.sweepMeter = runMeter
			raw.sweepJournal = nil
			raw.mu.Unlock()
			rep, serr = raw.sweepRunWithoutJournal(prefixScanCtx, absJDir, rid, &pol, apply)
		}
		outSummary.Reports = append(outSummary.Reports, rep)
		outSummary.ChargedNanoUSD += runMeter.Snapshot().ChargedNanoUSD
		outSummary.Deleted += len(rep.Deleted)
		outSummary.WouldDelete += len(rep.WouldDelete)
		outSummary.Absent += len(rep.Absent)
		outSummary.Retained += len(rep.Retained)
		outSummary.Failed += len(rep.Failed)
		outSummary.Pending += len(rep.Pending)
		outSummary.UnownedSkipped += len(rep.UnownedSkipped)
		if apply {
			outSummary.Swept += len(rep.Deleted)
		} else {
			outSummary.Swept += len(rep.WouldDelete)
		}
		if serr != nil {
			outSummary.OK = false
			errMsgs = append(errMsgs, raw.sanitizeString(serr.Error()))
		}
		if !rep.Clean() || len(rep.Retained) > 0 || len(rep.UnownedSkipped) > 0 {
			outSummary.OK = false
		}
	}
	if len(errMsgs) > 0 {
		outSummary.Error = strings.Join(errMsgs, "; ")
	}
	_ = json.NewEncoder(out).Encode(outSummary)
	if !outSummary.OK {
		return 1
	}
	return 0
}
