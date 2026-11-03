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
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

const (
	// RequiredLiveAccount is the operator-approved AWS account ID for Stage 1 live mode.
	RequiredLiveAccount = "254332045686"
	// RequiredLiveRegion is the operator-approved AWS region for Stage 1 live mode.
	RequiredLiveRegion = "us-east-1"

	// Conservative internet egress rate ($0.09 / GiB = 90,000,000 nano-USD / GiB).
	liveEgressGiBNanoUSD int64 = 90_000_000
	liveBytesPerGiB      int64 = 1024 * 1024 * 1024

	// Escaped-XML worst-case sizing for S3 ListObjectsV2:
	// A 1024-byte S3 key with every character XML-escaped (e.g. &quot; / &apos; = 6x)
	// is 6144 bytes, plus ~512 bytes of <Contents> metadata = 6656 bytes per item,
	// plus 32 KiB for the XML envelope and escaped Prefix/ContinuationToken.
	liveWorstCaseItemXMLBytes     int64 = 6656
	liveWorstCaseEnvelopeXMLBytes int64 = 32 * 1024

	// Hard response body and page bounds for Stage 1 read-only operations.
	maxLiveObjectListPageSize int   = 100
	maxLiveBucketListPageSize int32 = 100
	maxLiveQueueListPageSize  int32 = 100
	maxLiveSmallRespBodyBytes int64 = 64 * 1024  // 64 KiB bound for GetBucketLocation / GetQueueUrl
	maxLiveListRespBodyBytes  int64 = 512 * 1024 // 512 KiB bound for ListBuckets / ListQueues
	maxLiveResponseBodyBytes  int64 = int64(maxLiveObjectListPageSize)*liveWorstCaseItemXMLBytes + liveWorstCaseEnvelopeXMLBytes
)

// ErrLiveResponseTooLarge is returned when an HTTP response body exceeds the reserved byte bound.
var ErrLiveResponseTooLarge = errors.New("live response body exceeded maximum allowed byte bound")

var forbiddenLiveEndpointEnvs = []string{
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
	"AWS_ENDPOINT_URL_IAM",
	"AWS_ENDPOINT_URL_SSO",
	"AWS_ENDPOINT_URL_SSOOIDC",
	"AWS_EC2_METADATA_SERVICE_ENDPOINT",
	"STORAGE_EMULATOR_HOST",
	"PUBSUB_EMULATOR_HOST",
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
}

func isForbiddenLiveEndpointEnvKey(k string) bool {
	if slices.Contains(forbiddenLiveEndpointEnvs, k) {
		return true
	}
	if strings.HasPrefix(k, "AWS_ENDPOINT_URL") {
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
			if parsed > safety.DefaultCostCapUSD {
				return liveEnvConfig{}, hostkit.ProviderError(
					hostkit.PermissionDenied,
					0,
					"LiveCostCapExceedsDefault",
					fmt.Sprintf("%s=%.6f cannot raise the stage 1 default cap ($%.2f)", capVar, parsed, safety.DefaultCostCapUSD),
				)
			}
			if costCap == 0 || parsed < costCap {
				costCap = parsed
			}
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
	region  string
	account string
	base    http.RoundTripper
}

func isAllowedLiveS3Host(host, region string) bool {
	s3Regional := "s3." + region + ".amazonaws.com"
	if host == s3Regional || host == "s3.amazonaws.com" {
		return true
	}
	for _, suffix := range []string{"." + s3Regional, ".s3.amazonaws.com"} {
		if strings.HasSuffix(host, suffix) {
			prefix := strings.TrimSuffix(host, suffix)
			if prefix != "" && !strings.Contains(prefix, ".") {
				return true
			}
		}
	}
	return false
}

// validateSQSJSONBody strictly validates an SQS JSON protocol request body:
//   - Must be valid JSON (json.Valid).
//   - Top-level value must be a JSON object `{ ... }` (not null, array, or primitive).
//   - No duplicate keys are allowed.
//   - Only flat scalar fields allowed for the target operation are permitted.
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
		if _, isDelim := vTok.(json.Delim); isDelim || vTok == nil {
			return fmt.Errorf("non-scalar or null value for %q in SQS payload", key)
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
		isRootServiceHost := host == "s3."+t.region+".amazonaws.com" || host == "s3.amazonaws.com"
		if strings.Contains(req.URL.Path, "..") || strings.Contains(req.URL.RawPath, "..") || strings.Contains(req.URL.Path, "\\") {
			return nil, errors.New("live transport refused S3 path traversal segment")
		}
		vals, perr := parseStrictQuery(req.URL.RawQuery)
		if perr != nil {
			return nil, fmt.Errorf("live transport refused malformed S3 query: %w", perr)
		}
		if !isRootServiceHost && t.account != "" {
			ownerHdr := strings.TrimSpace(req.Header.Get("X-Amz-Expected-Bucket-Owner"))
			if ownerHdr != t.account {
				return nil, fmt.Errorf("live transport refused S3 bucket request without X-Amz-Expected-Bucket-Owner=%s", t.account)
			}
		}

		switch req.Method {
		case http.MethodHead:
			if isRootServiceHost {
				return nil, errors.New("live transport refused S3 HEAD on service root host")
			}
			if !hasOnlyAllowedKeys(vals, "x-id") {
				return nil, errors.New("live transport refused unexpected query parameters on S3 HEAD")
			}
			if xid := vals.Get("x-id"); xid != "" && xid != "HeadBucket" && xid != "HeadObject" {
				return nil, fmt.Errorf("live transport refused S3 HEAD x-id=%q", xid)
			}
			maxRespBytes = 0

		case http.MethodGet:
			// Every allowed Stage 1 S3 GET (ListBuckets, ListObjectsV2, GetBucketLocation)
			// operates on "/" (never an object key path).
			if (req.URL.Path != "" && req.URL.Path != "/") || (req.URL.RawPath != "" && req.URL.RawPath != "/") {
				return nil, fmt.Errorf("live transport refused S3 object-path GET %q in stage 1 read-only mode", req.URL.Path)
			}
			if isRootServiceHost {
				// ListBuckets only
				if !hasOnlyAllowedKeys(vals, "x-id", "continuation-token", "max-buckets", "bucket-region", "prefix") {
					return nil, errors.New("live transport refused unapproved query parameters on S3 ListBuckets")
				}
				if xid := vals.Get("x-id"); xid != "" && xid != "ListBuckets" {
					return nil, fmt.Errorf("live transport refused S3 root GET with x-id=%q", xid)
				}
				maxRespBytes = maxLiveListRespBodyBytes
			} else {
				isListObjects := vals.Get("list-type") == "2" &&
					!vals.Has("location") &&
					hasOnlyAllowedKeys(vals, "list-type", "x-id", "prefix", "max-keys", "continuation-token", "delimiter", "encoding-type", "fetch-owner", "start-after") &&
					(vals.Get("x-id") == "" || vals.Get("x-id") == "ListObjectsV2")
				isGetLocation := vals.Has("location") &&
					vals.Get("location") == "" &&
					hasOnlyAllowedKeys(vals, "location", "x-id") &&
					(vals.Get("x-id") == "" || vals.Get("x-id") == "GetBucketLocation")
				if !isListObjects && !isGetLocation {
					return nil, errors.New("live transport refused S3 GET in stage 1 read-only mode")
				}
				if isGetLocation {
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
		b, err := io.ReadAll(io.LimitReader(req.Body, 64*1024+1))
		if err != nil {
			return nil, err
		}
		if len(b) > 64*1024 {
			return nil, errors.New("live transport refused oversized SQS request body")
		}
		req.Body = io.NopCloser(bytes.NewReader(b))

		target := ""
		if len(targets) == 1 {
			target = strings.TrimSpace(targets[0])
		}
		if target != "" {
			if target != "AmazonSQS.ListQueues" && target != "AmazonSQS.GetQueueUrl" {
				return nil, fmt.Errorf("live transport refused SQS target %q in stage 1 read-only mode", target)
			}
			if err := validateSQSJSONBody(target, b); err != nil {
				return nil, fmt.Errorf("live transport refused SQS body: %w", err)
			}
			if target == "AmazonSQS.GetQueueUrl" {
				maxRespBytes = maxLiveSmallRespBodyBytes
			} else {
				maxRespBytes = maxLiveListRespBodyBytes
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

func (l *liveAdapter) ensureSession(ctx context.Context, envCfg liveEnvConfig) (*safety.Session, *safety.GuardStore, *safety.GuardQueue, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%.9f",
		envCfg.account, envCfg.region, envCfg.runID, envCfg.journalDir, envCfg.policyPath, envCfg.principal, envCfg.costCapUSD)
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

	var pol safety.Policy
	if envCfg.policyPath != "" {
		loaded, lerr := safety.LoadPolicy(envCfg.policyPath, envCfg.policyHash)
		if lerr != nil {
			return nil, nil, nil, hostkit.ProviderError(hostkit.InvalidArgument, 0, "InvalidLivePolicy", lerr.Error())
		}
		if !slices.Contains(loaded.AllowedAccounts, envCfg.account) {
			return nil, nil, nil, hostkit.ProviderError(
				hostkit.PermissionDenied,
				0,
				"LiveAccountNotAllowed",
				fmt.Sprintf("LMAWS_LIVE_ACCOUNT %q is not in policy allowed_accounts", envCfg.account),
			)
		}
		if !slices.Contains(loaded.AllowedRegions, envCfg.region) {
			return nil, nil, nil, hostkit.ProviderError(
				hostkit.PermissionDenied,
				0,
				"LiveRegionNotAllowed",
				fmt.Sprintf("LMAWS_LIVE_REGION %q is not in policy allowed_regions", envCfg.region),
			)
		}
		// Stage 1 is strictly read-only even if a custom policy file had allow_mutations: true.
		loaded.AllowMutations = false
		pol = loaded
	} else {
		pol = safety.DefaultAWSLivePolicy(absJDir, false)
		pol.AllowedAccounts = []string{envCfg.account}
		pol.AllowedRegions = []string{envCfg.region}
		if envCfg.principal != "" {
			pol.AllowedScopes = []string{envCfg.principal}
		} else {
			pol.AllowedScopes = []string{
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

	if envCfg.costCapUSD > 0 {
		if envCfg.costCapUSD > pol.Cost.CapUSD {
			return nil, nil, nil, hostkit.ProviderError(
				hostkit.PermissionDenied,
				0,
				"LiveCostCapExceedsPolicy",
				fmt.Sprintf("requested cost cap $%.6f exceeds policy cap $%.6f", envCfg.costCapUSD, pol.Cost.CapUSD),
			)
		}
		pol.Cost.CapUSD = envCfg.costCapUSD
		if pol.Cost.CleanupReserveUSD >= pol.Cost.CapUSD {
			pol.Cost.CleanupReserveUSD = pol.Cost.CapUSD * 0.2
		}
	}
	if err := pol.Validate(); err != nil {
		return nil, nil, nil, hostkit.ProviderError(hostkit.InvalidArgument, 0, "InvalidLivePolicy", err.Error())
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

// --- hostkit.ObjectStore & hostkit.Queue on liveAdapter ---

func (l *liveAdapter) CreateBucket(ctx context.Context, _ string) (bool, error) {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return false, cerr
	}
	return false, stage1MutationDisabledErr("bucket_create")
}

func (l *liveAdapter) DeleteBucket(ctx context.Context, _ string) error {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return cerr
	}
	return stage1MutationDisabledErr("bucket_delete")
}

func (l *liveAdapter) PutObject(ctx context.Context, _, _ string, _ []byte, _ string, _ map[string]string) (hostkit.ObjectMeta, error) {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}
	return hostkit.ObjectMeta{}, stage1MutationDisabledErr("object_put")
}

func (l *liveAdapter) DeleteObject(ctx context.Context, _, _ string) error {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return cerr
	}
	return stage1MutationDisabledErr("object_delete")
}

func (l *liveAdapter) GetObject(ctx context.Context, _, _ string, _ int64) ([]byte, error) {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return nil, cerr
	}
	return nil, stage1MutationDisabledErr("object_get")
}

func (l *liveAdapter) CreateQueue(ctx context.Context, _ string) (bool, error) {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return false, cerr
	}
	return false, stage1MutationDisabledErr("queue_create")
}

func (l *liveAdapter) DeleteQueue(ctx context.Context, _ string) error {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return cerr
	}
	return stage1MutationDisabledErr("queue_delete")
}

func (l *liveAdapter) Send(ctx context.Context, _, _ string) (string, error) {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return "", cerr
	}
	return "", stage1MutationDisabledErr("queue_send")
}

func (l *liveAdapter) Receive(ctx context.Context, _ string, _, _, _ int) ([]hostkit.RawMessage, error) {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return nil, cerr
	}
	return nil, stage1MutationDisabledErr("queue_receive")
}

func (l *liveAdapter) Ack(ctx context.Context, _, _ string) error {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return cerr
	}
	return stage1MutationDisabledErr("queue_ack")
}

func (l *liveAdapter) Nack(ctx context.Context, _, _ string, _ int) (string, error) {
	if _, cerr := validateLiveGates(ctx, l.getenv, l.opts); cerr != nil {
		return "", cerr
	}
	return "", stage1MutationDisabledErr("queue_nack")
}

func (l *liveAdapter) HeadBucket(ctx context.Context, name string) error {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return cerr
	}
	_, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return err
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
	_, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return hostkit.ObjectMeta{}, err
	}
	return store.HeadObject(ctx, bucket, key)
}

func (l *liveAdapter) ListObjects(ctx context.Context, bucket, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return hostkit.ObjectPage{}, cerr
	}
	_, store, _, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return hostkit.ObjectPage{}, err
	}
	return store.ListObjects(ctx, bucket, prefix, max, token)
}

func (l *liveAdapter) QueueCaps() hostkit.QueueCaps {
	return hostkit.QueueCaps{LongPoll: true, TextOnlyWire: true}
}

func (l *liveAdapter) LookupQueue(ctx context.Context, name string) error {
	envCfg, cerr := validateLiveGates(ctx, l.getenv, l.opts)
	if cerr != nil {
		return cerr
	}
	_, _, queue, err := l.ensureSession(ctx, envCfg)
	if err != nil {
		return err
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
	maxTotalBytes  int64

	mu              sync.Mutex
	redactedSecrets []string
	attestedAccount string
	attestedARN     string
	authMode        string
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
			region:  envCfg.region,
			account: envCfg.account,
			base:    enforcedBase.Transport,
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

// doLiveAWS executes an idempotent AWS read operation with pre-dispatch
// reservation of worst-case response egress cost & byte bounds and post-dispatch
// settlement of actual response egress bytes (or full reserved amount on failed/truncated reads).
func (r *liveRawBackend) doLiveAWS(ctx context.Context, opName, kind, parent, name string, maxRespBytes int64, idempotent bool, op func(ctx context.Context) error) error {
	var lastCallErr error
	r.retry.Do(ctx, idempotent, func(ctx context.Context, attempt int) hostkit.Attempt {
		var (
			res       *safety.AttemptReservation
			attemptID string
			baseFee   int64
		)
		if r.sess != nil && (attempt > 0 || maxRespBytes > 0) {
			if maxRespBytes > 0 {
				maxTotal := r.maxTotalBytes
				if maxTotal > 0 && r.sess.Journal().State().TotalPayloadBytes+maxRespBytes > maxTotal {
					lastCallErr = hostkit.ProviderError(
						hostkit.PermissionDenied,
						0,
						"LiveLimitExceeded",
						fmt.Sprintf("projected response bytes (%d + %d) exceed max_total_bytes (%d)",
							r.sess.Journal().State().TotalPayloadBytes, maxRespBytes, maxTotal),
					)
					return hostkit.Attempt{Status: http.StatusForbidden}
				}
			}
			// On attempt == 0, GuardStore/GuardQueue already reserved the base request fee,
			// so reserve only the conservative response-egress bound (via object_delete which
			// has a 0 base request fee) before dispatch. On attempt > 0, reserve both the
			// retry request fee and the response-egress bound.
			pricingOp := "object_delete"
			if attempt > 0 {
				pricingOp = opName
				if baseQuote, qerr := r.sess.Meter().QuoteAttempt(safety.AttemptPricingInput{Operation: opName}); qerr == nil {
					baseFee = baseQuote.AttemptNanoUSD
				}
			}
			var rerr error
			res, rerr = r.sess.Meter().ReserveAttempt(safety.AttemptPricingInput{
				Operation:   pricingOp,
				EgressBytes: maxRespBytes,
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
			reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD
			reason := opName + "_egress"
			if attempt > 0 {
				reason = opName + "_retry"
			}
			var jerr error
			attemptID, jerr = r.sess.Journal().BeginAttempt(kind, parent, name, reason, reservedNano, maxRespBytes)
			if jerr != nil {
				res.Commit(0, false)
				lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(jerr.Error()))
				return hostkit.Attempt{Status: http.StatusInternalServerError}
			}
		}

		tracker := &respBytesTracker{maxBytes: maxRespBytes}
		callCtx := context.WithValue(ctx, respBytesTrackerKey{}, tracker)
		lastCallErr = op(callCtx)
		actualBytes, completedEOF, tooLarge, readErr := tracker.snapshot()
		if maxRespBytes >= 0 && actualBytes > maxRespBytes {
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
			if completedEOF && !tooLarge && readErr == nil {
				actualNano := baseFee + liveEgressNanoUSD(actualBytes)
				if maxQuote := res.Quote().AttemptNanoUSD; actualNano > maxQuote {
					actualNano = maxQuote
				}
				charged := res.Commit(actualNano, false)
				if serr := r.sess.Journal().SettleAttempt(attemptID, charged, true); serr != nil {
					lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(serr.Error()))
					return hostkit.Attempt{Status: http.StatusInternalServerError}
				}
				if actualBytes > 0 {
					bID, berr := r.sess.Journal().BeginAttempt(kind, parent, name, opName+"_bytes", 0, actualBytes)
					if berr == nil {
						_ = r.sess.Journal().SettleAttempt(bID, 0, false)
					}
				}
			} else {
				charged := res.Commit(-1, false)
				if serr := r.sess.Journal().SettleAttempt(attemptID, charged, false); serr != nil && lastCallErr == nil {
					lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(serr.Error()))
					return hostkit.Attempt{Status: http.StatusInternalServerError}
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
	if r.sess == nil {
		return fn(ctx)
	}
	res, rerr := r.sess.Meter().ReserveAttempt(safety.AttemptPricingInput{Operation: opName})
	if rerr != nil {
		code := hostkit.PermissionDenied
		pcode := "LiveCostCapExceeded"
		if !errors.Is(rerr, safety.ErrCostCapExceeded) {
			code = hostkit.Internal
			pcode = "LivePricingFailure"
		}
		return hostkit.ProviderError(code, 0, pcode, r.sanitizeString(rerr.Error()))
	}
	reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD
	attemptID, jerr := r.sess.Journal().BeginAttempt(kind, parent, name, reason, reservedNano, 0)
	if jerr != nil {
		res.Commit(0, false)
		return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(jerr.Error()))
	}
	callErr := fn(ctx)
	charged := res.Commit(-1, false)
	if serr := r.sess.Journal().SettleAttempt(attemptID, charged, false); serr != nil && callErr == nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(serr.Error()))
	}
	return callErr
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

func (r *liveRawBackend) ReadOwnership(_ context.Context, _ safety.ResourceRef) (safety.RemoteOwnership, error) {
	return safety.RemoteOwnership{}, stage1MutationDisabledErr("read_ownership")
}

func (r *liveRawBackend) FindOwned(_ context.Context, _ string) ([]safety.ResourceRef, error) {
	return nil, nil
}

func (r *liveRawBackend) DeleteOwned(_ context.Context, _ safety.ResourceRef, _ safety.RemoteOwnership) error {
	return stage1MutationDisabledErr("delete_owned")
}

func (r *liveRawBackend) PollDelete(_ context.Context, _ safety.ResourceRef) (bool, error) {
	return false, stage1MutationDisabledErr("poll_delete")
}

func (r *liveRawBackend) ClassifyAbsent(err error) safety.AbsenceClass {
	if err == nil {
		return safety.AbsencePresentOrError
	}
	ce := r.classifyLive(err, scopeNone)
	switch ce.Code {
	case hostkit.NotFound:
		return safety.AbsenceDefinitive
	case hostkit.PermissionDenied, hostkit.Unauthenticated:
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

// --- Stage 1 Read-Only S3 & SQS Implementations on liveRawBackend ---

func (r *liveRawBackend) CreateBucket(_ context.Context, _ string) (bool, error) {
	return false, stage1MutationDisabledErr("bucket_create")
}

func (r *liveRawBackend) DeleteBucket(_ context.Context, _ string) error {
	return stage1MutationDisabledErr("bucket_delete")
}

func (r *liveRawBackend) PutObject(_ context.Context, _, _ string, _ []byte, _ string, _ map[string]string) (hostkit.ObjectMeta, error) {
	return hostkit.ObjectMeta{}, stage1MutationDisabledErr("object_put")
}

func (r *liveRawBackend) DeleteObject(_ context.Context, _, _ string) error {
	return stage1MutationDisabledErr("object_delete")
}

func (r *liveRawBackend) GetObject(_ context.Context, _, _ string, _ int64) ([]byte, error) {
	return nil, stage1MutationDisabledErr("object_get")
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
	cli := r.s3Client()
	owner := r.ownerAccount()
	var out *s3.HeadObjectOutput
	err := r.doLiveAWS(ctx, "object_head", safety.KindObject, bucket, key, 0, true, func(ctx context.Context) error {
		var hErr error
		out, hErr = cli.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:              aws.String(bucket),
			Key:                 aws.String(key),
			ExpectedBucketOwner: aws.String(owner),
		})
		return hErr
	})
	if err != nil {
		// Stage 1 invariant: NEVER call GetObject (not even ranged bytes=0-0) on 403.
		ce := r.classifyLive(err, scopeObject)
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

func (r *liveRawBackend) CreateQueue(_ context.Context, _ string) (bool, error) {
	return false, stage1MutationDisabledErr("queue_create")
}

func (r *liveRawBackend) DeleteQueue(_ context.Context, _ string) error {
	return stage1MutationDisabledErr("queue_delete")
}

func (r *liveRawBackend) Send(_ context.Context, _, _ string) (string, error) {
	return "", stage1MutationDisabledErr("queue_send")
}

func (r *liveRawBackend) Receive(_ context.Context, _ string, _, _, _ int) ([]hostkit.RawMessage, error) {
	return nil, stage1MutationDisabledErr("queue_receive")
}

func (r *liveRawBackend) Ack(_ context.Context, _, _ string) error {
	return stage1MutationDisabledErr("queue_ack")
}

func (r *liveRawBackend) Nack(_ context.Context, _, _ string, _ int) (string, error) {
	return "", stage1MutationDisabledErr("queue_nack")
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
