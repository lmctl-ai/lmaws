// SPDX-License-Identifier: MIT

package aws

import (
	"bytes"
	"context"
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
)

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
	"STORAGE_EMULATOR_HOST",
	"PUBSUB_EMULATOR_HOST",
}

var awsAccessKeyPattern = regexp.MustCompile(`\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`)

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

// liveEndpointGuardTransport enforces at the HTTP transport boundary that every
// outgoing business request in Stage 1 live mode:
//  1. Uses https:// with no userinfo or fragment.
//  2. Targets only the canonical AWS endpoints in the approved region (sts, s3, sqs).
//  3. Carries a non-empty SigV4 Authorization header (AWS4-HMAC-SHA256).
//  4. Executes only Stage 1 read-only operations (never PUT/DELETE, never S3 GetObject,
//     and never mutating or message-consuming SQS actions).
type liveEndpointGuardTransport struct {
	region string
	base   http.RoundTripper
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

func (t *liveEndpointGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("live transport: nil request or URL")
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return nil, fmt.Errorf("live transport refused non-HTTPS scheme %q", req.URL.Scheme)
	}
	if req.URL.User != nil || req.URL.Fragment != "" {
		return nil, errors.New("live transport refused URL with userinfo or fragment")
	}
	host := strings.ToLower(req.URL.Hostname())
	if host == "" || hostkit.IsLoopbackHost(host) {
		return nil, fmt.Errorf("live transport refused loopback or empty host %q", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil, fmt.Errorf("live transport refused raw IP literal %q", host)
	}

	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") ||
		!strings.Contains(auth, "Credential=") ||
		!strings.Contains(auth, "Signature=") {
		return nil, errors.New("live transport refused unsigned request (missing AWS4-HMAC-SHA256 Authorization)")
	}

	stsHost := "sts." + t.region + ".amazonaws.com"
	sqsHost := "sqs." + t.region + ".amazonaws.com"

	switch {
	case host == stsHost || host == "sts.amazonaws.com":
		if req.Method != http.MethodPost {
			return nil, fmt.Errorf("live transport refused STS method %s", req.Method)
		}
		if req.Body != nil {
			b, err := io.ReadAll(io.LimitReader(req.Body, 64*1024))
			if err != nil {
				return nil, err
			}
			req.Body = io.NopCloser(bytes.NewReader(b))
			if !strings.Contains(string(b), "Action=GetCallerIdentity") {
				return nil, errors.New("live transport refused STS action other than GetCallerIdentity")
			}
		}

	case isAllowedLiveS3Host(host, t.region):
		switch req.Method {
		case http.MethodHead:
			// HeadBucket and HeadObject are allowed.
		case http.MethodGet:
			// Allowed S3 GETs in Stage 1:
			//  - ListBuckets: GET / on s3.<region>.amazonaws.com
			//  - ListObjectsV2: GET with list-type=2
			//  - GetBucketLocation (403 auth-vs-permission probe): GET with ?location
			isRootServiceHost := host == "s3."+t.region+".amazonaws.com" || host == "s3.amazonaws.com"
			q := req.URL.Query()
			rawQ := req.URL.RawQuery
			isListBuckets := isRootServiceHost && (req.URL.Path == "" || req.URL.Path == "/") &&
				(rawQ == "" || q.Get("x-id") == "ListBuckets" || q.Has("continuation-token") || q.Has("max-buckets"))
			isListObjects := q.Get("list-type") == "2"
			isGetLocation := q.Has("location") || rawQ == "location" || strings.HasPrefix(rawQ, "location&") || strings.Contains(rawQ, "&location")
			if !isListBuckets && !isListObjects && !isGetLocation {
				return nil, errors.New("live transport refused S3 GetObject in stage 1 read-only mode")
			}
		default:
			return nil, fmt.Errorf("live transport refused S3 mutating method %s in stage 1 read-only mode", req.Method)
		}

	case host == sqsHost:
		if req.Method != http.MethodPost {
			return nil, fmt.Errorf("live transport refused SQS method %s", req.Method)
		}
		target := strings.TrimSpace(req.Header.Get("X-Amz-Target"))
		allowedSQS := target == "AmazonSQS.ListQueues" || target == "AmazonSQS.GetQueueUrl"
		if !allowedSQS && target == "" && req.Body != nil {
			b, err := io.ReadAll(io.LimitReader(req.Body, 64*1024))
			if err != nil {
				return nil, err
			}
			req.Body = io.NopCloser(bytes.NewReader(b))
			bodyStr := string(b)
			allowedSQS = strings.Contains(bodyStr, "Action=ListQueues") || strings.Contains(bodyStr, "Action=GetQueueUrl")
		}
		if !allowedSQS {
			return nil, fmt.Errorf("live transport refused SQS action %q in stage 1 read-only mode", target)
		}

	default:
		return nil, fmt.Errorf("live transport refused unapproved endpoint host %q", host)
	}

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
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

	raw, err := newLiveRawBackend(ctx, envCfg, l.opts, l.retry, l.baseCli)
	if err != nil {
		return nil, nil, nil, err
	}

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

// liveRawBackend implements hostkit.ObjectStore, hostkit.Queue, and
// safety.RecoveryAdapter against real AWS HTTPS endpoints in us-east-1.
type liveRawBackend struct {
	account        string
	region         string
	awsCfg         aws.Config
	businessClient *http.Client
	retry          hostkit.RetryPolicy
	sess           *safety.Session

	mu              sync.Mutex
	redactedSecrets []string
	attestedAccount string
	attestedARN     string
	authMode        string
}

func newLiveRawBackend(ctx context.Context, envCfg liveEnvConfig, opts *Options, retry hostkit.RetryPolicy, baseCli *http.Client) (*liveRawBackend, error) {
	enforcedBase := hostkit.EnforceClient(baseCli)
	businessCli := &http.Client{
		Timeout:       enforcedBase.Timeout,
		CheckRedirect: enforcedBase.CheckRedirect,
		Transport: &liveEndpointGuardTransport{
			region: envCfg.region,
			base:   enforcedBase.Transport,
		},
	}

	// Auth/credential resolution client: if a test injected a custom HTTPClient,
	// use businessCli so unit tests never contact external network or IMDS;
	// otherwise use a bounded hostkit HTTP client so EC2 IMDSv2 / OIDC web identity
	// can resolve credentials before business calls go through liveEndpointGuardTransport.
	credHTTPCli := hostkit.NewHTTPClient(10 * time.Second)
	if opts != nil && opts.HTTPClient != nil {
		credHTTPCli = businessCli
	}

	loadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	awsCfg, err := config.LoadDefaultConfig(
		loadCtx,
		config.WithRegion(envCfg.region),
		config.WithRetryMaxAttempts(1),
		config.WithClientLogMode(0),
		config.WithHTTPClient(credHTTPCli),
	)
	if err != nil {
		return nil, hostkit.ProviderError(
			hostkit.Unauthenticated,
			0,
			"LiveConfigLoadFailed",
			sanitizeStaticSecrets(err.Error()),
		)
	}
	awsCfg.Region = envCfg.region
	awsCfg.ClientLogMode = 0
	awsCfg.RetryMaxAttempts = 1
	awsCfg.Retryer = func() aws.Retryer { return aws.NopRetryer{} }

	raw := &liveRawBackend{
		account:        envCfg.account,
		region:         envCfg.region,
		awsCfg:         awsCfg,
		businessClient: businessCli,
		retry:          retry,
		authMode:       "imds_role",
	}
	for _, envSecret := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_ACCESS_KEY_ID"} {
		if v := strings.TrimSpace(os.Getenv(envSecret)); v != "" {
			raw.registerSecret(v)
		}
	}
	return raw, nil
}

func (r *liveRawBackend) registerSecret(s string) {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.redactedSecrets, s) {
		r.redactedSecrets = append(r.redactedSecrets, s)
	}
}

func sanitizeStaticSecrets(msg string) string {
	for _, envKey := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_ACCESS_KEY_ID"} {
		if v := strings.TrimSpace(os.Getenv(envKey)); len(v) >= 4 {
			msg = strings.ReplaceAll(msg, v, "[redacted]")
		}
	}
	msg = awsAccessKeyPattern.ReplaceAllString(msg, "[redacted-key-id]")
	return msg
}

func (r *liveRawBackend) sanitizeString(msg string) string {
	r.mu.Lock()
	secrets := slices.Clone(r.redactedSecrets)
	r.mu.Unlock()
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
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
	return &cp
}

func (r *liveRawBackend) classifyLive(err error, sc scope) *hostkit.CloudError {
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

// doLiveAWS executes an idempotent AWS read operation. Attempt 1 is already
// reserved and settled by LiveGuard; if RetryPolicy triggers a retry attempt
// (attempt > 0) after a transient 5xx/429, doLiveAWS reserves and settles an
// additional durable attempt on the session's CostMeter and Journal BEFORE
// dispatching the retry request.
func (r *liveRawBackend) doLiveAWS(ctx context.Context, opName, kind, parent, name string, idempotent bool, op func(ctx context.Context) error) error {
	var lastCallErr error
	r.retry.Do(ctx, idempotent, func(ctx context.Context, attempt int) hostkit.Attempt {
		if attempt > 0 && r.sess != nil {
			res, rerr := r.sess.Meter().ReserveAttempt(safety.AttemptPricingInput{Operation: opName})
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
			attemptID, jerr := r.sess.Journal().BeginAttempt(kind, parent, name, opName+"_retry", reservedNano, 0)
			if jerr != nil {
				res.Commit(0, false)
				lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(jerr.Error()))
				return hostkit.Attempt{Status: http.StatusInternalServerError}
			}
			lastCallErr = op(ctx)
			charged := res.Commit(-1, false)
			if serr := r.sess.Journal().SettleAttempt(attemptID, charged, false); serr != nil && lastCallErr == nil {
				lastCallErr = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", r.sanitizeString(serr.Error()))
				return hostkit.Attempt{Status: http.StatusInternalServerError}
			}
		} else {
			lastCallErr = op(ctx)
		}

		if lastCallErr == nil {
			return hostkit.Attempt{Status: http.StatusOK}
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
			"no AWS credential provider available in default chain",
		)
	}
	creds, err := r.awsCfg.Credentials.Retrieve(reqCtx)
	if err != nil {
		return safety.AttestedIdentity{}, hostkit.ProviderError(
			hostkit.Unauthenticated,
			0,
			"LiveCredentialsUnavailable",
			r.sanitizeString(err.Error()),
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

func (r *liveRawBackend) QuoteAttempt(_ safety.AttemptPricingInput, base safety.AttemptQuote) (safety.AttemptQuote, error) {
	return base, nil
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
	err := r.doLiveAWS(ctx, "bucket_exists", safety.KindBucket, "", name, true, func(ctx context.Context) error {
		_, hErr := cli.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(name)})
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
			return r.doLiveAWS(ctx, "bucket_exists", safety.KindBucket, "", name, true, func(ctx context.Context) error {
				_, pErr := cli.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(name)})
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
	in := &s3.ListBucketsInput{}
	if token != "" {
		in.ContinuationToken = aws.String(token)
	}
	var out *s3.ListBucketsOutput
	err := r.doLiveAWS(ctx, "bucket_list", safety.KindBucket, "", "", true, func(ctx context.Context) error {
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
	return names, strings.TrimSpace(aws.ToString(out.ContinuationToken)), nil
}

func (r *liveRawBackend) HeadObject(ctx context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	cli := r.s3Client()
	var out *s3.HeadObjectOutput
	err := r.doLiveAWS(ctx, "object_head", safety.KindObject, bucket, key, true, func(ctx context.Context) error {
		var hErr error
		out, hErr = cli.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
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
	cli := r.s3Client()
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
	err := r.doLiveAWS(ctx, "object_list", safety.KindObject, bucket, prefix, true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListObjectsV2(ctx, in)
		return lErr
	})
	if err != nil {
		return hostkit.ObjectPage{}, r.classifyLive(err, scopeBucket)
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
	err := r.doLiveAWS(ctx, "queue_exists", safety.KindQueue, "", name, true, func(ctx context.Context) error {
		var gErr error
		out, gErr = cli.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
			QueueName: aws.String(name),
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
	qName, verr := validateLiveQueueURL(aws.ToString(out.QueueUrl), r.region, r.account)
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
	in := &sqs.ListQueuesInput{}
	if token != "" {
		in.NextToken = aws.String(token)
	}
	var out *sqs.ListQueuesOutput
	err := r.doLiveAWS(ctx, "queue_list", safety.KindQueue, "", "", true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListQueues(ctx, in)
		return lErr
	})
	if err != nil {
		return nil, "", r.classifyLive(err, scopeQueue)
	}
	names := make([]string, 0, len(out.QueueUrls))
	for _, u := range out.QueueUrls {
		qName, verr := validateLiveQueueURL(u, r.region, r.account)
		if verr != nil {
			return nil, "", hostkit.ProviderError(hostkit.Internal, 0, "InvalidLiveQueueURL", r.sanitizeString(verr.Error()))
		}
		names = append(names, qName)
	}
	return names, strings.TrimSpace(aws.ToString(out.NextToken)), nil
}
