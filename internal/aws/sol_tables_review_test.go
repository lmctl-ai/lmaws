// SPDX-License-Identifier: MIT

package aws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/lmctl-ai/lmcloud/hostkit"
)

func solRemote(t *testing.T, handler http.HandlerFunc) (*remote, context.Context) {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	a := New(&Options{Getenv: func(string) string { return "" }})
	t.Cleanup(func() { _ = a.Close() })
	return a.remote, hostkit.WithEndpoint(context.Background(), s.URL)
}

func startSolAwssim(t *testing.T) string {
	t.Helper()
	if ep := strings.TrimSpace(os.Getenv("LMAWS_SOL_SIM_ENDPOINT")); ep != "" {
		return ep
	}
	simBin := "/home/ubuntu/cloud/lmcloud/.cache/sims/awssim"
	if _, err := os.Stat(simBin); err != nil {
		t.Skipf("skipping awssim-backed test: %s not found (%v)", simBin, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping awssim-backed test: cannot allocate loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command(simBin, "serve", "--port", fmt.Sprintf("%d", port))
	if err := cmd.Start(); err != nil {
		t.Skipf("skipping awssim-backed test: failed to start awssim: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	ep := fmt.Sprintf("http://127.0.0.1:%d", port)
	hc := &http.Client{Timeout: 200 * time.Millisecond}
	ready := false
	for i := 0; i < 50; i++ {
		resp, err := hc.Get(ep + "/_floci/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Skipf("skipping awssim-backed test: awssim at %s did not become healthy", ep)
	}
	return ep
}

func TestSolDeniedAdmission(t *testing.T) {
	calls := 0
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		calls++
		fmt.Fprint(w, `{}`)
	})
	ctx = hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{
		BeforeAttempt: func(context.Context, int) error {
			return errors.New("DENIED")
		},
	})
	err := r.doAWS(ctx, true, func(context.Context) error {
		calls++
		return nil
	})
	if err == nil {
		t.Fatal("admission error swallowed: expected non-nil error")
	}
	if calls != 0 {
		t.Fatalf("expected 0 calls when BeforeAttempt denied, got %d", calls)
	}
}

func TestSolTokenPhysicalAdmission(t *testing.T) {
	var calls, hooks int32
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		if strings.HasSuffix(q.Header.Get("X-Amz-Target"), "DescribeTable") {
			fmt.Fprint(w, `{"Table":{"TableName":"orders","TableStatus":"ACTIVE","TableArn":"arn:aws:dynamodb:us-east-1:123:table/orders","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]}}`)
		} else {
			fmt.Fprint(w, `{"Tags":[{"Key":"lmcloud:create-token","Value":"token"}]}`)
		}
	})
	ctx = hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{
		BeforeAttempt: func(context.Context, int) error {
			atomic.AddInt32(&hooks, 1)
			return errors.New("DENIED")
		},
	})
	_, err := r.TableCreateToken(ctx, "orders")
	if err == nil {
		t.Fatal("expected TableCreateToken to fail when admission hook denies")
	}
	if got := atomic.LoadInt32(&calls); got > 0 {
		t.Fatalf("physical dispatch despite denied hooks: calls=%d", got)
	}
	if got := atomic.LoadInt32(&hooks); got == 0 {
		t.Fatal("expected BeforeAttempt hook to be invoked")
	}
}

func TestSolMultiRequestPhysicalAdmission1To1(t *testing.T) {
	// Verify that every physical HTTP request in multi-step operations (TableCreateToken,
	// UpdateItem, QueueCreateToken, Send on uncached queue) invokes BeforeAttempt 1:1
	// and stops immediately when any step is denied.
	for denyAt := int32(1); denyAt <= 2; denyAt++ {
		var calls, hooks int32
		r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			if strings.HasSuffix(q.Header.Get("X-Amz-Target"), "DescribeTable") {
				fmt.Fprint(w, `{"Table":{"TableName":"orders","TableStatus":"ACTIVE","TableId":"id1","TableArn":"arn:aws:dynamodb:us-east-1:123:table/orders","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]}}`)
			} else {
				fmt.Fprint(w, `{"Tags":[{"Key":"lmcloud:create-token","Value":"token"}]}`)
			}
		})
		ctx = hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{
			BeforeAttempt: func(context.Context, int) error {
				if atomic.AddInt32(&hooks, 1) >= denyAt {
					return errors.New("DENIED")
				}
				return nil
			},
		})
		_, err := r.TableCreateToken(ctx, "orders")
		if err == nil {
			t.Fatalf("denyAt=%d: expected TableCreateToken to fail when hook denies", denyAt)
		}
		if gotCalls := atomic.LoadInt32(&calls); gotCalls != denyAt-1 {
			t.Fatalf("denyAt=%d: expected %d physical calls before denial, got %d", denyAt, denyAt-1, gotCalls)
		}
	}
}

func TestSolCreateConflictForeignLayout(t *testing.T) {
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		if strings.HasSuffix(q.Header.Get("X-Amz-Target"), "CreateTable") {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"__type":"ResourceInUseException","message":"exists"}`)
		} else {
			fmt.Fprint(w, `{"Table":{"TableName":"orders","TableStatus":"ACTIVE","TableId":"id1","KeySchema":[{"AttributeName":"foreign","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"foreign","AttributeType":"N"}]}}`)
		}
	})
	created, err := r.CreateTable(ctx, "orders", false)
	if err == nil {
		t.Fatalf("foreign incompatible key schema accepted: created=%v", created)
	}
	if ce := hostkit.AsCloudError(err); ce == nil || ce.Code != hostkit.Conflict {
		t.Fatalf("expected CONFLICT for incompatible foreign key schema, got %v", err)
	}
	if _, cached := r.getTableLayout(ctx, "orders"); cached {
		t.Fatal("foreign table layout must not be cached as a portable table")
	}
	if _, descErr := r.DescribeTable(ctx, "orders"); descErr == nil || hostkit.AsCloudError(descErr).Code != hostkit.Conflict {
		t.Fatalf("expected DescribeTable to reject foreign key schema with CONFLICT, got %v", descErr)
	}
}

func TestSolUpdateMetricsShrink(t *testing.T) {
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		if strings.HasSuffix(q.Header.Get("X-Amz-Target"), "GetItem") {
			big := strings.Repeat("x", 32768)
			fmt.Fprintf(w, `{"Item":{"pk":{"S":"p"},"__lmcloud_v":{"S":"v0"},"__lmt":{"M":{}},"value":{"S":%q}}}`, big)
			return
		}
		fmt.Fprint(w, `{"Attributes":{"pk":{"S":"p"},"__lmcloud_v":{"S":"v"},"__lmt":{"M":{}},"value":{"S":"x"}}}`)
	})
	var m hostkit.TableOpMetrics
	ctx = hostkit.WithTableOpMetrics(ctx, &m)
	_, err := r.UpdateItem(ctx, "orders", "p", "", hostkit.Item{
		Attrs: map[string]hostkit.Attr{"value": hostkit.StringAttr("x")},
	})
	if err != nil {
		t.Fatalf("UpdateItem failed: %v", err)
	}
	if m.Authoritative && m.PriorBytes < 32768 {
		t.Fatalf("claims authoritative old bytes from new-only response: %+v", m)
	}
	if m.Authoritative {
		t.Fatalf("expected UpdateItem metrics to remain non-authoritative, got %+v", m)
	}
}

func TestSolConditionalMissingOld(t *testing.T) {
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"__type":"ConditionalCheckFailedException","message":"wrong version; provider omitted old item"}`)
	})
	_, err := r.PutItem(ctx, "orders", hostkit.Item{PK: "p", Attrs: map[string]hostkit.Attr{}}, hostkit.PutIfVersion, "stale")
	if err == nil {
		t.Fatal("expected error from conditional failure")
	}
	if hostkit.AsCloudError(err).Code == hostkit.NotFound {
		t.Fatalf("unproven absence classified NOT_FOUND: %v", err)
	}
}

func TestSolWaitPhysicalAdmission(t *testing.T) {
	var calls, hooks int32
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		fmt.Fprint(w, `{"Table":{"TableStatus":"ACTIVE","TableId":"id","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]}}`)
	})
	ctx = hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{
		BeforeAttempt: func(context.Context, int) error {
			atomic.AddInt32(&hooks, 1)
			return errors.New("DENIED")
		},
	})
	err := r.waitTableActive(ctx, "orders", types.TableStatusCreating)
	if err == nil {
		t.Fatal("expected waitTableActive to fail when admission hook denies")
	}
	if got := atomic.LoadInt32(&calls); got > 0 {
		t.Fatalf("poll bypasses admission: calls=%d", got)
	}
	if got := atomic.LoadInt32(&hooks); got == 0 {
		t.Fatal("expected BeforeAttempt hook to be invoked")
	}
}

func TestSolUnboundedDDBBody(t *testing.T) {
	padding := strings.Repeat("x", 17*1024*1024)
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		fmt.Fprintf(w, `{"IgnoredPadding":"%s","Item":{"pk":{"S":"p"},"__lmcloud_v":{"S":"v"}}}`, padding)
	})
	out, err := r.GetItem(ctx, "orders", "p", "")
	if err == nil {
		t.Fatalf("unbounded SDK body accepted: exists=%v", out.Exists)
	}
	if ce := hostkit.AsCloudError(err); ce == nil || ce.Code != hostkit.Internal {
		t.Fatalf("expected INTERNAL ResponseTooLarge error, got %v", err)
	}
}

func TestSolTransientDescribe404(t *testing.T) {
	var calls int32
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		c := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		if c == 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"__type":"ResourceNotFoundException","message":"metadata not propagated"}`)
		} else {
			fmt.Fprint(w, `{"Table":{"TableStatus":"ACTIVE","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]}}`)
		}
	})
	err := r.waitTableActive(ctx, "orders", types.TableStatusCreating)
	if err != nil {
		t.Fatalf("readiness poll terminated on expected transient describe absence: err=%v calls=%d", err, atomic.LoadInt32(&calls))
	}
	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Fatalf("expected at least 2 DescribeTable polls, got %d", got)
	}
}

func TestSolWaitTableTimeoutFailsClosed(t *testing.T) {
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		fmt.Fprint(w, `{"Table":{"TableStatus":"CREATING","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]}}`)
	})
	err := r.waitTableActiveWithTiming(ctx, "orders", types.TableStatusCreating, 30*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected waitTableActiveWithTiming to fail when ACTIVE is never observed before timeout")
	}
	if ce := hostkit.AsCloudError(err); ce == nil || ce.Code != hostkit.Internal {
		t.Fatalf("expected INTERNAL TableWaitTimeout error, got %v", err)
	}
}

func TestSolDescribeMissingIncarnationTokenFailsClosed(t *testing.T) {
	r, ctx := solRemote(t, func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		fmt.Fprint(w, `{"Table":{"TableName":"orders","TableStatus":"ACTIVE","TableArn":"arn:aws:dynamodb:us-east-1:123:table/orders","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]}}`)
	})
	_, err := r.DescribeTable(ctx, "orders")
	if err == nil {
		t.Fatal("expected DescribeTable to fail closed when neither TableId nor CreationDateTime is present")
	}
	if ce := hostkit.AsCloudError(err); ce == nil || ce.Code != hostkit.Internal {
		t.Fatalf("expected INTERNAL MissingTableIncarnationToken error, got %v", err)
	}
}

func TestSolSimUpdateLimit(t *testing.T) {
	ep := startSolAwssim(t)
	a := New(&Options{Getenv: func(string) string { return "" }})
	defer a.Close()
	r := a.remote
	ctx := hostkit.WithEndpoint(context.Background(), ep)

	table := "lmsolprobe20261103"
	_ = r.DeleteTable(ctx, table)
	_, err := r.CreateTable(ctx, table, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.DeleteTable(ctx, table)

	// 1. 240-attribute item + 1 new attribute via UpdateItem must fail and leave item & version intact.
	attrs := make(map[string]hostkit.Attr, 240)
	for i := 0; i < 240; i++ {
		attrs[fmt.Sprintf("a%03d", i)] = hostkit.StringAttr("x")
	}
	putOut, err := r.PutItem(ctx, table, hostkit.Item{PK: "p", Attrs: attrs}, hostkit.PutUnconditional, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.UpdateItem(ctx, table, "p", "", hostkit.Item{
		Attrs: map[string]hostkit.Attr{"extra": hostkit.StringAttr("y")},
	})
	if err == nil {
		t.Fatal("expected UpdateItem adding 241st attribute to fail with INVALID_ARGUMENT")
	}
	if ce := hostkit.AsCloudError(err); ce == nil || ce.Code != hostkit.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT for 241st attribute, got %v", err)
	}
	got, gerr := r.GetItem(ctx, table, "p", "")
	if gerr != nil {
		t.Fatalf("GetItem after rejected update: %v", gerr)
	}
	if len(got.Attrs) != 240 {
		t.Fatalf("expected 240 attributes intact after rejected update, got %d", len(got.Attrs))
	}
	if _, hasExtra := got.Attrs["extra"]; hasExtra {
		t.Fatal("rejected update must not persist extra attribute")
	}
	if got.Version != putOut.Version {
		t.Fatalf("rejected update must leave version intact: want %q, got %q", putOut.Version, got.Version)
	}

	// 2. Canonical byte ceiling (262144 bytes) exceeded on merged UpdateItem must also fail and leave item & version intact.
	chunk := strings.Repeat("a", 65000)
	put2, err := r.PutItem(ctx, table, hostkit.Item{
		PK: "p-bytes",
		Attrs: map[string]hostkit.Attr{
			"c1": hostkit.StringAttr(chunk),
			"c2": hostkit.StringAttr(chunk),
			"c3": hostkit.StringAttr(chunk),
			"c4": hostkit.StringAttr(chunk),
		},
	}, hostkit.PutUnconditional, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.UpdateItem(ctx, table, "p-bytes", "", hostkit.Item{
		Attrs: map[string]hostkit.Attr{"c5": hostkit.StringAttr(chunk)},
	})
	if err == nil || hostkit.AsCloudError(err).Code != hostkit.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT when merged canonical bytes exceed 262144, got %v", err)
	}
	got2, gerr := r.GetItem(ctx, table, "p-bytes", "")
	if gerr != nil {
		t.Fatalf("GetItem p-bytes after rejected update: %v", gerr)
	}
	if len(got2.Attrs) != 4 || got2.Version != put2.Version {
		t.Fatalf("rejected byte-limit update must leave item and version intact: attrs=%d ver=%q (want %q)", len(got2.Attrs), got2.Version, put2.Version)
	}
}

func TestSolSimRecreateIncarnation(t *testing.T) {
	ep := startSolAwssim(t)
	a := New(&Options{Getenv: func(string) string { return "" }})
	defer a.Close()
	r := a.remote
	ctx := hostkit.WithEndpoint(context.Background(), ep)

	name := "lmsolincarnation"
	_ = r.DeleteTable(ctx, name)
	defer r.DeleteTable(ctx, name)

	if _, e := r.CreateTable(ctx, name, false); e != nil {
		t.Fatal(e)
	}
	x, e := r.DescribeTable(ctx, name)
	if e != nil {
		t.Fatal(e)
	}
	if e := r.DeleteTable(ctx, name); e != nil {
		t.Fatal(e)
	}
	if _, e := r.CreateTable(ctx, name, false); e != nil {
		t.Fatal(e)
	}
	y, e := r.DescribeTable(ctx, name)
	if e != nil {
		t.Fatal(e)
	}
	if x.CreateToken == "" || y.CreateToken == "" || x.CreateToken == y.CreateToken {
		t.Fatalf("recreate kept same or empty incarnation token: old=%q new=%q", x.CreateToken, y.CreateToken)
	}
}

func TestSolSimShrinkActualMetrics(t *testing.T) {
	ep := startSolAwssim(t)
	a := New(&Options{Getenv: func(string) string { return "" }})
	defer a.Close()
	r := a.remote
	ctx := hostkit.WithEndpoint(context.Background(), ep)

	name := "lmsolshrinkmetrics"
	_ = r.DeleteTable(ctx, name)
	defer r.DeleteTable(ctx, name)

	if _, e := r.CreateTable(ctx, name, false); e != nil {
		t.Fatal(e)
	}
	old, e := r.PutItem(ctx, name, hostkit.Item{
		PK:    "p",
		Attrs: map[string]hostkit.Attr{"value": hostkit.StringAttr(strings.Repeat("x", 32768))},
	}, hostkit.PutUnconditional, "")
	if e != nil {
		t.Fatal(e)
	}
	var m hostkit.TableOpMetrics
	ctx = hostkit.WithTableOpMetrics(ctx, &m)
	_, e = r.UpdateItem(ctx, name, "p", "", hostkit.Item{
		Attrs: map[string]hostkit.Attr{"value": hostkit.StringAttr("x")},
	})
	if e != nil {
		t.Fatal(e)
	}
	if m.Authoritative && m.PriorBytes < hostkit.NativeItemBillableBytes(old) {
		t.Fatalf("actual shrink undercharged: actual_prior=%d reported=%+v", hostkit.NativeItemBillableBytes(old), m)
	}
	if m.PriorBytes != hostkit.NativeItemBillableBytes(old) {
		t.Fatalf("expected PriorBytes=%d, got %d", hostkit.NativeItemBillableBytes(old), m.PriorBytes)
	}
}
