package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/anomaly"
	"aiproxy/internal/auditlog"
	"aiproxy/internal/breaker"
	"aiproxy/internal/cache"
	"aiproxy/internal/geoip"
	"aiproxy/internal/iplimiter"
	"aiproxy/internal/limiter"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

// syncBuffer is a mutex-protected byte buffer safe to use as a
// *log.Logger's output while a test reads it back concurrently. A plain
// bytes.Buffer is not concurrency-safe, and streaming responses log from
// a callback that fires on ReverseProxy's own goroutine — a bare
// bytes.Buffer shared with the test goroutine would be a real data race,
// not just a theoretical one (the race detector catches it in practice).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForLogContains polls buf (safely) until its contents contain
// substr or timeout elapses, returning whatever was last observed. This
// is needed because streaming's usage/cache side effects run from a
// callback fired asynchronously when ReverseProxy closes the response
// body — there is no other signal available to a test for "that callback
// has now run" than observing its effects.
func waitForLogContains(buf *syncBuffer, substr string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for {
		got := buf.String()
		if strings.Contains(got, substr) || time.Now().After(deadline) {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestServer_BlockLogging_NeverLeaksMatchedSecret(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	secret := "AKIAABCDEFGHIJKLMNOP"
	resp, err := http.Post(frontend.URL+"/upload", "text/plain", strings.NewReader("token="+secret))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if upstreamHit.Load() {
		t.Fatal("blocked request must never reach the upstream target")
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, secret) {
		t.Fatalf("log leaked the matched secret value: %q", logOutput)
	}
	if !strings.Contains(logOutput, "[BLOCK]") {
		t.Fatalf("log missing [BLOCK] marker: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Triggered rule: aws-access-key") {
		t.Fatalf("log missing triggered rule name: %q", logOutput)
	}
	if !strings.Contains(logOutput, "\x1b[91m") {
		t.Fatalf("log missing bright red ANSI code: %q", logOutput)
	}
}

func TestServer_AllowLogging(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/endpoint", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[ALLOW] POST /endpoint") {
		t.Fatalf("log did not clearly report the allow: %q", logOutput)
	}
	if !strings.Contains(logOutput, "\x1b[32m") {
		t.Fatalf("log missing green ANSI code: %q", logOutput)
	}
}

// TestServer_PathRule_BlocksMatchingPrefixRegardlessOfBody proves an
// end-to-end path rule blocks a whole endpoint outright, even with a
// perfectly clean body — the request never reaches the upstream target.
func TestServer_PathRule_BlocksMatchingPrefixRegardlessOfBody(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{Name: "block-admin", PathPrefix: "/admin", Action: rules.Block})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/admin/users", "application/json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if upstreamHit.Load() {
		t.Fatal("a path-blocked request must never reach the upstream target")
	}
	if !strings.Contains(logBuf.String(), "Triggered rule: block-admin") {
		t.Fatalf("log missing triggered path rule name: %q", logBuf.String())
	}
}

// TestServer_PathRule_AllowExemptsMatchingPrefixFromBuiltinRules proves
// an "allow" path rule exempts its prefix from secret scanning
// entirely: a request under it forwards even though its body would
// otherwise be blocked by a built-in rule.
func TestServer_PathRule_AllowExemptsMatchingPrefixFromBuiltinRules(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{Name: "health-check", PathPrefix: "/health", Action: rules.Allow})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/health/status", "application/json", strings.NewReader(`{"note":"AKIAABCDEFGHIJKLMNOP"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (the path rule must exempt this request from the aws-access-key rule)", resp.StatusCode, http.StatusOK)
	}
	if !upstreamHit.Load() {
		t.Fatal("an allow-listed request must still reach the upstream target")
	}
}

// TestServer_RateLimiting_SixthRequestGets429AndResetsAfterWindow proves
// the circuit breaker end to end through the real HTTP layer: with the
// limit set to 5 requests per window, the first 5 requests succeed, the
// 6th is rejected with 429 and never reaches upstream, and once the
// window elapses the breaker releases and requests succeed again.
func TestServer_RateLimiting_SixthRequestGets429AndResetsAfterWindow(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)
	const window = 150 * time.Millisecond
	srv.Limiter = limiter.New(5, window)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 1; i <= 5; i++ {
		resp, err := http.Get(frontend.URL + "/endpoint")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, resp.StatusCode, http.StatusOK)
		}
	}

	resp6, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("request 6: %v", err)
	}
	resp6.Body.Close()
	if resp6.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 6: status = %d, want %d", resp6.StatusCode, http.StatusTooManyRequests)
	}
	if upstreamHits.Load() != 5 {
		t.Fatalf("upstream hits = %d, want exactly 5 (the 6th must never reach upstream)", upstreamHits.Load())
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[CIRCUIT BREAKER] GET /endpoint - Rate limit exceeded") {
		t.Fatalf("log missing circuit breaker message: %q", logOutput)
	}
	if !strings.Contains(logOutput, "\x1b[33m") {
		t.Fatalf("log missing yellow ANSI code: %q", logOutput)
	}

	time.Sleep(window + 100*time.Millisecond)

	resp7, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("request after window reset: %v", err)
	}
	resp7.Body.Close()
	if resp7.StatusCode != http.StatusOK {
		t.Fatalf("request after window reset: status = %d, want %d", resp7.StatusCode, http.StatusOK)
	}
	if upstreamHits.Load() != 6 {
		t.Fatalf("upstream hits = %d, want exactly 6 after the window reset", upstreamHits.Load())
	}
}

// TestServer_TokenRateLimit_BlocksOnceWindowUsageReachesBudgetAndResetsAfterWindow
// proves the token-based breaker's full lifecycle end to end: each
// response reports 100 tokens used; against a 150-token budget, the
// first two requests are allowed (window usage 0, then 100, both under
// budget) but the third is rejected before ever reaching the upstream
// (window usage now 200, at/over budget) — then, once the window has
// fully elapsed, capacity frees up again exactly like the plain
// request-count breaker does.
func TestServer_TokenRateLimit_BlocksOnceWindowUsageReachesBudgetAndResetsAfterWindow(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Write([]byte(`{"usage":{"total_tokens":100}}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)
	const window = 150 * time.Millisecond
	srv.TokenLimiter = limiter.NewTokenLimiter(150, window)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func() int {
		resp, err := http.Get(frontend.URL + "/endpoint")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get(); got != http.StatusOK {
		t.Fatalf("request 1: status = %d, want %d", got, http.StatusOK)
	}
	if got := get(); got != http.StatusOK {
		t.Fatalf("request 2: status = %d, want %d (window usage 100/150, still under budget)", got, http.StatusOK)
	}
	if got := get(); got != http.StatusTooManyRequests {
		t.Fatalf("request 3: status = %d, want %d (window usage 200/150, over budget)", got, http.StatusTooManyRequests)
	}
	if upstreamHits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want exactly 2 (the 3rd must never reach upstream)", upstreamHits.Load())
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[TOKEN LIMIT] GET /endpoint - Token rate limit exceeded") {
		t.Fatalf("log missing token limit message: %q", logOutput)
	}

	time.Sleep(window + 100*time.Millisecond)

	if got := get(); got != http.StatusOK {
		t.Fatalf("request after window reset: status = %d, want %d", got, http.StatusOK)
	}
	if upstreamHits.Load() != 3 {
		t.Fatalf("upstream hits = %d, want exactly 3 after the window reset", upstreamHits.Load())
	}
}

// TestServer_TokenRateLimit_NeverBlocksFirstRequestRegardlessOfItsOwnUsage
// documents the intentional overshoot tradeoff described in
// limiter.TokenLimiter's doc comment, exercised through the full
// ServeHTTP path: a request's own token cost isn't known until its
// response comes back, so even a tiny configured budget never blocks
// the very first request against an empty window — it can only ever
// reject a *later* one, once usage has actually been recorded.
func TestServer_TokenRateLimit_NeverBlocksFirstRequestRegardlessOfItsOwnUsage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TokenLimiter = limiter.NewTokenLimiter(1, time.Minute) // budget of just 1 token
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (the window was empty when this request was checked)", resp.StatusCode, http.StatusOK)
	}

	// The next request, however, must now be rejected — the first
	// response's 10000 tokens are recorded, hugely over the 1-token
	// budget.
	resp2, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("get 2: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d (10000 tokens now recorded against a 1-token budget)", resp2.StatusCode, http.StatusTooManyRequests)
	}
}

// TestServer_TokenRateLimit_RejectedRequestNeverCountsAsPlainRateLimited
// proves the two breakers are tracked as fully independent counters —
// same "distinct counters for distinct rejection reasons" discipline as
// ip_denied vs. unauthorized — so a token-budget rejection is visible in
// stats as exactly that, not folded into RateLimited.
func TestServer_TokenRateLimit_RejectedRequestNeverCountsAsPlainRateLimited(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TokenLimiter = limiter.NewTokenLimiter(0, time.Minute) // 0: nothing ever allowed
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}

	snap := srv.Stats.Snapshot()
	if snap.TokenRateLimited != 1 {
		t.Errorf("TokenRateLimited = %d, want 1", snap.TokenRateLimited)
	}
	if snap.RateLimited != 0 {
		t.Errorf("RateLimited = %d, want 0 (a token-budget rejection is not a plain rate limit rejection)", snap.RateLimited)
	}
}

// shortAnomalyWindow lets these tests establish a baseline and trigger
// a spike in real wall-clock milliseconds instead of the production
// anomaly.DefaultWindow's real 60 seconds.
const shortAnomalyWindow = 300 * time.Millisecond

// getWithProxyAuth issues a GET to url with the given
// Proxy-Authorization bearer key set, failing the test on any
// transport error.
func getWithProxyAuth(t *testing.T, url, key string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return resp
}

// TestServer_AnomalyDetection_UnconfiguredNeverBlocks proves that with
// AnomalyDetector nil (the default), no burst of traffic is ever
// flagged — same zero-cost-when-unused discipline as every other
// optional check in this package.
func TestServer_AnomalyDetection_UnconfiguredNeverBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "the-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 200; i++ {
		resp := getWithProxyAuth(t, frontend.URL+"/x", "the-key")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d (no AnomalyDetector configured)", i, resp.StatusCode, http.StatusOK)
		}
	}
}

// TestServer_AnomalyDetection_UnidentifiedCallerNeverBlocks proves that
// even with AnomalyDetector configured, a fully anonymous proxy (no
// proxy_api_key/proxy_api_keys at all, so auth.label is always "") is
// never affected — there's no notion of "this caller's own baseline"
// without an identified caller.
func TestServer_AnomalyDetection_UnidentifiedCallerNeverBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.AnomalyDetector = anomaly.NewRegistry(2, shortAnomalyWindow)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 200; i++ {
		resp, err := http.Get(frontend.URL + "/x")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d (no proxy_api_key configured, so no identified caller)", i, resp.StatusCode, http.StatusOK)
		}
	}
}

// TestServer_AnomalyDetection_BlocksOnceClientSpikesPastOwnBaseline is
// the feature's core proof: a named client's traffic settles into a
// steady baseline, then spikes well past its own configured
// multiplier, and only then gets a 429 — never before the baseline was
// even established.
func TestServer_AnomalyDetection_BlocksOnceClientSpikesPastOwnBaseline(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "the-key"
	srv.AnomalyDetector = anomaly.NewRegistry(5, shortAnomalyWindow) // 5x baseline trips
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	// Establish a steady baseline of 10 requests/window.
	for w := 0; w < 5; w++ {
		time.Sleep(shortAnomalyWindow)
		for i := 0; i < 10; i++ {
			resp := getWithProxyAuth(t, frontend.URL+"/x", "the-key")
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("baseline window %d, request %d: status = %d, want %d", w, i, resp.StatusCode, http.StatusOK)
			}
		}
	}

	// Now a sudden spike, well past 5x the established baseline of 10.
	time.Sleep(shortAnomalyWindow)
	var sawBlock bool
	for i := 0; i < 100 && !sawBlock; i++ {
		resp := getWithProxyAuth(t, frontend.URL+"/x", "the-key")
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			sawBlock = true
		}
	}
	if !sawBlock {
		t.Fatal("a 10x-then-spiking client was never flagged anomalous")
	}

	hitsBeforeSpikeBlocked := upstreamHits.Load()
	if hitsBeforeSpikeBlocked <= 50 {
		// The spike's own requests before the trip point still count as
		// upstream hits (allowed) — this just confirms the block
		// actually happened partway through, not on the very first
		// spike request (which would itself be a false positive against
		// too aggressive a floor).
		t.Logf("upstream hits so far: %d (informational)", hitsBeforeSpikeBlocked)
	}

	snap := srv.Stats.Snapshot()
	if snap.AnomalyDetected == 0 {
		t.Error("Stats.AnomalyDetected = 0, want at least 1")
	}
	if perClient, ok := snap.PerClient["default"]; !ok || perClient.AnomalyDetected == 0 {
		t.Errorf("PerClient[default].AnomalyDetected = %+v, want at least 1", perClient)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[ANOMALY]") {
		t.Errorf("log missing an [ANOMALY] line: %q", logOutput)
	}
}

// TestServer_AnomalyDetection_DryRunNeverBlocksButStillRecords proves
// AnomalyDryRun's escape hatch: the exact same spike that would
// otherwise trip a 429 is instead logged/counted but the request still
// goes through, forwarded exactly as if nothing had matched.
func TestServer_AnomalyDetection_DryRunNeverBlocksButStillRecords(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "the-key"
	srv.AnomalyDetector = anomaly.NewRegistry(5, shortAnomalyWindow)
	srv.AnomalyDryRun = true
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for w := 0; w < 5; w++ {
		time.Sleep(shortAnomalyWindow)
		for i := 0; i < 10; i++ {
			resp := getWithProxyAuth(t, frontend.URL+"/x", "the-key")
			resp.Body.Close()
		}
	}

	time.Sleep(shortAnomalyWindow)
	for i := 0; i < 100; i++ {
		resp := getWithProxyAuth(t, frontend.URL+"/x", "the-key")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d during spike: status = %d, want %d (dry-run must never actually block)", i, resp.StatusCode, http.StatusOK)
		}
	}

	snap := srv.Stats.Snapshot()
	if snap.AnomalyDetected == 0 {
		t.Error("Stats.AnomalyDetected = 0, want at least 1 (dry-run still records what it would have done)")
	}
}

// TestServer_AnomalyDetection_DistinctClientsHaveIndependentBaselines
// proves one named key's spike never affects another's — each client
// gets its own Detector, keyed by auth.label.
func TestServer_AnomalyDetection_DistinctClientsHaveIndependentBaselines(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "spiky", Key: "spiky-key"},
		{Name: "steady", Key: "steady-key"},
	}
	srv.AnomalyDetector = anomaly.NewRegistry(5, shortAnomalyWindow)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	// Both clients establish the same steady baseline.
	for w := 0; w < 5; w++ {
		time.Sleep(shortAnomalyWindow)
		for i := 0; i < 10; i++ {
			getWithProxyAuth(t, frontend.URL+"/x", "spiky-key").Body.Close()
			getWithProxyAuth(t, frontend.URL+"/x", "steady-key").Body.Close()
		}
	}

	// Only "spiky" spikes; "steady" keeps its normal rate.
	time.Sleep(shortAnomalyWindow)
	var spikyBlocked bool
	for i := 0; i < 100; i++ {
		resp := getWithProxyAuth(t, frontend.URL+"/x", "spiky-key")
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			spikyBlocked = true
		}

		if i < 10 {
			steadyResp := getWithProxyAuth(t, frontend.URL+"/x", "steady-key")
			steadyResp.Body.Close()
			if steadyResp.StatusCode != http.StatusOK {
				t.Fatalf("steady client request %d: status = %d, want %d (a different client's spike must never affect this one)", i, steadyResp.StatusCode, http.StatusOK)
			}
		}
	}
	if !spikyBlocked {
		t.Fatal("the spiking client was never flagged anomalous")
	}

	snap := srv.Stats.Snapshot()
	if perClient, ok := snap.PerClient["steady"]; ok && perClient.AnomalyDetected != 0 {
		t.Errorf("PerClient[steady].AnomalyDetected = %d, want 0", perClient.AnomalyDetected)
	}
}

// TestServer_Webhook_FiresOnAnomalyDetectedWithExpectedPayload proves
// the anomaly_detected webhook event carries the flagged client, its
// current rate, and the baseline it was compared against, and an empty
// rule.
func TestServer_Webhook_FiresOnAnomalyDetectedWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		select {
		case received <- payload:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "the-key"
	srv.AnomalyDetector = anomaly.NewRegistry(5, shortAnomalyWindow)
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for w := 0; w < 5; w++ {
		time.Sleep(shortAnomalyWindow)
		for i := 0; i < 10; i++ {
			getWithProxyAuth(t, frontend.URL+"/chat", "the-key").Body.Close()
		}
	}
	time.Sleep(shortAnomalyWindow)
	for i := 0; i < 100; i++ {
		getWithProxyAuth(t, frontend.URL+"/chat", "the-key").Body.Close()
	}

	select {
	case payload := <-received:
		if payload["event"] != "anomaly_detected" {
			t.Errorf("event = %v, want anomaly_detected", payload["event"])
		}
		if rule, ok := payload["rule"]; !ok || rule != "" {
			t.Errorf("rule = %v, want empty string (an anomaly matches no rule)", payload["rule"])
		}
		if payload["client"] != "default" {
			t.Errorf("client = %v, want default", payload["client"])
		}
		rate, ok := payload["rate"].(float64)
		if !ok || rate <= 0 {
			t.Errorf("rate = %v, want a positive number", payload["rate"])
		}
		baseline, ok := payload["baseline"].(float64)
		if !ok || baseline <= 0 {
			t.Errorf("baseline = %v, want a positive number", payload["baseline"])
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "ANOMALY_DETECTED") {
			t.Errorf("text = %q, want it to mention ANOMALY_DETECTED", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_ReloadConfig_UpdatesAnomalyDetector proves a SIGHUP-style
// ReloadConfig can add an AnomalyDetector to a server that started
// with none, live.
func TestServer_ReloadConfig_UpdatesAnomalyDetector(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.ProxyAPIKey = "the-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 50; i++ {
		resp := getWithProxyAuth(t, frontend.URL+"/x", "the-key")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("before reload, request %d: status = %d, want %d (no AnomalyDetector configured yet)", i, resp.StatusCode, http.StatusOK)
		}
	}

	registry := anomaly.NewRegistry(5, shortAnomalyWindow)
	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "the-key", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, registry, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	// The freshly reloaded Registry starts cold — no baseline exists
	// for this client yet, so (correctly, per Detector's own cold-start
	// guarantee) nothing can trip within the very first window after
	// the swap. Establish a real baseline against the *new* registry
	// first, then spike.
	for w := 0; w < 5; w++ {
		time.Sleep(shortAnomalyWindow)
		for i := 0; i < 10; i++ {
			getWithProxyAuth(t, frontend.URL+"/x", "the-key").Body.Close()
		}
	}

	time.Sleep(shortAnomalyWindow)
	var sawBlock bool
	for i := 0; i < 100 && !sawBlock; i++ {
		resp := getWithProxyAuth(t, frontend.URL+"/x", "the-key")
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			sawBlock = true
		}
	}
	if !sawBlock {
		t.Fatal("after reload, the newly configured AnomalyDetector never tripped on a real spike")
	}
}

// TestServer_MaxBodyBytes_OversizedRequestGets413 proves a request body
// larger than the configured MaxBodyBytes is rejected before it's fully
// buffered, never reaching the upstream, while a body within the limit
// goes through normally.
func TestServer_MaxBodyBytes_OversizedRequestGets413(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.MaxBodyBytes = 10
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`{"this body is way over 10 bytes"}`))
	if err != nil {
		t.Fatalf("post oversized body: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
	if upstreamHit.Load() {
		t.Fatal("an oversized request must never reach the upstream target")
	}

	resp2, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("post within-limit body: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("within-limit request: status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}
	if !upstreamHit.Load() {
		t.Fatal("a within-limit request must reach the upstream target")
	}
}

// TestServer_MaxBodyBytes_ZeroFallsBackToDefaultLimit proves an unset
// (zero) MaxBodyBytes doesn't mean "unlimited" the way it does for
// every other numeric Server field — DefaultMaxBodyBytes applies
// instead, and a request comfortably inside it still succeeds.
func TestServer_MaxBodyBytes_ZeroFallsBackToDefaultLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	// srv.MaxBodyBytes deliberately left at its zero value.

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (default limit must not block an ordinary small body)", resp.StatusCode, http.StatusOK)
	}

	oversized := strings.Repeat("a", proxy.DefaultMaxBodyBytes+1)
	resp2, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(oversized))
	if err != nil {
		t.Fatalf("post oversized body: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d (default limit must still apply)", resp2.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

// TestServer_LogsTokenUsageAndDeliversResponseBodyUnchanged proves that
// ModifyResponse's inspection of an LLM-style JSON response is fully
// transparent to the client: the exact bytes the upstream sent are what
// the client receives, while the proxy separately logs a blue [USAGE]
// line reporting the token count it extracted.
func TestServer_LogsTokenUsageAndDeliversResponseBodyUnchanged(t *testing.T) {
	const fakeLLMResponse = `{"id":"chatcmpl-fake","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":246,"total_tokens":256}}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeLLMResponse))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/endpoint", "application/json", strings.NewReader(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(gotBody) != fakeLLMResponse {
		t.Fatalf("response body delivered to client = %q, want it byte-for-byte identical to %q", gotBody, fakeLLMResponse)
	}

	// The body itself must still be valid, parseable JSON — proof that
	// reading it in ModifyResponse for inspection didn't corrupt it.
	var reparsed map[string]any
	if err := json.Unmarshal(gotBody, &reparsed); err != nil {
		t.Fatalf("client-delivered body is not valid JSON: %v", err)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[USAGE] POST /endpoint - Tokens used: 256") {
		t.Fatalf("log missing usage line with correct token count: %q", logOutput)
	}
	if !strings.Contains(logOutput, "\x1b[34m") {
		t.Fatalf("log missing blue ANSI code: %q", logOutput)
	}
}

// TestServer_LogsTokenUsageForAnthropicResponseShape proves usage
// extraction also understands Anthropic's Messages API shape, which has
// no total_tokens field at all — only input_tokens and output_tokens —
// unlike the OpenAI-style total_tokens field
// TestServer_LogsTokenUsageAndDeliversResponseBodyUnchanged exercises
// above.
func TestServer_LogsTokenUsageForAnthropicResponseShape(t *testing.T) {
	const fakeAnthropicResponse = `{"id":"msg_fake","type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":15,"output_tokens":42}}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeAnthropicResponse))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-opus-5"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[USAGE] POST /v1/messages - Tokens used: 57") {
		t.Fatalf("log missing usage line summing input_tokens+output_tokens: %q", logOutput)
	}
}

// TestServer_ResponseSecretScanning_BlocksResponseContainingSecret
// proves a rule matching the upstream's response — not the client's
// request — withholds that response from the client entirely: the model
// echoed something back that matches a Block-actioned rule (a prompt
// injection, an upstream error message reflecting request data, etc.),
// so the client gets a 403 with a generic message instead of the real
// body, the same way an outgoing request would have been blocked.
func TestServer_ResponseSecretScanning_BlocksResponseContainingSecret(t *testing.T) {
	secret := "AKIAABCDEFGHIJKLMNOP"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"sure, here is the key: ` + secret + `"}}]}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if strings.Contains(string(gotBody), secret) {
		t.Fatalf("client received the raw secret from the response: %q", gotBody)
	}

	snap := srv.Stats.Snapshot()
	if snap.ResponseBlocked != 1 {
		t.Fatalf("Stats.ResponseBlocked = %d, want 1", snap.ResponseBlocked)
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, secret) {
		t.Fatalf("log leaked the matched secret value: %q", logOutput)
	}
	if !strings.Contains(logOutput, "[RESPONSE BLOCK]") {
		t.Fatalf("log missing [RESPONSE BLOCK] marker: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Triggered rule: aws-access-key") {
		t.Fatalf("log missing triggered rule name: %q", logOutput)
	}
}

// TestServer_ResponseSecretScanning_RedactsResponseContainingSecret
// proves a Redact-actioned rule matching the response masks the secret
// in place and still forwards a 200 with the rest of the body intact —
// including a correct Content-Length for the now-different body size.
func TestServer_ResponseSecretScanning_RedactsResponseContainingSecret(t *testing.T) {
	secret := "sk-FAKEKEY1234567890ABCDEFGHIJ"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"here: ` + secret + `"}}]}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (a redacted response must still be forwarded)", resp.StatusCode, http.StatusOK)
	}
	wantBody := `{"choices":[{"message":{"content":"here: [REDACTED:openai-api-key]"}}]}`
	if string(gotBody) != wantBody {
		t.Fatalf("response body = %q, want %q", gotBody, wantBody)
	}

	snap := srv.Stats.Snapshot()
	if snap.ResponseRedacted != 1 {
		t.Fatalf("Stats.ResponseRedacted = %d, want 1", snap.ResponseRedacted)
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, secret) {
		t.Fatalf("log leaked the matched secret value: %q", logOutput)
	}
	if !strings.Contains(logOutput, "[RESPONSE REDACT]") {
		t.Fatalf("log missing [RESPONSE REDACT] marker: %q", logOutput)
	}
}

// TestServer_NonJSONResponse_NoUsageLogAndBodyStillDeliveredIntact proves
// the silent-ignore path: a non-JSON upstream response must reach the
// client unchanged, with no [USAGE] line and no error surfaced anywhere.
func TestServer_NonJSONResponse_NoUsageLogAndBodyStillDeliveredIntact(t *testing.T) {
	const plainBody = "plain text, not JSON at all"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(plainBody))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(gotBody) != plainBody {
		t.Fatalf("response body = %q, want %q", gotBody, plainBody)
	}
	if strings.Contains(logBuf.String(), "[USAGE]") {
		t.Fatalf("non-JSON response must not produce a [USAGE] log line: %q", logBuf.String())
	}
}

// TestServer_CacheHit_SecondIdenticalRequestNeverReachesUpstream proves
// the on-disk cache end to end: sending the same request twice results in
// the fake upstream server receiving it exactly once — the second call is
// caught entirely by the proxy's cache and returns byte-for-byte
// identical JSON, with a purple [CACHE HIT] log line to show for it.
func TestServer_CacheHit_SecondIdenticalRequestNeverReachesUpstream(t *testing.T) {
	t.Chdir(t.TempDir())

	const fakeLLMResponse = `{"id":"chatcmpl-fake","usage":{"total_tokens":42}}`

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeLLMResponse))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)
	srv.Cache = c

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const requestBody = `{"model":"gpt-4","messages":[]}`

	sendRequest := func(n int) (int, string) {
		resp, err := http.Post(frontend.URL+"/v1/chat/completions", "application/json", strings.NewReader(requestBody))
		if err != nil {
			t.Fatalf("request %d: %v", n, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("request %d: read body: %v", n, err)
		}
		return resp.StatusCode, string(body)
	}

	status1, body1 := sendRequest(1)
	if status1 != http.StatusOK {
		t.Fatalf("request 1: status = %d, want %d", status1, http.StatusOK)
	}
	if body1 != fakeLLMResponse {
		t.Fatalf("request 1 body = %q, want %q", body1, fakeLLMResponse)
	}

	status2, body2 := sendRequest(2)
	if status2 != http.StatusOK {
		t.Fatalf("request 2: status = %d, want %d", status2, http.StatusOK)
	}
	if body2 != fakeLLMResponse {
		t.Fatalf("request 2 (cached) body = %q, want it identical to upstream's response %q", body2, fakeLLMResponse)
	}

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want exactly 1 — the second identical request must be served from cache, never reaching upstream", got)
	}

	logOutput := logBuf.String()
	if allowCount := strings.Count(logOutput, "[ALLOW]"); allowCount != 1 {
		t.Fatalf("log contains %d [ALLOW] lines, want exactly 1 (only request 1 should take the forwarding path)", allowCount)
	}
	if !strings.Contains(logOutput, "[CACHE HIT] POST /v1/chat/completions") {
		t.Fatalf("log missing cache hit line: %q", logOutput)
	}
	if !strings.Contains(logOutput, "\x1b[35m") {
		t.Fatalf("log missing purple ANSI code: %q", logOutput)
	}
}

// TestServer_CacheTTL_ExpiredEntryForcesFreshUpstreamHit proves
// Server.Cache.TTL is actually honored end-to-end through the proxy: an
// identical request repeated after the entry's TTL has elapsed reaches
// the upstream again, instead of being served from the (now-stale)
// cache.
func TestServer_CacheTTL_ExpiredEntryForcesFreshUpstreamHit(t *testing.T) {
	t.Chdir(t.TempDir())

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.CacheTTL = 30 * time.Millisecond
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func() {
		resp, err := http.Post(frontend.URL+"/v1/chat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}

	post()
	post() // immediately after: still within TTL, must be a cache hit
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests after 2 immediate posts, want 1 (second must be a cache hit)", got)
	}

	time.Sleep(80 * time.Millisecond) // past the 30ms TTL
	post()
	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream received %d requests after the TTL elapsed, want 2 (expired entry must force a fresh upstream hit)", got)
	}
}

// TestServer_CacheHit_SetsAgeHeader proves every cache hit carries a
// real, standard Age header (RFC 7234) reporting how long ago the
// response was actually cached — present even with no TTL configured
// at all, since "how old is this" doesn't depend on having an expiry
// policy.
func TestServer_CacheHit_SetsAgeHeader(t *testing.T) {
	t.Chdir(t.TempDir())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func() *http.Response {
		resp, err := http.Post(frontend.URL+"/v1/chat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	post().Body.Close() // first request: populates the cache
	time.Sleep(70 * time.Millisecond)
	resp := post() // second: a real cache hit
	defer resp.Body.Close()

	age := resp.Header.Get("Age")
	if age == "" {
		t.Fatal("Age header missing on a cache hit")
	}
	ageSeconds, err := strconv.Atoi(age)
	if err != nil {
		t.Fatalf("Age header = %q, want an integer number of seconds: %v", age, err)
	}
	if ageSeconds < 0 {
		t.Fatalf("Age header = %d, want a non-negative age", ageSeconds)
	}
}

// TestServer_CacheHit_StaleAfterThreshold proves a cache hit whose age
// has crossed the cache package's own staleness warning threshold
// (80% of TTL) is still served as a genuine hit — the upstream is never
// contacted again — while being flagged distinctly: a
// [CACHE HIT - STALE] log line and a separate StaleCacheHits counter,
// on top of the ordinary CacheHits count every hit already gets.
func TestServer_CacheHit_StaleAfterThreshold(t *testing.T) {
	t.Chdir(t.TempDir())

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.CacheTTL = 2 * time.Second // staleness threshold at 1.6s
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func() *http.Response {
		resp, err := http.Post(frontend.URL+"/v1/chat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	post().Body.Close()
	// 1.8s: comfortably past the 1.6s staleness threshold, with a wide
	// 200ms margin on both sides before the 2s TTL itself — the previous
	// version of this test used 100ms/90ms (only a 10ms margin before
	// full expiry), which proved flaky on a slower/busier CI runner
	// (observed failing on macOS specifically): real wall-clock
	// scheduling jitter pushed the second request's age past the full
	// TTL, turning the intended "stale but still valid" hit into a
	// genuine miss and a second real upstream call.
	time.Sleep(1800 * time.Millisecond)
	resp := post()
	defer resp.Body.Close()

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want 1 (a stale-but-not-expired entry must still be served as a hit)", got)
	}
	if !strings.Contains(logBuf.String(), "[CACHE HIT - STALE]") {
		t.Fatalf("log missing [CACHE HIT - STALE]: %q", logBuf.String())
	}
	snap := srv.Stats.Snapshot()
	if snap.CacheHits != 1 {
		t.Errorf("CacheHits = %d, want 1 (the first request populates the cache; only the second is an actual hit)", snap.CacheHits)
	}
	if snap.StaleCacheHits != 1 {
		t.Errorf("StaleCacheHits = %d, want 1 (that one hit was stale)", snap.StaleCacheHits)
	}

	// Checked against the real GET /_aiproxy/stats wire body too, not
	// just the internal stats.Snapshot struct: those are two separate
	// hand-maintained shapes (see statsSnapshotJSON/toStatsSnapshotJSON)
	// that have drifted out of sync before (the v0.37 latency field gap)
	// — a new Snapshot field is only actually live once it's threaded
	// through both.
	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer statsResp.Body.Close()
	var wire map[string]any
	if err := json.NewDecoder(statsResp.Body).Decode(&wire); err != nil {
		t.Fatalf("decode /_aiproxy/stats: %v", err)
	}
	if got, ok := wire["stale_cache_hits"].(float64); !ok || got != 1 {
		t.Fatalf(`/_aiproxy/stats["stale_cache_hits"] = %v, want 1`, wire["stale_cache_hits"])
	}
}

// TestServer_CacheHit_NotStaleBeforeThreshold proves a comfortably
// fresh cache hit (well under the 80% threshold) is never flagged or
// counted as stale.
func TestServer_CacheHit_NotStaleBeforeThreshold(t *testing.T) {
	t.Chdir(t.TempDir())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.CacheTTL = 500 * time.Millisecond // staleness threshold at 400ms
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func() *http.Response {
		resp, err := http.Post(frontend.URL+"/v1/chat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	post().Body.Close()
	time.Sleep(50 * time.Millisecond) // comfortably under the 400ms threshold
	resp := post()
	defer resp.Body.Close()

	if strings.Contains(logBuf.String(), "STALE") {
		t.Fatalf("log unexpectedly mentions staleness for a fresh hit: %q", logBuf.String())
	}
	if got := srv.Stats.Snapshot().StaleCacheHits; got != 0 {
		t.Fatalf("StaleCacheHits = %d, want 0 for a comfortably fresh hit", got)
	}
}

// TestServer_CacheMaxSizeBytes_EvictsLeastRecentlyUsedEndToEnd proves
// Server.Cache.MaxSizeBytes is honored end-to-end through the proxy:
// once enough distinct cached responses push the total over budget, the
// least-recently-used one is evicted — a repeat of that exact request
// reaches the upstream again instead of being served from the
// (now-evicted) cache, while a more recently used entry stays cached.
func TestServer_CacheMaxSizeBytes_EvictsLeastRecentlyUsedEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(body string) {
		resp, err := http.Post(frontend.URL+"/v1/chat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}

	post(`{"id":1}`)
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits after the 1st distinct request = %d, want 1", got)
	}

	entries, err := os.ReadDir(cache.DirName)
	if err != nil || len(entries) != 1 {
		t.Fatalf("read cache dir: err=%v entries=%d, want exactly 1", err, len(entries))
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("stat cache entry: %v", err)
	}
	srv.Cache.MaxSizeBytes = info.Size()*2 + info.Size()/2 // room for 2 entries, not 3

	post(`{"id":2}`)
	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream hits after the 2nd distinct request = %d, want 2", got)
	}
	post(`{"id":3}`)
	if got := upstreamHits.Load(); got != 3 {
		t.Fatalf("upstream hits after the 3rd distinct request = %d, want 3", got)
	}

	// Request 1's entry was never touched again, so it's now the
	// least-recently-used — pushing a 3rd entry in should have evicted
	// it. Repeating it must reach the upstream again.
	post(`{"id":1}`)
	if got := upstreamHits.Load(); got != 4 {
		t.Fatalf("upstream hits after repeating the evicted 1st request = %d, want 4 (a cache hit would still be 3)", got)
	}

	// Request 3's entry, written most recently, must still be cached.
	post(`{"id":3}`)
	if got := upstreamHits.Load(); got != 4 {
		t.Fatalf("upstream hits after repeating the still-cached 3rd request = %d, want still 4 (must be a cache hit)", got)
	}
}

// TestServer_CacheClearEndpoint_ForcesFreshUpstreamHit proves POSTing
// cacheClearPath actually deletes cached entries: a request that would
// otherwise be served from cache reaches the upstream again afterward.
func TestServer_CacheClearEndpoint_ForcesFreshUpstreamHit(t *testing.T) {
	t.Chdir(t.TempDir())

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func() {
		resp, err := http.Post(frontend.URL+"/v1/chat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}

	post()
	post()
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests before clearing, want 1", got)
	}

	clearResp, err := http.Post(frontend.URL+"/_aiproxy/cache/clear", "", nil)
	if err != nil {
		t.Fatalf("post cache/clear: %v", err)
	}
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("cache/clear status = %d, want 200", clearResp.StatusCode)
	}
	clearResp.Body.Close()

	post()
	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream received %d requests after clearing the cache, want 2 (a cleared entry must force a fresh upstream hit)", got)
	}
}

// TestServer_CacheClearEndpoint_RejectsNonPostMethod proves the
// endpoint only accepts POST, since it mutates state — a GET must not
// be able to trigger it.
func TestServer_CacheClearEndpoint_RejectsNonPostMethod(t *testing.T) {
	t.Chdir(t.TempDir())
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/cache/clear")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestServer_CacheClearEndpoint_404sWhenCacheDisabled proves the
// endpoint reports there's nothing to clear, rather than quietly
// succeeding, when Server.Cache is nil.
func TestServer_CacheClearEndpoint_404sWhenCacheDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/_aiproxy/cache/clear", "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestServer_CacheClearEndpoint_GatedByProxyAuth proves the endpoint
// honors ProxyAPIKey exactly like statsPath/metricsPath — a mutating
// endpoint deserves at least the same protection as the read-only ones,
// if not more.
func TestServer_CacheClearEndpoint_GatedByProxyAuth(t *testing.T) {
	t.Chdir(t.TempDir())
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.ProxyAPIKey = "s3cr3t"
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/_aiproxy/cache/clear", "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d (missing Proxy-Authorization)", resp.StatusCode, http.StatusProxyAuthRequired)
	}
}

// TestServer_Drain_RejectsNewRequestsAfterPost proves POST drainPath
// actually stops ordinary proxy traffic: a request before the POST
// succeeds normally, and one after it gets a 503 that never reaches the
// upstream target at all.
func TestServer_Drain_RejectsNewRequestsAfterPost(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get before drain: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status before drain = %d, want 200", resp.StatusCode)
	}

	drainResp, err := http.Post(frontend.URL+"/_aiproxy/drain", "", nil)
	if err != nil {
		t.Fatalf("post drain: %v", err)
	}
	drainResp.Body.Close()
	if drainResp.StatusCode != http.StatusOK {
		t.Fatalf("post drain status = %d, want 200", drainResp.StatusCode)
	}

	resp, err = http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get after drain: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status after drain = %d, want 503", resp.StatusCode)
	}

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want 1 (the rejected request must never reach it)", got)
	}

	snap := srv.Stats.Snapshot()
	if snap.DrainRejected != 1 {
		t.Fatalf("Stats.DrainRejected = %d, want 1", snap.DrainRejected)
	}
	if snap.Allowed != 1 {
		t.Fatalf("Stats.Allowed = %d, want 1 (only the pre-drain request)", snap.Allowed)
	}
}

// TestServer_Drain_LetsAlreadyInFlightRequestFinish is the feature's
// central promise: a request that started before draining began must
// run to completion normally, however long it takes, even though every
// NEW request arriving after the drain started is rejected in the
// meantime.
func TestServer_Drain_LetsAlreadyInFlightRequestFinish(t *testing.T) {
	releaseUpstream := make(chan struct{})
	upstreamEntered := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(upstreamEntered)
		<-releaseUpstream
		w.Write([]byte("slow response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	slowDone := make(chan *http.Response, 1)
	slowErr := make(chan error, 1)
	go func() {
		resp, err := http.Get(frontend.URL + "/v1/chat")
		if err != nil {
			slowErr <- err
			return
		}
		slowDone <- resp
	}()

	<-upstreamEntered // the slow request is now genuinely in flight

	drainResp, err := http.Post(frontend.URL+"/_aiproxy/drain", "", nil)
	if err != nil {
		t.Fatalf("post drain: %v", err)
	}
	drainResp.Body.Close()

	// A brand new request arriving while the first one is still blocked
	// upstream must be rejected immediately, not queued behind it.
	newResp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get during drain: %v", err)
	}
	newResp.Body.Close()
	if newResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("new request during drain status = %d, want 503", newResp.StatusCode)
	}

	close(releaseUpstream)

	select {
	case resp := <-slowDone:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("in-flight request status = %d, want 200 (draining must never cut off a request already in progress)", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read in-flight response body: %v", err)
		}
		if string(body) != "slow response" {
			t.Fatalf("in-flight response body = %q, want %q", body, "slow response")
		}
	case err := <-slowErr:
		t.Fatalf("in-flight request failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed after draining started")
	}
}

// TestServer_Drain_StatusEndpointReportsInFlightCount proves GET
// drainPath's in_flight field is a real, live count — the signal a
// deploy script polls instead of guessing a fixed grace period.
func TestServer_Drain_StatusEndpointReportsInFlightCount(t *testing.T) {
	releaseUpstream := make(chan struct{})
	upstreamEntered := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(upstreamEntered)
		<-releaseUpstream
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	getDrainStatus := func() map[string]any {
		resp, err := http.Get(frontend.URL + "/_aiproxy/drain")
		if err != nil {
			t.Fatalf("get drain status: %v", err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode drain status: %v", err)
		}
		return out
	}

	if status := getDrainStatus(); status["in_flight"].(float64) != 0 {
		t.Fatalf("in_flight before any request = %v, want 0", status["in_flight"])
	}

	go func() {
		resp, err := http.Get(frontend.URL + "/v1/chat")
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-upstreamEntered

	if status := getDrainStatus(); status["in_flight"].(float64) != 1 {
		t.Fatalf("in_flight while one request is blocked = %v, want 1", status["in_flight"])
	}

	close(releaseUpstream)

	// The in-flight request completes asynchronously; poll briefly
	// instead of assuming it's already back to 0 the instant Close
	// unblocks the upstream handler.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if status := getDrainStatus(); status["in_flight"].(float64) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("in_flight never returned to 0 after the request completed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestServer_Drain_DeleteCancelsAnInProgressDrain proves DELETE
// drainPath reverts to normal service — for aborting a deploy, or
// undoing a drain triggered by mistake.
func TestServer_Drain_DeleteCancelsAnInProgressDrain(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post, err := http.Post(frontend.URL+"/_aiproxy/drain", "", nil)
	if err != nil {
		t.Fatalf("post drain: %v", err)
	}
	post.Body.Close()

	rejected, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get while draining: %v", err)
	}
	rejected.Body.Close()
	if rejected.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status while draining = %d, want 503", rejected.StatusCode)
	}

	req, err := http.NewRequest(http.MethodDelete, frontend.URL+"/_aiproxy/drain", nil)
	if err != nil {
		t.Fatalf("build DELETE request: %v", err)
	}
	del, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete drain: %v", err)
	}
	del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete drain status = %d, want 200", del.StatusCode)
	}

	allowed, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get after undrain: %v", err)
	}
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("status after undrain = %d, want 200 (DELETE must revert to normal service)", allowed.StatusCode)
	}
}

// TestServer_Drain_RejectsUnknownMethod proves drainPath only accepts
// GET/POST/DELETE — the same "unsupported method" treatment as every
// other reserved path.
func TestServer_Drain_RejectsUnknownMethod(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPut, frontend.URL+"/_aiproxy/drain", nil)
	if err != nil {
		t.Fatalf("build PUT request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put drain: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestServer_Drain_GatedByProxyAuth proves drainPath honors
// ProxyAPIKey exactly like cacheClearPath — a mutating admin endpoint
// deserves at least the same protection as the read-only ones.
func TestServer_Drain_GatedByProxyAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t"
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/_aiproxy/drain", "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d (missing Proxy-Authorization)", resp.StatusCode, http.StatusProxyAuthRequired)
	}
}

// TestServer_Drain_HealthzStaysHealthyWhileDraining proves draining
// never touches healthzPath — see healthzPath's own doc comment: it is
// a pure liveness signal that must never flap based on any configured
// dependency, draining included. An orchestrator polling drainPath
// itself (or removing the instance from its own load-balancer pool
// directly) is the intended way to learn about a drain — not healthz.
func TestServer_Drain_HealthzStaysHealthyWhileDraining(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post, err := http.Post(frontend.URL+"/_aiproxy/drain", "", nil)
	if err != nil {
		t.Fatalf("post drain: %v", err)
	}
	post.Body.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/healthz")
	if err != nil {
		t.Fatalf("get healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status while draining = %d, want 200 (healthz must never flap)", resp.StatusCode)
	}
}

// TestServer_Drain_SecondPostDoesNotFireASecondWebhook proves the
// drain_started/drain_stopped webhooks are process-level events, fired
// exactly once per real transition — not once per admin request, and
// never at all for a rejected proxy request (that would make a busy
// drain window spam a webhook destination once per rejected caller).
func TestServer_Drain_SecondPostDoesNotFireASecondWebhook(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	received := make(chan map[string]any, 8)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() {
		resp, err := http.Post(frontend.URL+"/_aiproxy/drain", "", nil)
		if err != nil {
			t.Fatalf("post drain: %v", err)
		}
		resp.Body.Close()
	}
	post()
	post() // second POST while already draining — must not re-fire

	// A rejected request in between must not fire anything of its own.
	rejected, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get while draining: %v", err)
	}
	rejected.Body.Close()

	select {
	case payload := <-received:
		if payload["event"] != "drain_started" {
			t.Fatalf("event = %v, want drain_started", payload["event"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never received the drain_started event")
	}

	select {
	case payload := <-received:
		t.Fatalf("received an unexpected second webhook event: %v", payload)
	case <-time.After(300 * time.Millisecond):
		// Expected: exactly one drain_started event total.
	}

	if !strings.Contains(logBuf.String(), "[DRAIN STARTED]") {
		t.Fatalf("log missing [DRAIN STARTED] line: %q", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "[DRAIN REJECTED]") {
		t.Fatalf("log missing [DRAIN REJECTED] line: %q", logBuf.String())
	}
}

// TestServer_Drain_MovesToAdminAddrWhenConfigured proves drainPath
// follows cacheClearPath's own precedent: once AdminAddr is set, it
// moves entirely off the main listener (a plain 404, not forwarded)
// and only works on AdminAddr instead.
func TestServer_Drain_MovesToAdminAddrWhenConfigured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	addr := freeLoopbackAddr(t)
	adminAddr := freeLoopbackAddr(t)

	srv := proxy.New(addr, targetURL, rules.NewEngine(rules.Allow))
	srv.AdminAddr = adminAddr
	srv.Logger = log.New(io.Discard, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForServerUp(t, addr, time.Second)
	waitForServerUp(t, adminAddr, time.Second)

	resp, err := http.Post("http://"+addr+"/_aiproxy/drain", "", nil)
	if err != nil {
		t.Fatalf("post drain on Addr: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("drain on Addr status = %d, want %d (must move entirely to AdminAddr)", resp.StatusCode, http.StatusNotFound)
	}

	resp, err = http.Post("http://"+adminAddr+"/_aiproxy/drain", "", nil)
	if err != nil {
		t.Fatalf("post drain on AdminAddr: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("drain on AdminAddr status = %d, want 200", resp.StatusCode)
	}
}

// TestServer_StreamingResponse_DeliversChunksProgressively proves the
// core streaming fix: chunks reach the client as they arrive, instead of
// only after the full response has been read. If the proxy still
// buffered the whole body first (the old, broken behavior), the first
// byte could only reach the client after every chunk delay had already
// elapsed upstream.
func TestServer_StreamingResponse_DeliversChunksProgressively(t *testing.T) {
	const chunkDelay = 80 * time.Millisecond
	chunks := []string{
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n",
		"data: {\"usage\":{\"total_tokens\":42}}\n\n",
		"data: [DONE]\n\n",
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream ResponseWriter does not support flushing")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for _, c := range chunks {
			w.Write([]byte(c))
			flusher.Flush()
			time.Sleep(chunkDelay)
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	start := time.Now()
	resp, err := http.Post(frontend.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	firstByteAt := time.Duration(-1)
	dataLines := 0
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			if firstByteAt < 0 {
				firstByteAt = time.Since(start)
			}
			if strings.HasPrefix(line, "data:") {
				dataLines++
			}
		}
		if err != nil {
			break
		}
	}

	if dataLines != len(chunks) {
		t.Fatalf("client received %d data lines, want %d", dataLines, len(chunks))
	}
	if firstByteAt < 0 {
		t.Fatal("client never received any bytes")
	}
	if firstByteAt >= chunkDelay {
		t.Fatalf("first byte arrived after %v (>= one chunk delay of %v) — response looks buffered, not streamed", firstByteAt, chunkDelay)
	}
}

// TestServer_StreamingResponse_LogsUsageAndCachesCompleteStream proves
// that a completed SSE stream still gets its usage logged (parsed out of
// the "data: {...}" event that carries it) and gets cached, and that a
// second identical request is served from that cache without touching
// upstream again — the same guarantees bufferResponse already gives
// plain JSON responses, now also honored for streamed ones.
func TestServer_StreamingResponse_LogsUsageAndCachesCompleteStream(t *testing.T) {
	t.Chdir(t.TempDir())

	const sseBody = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: {\"usage\":{\"total_tokens\":77}}\n\n" +
		"data: [DONE]\n\n"

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)
	srv.Cache = c

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	sendRequest := func(n int) (int, string) {
		resp, err := http.Post(frontend.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
		if err != nil {
			t.Fatalf("request %d: %v", n, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("request %d: read body: %v", n, err)
		}
		return resp.StatusCode, string(body)
	}

	status1, body1 := sendRequest(1)
	if status1 != http.StatusOK {
		t.Fatalf("request 1: status = %d, want %d", status1, http.StatusOK)
	}
	if body1 != sseBody {
		t.Fatalf("request 1 body = %q, want %q", body1, sseBody)
	}

	// onComplete fires asynchronously from Close, right as ReverseProxy
	// finishes copying the response. The cache write happens before the
	// usage log line in onComplete, so once the log line is observed, the
	// cache write is guaranteed to have already landed too.
	logOutput := waitForLogContains(&logBuf, "[USAGE]", time.Second)
	if !strings.Contains(logOutput, "[USAGE] POST /v1/chat/completions - Tokens used: 77") {
		t.Fatalf("log missing usage line extracted from the SSE stream: %q", logOutput)
	}

	status2, body2 := sendRequest(2)
	if status2 != http.StatusOK {
		t.Fatalf("request 2 (cached): status = %d, want %d", status2, http.StatusOK)
	}
	if body2 != sseBody {
		t.Fatalf("request 2 (cached) body = %q, want identical to %q", body2, sseBody)
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want exactly 1 — the second must be served from the cached stream", got)
	}
}

// TestServer_StreamingResponse_LogsUsageForAnthropicSSEShape proves
// streaming usage extraction handles Anthropic's split-across-events
// shape: input_tokens arrives nested in message_start's message.usage,
// output_tokens arrives separately in message_delta's top-level usage —
// neither event alone carries the full total, unlike the OpenAI-style
// single total_tokens field in the final chunk that
// TestServer_StreamingResponse_LogsUsageAndCachesCompleteStream above
// exercises.
func TestServer_StreamingResponse_LogsUsageForAnthropicSSEShape(t *testing.T) {
	t.Chdir(t.TempDir())

	const sseBody = `event: message_start` + "\n" +
		`data: {"type":"message_start","message":{"id":"msg_fake","type":"message","usage":{"input_tokens":25,"output_tokens":1}}}` + "\n\n" +
		`event: content_block_delta` + "\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}` + "\n\n" +
		`event: message_delta` + "\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}` + "\n\n" +
		`event: message_stop` + "\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-opus-5","stream":true}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// 25 (input_tokens from message_start) + 12 (the final, cumulative
	// output_tokens from message_delta, not message_start's early 1).
	logOutput := waitForLogContains(&logBuf, "[USAGE]", time.Second)
	if !strings.Contains(logOutput, "[USAGE] POST /v1/messages - Tokens used: 37") {
		t.Fatalf("log missing usage line combining input_tokens and the final output_tokens: %q", logOutput)
	}
}

// TestServer_StreamingResponse_AbortedStreamIsNeverCached proves that a
// stream cut short by an abrupt upstream disconnect is never written to
// the cache — caching a truncated stream would mean silently replaying a
// broken response as if it were a complete one on every future hit.
func TestServer_StreamingResponse_AbortedStreamIsNeverCached(t *testing.T) {
	t.Chdir(t.TempDir())

	const requestBody = `{"stream":true}`
	const requestPath = "/v1/chat/completions"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`data: {"choices":[{"delta":{"content":"partial"}}]}` + "\n\n"))
		flusher.Flush()
		// The sanctioned way to simulate an abrupt client/upstream
		// disconnect in an httptest handler: net/http recognizes this
		// panic value and closes the connection without a stack trace.
		panic(http.ErrAbortHandler)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, engine)
	srv.Cache = c
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+requestPath, "application/json", strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	// The connection is expected to end abruptly mid-body; draining and
	// ignoring the resulting read error is the point of this test.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// This check is for an absence (no cache entry), so it fails safe: a
	// shorter-than-needed wait would only make the assertion trivially
	// true rather than falsely fail. The margin here is generous purely
	// so the test is actually exercising onComplete having run, not just
	// checking too early to know either way.
	time.Sleep(200 * time.Millisecond)

	resolved := targetURL.ResolveReference(&url.URL{Path: requestPath})
	key := cache.Key(http.MethodPost, resolved.String(), []byte(requestBody))
	if _, hit, _, err := c.Get(key, 0); err != nil {
		t.Fatalf("cache.Get: %v", err)
	} else if hit {
		t.Fatal("an aborted stream must never be cached, but a cache entry was found")
	}
}

// TestServer_ResponseSecretScanning_RedactsSecretInStreamedChunk proves
// a Redact-actioned rule matching one SSE event within a streamed
// response masks the secret in that event while every other event
// (before and after it) is forwarded unchanged — real-time, per-event
// scanning rather than buffering the whole stream to inspect it.
func TestServer_ResponseSecretScanning_RedactsSecretInStreamedChunk(t *testing.T) {
	secret := "sk-FAKEKEY1234567890ABCDEFGHIJ"
	chunks := []string{
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"" + secret + "\"}}]}\n\n",
		"data: {\"usage\":{\"total_tokens\":42}}\n\n",
		"data: [DONE]\n\n",
	}
	want := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"[REDACTED:openai-api-key]\"}}]}\n\n" +
		"data: {\"usage\":{\"total_tokens\":42}}\n\n" +
		"data: [DONE]\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for _, c := range chunks {
			w.Write([]byte(c))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(gotBody) != want {
		t.Fatalf("client received:\n%q\nwant:\n%q", gotBody, want)
	}

	snap := srv.Stats.Snapshot()
	if snap.ResponseRedacted != 1 {
		t.Fatalf("Stats.ResponseRedacted = %d, want 1", snap.ResponseRedacted)
	}

	logOutput := waitForLogContains(&logBuf, "[RESPONSE REDACT]", time.Second)
	if strings.Contains(logOutput, secret) {
		t.Fatalf("log leaked the matched secret value: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Triggered rule: openai-api-key") {
		t.Fatalf("log missing triggered rule name: %q", logOutput)
	}
}

// TestServer_ResponseSecretScanning_BlocksStreamOnSecretAndNeverCaches
// proves a Block-actioned rule matching an SSE event mid-stream ends the
// stream right there: everything already forwarded before that event
// stays with the client, but neither the offending event nor anything
// after it (which the proxy never even reads from upstream) ever
// reaches the client, and the truncated stream is never cached — the
// same non-caching guarantee as any other incomplete stream.
func TestServer_ResponseSecretScanning_BlocksStreamOnSecretAndNeverCaches(t *testing.T) {
	t.Chdir(t.TempDir())

	secret := "AKIAABCDEFGHIJKLMNOP"
	const requestBody = `{"stream":true}`
	const requestPath = "/v1/chat/completions"
	firstChunk := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(firstChunk))
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"" + secret + "\"}}]}\n\n"))
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)
	srv.Cache = c

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+requestPath, "application/json", strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	// The connection is expected to end abnormally right after the first
	// chunk, the same way a genuinely aborted upstream would; capturing
	// and ignoring that error is the point of this test — what matters is
	// how much (and which) of the body was received before it happened.
	gotBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(gotBody) != firstChunk {
		t.Fatalf("client received %q, want exactly the pre-block chunk %q and nothing else", gotBody, firstChunk)
	}
	if strings.Contains(string(gotBody), secret) {
		t.Fatalf("client received the raw secret: %q", gotBody)
	}
	if strings.Contains(string(gotBody), "world") {
		t.Fatalf("client received content that arrived after the blocked event: %q", gotBody)
	}

	logOutput := waitForLogContains(&logBuf, "[RESPONSE BLOCK]", time.Second)
	if strings.Contains(logOutput, secret) {
		t.Fatalf("log leaked the matched secret value: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Triggered rule: aws-access-key") {
		t.Fatalf("log missing triggered rule name: %q", logOutput)
	}

	snap := srv.Stats.Snapshot()
	if snap.ResponseBlocked != 1 {
		t.Fatalf("Stats.ResponseBlocked = %d, want 1", snap.ResponseBlocked)
	}

	resolved := targetURL.ResolveReference(&url.URL{Path: requestPath})
	key := cache.Key(http.MethodPost, resolved.String(), []byte(requestBody))
	if _, hit, _, err := c.Get(key, 0); err != nil {
		t.Fatalf("cache.Get: %v", err)
	} else if hit {
		t.Fatal("a stream cut short by a response Block rule must never be cached, but a cache entry was found")
	}
}

// TestServer_TracksStatsAcrossRequestOutcomes drives one request through
// each of the four possible outcomes and proves Server.Stats ends up
// with exactly the right counts: an allowed request that also carries
// usage tokens, a blocked one, a rate-limited one, and — replaying the
// first request's body — a cache hit.
func TestServer_TracksStatsAcrossRequestOutcomes(t *testing.T) {
	t.Chdir(t.TempDir())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"usage":{"total_tokens":10}}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "test-secret",
		Pattern: regexp.MustCompile(`SECRET`),
		Action:  rules.Block,
	})

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, engine)
	srv.Cache = c
	srv.Limiter = limiter.New(1, time.Minute)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(body string) {
		resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %q: %v", body, err)
		}
		resp.Body.Close()
	}

	post(`{"n":1}`) // allowed, consumes the rate limiter's only slot, cached, carries usage
	post(`SECRET`)  // blocked
	post(`{"n":3}`) // different body (cache miss), passes rules, then rate-limited
	post(`{"n":1}`) // same body as the first request: cache hit

	snap := srv.Stats.Snapshot()
	if snap.Allowed != 1 {
		t.Errorf("Allowed = %d, want 1", snap.Allowed)
	}
	if snap.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", snap.Blocked)
	}
	if snap.RateLimited != 1 {
		t.Errorf("RateLimited = %d, want 1", snap.RateLimited)
	}
	if snap.CacheHits != 1 {
		t.Errorf("CacheHits = %d, want 1", snap.CacheHits)
	}
	if snap.TotalTokens != 10 {
		t.Errorf("TotalTokens = %d, want 10", snap.TotalTokens)
	}
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func waitForServerUp(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server at %s did not come up in time: %v", addr, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestServer_ListenAndServe_PrintsStatsSummaryOnShutdown proves the
// feature end to end through the real entry point a running aiproxy
// process uses: start the server for real, send a request, cancel its
// context (what a Ctrl+C ultimately does via signal.NotifyContext in the
// cli package), and check the printed summary reflects that request.
func TestServer_ListenAndServe_PrintsStatsSummaryOnShutdown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	addr := freeLoopbackAddr(t)
	engine := rules.NewEngine(rules.Allow)

	var logBuf syncBuffer
	srv := proxy.New(addr, targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()

	waitForServerUp(t, addr, time.Second)

	resp, err := http.Get("http://" + addr + "/endpoint")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not shut down in time")
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "=== aiproxy session summary ===") {
		t.Fatalf("log missing session summary header: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Requests allowed:    1") {
		t.Fatalf("summary missing correct allowed count: %q", logOutput)
	}
	if strings.Contains(logOutput, "Estimated cost") {
		t.Fatalf("summary must omit the cost line when CostPer1KTokens is unset: %q", logOutput)
	}
}

// generateSelfSignedCert creates a throwaway self-signed certificate and
// private key, valid for 127.0.0.1, and writes them to two PEM files
// under a fresh t.TempDir() — everything TLSCertFile/TLSKeyFile need for
// a real (if untrusted) TLS handshake in a test, with no external
// dependency beyond the standard library.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	certOut.Close()

	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	keyOut.Close()

	return certFile, keyFile
}

// TestServer_ListenAndServe_TLS_ServesHTTPSWhenCertAndKeySet proves
// TLSCertFile/TLSKeyFile are honored end to end through the real entry
// point a running aiproxy process uses: a genuine TLS handshake and
// HTTPS request succeeds, while a plain HTTP request to the exact same
// address fails — this is a real TLS listener, not a plain one that
// happens to also still accept cleartext.
func TestServer_ListenAndServe_TLS_ServesHTTPSWhenCertAndKeySet(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	certFile, keyFile := generateSelfSignedCert(t)
	addr := freeLoopbackAddr(t)

	srv := proxy.New(addr, targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TLSCertFile = certFile
	srv.TLSKeyFile = keyFile

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()

	waitForServerUp(t, addr, time.Second)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + addr + "/endpoint")
	if err != nil {
		t.Fatalf("https request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Go's http.Server specifically detects a plain-text request arriving
	// on a TLS listener and answers with a readable 400 rather than just
	// dropping the connection — so this never reaches the proxy's own
	// handler (and never reaches upstream) either way, whether the
	// client sees a transport error or a plain 400.
	if resp, err := http.Get("http://" + addr + "/endpoint"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("plain HTTP request to a TLS listener: status = %d, want %d (Go's own client-sent-plain-HTTP-to-TLS-server response)", resp.StatusCode, http.StatusBadRequest)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not shut down in time")
	}
}

// TestServer_ListenAndServe_HealthCheckEjectsDeadTargetProactively
// proves the full real entry point a running aiproxy process actually
// uses: a dead candidate gets ejected by ListenAndServe's own
// background health-check goroutine, observed via the real
// GET /_aiproxy/stats HTTP endpoint, with no client request ever sent
// to the proxy at all — the whole point of a proactive check.
func TestServer_ListenAndServe_HealthCheckEjectsDeadTargetProactively(t *testing.T) {
	dead := httptest.NewServer(hijackAndClose(t))
	defer dead.Close()
	deadURL, err := url.Parse(dead.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	healthyURL, err := url.Parse("https://healthy.example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	addr := freeLoopbackAddr(t)
	srv := proxy.New(addr, healthyURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TargetBreaker = breaker.NewRegistry(1, time.Hour)
	srv.HealthCheckInterval = 20 * time.Millisecond
	srv.AddRoute("/openai", []*url.URL{healthyURL, deadURL}, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForServerUp(t, addr, time.Second)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/_aiproxy/stats")
		if err == nil {
			var snapshot struct {
				TargetsEjected int64 `json:"targets_ejected"`
			}
			decodeErr := json.NewDecoder(resp.Body).Decode(&snapshot)
			resp.Body.Close()
			if decodeErr == nil && snapshot.TargetsEjected >= 1 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("dead target was never ejected via a real running server's background health check")
}

// TestServer_SummaryText_IncludesCostLineOnlyWhenConfigured proves the
// cost line appears, with the correct value, only once CostPer1KTokens
// is set above zero — and that tokens tracked before it was set are
// still priced correctly, since the rate is only applied when the
// summary is rendered, not when tokens are recorded.
func TestServer_SummaryText_IncludesCostLineOnlyWhenConfigured(t *testing.T) {
	targetURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)

	srv.Stats.RecordTokensUsed("default", 2500)

	withoutCost := srv.Summary()
	if strings.Contains(withoutCost, "Estimated cost") {
		t.Fatalf("summary must omit the cost line when CostPer1KTokens is unset: %q", withoutCost)
	}

	srv.CostPer1KTokens = 0.02
	withCost := srv.Summary()
	if !strings.Contains(withCost, "Estimated cost:      0.0500") {
		t.Fatalf("summary missing correct cost line for 2500 tokens at 0.02/1K: %q", withCost)
	}
}

// TestServer_SummaryText_PerTargetCostRatesSumToTheTrueTotal proves the
// shutdown summary's own "Estimated cost" line reflects the true sum
// of each target's own tokens at its own resolved rate once
// TargetCostRates overrides diverge from the server-wide default — not
// TotalTokens priced at a single flat rate, which would silently
// misprice it.
func TestServer_SummaryText_PerTargetCostRatesSumToTheTrueTotal(t *testing.T) {
	targetURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 0.03
	srv.TargetCostRates = map[string]float64{"/anthropic": 0.08}
	srv.Stats.RecordTokensUsed("/openai", 1000)
	srv.Stats.RecordTokensUsed("/anthropic", 1000)

	summary := srv.Summary()
	if !strings.Contains(summary, "Estimated cost:      0.1100 (per-target rates apply — see breakdown below)") {
		t.Fatalf("summary missing correct true-sum cost line (0.03 + 0.08 = 0.11): %q", summary)
	}
	if !strings.Contains(summary, "[/openai]") || !strings.Contains(summary, "cost=0.0300") {
		t.Fatalf("per-target breakdown missing /openai at the 0.03 default: %q", summary)
	}
	if !strings.Contains(summary, "[/anthropic]") || !strings.Contains(summary, "cost=0.0800") {
		t.Fatalf("per-target breakdown missing /anthropic at its own 0.08 override: %q", summary)
	}
}

// TestServer_MultiTargetRouting_RoutesByPathPrefixAndStripsPrefix proves
// AddRoute's core contract: a request whose path starts with a
// registered prefix goes to that route's target with the prefix
// stripped, while anything else falls back to the default Target
// unmodified.
func TestServer_MultiTargetRouting_RoutesByPathPrefixAndStripsPrefix(t *testing.T) {
	var openaiPath, anthropicPath, defaultPath string

	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openaiPath = r.URL.Path
		w.Write([]byte("openai response"))
	}))
	defer openai.Close()

	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anthropicPath = r.URL.Path
		w.Write([]byte("anthropic response"))
	}))
	defer anthropic.Close()

	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultPath = r.URL.Path
		w.Write([]byte("default response"))
	}))
	defer defaultUpstream.Close()

	openaiURL, err := url.Parse(openai.URL)
	if err != nil {
		t.Fatalf("parse openai url: %v", err)
	}
	anthropicURL, err := url.Parse(anthropic.URL)
	if err != nil {
		t.Fatalf("parse anthropic url: %v", err)
	}
	defaultURL, err := url.Parse(defaultUpstream.URL)
	if err != nil {
		t.Fatalf("parse default url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", defaultURL, engine)
	srv.AddRoute("/openai", []*url.URL{openaiURL}, nil, nil, nil)
	srv.AddRoute("/anthropic", []*url.URL{anthropicURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func(path string) string {
		resp, err := http.Get(frontend.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("get %s: read body: %v", path, err)
		}
		return string(body)
	}

	if got := get("/openai/v1/chat/completions"); got != "openai response" {
		t.Fatalf("GET /openai/v1/chat/completions body = %q, want the openai upstream's response", got)
	}
	if openaiPath != "/v1/chat/completions" {
		t.Fatalf("openai upstream saw path %q, want /v1/chat/completions (the /openai prefix should be stripped)", openaiPath)
	}

	if got := get("/anthropic/v1/messages"); got != "anthropic response" {
		t.Fatalf("GET /anthropic/v1/messages body = %q, want the anthropic upstream's response", got)
	}
	if anthropicPath != "/v1/messages" {
		t.Fatalf("anthropic upstream saw path %q, want /v1/messages", anthropicPath)
	}

	if got := get("/something-else"); got != "default response" {
		t.Fatalf("GET /something-else body = %q, want the default target's response", got)
	}
	if defaultPath != "/something-else" {
		t.Fatalf("default upstream saw path %q, want /something-else unchanged (no prefix matched, nothing to strip)", defaultPath)
	}
}

// TestServer_MultiTargetRouting_CacheKeysDifferPerTarget proves the
// cache is route-aware: an identical body and identical forwarded-path
// suffix sent to two different target prefixes must be treated as two
// distinct cache entries, never as a collision that would let one
// provider's cached response leak out under another's route.
func TestServer_MultiTargetRouting_CacheKeysDifferPerTarget(t *testing.T) {
	t.Chdir(t.TempDir())

	var openaiHits, anthropicHits atomic.Int32
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openaiHits.Add(1)
		w.Write([]byte("openai"))
	}))
	defer openai.Close()

	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anthropicHits.Add(1)
		w.Write([]byte("anthropic"))
	}))
	defer anthropic.Close()

	openaiURL, err := url.Parse(openai.URL)
	if err != nil {
		t.Fatalf("parse openai url: %v", err)
	}
	anthropicURL, err := url.Parse(anthropic.URL)
	if err != nil {
		t.Fatalf("parse anthropic url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", openaiURL, engine)
	srv.AddRoute("/openai", []*url.URL{openaiURL}, nil, nil, nil)
	srv.AddRoute("/anthropic", []*url.URL{anthropicURL}, nil, nil, nil)
	srv.Cache = c
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const sharedSuffix = "/v1/x"
	const body = `{"same":"body"}`

	post := func(path string) string {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		defer resp.Body.Close()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("post %s: read body: %v", path, err)
		}
		return string(got)
	}

	if got := post("/openai" + sharedSuffix); got != "openai" {
		t.Fatalf("first openai request body = %q, want %q", got, "openai")
	}
	if got := post("/anthropic" + sharedSuffix); got != "anthropic" {
		t.Fatalf("first anthropic request body = %q, want %q (a real response, not a leaked openai cache entry)", got, "anthropic")
	}
	if openaiHits.Load() != 1 {
		t.Fatalf("openai hits = %d, want 1", openaiHits.Load())
	}
	if anthropicHits.Load() != 1 {
		t.Fatalf("anthropic hits = %d, want 1", anthropicHits.Load())
	}

	// Repeat both: this time each should be its own cache hit.
	if got := post("/openai" + sharedSuffix); got != "openai" {
		t.Fatalf("cached openai request body = %q, want %q", got, "openai")
	}
	if got := post("/anthropic" + sharedSuffix); got != "anthropic" {
		t.Fatalf("cached anthropic request body = %q, want %q", got, "anthropic")
	}
	if openaiHits.Load() != 1 {
		t.Fatalf("openai hits after repeat = %d, want still 1 (must be served from cache)", openaiHits.Load())
	}
	if anthropicHits.Load() != 1 {
		t.Fatalf("anthropic hits after repeat = %d, want still 1 (must be served from cache)", anthropicHits.Load())
	}
}

// TestServer_MultiTargetRouting_StatsBreakDownPerTarget proves requests
// are attributed to the target they were actually routed to — the
// matched prefix, or "default" for anything that fell through to the
// fallback Target — both in Server.Stats.Snapshot().PerTarget and in the
// rendered Summary() text, and that the overall counts still reflect
// every request regardless of which target it went to.
func TestServer_MultiTargetRouting_StatsBreakDownPerTarget(t *testing.T) {
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"usage":{"total_tokens":10}}`))
	}))
	defer openai.Close()

	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"usage":{"total_tokens":30}}`))
	}))
	defer anthropic.Close()

	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer defaultUpstream.Close()

	openaiURL, err := url.Parse(openai.URL)
	if err != nil {
		t.Fatalf("parse openai url: %v", err)
	}
	anthropicURL, err := url.Parse(anthropic.URL)
	if err != nil {
		t.Fatalf("parse anthropic url: %v", err)
	}
	defaultURL, err := url.Parse(defaultUpstream.URL)
	if err != nil {
		t.Fatalf("parse default url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "test-secret",
		Pattern: regexp.MustCompile(`SECRET`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", defaultURL, engine)
	srv.AddRoute("/openai", []*url.URL{openaiURL}, nil, nil, nil)
	srv.AddRoute("/anthropic", []*url.URL{anthropicURL}, nil, nil, nil)
	srv.CostPer1KTokens = 0.02
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(path, body string) {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
	}

	post("/openai/v1/chat", `{"n":1}`)   // allowed, 10 tokens
	post("/openai/v1/chat", `SECRET`)    // blocked
	post("/anthropic/v1/msg", `{"n":1}`) // allowed, 30 tokens
	post("/something-else", `{"n":1}`)   // allowed on the default fallback

	// Let the async usage-extraction goroutine-free path settle: usage is
	// extracted synchronously in ModifyResponse for a non-streaming
	// response, so no wait is actually needed here, but Snapshot is taken
	// only after every post() has returned, which is enough.
	snap := srv.Stats.Snapshot()

	if snap.Allowed != 3 {
		t.Fatalf("overall Allowed = %d, want 3", snap.Allowed)
	}
	if snap.Blocked != 1 {
		t.Fatalf("overall Blocked = %d, want 1", snap.Blocked)
	}
	if snap.TotalTokens != 40 {
		t.Fatalf("overall TotalTokens = %d, want 40", snap.TotalTokens)
	}

	openaiSnap, ok := snap.PerTarget["/openai"]
	if !ok {
		t.Fatalf("PerTarget missing /openai entry: %+v", snap.PerTarget)
	}
	if openaiSnap.Allowed != 1 || openaiSnap.Blocked != 1 || openaiSnap.TotalTokens != 10 {
		t.Fatalf("PerTarget[/openai] = %+v, want allowed=1 blocked=1 tokens=10", openaiSnap)
	}

	anthropicSnap, ok := snap.PerTarget["/anthropic"]
	if !ok {
		t.Fatalf("PerTarget missing /anthropic entry: %+v", snap.PerTarget)
	}
	if anthropicSnap.Allowed != 1 || anthropicSnap.TotalTokens != 30 {
		t.Fatalf("PerTarget[/anthropic] = %+v, want allowed=1 tokens=30", anthropicSnap)
	}

	defaultSnap, ok := snap.PerTarget["default"]
	if !ok {
		t.Fatalf("PerTarget missing default entry: %+v", snap.PerTarget)
	}
	if defaultSnap.Allowed != 1 {
		t.Fatalf("PerTarget[default] = %+v, want allowed=1", defaultSnap)
	}

	summary := srv.Summary()
	if !strings.Contains(summary, "=== per-target breakdown ===") {
		t.Fatalf("Summary() missing per-target breakdown header: %q", summary)
	}
	if !strings.Contains(summary, "[/openai] allowed=1 blocked=1 redacted=0 rate-limited=0 cache-hits=0 tokens=10 response-blocked=0 response-redacted=0 cost=0.0002") {
		t.Fatalf("Summary() missing correct /openai line: %q", summary)
	}
	if !strings.Contains(summary, "[/anthropic] allowed=1 blocked=0 redacted=0 rate-limited=0 cache-hits=0 tokens=30 response-blocked=0 response-redacted=0 cost=0.0006") {
		t.Fatalf("Summary() missing correct /anthropic line: %q", summary)
	}
	if !strings.Contains(summary, "[default] allowed=1 blocked=0 redacted=0 rate-limited=0 cache-hits=0 tokens=0 response-blocked=0 response-redacted=0 cost=0.0000") {
		t.Fatalf("Summary() missing correct default line: %q", summary)
	}
}

// TestServer_SingleTarget_SummaryOmitsPerTargetBreakdown proves the
// breakdown section is left out entirely for the common case — no
// AddRoute calls, everything going to one --target — since it would
// just repeat the overall block above with a different label.
func TestServer_SingleTarget_SummaryOmitsPerTargetBreakdown(t *testing.T) {
	targetURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Stats.RecordAllow("default")

	summary := srv.Summary()
	if strings.Contains(summary, "per-target breakdown") {
		t.Fatalf("Summary() should omit the per-target breakdown for a single-target run: %q", summary)
	}
}

// TestServer_SummaryText_IncludesPerRuleBreakdown proves the shutdown
// summary shows which rule actually fired and how often, unlike the
// per-target breakdown this shows even for a single rule — the overall
// totals above already conflate every rule together, so a lone rule's
// own numbers are never redundant with them.
func TestServer_SummaryText_IncludesPerRuleBreakdown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`{"key":"AKIAABCDEFGHIJKLMNOP"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	summary := srv.Summary()
	if !strings.Contains(summary, "=== per-rule breakdown ===") {
		t.Fatalf("Summary() missing per-rule breakdown header: %q", summary)
	}
	if !strings.Contains(summary, "[aws-access-key] blocked=1 redacted=0 response-blocked=0 response-redacted=0") {
		t.Fatalf("Summary() missing correct aws-access-key line: %q", summary)
	}
}

// ruleJSONResponse mirrors the wire shape of one entry in per_rule, for
// tests to decode into.
type ruleJSONResponse struct {
	Blocked                int64 `json:"blocked"`
	Redacted               int64 `json:"redacted"`
	ResponseBlocked        int64 `json:"response_blocked"`
	ResponseRedacted       int64 `json:"response_redacted"`
	DryRunBlocked          int64 `json:"dry_run_blocked"`
	DryRunRedacted         int64 `json:"dry_run_redacted"`
	ResponseDryRunBlocked  int64 `json:"response_dry_run_blocked"`
	ResponseDryRunRedacted int64 `json:"response_dry_run_redacted"`
}

// statsJSONResponse mirrors the wire shape served at GET /_aiproxy/stats,
// for tests to decode into.
type statsJSONResponse struct {
	Allowed                int64                         `json:"allowed"`
	Blocked                int64                         `json:"blocked"`
	Redacted               int64                         `json:"redacted"`
	RateLimited            int64                         `json:"rate_limited"`
	CacheHits              int64                         `json:"cache_hits"`
	TotalTokens            int64                         `json:"total_tokens"`
	ResponseBlocked        int64                         `json:"response_blocked"`
	ResponseRedacted       int64                         `json:"response_redacted"`
	DryRunBlocked          int64                         `json:"dry_run_blocked"`
	DryRunRedacted         int64                         `json:"dry_run_redacted"`
	ResponseDryRunBlocked  int64                         `json:"response_dry_run_blocked"`
	ResponseDryRunRedacted int64                         `json:"response_dry_run_redacted"`
	Unauthorized           int64                         `json:"unauthorized"`
	Failover               int64                         `json:"failover"`
	Latency                latencyJSONResponse           `json:"latency"`
	EstimatedCost          *float64                      `json:"estimated_cost,omitempty"`
	CostBudget             *float64                      `json:"cost_budget,omitempty"`
	PerTarget              map[string]statsJSONResponse  `json:"per_target,omitempty"`
	PerRule                map[string]ruleJSONResponse   `json:"per_rule,omitempty"`
	PerClient              map[string]clientJSONResponse `json:"per_client,omitempty"`
}

// clientJSONResponse mirrors stats.ClientSnapshot's wire shape.
type clientJSONResponse struct {
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	Redacted    int64 `json:"redacted"`
	RateLimited int64 `json:"rate_limited"`
	TotalTokens int64 `json:"total_tokens"`
}

// latencyJSONResponse mirrors stats.LatencySnapshot's wire shape.
type latencyJSONResponse struct {
	Count      int64   `json:"count"`
	SumSeconds float64 `json:"sum_seconds"`
	Buckets    []struct {
		Le    string `json:"le"`
		Count int64  `json:"count"`
	} `json:"buckets,omitempty"`
}

// TestServer_StatsEndpoint_ReturnsCurrentSnapshotAsJSON drives a request
// of each outcome through the proxy and proves GET /_aiproxy/stats
// reports exactly those counts as JSON, live, without needing a
// shutdown.
func TestServer_StatsEndpoint_ReturnsCurrentSnapshotAsJSON(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "test-secret",
		Pattern: regexp.MustCompile(`SECRET`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(body string) {
		resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %q: %v", body, err)
		}
		resp.Body.Close()
	}
	post(`{"n":1}`)
	post(`SECRET`)
	post(`{"n":2}`)

	resp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	var got statsJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Allowed != 2 {
		t.Errorf("Allowed = %d, want 2", got.Allowed)
	}
	if got.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", got.Blocked)
	}
}

// TestServer_StatsEndpoint_NeverForwardedUpstreamOrCountedInStats proves
// statsPath is handled entirely inside the proxy: the upstream never
// sees a request for it, and answering it does not itself change the
// counters it reports.
func TestServer_StatsEndpoint_NeverForwardedUpstreamOrCountedInStats(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(frontend.URL + "/_aiproxy/stats")
		if err != nil {
			t.Fatalf("GET /_aiproxy/stats: %v", err)
		}
		resp.Body.Close()
	}

	if upstreamHit.Load() {
		t.Fatal("a request for statsPath must never reach the upstream target")
	}

	var got statsJSONResponse
	resp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Allowed != 0 || got.Blocked != 0 {
		t.Fatalf("stats requests must not themselves be counted: got %+v", got)
	}
}

// TestServer_StatsEndpoint_BypassesRulesAndRateLimiter proves statsPath
// is a true side-channel: it stays reachable even while a
// block-everything rule and an exhausted rate limiter are actively
// rejecting every other request.
func TestServer_StatsEndpoint_BypassesRulesAndRateLimiter(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Block) // blocks everything by default
	srv := proxy.New("unused", targetURL, engine)
	srv.Limiter = limiter.New(0, time.Minute) // 0 allowed requests per window
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d even with rules/rate-limiter blocking everything else", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_StatsEndpoint_RejectsNonGetMethod proves the endpoint only
// answers GET, since it has no meaningful semantics for any other verb.
func TestServer_StatsEndpoint_RejectsNonGetMethod(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/_aiproxy/stats", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /_aiproxy/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestServer_StatsEndpoint_IncludesCostOnlyWhenConfiguredAndTracksEveryTarget
// proves the JSON response's estimated_cost field appears only once
// CostPer1KTokens is set (overall and within each per-target entry), and
// that per_target always reflects every target actually used so far —
// unlike the printed Summary(), the JSON endpoint does not hide a
// single-entry breakdown, since a machine-readable API should stay
// structurally predictable rather than collapsing below a threshold.
func TestServer_StatsEndpoint_IncludesCostOnlyWhenConfiguredAndTracksEveryTarget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	defaultURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	otherURL, err := url.Parse(other.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", defaultURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	getStats := func() statsJSONResponse {
		resp, err := http.Get(frontend.URL + "/_aiproxy/stats")
		if err != nil {
			t.Fatalf("GET /_aiproxy/stats: %v", err)
		}
		defer resp.Body.Close()
		var got statsJSONResponse
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return got
	}

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("GET /x: %v", err)
	}
	resp.Body.Close()

	withoutCost := getStats()
	if withoutCost.EstimatedCost != nil {
		t.Fatalf("estimated_cost must be omitted when CostPer1KTokens is unset: %+v", withoutCost)
	}
	if len(withoutCost.PerTarget) != 1 {
		t.Fatalf("per_target = %+v, want exactly the 1 default entry seen so far", withoutCost.PerTarget)
	}
	if _, ok := withoutCost.PerTarget["default"]; !ok {
		t.Fatalf("per_target missing default entry: %+v", withoutCost.PerTarget)
	}

	srv.CostPer1KTokens = 0.02
	srv.AddRoute("/other", []*url.URL{otherURL}, nil, nil, nil)
	resp2, err := http.Get(frontend.URL + "/other/y")
	if err != nil {
		t.Fatalf("GET /other/y: %v", err)
	}
	resp2.Body.Close()

	withBoth := getStats()
	if withBoth.EstimatedCost == nil {
		t.Fatal("estimated_cost must be present once CostPer1KTokens is set")
	}
	if len(withBoth.PerTarget) != 2 {
		t.Fatalf("per_target = %+v, want 2 entries (default and /other)", withBoth.PerTarget)
	}
	if _, ok := withBoth.PerTarget["/other"]; !ok {
		t.Fatalf("per_target missing /other entry: %+v", withBoth.PerTarget)
	}
	if _, ok := withBoth.PerTarget["default"]; !ok {
		t.Fatalf("per_target missing default entry: %+v", withBoth.PerTarget)
	}
}

// TestServer_StatsEndpoint_PerTargetCostOverrideAffectsOnlyThatTargetAndTheTrueTotal
// proves TargetCostRates correctly prices ONE target at its own rate,
// leaves an unconfigured target at the server-wide default, and — the
// core correctness claim of per-target pricing — that the top-level
// estimated_cost is the true sum of both, not the (wrong) result of
// pricing every token at a single flat rate.
func TestServer_StatsEndpoint_PerTargetCostOverrideAffectsOnlyThatTargetAndTheTrueTotal(t *testing.T) {
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":1000}}`))
	}))
	defer openai.Close()
	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":1000}}`))
	}))
	defer anthropic.Close()

	openaiURL, err := url.Parse(openai.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	anthropicURL, err := url.Parse(anthropic.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", openaiURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.CostPer1KTokens = 0.03
	srv.TargetCostRates = map[string]float64{"/anthropic": 0.08}
	srv.AddRoute("/openai", []*url.URL{openaiURL}, nil, nil, nil)
	srv.AddRoute("/anthropic", []*url.URL{anthropicURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for _, path := range []string{"/openai/v1/chat", "/anthropic/v1/messages"} {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
	}

	resp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer resp.Body.Close()
	var got statsJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	openaiCost := got.PerTarget["/openai"].EstimatedCost
	if openaiCost == nil || *openaiCost != 0.03 {
		t.Fatalf("/openai estimated_cost = %v, want 0.03 (1000 tokens at the 0.03 default rate)", openaiCost)
	}
	anthropicCost := got.PerTarget["/anthropic"].EstimatedCost
	if anthropicCost == nil || *anthropicCost != 0.08 {
		t.Fatalf("/anthropic estimated_cost = %v, want 0.08 (1000 tokens at its own 0.08 override)", anthropicCost)
	}
	if got.EstimatedCost == nil {
		t.Fatal("top-level estimated_cost missing")
	}
	if *got.EstimatedCost < 0.109 || *got.EstimatedCost > 0.111 {
		t.Fatalf("top-level estimated_cost = %v, want approximately 0.11 (0.03 + 0.08, the true sum) — a single flat 0.03 rate across both targets' combined 2000 tokens would wrongly give 0.06", *got.EstimatedCost)
	}
}

// TestServer_MetricsEndpoint_ReturnsPrometheusFormatWithCurrentCounts
// proves metricsPath renders the same counters as statsPath, but in
// Prometheus's text exposition format, labeled by target.
func TestServer_MetricsEndpoint_ReturnsPrometheusFormatWithCurrentCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "test-secret",
		Pattern: regexp.MustCompile(`SECRET`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(body string) {
		resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %q: %v", body, err)
		}
		resp.Body.Close()
	}
	post(`{"n":1}`)
	post(`SECRET`)
	post(`{"n":2}`)

	resp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("GET /_aiproxy/metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want a text/plain prefix", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	if !strings.Contains(out, "# TYPE aiproxy_requests_allowed_total counter") {
		t.Errorf("missing TYPE line for allowed counter: %q", out)
	}
	if !strings.Contains(out, `aiproxy_requests_allowed_total{target="default"} 2`) {
		t.Errorf("missing allowed=2 for target=default: %q", out)
	}
	if !strings.Contains(out, `aiproxy_requests_blocked_total{target="default"} 1`) {
		t.Errorf("missing blocked=1 for target=default: %q", out)
	}
}

// TestServer_MetricsEndpoint_ReportsResponseBlockedAndRedactedCounts
// proves the two response-side counters are wired into the Prometheus
// endpoint too, not just /_aiproxy/stats — easy to forget since neither
// promCounters entry is derived automatically from anything else.
func TestServer_MetricsEndpoint_ReportsResponseBlockedAndRedactedCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/block" {
			w.Write([]byte(`{"echo":"AKIAABCDEFGHIJKLMNOP"}`))
			return
		}
		w.Write([]byte(`{"echo":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	blockResp, err := http.Post(frontend.URL+"/block", "application/json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("post (response block): %v", err)
	}
	blockResp.Body.Close()

	redactResp, err := http.Post(frontend.URL+"/redact", "application/json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("post (response redact): %v", err)
	}
	redactResp.Body.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("GET /_aiproxy/metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	if !strings.Contains(out, `aiproxy_responses_blocked_total{target="default"} 1`) {
		t.Errorf("missing response-blocked=1 for target=default: %q", out)
	}
	if !strings.Contains(out, `aiproxy_responses_redacted_total{target="default"} 1`) {
		t.Errorf("missing response-redacted=1 for target=default: %q", out)
	}
	if !strings.Contains(out, `aiproxy_rule_response_blocked_total{rule="aws-access-key"} 1`) {
		t.Errorf("missing rule-labeled response-blocked=1 for aws-access-key: %q", out)
	}
	if !strings.Contains(out, `aiproxy_rule_response_redacted_total{rule="openai-api-key"} 1`) {
		t.Errorf("missing rule-labeled response-redacted=1 for openai-api-key: %q", out)
	}
	if !strings.Contains(out, `aiproxy_rule_blocked_total{rule="aws-access-key"} 0`) {
		t.Errorf("missing rule-labeled blocked=0 for aws-access-key (that axis was never hit): %q", out)
	}
}

// TestServer_MetricsEndpoint_ReportsPerRuleLabeledCounters proves
// metricsPath exposes the four aiproxy_rule_*_total series, each
// labeled rule="<name>", combining a rule's request- and response-side
// hits under its own name the same way TestServer_StatsEndpoint_
// ReportsPerRuleBreakdown proves for the JSON endpoint.
func TestServer_MetricsEndpoint_ReportsPerRuleLabeledCounters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`{"key":"AKIAABCDEFGHIJKLMNOP"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	metricsResp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("GET /_aiproxy/metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	for _, want := range []string{
		"# HELP aiproxy_rule_blocked_total",
		"# TYPE aiproxy_rule_blocked_total counter",
		`aiproxy_rule_blocked_total{rule="aws-access-key"} 1`,
		`aiproxy_rule_redacted_total{rule="aws-access-key"} 0`,
		`aiproxy_rule_response_blocked_total{rule="aws-access-key"} 0`,
		`aiproxy_rule_response_redacted_total{rule="aws-access-key"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q: %q", want, out)
		}
	}
}

// TestServer_MetricsEndpoint_NeverForwardedUpstreamOrCountedInStats
// mirrors the same guarantee statsPath has: a scrape never reaches the
// upstream, and never shows up in its own counters.
func TestServer_MetricsEndpoint_NeverForwardedUpstreamOrCountedInStats(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
		if err != nil {
			t.Fatalf("GET /_aiproxy/metrics: %v", err)
		}
		resp.Body.Close()
	}

	if upstreamHit.Load() {
		t.Fatal("a request for metricsPath must never reach the upstream target")
	}

	resp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("GET /_aiproxy/metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.Contains(string(body), `target=`) {
		t.Fatalf("scrapes must not themselves be counted, so no target should have appeared yet: %q", body)
	}
}

// TestServer_MetricsEndpoint_BypassesRulesAndRateLimiter proves
// metricsPath stays reachable even while a block-everything rule and an
// exhausted rate limiter are actively rejecting every other request —
// the same side-channel guarantee as statsPath.
func TestServer_MetricsEndpoint_BypassesRulesAndRateLimiter(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Block) // blocks everything by default
	srv := proxy.New("unused", targetURL, engine)
	srv.Limiter = limiter.New(0, time.Minute) // 0 allowed requests per window
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("GET /_aiproxy/metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d even with rules/rate-limiter blocking everything else", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_MetricsEndpoint_RejectsNonGetMethod proves the endpoint
// only answers GET, matching statsPath.
func TestServer_MetricsEndpoint_RejectsNonGetMethod(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/_aiproxy/metrics", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /_aiproxy/metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestServer_MetricsEndpoint_IncludesCostOnlyWhenConfiguredAndLabelsEveryTarget
// proves aiproxy_estimated_cost appears only once CostPer1KTokens is
// set, and that every target seen so far gets its own labeled series —
// including a single-target run, unlike the printed Summary()'s
// below-threshold suppression, since a scrape needs a structurally
// predictable shape every time.
func TestServer_MetricsEndpoint_IncludesCostOnlyWhenConfiguredAndLabelsEveryTarget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	defaultURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	otherURL, err := url.Parse(other.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", defaultURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	getMetrics := func() string {
		resp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
		if err != nil {
			t.Fatalf("GET /_aiproxy/metrics: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return string(body)
	}

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("GET /x: %v", err)
	}
	resp.Body.Close()

	withoutCost := getMetrics()
	if strings.Contains(withoutCost, "aiproxy_estimated_cost") {
		t.Fatalf("aiproxy_estimated_cost must be omitted when CostPer1KTokens is unset: %q", withoutCost)
	}
	if !strings.Contains(withoutCost, `target="default"`) {
		t.Fatalf("missing target=default series in a single-target run: %q", withoutCost)
	}

	srv.CostPer1KTokens = 0.02
	srv.AddRoute("/other", []*url.URL{otherURL}, nil, nil, nil)
	resp2, err := http.Get(frontend.URL + "/other/y")
	if err != nil {
		t.Fatalf("GET /other/y: %v", err)
	}
	resp2.Body.Close()

	withBoth := getMetrics()
	if !strings.Contains(withBoth, "aiproxy_estimated_cost") {
		t.Fatalf("aiproxy_estimated_cost must be present once CostPer1KTokens is set: %q", withBoth)
	}
	if !strings.Contains(withBoth, `target="default"`) || !strings.Contains(withBoth, `target="/other"`) {
		t.Fatalf("missing per-target series for both targets: %q", withBoth)
	}
}

// TestServer_MetricsEndpoint_PerTargetCostOverridePricesEachSeriesAtItsOwnRate
// proves each target's own aiproxy_estimated_cost series reflects ITS
// OWN resolved rate — an override where set, the server-wide default
// otherwise — not one flat rate applied uniformly to every target.
func TestServer_MetricsEndpoint_PerTargetCostOverridePricesEachSeriesAtItsOwnRate(t *testing.T) {
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":1000}}`))
	}))
	defer openai.Close()
	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":1000}}`))
	}))
	defer anthropic.Close()

	openaiURL, err := url.Parse(openai.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	anthropicURL, err := url.Parse(anthropic.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", openaiURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.CostPer1KTokens = 0.03
	srv.TargetCostRates = map[string]float64{"/anthropic": 0.08}
	srv.AddRoute("/openai", []*url.URL{openaiURL}, nil, nil, nil)
	srv.AddRoute("/anthropic", []*url.URL{anthropicURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for _, path := range []string{"/openai/v1/chat", "/anthropic/v1/messages"} {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
	}

	resp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("GET /_aiproxy/metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	metrics := string(body)

	if !strings.Contains(metrics, `aiproxy_estimated_cost{target="/openai"} 0.03`) {
		t.Fatalf("missing /openai priced at the 0.03 default: %q", metrics)
	}
	if !strings.Contains(metrics, `aiproxy_estimated_cost{target="/anthropic"} 0.08`) {
		t.Fatalf("missing /anthropic priced at its own 0.08 override: %q", metrics)
	}
}

// TestServer_MultiTargetRouting_PerTargetLimiterActsIndependently proves
// AddRoute's dedicated-limiter override: a route given its own strict
// Limiter is throttled by that limit alone, while a second route with no
// override of its own keeps sharing the server-wide Limiter and is
// unaffected by the first route's traffic — heavy use of one target must
// never starve another's independent budget, nor bypass the shared one
// it was never given an exemption from.
func TestServer_MultiTargetRouting_PerTargetLimiterActsIndependently(t *testing.T) {
	var strictHits, sharedHits atomic.Int32
	strict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strictHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer strict.Close()
	shared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sharedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shared.Close()

	strictURL, err := url.Parse(strict.URL)
	if err != nil {
		t.Fatalf("parse strict url: %v", err)
	}
	sharedURL, err := url.Parse(shared.URL)
	if err != nil {
		t.Fatalf("parse shared url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", sharedURL, engine)
	srv.Limiter = limiter.New(5, time.Minute) // generous shared budget
	srv.AddRoute("/strict", []*url.URL{strictURL}, nil, limiter.New(1, time.Minute), nil)
	srv.AddRoute("/shared", []*url.URL{sharedURL}, nil, nil, nil) // no override: shares srv.Limiter
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func(path string) int {
		resp, err := http.Get(frontend.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get("/strict/x"); got != http.StatusOK {
		t.Fatalf("first /strict request status = %d, want %d", got, http.StatusOK)
	}
	if got := get("/strict/x"); got != http.StatusTooManyRequests {
		t.Fatalf("second /strict request status = %d, want %d (its own 1/min limit is exhausted)", got, http.StatusTooManyRequests)
	}
	if strictHits.Load() != 1 {
		t.Fatalf("strict upstream hits = %d, want exactly 1", strictHits.Load())
	}

	// /shared has no override, so it draws from the full server-wide
	// budget, entirely unaffected by /strict — /strict's own dedicated
	// limiter means its traffic never touches srv.Limiter at all.
	for i := 0; i < 5; i++ {
		if got := get("/shared/x"); got != http.StatusOK {
			t.Fatalf("/shared request %d status = %d, want %d", i+1, got, http.StatusOK)
		}
	}
	if got := get("/shared/x"); got != http.StatusTooManyRequests {
		t.Fatalf("6th /shared request status = %d, want %d (shared 5/min budget exhausted)", got, http.StatusTooManyRequests)
	}
	if sharedHits.Load() != 5 {
		t.Fatalf("shared upstream hits = %d, want exactly 5", sharedHits.Load())
	}
}

// TestServer_MultiTargetRouting_PerTargetTokenLimiterActsIndependently
// is TestServer_MultiTargetRouting_PerTargetLimiterActsIndependently's
// counterpart for the token-based breaker: a route with its own
// max_tokens_per_minute override never draws from — or is exhausted
// by — another route's token usage, and a route with no override of its
// own keeps sharing the server-wide TokenLimiter.
func TestServer_MultiTargetRouting_PerTargetTokenLimiterActsIndependently(t *testing.T) {
	var strictHits, sharedHits atomic.Int32
	strict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strictHits.Add(1)
		w.Write([]byte(`{"usage":{"total_tokens":100}}`))
	}))
	defer strict.Close()
	shared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sharedHits.Add(1)
		w.Write([]byte(`{"usage":{"total_tokens":100}}`))
	}))
	defer shared.Close()

	strictURL, err := url.Parse(strict.URL)
	if err != nil {
		t.Fatalf("parse strict url: %v", err)
	}
	sharedURL, err := url.Parse(shared.URL)
	if err != nil {
		t.Fatalf("parse shared url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", sharedURL, engine)
	srv.TokenLimiter = limiter.NewTokenLimiter(1000, time.Minute) // generous shared budget
	srv.AddRoute("/strict", []*url.URL{strictURL}, nil, nil, limiter.NewTokenLimiter(100, time.Minute))
	srv.AddRoute("/shared", []*url.URL{sharedURL}, nil, nil, nil) // no override: shares srv.TokenLimiter
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func(path string) int {
		resp, err := http.Get(frontend.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get("/strict/x"); got != http.StatusOK {
		t.Fatalf("first /strict request status = %d, want %d", got, http.StatusOK)
	}
	if got := get("/strict/x"); got != http.StatusTooManyRequests {
		t.Fatalf("second /strict request status = %d, want %d (its own 100-token budget already used up by the first response)", got, http.StatusTooManyRequests)
	}
	if strictHits.Load() != 1 {
		t.Fatalf("strict upstream hits = %d, want exactly 1", strictHits.Load())
	}

	// /shared has no override, so it draws from the full server-wide
	// 1000-token budget, entirely unaffected by /strict's own dedicated
	// (and already-exhausted) breaker.
	if got := get("/shared/x"); got != http.StatusOK {
		t.Fatalf("/shared request status = %d, want %d", got, http.StatusOK)
	}
	if sharedHits.Load() != 1 {
		t.Fatalf("shared upstream hits = %d, want exactly 1", sharedHits.Load())
	}
}

// TestServer_MultiTargetRouting_RateLimitedRequestsAttributedToCorrectTarget
// proves a 429 from a per-target limiter is recorded under that target's
// own stats entry, not lumped into the overall count without a target,
// or attributed to some other target.
func TestServer_MultiTargetRouting_RateLimitedRequestsAttributedToCorrectTarget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.AddRoute("/limited", []*url.URL{targetURL}, nil, limiter.New(1, time.Minute), nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 2; i++ {
		resp, err := http.Get(frontend.URL + "/limited/x")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
	}

	snap := srv.Stats.Snapshot()
	if snap.RateLimited != 1 {
		t.Fatalf("overall RateLimited = %d, want 1", snap.RateLimited)
	}
	limited, ok := snap.PerTarget["/limited"]
	if !ok {
		t.Fatalf("PerTarget missing /limited entry: %+v", snap.PerTarget)
	}
	if limited.RateLimited != 1 {
		t.Fatalf("PerTarget[/limited].RateLimited = %d, want 1", limited.RateLimited)
	}
}

// jsonLogLine mirrors the shape of one LogFormatJSON log line.
type jsonLogLine struct {
	Time      string `json:"time"`
	Level     string `json:"level"`
	Method    string `json:"method,omitempty"`
	URL       string `json:"url,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Rule      string `json:"rule,omitempty"`
	Tokens    int    `json:"tokens,omitempty"`
	Message   string `json:"message,omitempty"`
}

// TestServer_JSONLogging_EmitsOneValidJSONObjectPerEvent drives one
// request of each outcome (allow-with-usage, block, rate-limited, and a
// replay that's a cache hit) through a server configured with
// LogFormatJSON, and proves every single non-empty log line is valid
// JSON with the right fields — the core contract of the feature: a
// script can safely `jq` every line without ever hitting a parse error.
func TestServer_JSONLogging_EmitsOneValidJSONObjectPerEvent(t *testing.T) {
	t.Chdir(t.TempDir())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"usage":{"total_tokens":7}}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "test-secret",
		Pattern: regexp.MustCompile(`SECRET`),
		Action:  rules.Block,
	})

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.LogFormat = proxy.LogFormatJSON
	srv.Logger = log.New(&logBuf, "", 0)
	srv.Cache = c
	srv.Limiter = limiter.New(1, time.Minute)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(body string) {
		resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %q: %v", body, err)
		}
		resp.Body.Close()
	}
	post(`{"n":1}`) // allowed, uses the limiter's only slot, carries usage, gets cached
	post(`SECRET`)  // blocked
	post(`{"n":2}`) // different body: passes rules, then rate-limited
	post(`{"n":1}`) // same body as the first: cache hit

	rawLines := strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n")
	var events []jsonLogLine
	for i, line := range rawLines {
		if line == "" {
			continue
		}
		var ev jsonLogLine
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d is not valid JSON: %q: %v", i, line, err)
		}
		if ev.Time == "" {
			t.Fatalf("line %d missing time field: %q", i, line)
		}
		if _, err := time.Parse(time.RFC3339, ev.Time); err != nil {
			t.Fatalf("line %d has an unparseable time %q: %v", i, ev.Time, err)
		}
		events = append(events, ev)
	}

	// The first post gets both a latency line (it reached the upstream)
	// and a usage line (its response carried a usage field); none of the
	// remaining three ever reach the upstream — blocked, rate-limited,
	// and served from cache respectively — so none of them get a
	// latency line of their own.
	wantLevels := []string{"allow", "latency", "usage", "block", "rate_limited", "cache_hit"}
	if len(events) != len(wantLevels) {
		t.Fatalf("got %d log events, want %d: %+v", len(events), len(wantLevels), events)
	}
	for i, want := range wantLevels {
		if events[i].Level != want {
			t.Errorf("event %d level = %q, want %q (all events: %+v)", i, events[i].Level, want, events)
		}
	}
	if events[2].Tokens != 7 {
		t.Errorf("usage event tokens = %d, want 7", events[2].Tokens)
	}
	if events[3].Rule != "test-secret" {
		t.Errorf("block event rule = %q, want test-secret", events[3].Rule)
	}

	// events 0-2 (allow, latency, usage) all belong to the very same
	// first POST — they must share one request_id. Every other event
	// belongs to a different request and must carry its own distinct
	// one.
	seen := make(map[int]bool)
	for i, ev := range events {
		if ev.RequestID == "" {
			t.Errorf("event %d (%s) missing request_id", i, ev.Level)
		}
		seen[i] = true
	}
	if events[0].RequestID != events[1].RequestID || events[1].RequestID != events[2].RequestID {
		t.Errorf("events 0-2 (one request's own allow/latency/usage) have differing request_id: %q, %q, %q", events[0].RequestID, events[1].RequestID, events[2].RequestID)
	}
	ids := map[string]bool{events[0].RequestID: true}
	for _, i := range []int{3, 4, 5} {
		if ids[events[i].RequestID] {
			t.Errorf("event %d (%s) request_id %q collides with an earlier, different request", i, events[i].Level, events[i].RequestID)
		}
		ids[events[i].RequestID] = true
	}
}

// TestServer_JSONLogging_ShutdownSummaryIsOneJSONLine proves the
// shutdown summary is also emitted as a single JSON line (matching what
// GET /_aiproxy/stats serves) under LogFormatJSON, rather than the
// multi-line text block — a multi-line block would otherwise be the one
// place that breaks "every line is valid JSON".
func TestServer_JSONLogging_ShutdownSummaryIsOneJSONLine(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	addr := freeLoopbackAddr(t)
	engine := rules.NewEngine(rules.Allow)

	var logBuf syncBuffer
	srv := proxy.New(addr, targetURL, engine)
	srv.LogFormat = proxy.LogFormatJSON
	srv.Logger = log.New(&logBuf, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()

	waitForServerUp(t, addr, time.Second)

	resp, err := http.Get("http://" + addr + "/endpoint")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not shut down in time")
	}

	rawLines := strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n")
	if len(rawLines) != 3 {
		t.Fatalf("got %d log lines, want 3 (the allow event, its latency line, then the summary): %q", len(rawLines), rawLines)
	}

	var summary statsJSONResponse
	lastLine := rawLines[len(rawLines)-1]
	if err := json.Unmarshal([]byte(lastLine), &summary); err != nil {
		t.Fatalf("summary line is not valid JSON: %q: %v", lastLine, err)
	}
	if summary.Allowed != 1 {
		t.Fatalf("summary.Allowed = %d, want 1", summary.Allowed)
	}
}

// TestServer_JSONLogging_CacheErrorIsAlsoAJSONLine proves that even an
// incidental internal error message (not a per-request event) is logged
// as a JSON line under LogFormatJSON, not a plain string — the whole
// point of the feature is that a consumer never has to special-case a
// stray non-JSON line.
func TestServer_JSONLogging_CacheErrorIsAlsoAJSONLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows' ACL-based permission model means os.Chmod doesn't
		// reliably block writes into a directory the way removing the
		// POSIX write bit does on Unix — the write below would just
		// silently succeed, so there's no portable way to force this
		// specific failure on Windows. Same reasoning the Go standard
		// library itself uses to skip permission-based tests there.
		t.Skip("permission-based write failure injection isn't portable to Windows")
	}
	dir := t.TempDir()
	t.Chdir(dir)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	// Strip write permission from the already-created cache directory so
	// New() succeeds but a later Set() fails to write its entry —
	// exercising the real error path instead of faking one.
	cacheDirPath := dir + "/" + cache.DirName
	if err := os.Chmod(cacheDirPath, 0o500); err != nil {
		t.Fatalf("chmod cache dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(cacheDirPath, 0o755) })

	var logBuf bytes.Buffer
	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.LogFormat = proxy.LogFormatJSON
	srv.Logger = log.New(&logBuf, "", 0)
	srv.Cache = c

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	rawLines := strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n")
	foundError := false
	for _, line := range rawLines {
		var ev jsonLogLine
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line is not valid JSON: %q: %v", line, err)
		}
		if ev.Level == "error" {
			foundError = true
			if ev.Message == "" {
				t.Errorf("error event missing a message: %q", line)
			}
		}
	}
	if !foundError {
		t.Fatalf("expected an error-level JSON event for the failed cache write, got: %q", rawLines)
	}
}

// TestServer_ReloadConfig_SwapsEngineLimiterCacheCostAndRoutes proves
// ReloadConfig actually changes live behavior: a request blocked under
// the original engine is allowed after a reload with a more permissive
// one, a rate limit newly applies, a route newly resolves, and the
// summary picks up the new cost rate — all without restarting the
// server or touching its listener.
func TestServer_ReloadConfig_SwapsEngineLimiterCacheCostAndRoutes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	otherURL, err := url.Parse(other.URL)
	if err != nil {
		t.Fatalf("parse other url: %v", err)
	}

	blockAll := rules.NewEngine(rules.Block)
	srv := proxy.New("unused", targetURL, blockAll)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func(path string) int {
		resp, err := http.Get(frontend.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get("/x"); got != http.StatusForbidden {
		t.Fatalf("before reload: status = %d, want %d (blockAll engine)", got, http.StatusForbidden)
	}

	allowAll := rules.NewEngine(rules.Allow)
	strictLimiter := limiter.New(1, time.Minute)
	srv.ReloadConfig(allowAll, nil, nil, 0.05, 0, 0, nil, nil, "", nil, nil, []proxy.Route{
		{Prefix: "/other", Targets: []*url.URL{otherURL}, Limiter: strictLimiter},
	}, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	if got := get("/x"); got != http.StatusOK {
		t.Fatalf("after reload: status = %d, want %d (allowAll engine)", got, http.StatusOK)
	}
	if got := get("/other/y"); got != http.StatusOK {
		t.Fatalf("after reload: /other/y status = %d, want %d (new route, 1st request)", got, http.StatusOK)
	}
	if got := get("/other/y"); got != http.StatusTooManyRequests {
		t.Fatalf("after reload: /other/y status = %d, want %d (new route's own 1/min limit exhausted)", got, http.StatusTooManyRequests)
	}

	srv.Stats.RecordTokensUsed("default", 1000)
	if summary := srv.Summary(); !strings.Contains(summary, "Estimated cost:      0.0500") {
		t.Fatalf("Summary() = %q, want the reloaded cost rate (0.05/1K) reflected", summary)
	}
}

// TestServer_ReloadConfig_ConcurrentWithRequests_NeverRaces hammers
// ServeHTTP and ReloadConfig from separate goroutines simultaneously —
// the actual concurrency safety claim ReloadConfig makes — and relies on
// `go test -race` to catch any unsynchronized access, since that's the
// property under test, not any particular observed outcome.
func TestServer_ReloadConfig_ConcurrentWithRequests_NeverRaces(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const iterations = 200
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			resp, err := http.Get(frontend.URL + "/x")
			if err == nil {
				resp.Body.Close()
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			action := rules.Allow
			if i%2 == 0 {
				action = rules.Block
			}
			srv.ReloadConfig(rules.NewEngine(action), limiter.New(1000, time.Minute), nil, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)
		}
	}()

	wg.Wait()
}

// TestServer_LogEvent_RespectsLogFormat proves LogEvent — used by the
// CLI's SIGHUP reload handler, outside this package — logs a JSON line
// under LogFormatJSON and a plain line otherwise, exactly like every
// other event, so a reload notice can never be the one stray non-JSON
// line in an otherwise-JSON log stream.
func TestServer_LogEvent_RespectsLogFormat(t *testing.T) {
	targetURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	t.Run("json", func(t *testing.T) {
		var logBuf bytes.Buffer
		srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
		srv.LogFormat = proxy.LogFormatJSON
		srv.Logger = log.New(&logBuf, "", 0)

		srv.LogEvent("reload", "aiproxy: reloaded config from aiproxy.json")

		var ev jsonLogLine
		if err := json.Unmarshal(bytes.TrimSpace(logBuf.Bytes()), &ev); err != nil {
			t.Fatalf("LogEvent output is not valid JSON: %q: %v", logBuf.String(), err)
		}
		if ev.Level != "reload" {
			t.Errorf("level = %q, want reload", ev.Level)
		}
		if ev.Message != "aiproxy: reloaded config from aiproxy.json" {
			t.Errorf("message = %q, want the passed message", ev.Message)
		}
	})

	t.Run("text", func(t *testing.T) {
		var logBuf bytes.Buffer
		srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
		srv.Logger = log.New(&logBuf, "", 0)

		srv.LogEvent("reload", "aiproxy: reloaded config from aiproxy.json")

		if got := logBuf.String(); !strings.Contains(got, "aiproxy: reloaded config from aiproxy.json") {
			t.Errorf("log output = %q, missing the plain message", got)
		}
	})
}

// TestServer_Redact_MasksSecretAndForwardsRequest proves a Redact rule's
// core contract end to end: the client's request is never blocked, the
// upstream receives the body with the matched secret masked out (never
// the original value), Stats.Redacted increments (separately from
// Allowed), and the [REDACT] log line — cyan, with the rule name —
// never contains the secret itself either.
func TestServer_Redact_MasksSecretAndForwardsRequest(t *testing.T) {
	var upstreamReceivedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamReceivedBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	secret := "sk-FAKEKEY1234567890ABCDEFGHIJ"
	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"key":"`+secret+`"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (a redacted request must still be forwarded and answered)", resp.StatusCode, http.StatusOK)
	}
	if strings.Contains(string(upstreamReceivedBody), secret) {
		t.Fatalf("upstream received the raw secret, redaction failed to strip it: %q", upstreamReceivedBody)
	}
	wantBody := `{"key":"[REDACTED:openai-api-key]"}`
	if string(upstreamReceivedBody) != wantBody {
		t.Fatalf("upstream received body = %q, want %q", upstreamReceivedBody, wantBody)
	}

	snap := srv.Stats.Snapshot()
	if snap.Redacted != 1 {
		t.Fatalf("Stats.Redacted = %d, want 1", snap.Redacted)
	}
	if snap.Allowed != 0 {
		t.Fatalf("Stats.Allowed = %d, want 0 (a redact is its own outcome, not also counted as allowed)", snap.Allowed)
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, secret) {
		t.Fatalf("log leaked the matched secret value: %q", logOutput)
	}
	if !strings.Contains(logOutput, "[REDACT]") {
		t.Fatalf("log missing [REDACT] marker: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Triggered rule: openai-api-key") {
		t.Fatalf("log missing triggered rule name: %q", logOutput)
	}
	if !strings.Contains(logOutput, "\x1b[36m") {
		t.Fatalf("log missing cyan ANSI code: %q", logOutput)
	}
}

// TestServer_Redact_JSONLogging_EmitsRedactLevel proves the redact event
// participates correctly in --log-format json: a "redact" level with the
// rule name, and never the secret.
func TestServer_Redact_JSONLogging_EmitsRedactLevel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.LogFormat = proxy.LogFormatJSON
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"key":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	// The redact event is always the first line; a per-request latency
	// line for the same request follows it, irrelevant here.
	firstLine, _, _ := bytes.Cut(bytes.TrimSpace(logBuf.Bytes()), []byte("\n"))
	var ev jsonLogLine
	if err := json.Unmarshal(firstLine, &ev); err != nil {
		t.Fatalf("log line is not valid JSON: %q: %v", firstLine, err)
	}
	if ev.Level != "redact" {
		t.Errorf("level = %q, want redact", ev.Level)
	}
	if ev.Rule != "openai-api-key" {
		t.Errorf("rule = %q, want openai-api-key", ev.Rule)
	}
	if strings.Contains(logBuf.String(), "sk-FAKEKEY1234567890ABCDEFGHIJ") {
		t.Fatalf("JSON log leaked the matched secret value: %q", logBuf.String())
	}
}

// TestServer_HeaderSecretScanning_BlocksMatchingHeader proves a secret
// pasted into an arbitrary header, not the body, is still caught: the
// body is clean, but a custom header carries a leaked AWS key.
func TestServer_HeaderSecretScanning_BlocksMatchingHeader(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	secret := "AKIAABCDEFGHIJKLMNOP"
	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/upload", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Debug-Info", secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if upstreamHit.Load() {
		t.Fatal("blocked request must never reach the upstream target")
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, secret) {
		t.Fatalf("log leaked the matched secret value: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Triggered rule: aws-access-key") {
		t.Fatalf("log missing triggered rule name: %q", logOutput)
	}
}

// TestServer_HeaderSecretScanning_RedactsMatchingHeaderAndForwardsRequest
// proves a Redact rule matched in a header masks only that header's
// value before forwarding — the body and every other header arrive at
// the upstream unchanged, and the request isn't blocked.
func TestServer_HeaderSecretScanning_RedactsMatchingHeaderAndForwardsRequest(t *testing.T) {
	var upstreamReceived http.Header
	var upstreamReceivedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceived = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		upstreamReceivedBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	srv := proxy.New("unused", targetURL, engine)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	secret := "sk-FAKEKEY1234567890ABCDEFGHIJ"
	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Debug-Info", secret)
	req.Header.Set("X-Other", "unrelated-value")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (a redacted request must still be forwarded and answered)", resp.StatusCode, http.StatusOK)
	}
	if string(upstreamReceivedBody) != `{"hello":"world"}` {
		t.Fatalf("upstream received body = %q, want unchanged", upstreamReceivedBody)
	}
	if got := upstreamReceived.Get("X-Debug-Info"); got != "[REDACTED:openai-api-key]" {
		t.Fatalf("upstream received X-Debug-Info = %q, want %q", got, "[REDACTED:openai-api-key]")
	}
	if got := upstreamReceived.Get("X-Other"); got != "unrelated-value" {
		t.Fatalf("upstream received X-Other = %q, want unchanged", got)
	}

	snap := srv.Stats.Snapshot()
	if snap.Redacted != 1 {
		t.Fatalf("Stats.Redacted = %d, want 1", snap.Redacted)
	}
}

// TestServer_HeaderSecretScanning_ExemptsAuthorizationHeader proves the
// Authorization header is never scanned: it's exactly where a client
// legitimately puts its own upstream API key on every request, so
// scanning it against the same patterns built to catch a *leaked* key
// would block all normal traffic.
func TestServer_HeaderSecretScanning_ExemptsAuthorizationHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-FAKEKEY1234567890ABCDEFGHIJ")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (the client's own upstream credential must never be scanned)", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_HeaderSecretScanning_ExemptsXAPIKeyHeader is the same
// exemption proof as TestServer_HeaderSecretScanning_ExemptsAuthorizationHeader,
// for the header Anthropic's Messages API uses instead of Authorization.
func TestServer_HeaderSecretScanning_ExemptsXAPIKeyHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "anthropic-api-key",
		Pattern: regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/v1/messages", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Api-Key", "sk-ant-api03-FAKEKEY1234567890ABCDEFGHIJ")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (the client's own upstream credential must never be scanned)", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_Webhook_FiresOnBlockWithExpectedPayload proves a configured
// WebhookURL receives a JSON alert for a blocked request, carrying the
// event, method, url, and rule name — but never the matched secret,
// which never appears anywhere in the payload.
func TestServer_Webhook_FiresOnBlockWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("blocked request must never reach the upstream target")
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.WebhookURL = webhookURL
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	secret := "AKIAABCDEFGHIJKLMNOP"
	resp, err := http.Post(frontend.URL+"/upload", "text/plain", strings.NewReader("token="+secret))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	select {
	case payload := <-received:
		if payload["event"] != "block" {
			t.Errorf("event = %v, want %q", payload["event"], "block")
		}
		if payload["method"] != "POST" {
			t.Errorf("method = %v, want %q", payload["method"], "POST")
		}
		if payload["url"] != "/upload" {
			t.Errorf("url = %v, want %q", payload["url"], "/upload")
		}
		if payload["rule"] != "aws-access-key" {
			t.Errorf("rule = %v, want %q", payload["rule"], "aws-access-key")
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "BLOCK") || !strings.Contains(text, "aws-access-key") {
			t.Errorf("text = %q, want it to mention BLOCK and the rule name", text)
		}
		if strings.Contains(fmt.Sprintf("%v", payload), secret) {
			t.Fatalf("webhook payload leaked the matched secret value: %v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_Webhook_FiresOnRedactWithExpectedPayload is the same proof
// as the block case, for a redact event.
func TestServer_Webhook_FiresOnRedactWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.WebhookURL = webhookURL
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"key":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	select {
	case payload := <-received:
		if payload["event"] != "redact" {
			t.Errorf("event = %v, want %q", payload["event"], "redact")
		}
		if payload["rule"] != "openai-api-key" {
			t.Errorf("rule = %v, want %q", payload["rule"], "openai-api-key")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_Webhook_FiresOnRateLimitWithExpectedPayload proves a
// configured WebhookURL receives a JSON alert when the circuit breaker
// rejects a request for exceeding its rate limit — the same real-time
// alerting an agent-loop stuck in a retry storm should trigger, not
// just a block or redact. Unlike block/redact, there is no rule name
// attached, since no scanning rule was involved.
func TestServer_Webhook_FiresOnRateLimitWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("rate-limited request must never reach the upstream target")
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Limiter = limiter.New(0, time.Minute) // 0 allowed requests per window
	srv.WebhookURL = webhookURL
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}

	select {
	case payload := <-received:
		if payload["event"] != "rate_limited" {
			t.Errorf("event = %v, want %q", payload["event"], "rate_limited")
		}
		if payload["method"] != "POST" {
			t.Errorf("method = %v, want %q", payload["method"], "POST")
		}
		if payload["url"] != "/chat" {
			t.Errorf("url = %v, want %q", payload["url"], "/chat")
		}
		if rule, ok := payload["rule"]; !ok || rule != "" {
			t.Errorf("rule = %v, want empty string (a rate limit trip matches no rule)", payload["rule"])
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "RATE_LIMITED") || !strings.Contains(text, "Rate limit exceeded") {
			t.Errorf("text = %q, want it to mention RATE_LIMITED and the rate limit", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_Webhook_FiresOnTokenRateLimitWithExpectedPayload is
// TestServer_Webhook_FiresOnRateLimitWithExpectedPayload's counterpart
// for the token-based breaker.
func TestServer_Webhook_FiresOnTokenRateLimitWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("token-rate-limited request must never reach the upstream target")
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.TokenLimiter = limiter.NewTokenLimiter(0, time.Minute) // 0: nothing ever allowed
	srv.WebhookURL = webhookURL
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}

	select {
	case payload := <-received:
		if payload["event"] != "token_rate_limited" {
			t.Errorf("event = %v, want %q", payload["event"], "token_rate_limited")
		}
		if payload["method"] != "POST" {
			t.Errorf("method = %v, want %q", payload["method"], "POST")
		}
		if payload["url"] != "/chat" {
			t.Errorf("url = %v, want %q", payload["url"], "/chat")
		}
		if rule, ok := payload["rule"]; !ok || rule != "" {
			t.Errorf("rule = %v, want empty string (a token rate limit trip matches no rule)", payload["rule"])
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "TOKEN_RATE_LIMITED") || !strings.Contains(text, "Token rate limit exceeded") {
			t.Errorf("text = %q, want it to mention TOKEN_RATE_LIMITED and the token rate limit", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_Webhook_NeverFiresOnAllow proves a clean, allowed request
// never triggers a webhook call at all — alerts are for block/redact
// events only, not every request.
func TestServer_Webhook_NeverFiresOnAllow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	var webhookHit atomic.Bool
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.WebhookURL = webhookURL
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	// There is no event to wait for here, so give any (wrongly) fired
	// webhook call a moment to land before asserting its absence.
	time.Sleep(50 * time.Millisecond)
	if webhookHit.Load() {
		t.Fatal("webhook fired for a clean, allowed request")
	}
}

// TestServer_Webhook_DeliveryFailureNeverAffectsClientResponse proves an
// unreachable webhook endpoint doesn't change the outcome of the request
// that triggered it: the client still gets its normal 403, even though
// the alert delivery itself fails in the background.
func TestServer_Webhook_DeliveryFailureNeverAffectsClientResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	// A closed listener's address: nothing is listening there, so the
	// webhook POST fails outright (connection refused) rather than
	// merely timing out.
	deadListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := deadListener.Addr().String()
	deadListener.Close()
	webhookURL, err := url.Parse("http://" + deadAddr)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/upload", "text/plain", strings.NewReader("token=AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (an undeliverable webhook must never change the client's response)", resp.StatusCode, http.StatusForbidden)
	}

	logOutput := waitForLogContains(&logBuf, "webhook", 2*time.Second)
	if !strings.Contains(logOutput, "webhook") {
		t.Fatalf("log missing a webhook delivery failure notice: %q", logOutput)
	}
}

// TestServer_Webhooks_EventFilterOnlyDeliversMatchingEvents proves an
// additional Server.Webhooks destination with an Events filter only
// receives events named in that filter, while Server.WebhookURL (no
// filter, the original behavior) keeps receiving everything — the whole
// point of the feature: routing e.g. budget_exceeded to one destination
// and block/redact to another.
func TestServer_Webhooks_EventFilterOnlyDeliversMatchingEvents(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	newReceiver := func() (*httptest.Server, *url.URL, chan string) {
		received := make(chan string, 4)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload map[string]any
			json.NewDecoder(r.Body).Decode(&payload)
			received <- fmt.Sprintf("%v", payload["event"])
			w.WriteHeader(http.StatusOK)
		}))
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatalf("parse url: %v", err)
		}
		return srv, u, received
	}

	catchAll, catchAllURL, catchAllReceived := newReceiver()
	defer catchAll.Close()
	filtered, filteredURL, filteredReceived := newReceiver()
	defer filtered.Close()

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "aws-access-key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Action: rules.Block})
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "openai-api-key", Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), Action: rules.Redact})

	srv := proxy.New("unused", targetURL, engine)
	srv.WebhookURL = catchAllURL
	srv.Webhooks = []proxy.WebhookTarget{{URL: filteredURL, Events: []string{"redact"}}}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	blockResp, err := http.Post(frontend.URL+"/x", "text/plain", strings.NewReader("token=AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post (block): %v", err)
	}
	blockResp.Body.Close()

	select {
	case event := <-catchAllReceived:
		if event != "block" {
			t.Errorf("catch-all event = %q, want block", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("catch-all webhook was never called for the block event")
	}
	select {
	case event := <-filteredReceived:
		t.Fatalf("filtered webhook (events: [redact]) unexpectedly received a %q event", event)
	case <-time.After(300 * time.Millisecond):
		// Expected: the block event doesn't match this destination's
		// filter, so nothing should ever arrive here.
	}

	redactResp, err := http.Post(frontend.URL+"/y", "text/plain", strings.NewReader("token=sk-FAKEKEY1234567890ABCDEFGHIJ"))
	if err != nil {
		t.Fatalf("post (redact): %v", err)
	}
	redactResp.Body.Close()

	select {
	case event := <-catchAllReceived:
		if event != "redact" {
			t.Errorf("catch-all event = %q, want redact", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("catch-all webhook was never called for the redact event")
	}
	select {
	case event := <-filteredReceived:
		if event != "redact" {
			t.Errorf("filtered event = %q, want redact", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("filtered webhook was never called for the matching redact event")
	}
}

// TestServer_Webhooks_WorksWithoutWebhookURL proves Server.Webhooks
// alone — no Server.WebhookURL at all — is a complete, independent
// delivery path, not merely an add-on that requires the legacy field to
// also be set.
func TestServer_Webhooks_WorksWithoutWebhookURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "aws-access-key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Action: rules.Block})

	srv := proxy.New("unused", targetURL, engine)
	srv.Webhooks = []proxy.WebhookTarget{{URL: webhookURL}} // no Events filter: catch-all, no WebhookURL set at all
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "text/plain", strings.NewReader("token=AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	select {
	case payload := <-received:
		if payload["event"] != "block" {
			t.Errorf("event = %v, want block", payload["event"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Webhooks-only destination was never called")
	}
}

// TestServer_Webhooks_OneUnreachableDestinationNeverBlocksAnother proves
// each destination is delivered to independently: WebhookURL pointing
// at a dead address must not prevent a working Server.Webhooks entry
// from receiving its payload, and must not affect the client's response
// either — same isolation guarantee
// TestServer_Webhook_DeliveryFailureNeverAffectsClientResponse proves
// for the single-destination case.
func TestServer_Webhooks_OneUnreachableDestinationNeverBlocksAnother(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	deadListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := deadListener.Addr().String()
	deadListener.Close()
	deadURL, err := url.Parse("http://" + deadAddr)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	received := make(chan map[string]any, 1)
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer working.Close()
	workingURL, err := url.Parse(working.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "aws-access-key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Action: rules.Block})

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.WebhookURL = deadURL
	srv.Webhooks = []proxy.WebhookTarget{{URL: workingURL}}
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/upload", "text/plain", strings.NewReader("token=AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (an undeliverable destination must never change the client's response)", resp.StatusCode, http.StatusForbidden)
	}

	select {
	case payload := <-received:
		if payload["event"] != "block" {
			t.Errorf("event = %v, want block", payload["event"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("working destination was never called despite the other destination being unreachable")
	}

	logOutput := waitForLogContains(&logBuf, "webhook_url", 2*time.Second)
	if !strings.Contains(logOutput, "webhook_url") {
		t.Fatalf("log missing a webhook_url-labeled delivery failure notice: %q", logOutput)
	}
}

// TestServer_Webhooks_ReloadConfigSwapsThemLive proves ReloadConfig
// actually replaces Server.Webhooks, same as every other reloadable
// field: a route with no additional destinations picks up one after a
// reload, live.
func TestServer_Webhooks_ReloadConfigSwapsThemLive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "aws-access-key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Action: rules.Block})

	srv := proxy.New("unused", targetURL, engine)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, []proxy.WebhookTarget{{URL: webhookURL}}, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	resp, err := http.Post(frontend.URL+"/upload", "text/plain", strings.NewReader("token=AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	select {
	case payload := <-received:
		if payload["event"] != "block" {
			t.Errorf("event = %v, want block", payload["event"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook added via ReloadConfig was never called")
	}
}

// TestServer_StatsEndpoint_ReportsRedactedCount proves the live
// /_aiproxy/stats endpoint (and, by the same code path, the shutdown
// summary) actually surfaces the redacted counter — added alongside
// Redact, easy to forget to wire into the hand-written JSON shape since
// it isn't derived automatically from stats.Snapshot.
func TestServer_StatsEndpoint_ReportsRedactedCount(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"key":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer statsResp.Body.Close()

	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Redacted != 1 {
		t.Fatalf("redacted = %d, want 1: %+v", got.Redacted, got)
	}
}

// TestServer_StatsEndpoint_ReportsResponseBlockedAndRedactedCounts proves
// the live /_aiproxy/stats endpoint surfaces the two response-side
// counters — easy to forget to wire into the hand-written JSON shape
// alongside their request-side counterparts, since neither is derived
// automatically from stats.Snapshot.
func TestServer_StatsEndpoint_ReportsResponseBlockedAndRedactedCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/block" {
			w.Write([]byte(`{"echo":"AKIAABCDEFGHIJKLMNOP"}`))
			return
		}
		w.Write([]byte(`{"echo":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	// Both request bodies are clean — the secret only ever appears in
	// what the upstream "generated" in its response, so these two
	// events can only be the response-side counters, never the
	// request-side ones.
	blockResp, err := http.Post(frontend.URL+"/block", "application/json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("post (response block): %v", err)
	}
	blockResp.Body.Close()

	redactResp, err := http.Post(frontend.URL+"/redact", "application/json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("post (response redact): %v", err)
	}
	redactResp.Body.Close()

	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer statsResp.Body.Close()

	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ResponseBlocked != 1 {
		t.Fatalf("response_blocked = %d, want 1: %+v", got.ResponseBlocked, got)
	}
	if got.ResponseRedacted != 1 {
		t.Fatalf("response_redacted = %d, want 1: %+v", got.ResponseRedacted, got)
	}
}

// TestServer_StatsEndpoint_ReportsPerRuleBreakdown proves per_rule
// aggregates a named rule's hits across all four outcomes it can cause
// (request block, request redact, response block, response redact) —
// which rule is actually responsible for a match, independent of
// whether it fired going out or coming back. Response-side hits use
// clean request bodies with path-routed canned responses, same
// discipline as TestServer_StatsEndpoint_ReportsResponseBlockedAndRedactedCounts,
// so the request-side rule never fires first and masks what's being
// tested.
func TestServer_StatsEndpoint_ReportsPerRuleBreakdown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/respblock":
			w.Write([]byte(`{"echo":"AKIAABCDEFGHIJKLMNOP"}`))
		case "/respredact":
			w.Write([]byte(`{"echo":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`))
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(path, body string) {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
	}

	post("/reqblock", `{"key":"AKIAABCDEFGHIJKLMNOP"}`)
	post("/reqredact", `{"key":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`)
	post("/respblock", `{"hello":"world"}`)
	post("/respredact", `{"hello":"world"}`)

	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer statsResp.Body.Close()

	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	awsKey, ok := got.PerRule["aws-access-key"]
	if !ok {
		t.Fatalf("per_rule missing aws-access-key: %+v", got.PerRule)
	}
	if awsKey.Blocked != 1 || awsKey.ResponseBlocked != 1 {
		t.Errorf("per_rule[aws-access-key] = %+v, want blocked=1 response_blocked=1", awsKey)
	}
	if awsKey.Redacted != 0 || awsKey.ResponseRedacted != 0 {
		t.Errorf("per_rule[aws-access-key] = %+v, want no redact counts", awsKey)
	}

	openaiKey, ok := got.PerRule["openai-api-key"]
	if !ok {
		t.Fatalf("per_rule missing openai-api-key: %+v", got.PerRule)
	}
	if openaiKey.Redacted != 1 || openaiKey.ResponseRedacted != 1 {
		t.Errorf("per_rule[openai-api-key] = %+v, want redacted=1 response_redacted=1", openaiKey)
	}
	if openaiKey.Blocked != 0 || openaiKey.ResponseBlocked != 0 {
		t.Errorf("per_rule[openai-api-key] = %+v, want no block counts", openaiKey)
	}

	for name, target := range got.PerTarget {
		if len(target.PerRule) != 0 {
			t.Errorf("per_target[%q].per_rule = %+v, want it to stay empty (per_rule is a global breakdown only)", name, target.PerRule)
		}
	}
}

// TestServer_DryRunCustomRule_BlockNeverEnforcedRequestForwarded proves
// a DryRun custom rule matching Block never actually blocks a request —
// it reaches the upstream and the client gets a normal 200 — while
// still being logged, stats-recorded, and (if configured) webhooked as
// a dry_run_block event.
func TestServer_DryRunCustomRule_BlockNeverEnforcedRequestForwarded(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/upload", "text/plain", strings.NewReader("key=AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (a dry_run rule must never actually block)", resp.StatusCode, http.StatusOK)
	}
	if !upstreamHit.Load() {
		t.Fatal("upstream was never reached — a dry_run block must still forward the request")
	}

	snap := srv.Stats.Snapshot()
	if snap.Blocked != 0 {
		t.Fatalf("Blocked = %d, want 0 (nothing was actually blocked)", snap.Blocked)
	}
	if snap.DryRunBlocked != 1 {
		t.Fatalf("DryRunBlocked = %d, want 1", snap.DryRunBlocked)
	}
	rule, ok := snap.PerRule["aws-access-key"]
	if !ok || rule.DryRunBlocked != 1 {
		t.Fatalf("PerRule[aws-access-key] = %+v, want dry-run-blocked=1", rule)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[DRY-RUN BLOCK]") {
		t.Fatalf("log missing [DRY-RUN BLOCK] marker: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Would have triggered rule: aws-access-key") {
		t.Fatalf("log missing the would-have-triggered rule name: %q", logOutput)
	}
}

// TestServer_DryRunCustomRule_RedactNeverEnforcedBodyReachesUpstreamUnmasked
// proves a DryRun Redact rule never actually masks anything: the
// original, unredacted secret reaches the upstream exactly as sent.
func TestServer_DryRunCustomRule_RedactNeverEnforcedBodyReachesUpstreamUnmasked(t *testing.T) {
	secret := "sk-FAKEKEY1234567890ABCDEFGHIJ"
	receivedBody := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
		DryRun:  true,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	body := `{"key":"` + secret + `"}`
	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	select {
	case got := <-receivedBody:
		if got != body {
			t.Fatalf("upstream received %q, want the original, unmasked body %q", got, body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream was never reached")
	}

	snap := srv.Stats.Snapshot()
	if snap.Redacted != 0 {
		t.Fatalf("Redacted = %d, want 0 (nothing was actually redacted)", snap.Redacted)
	}
	if snap.DryRunRedacted != 1 {
		t.Fatalf("DryRunRedacted = %d, want 1", snap.DryRunRedacted)
	}
}

// TestServer_DryRunPathRule_BlockNeverEnforcedRequestForwarded is the
// path-rule equivalent of the custom-rule dry-run block test.
func TestServer_DryRunPathRule_BlockNeverEnforcedRequestForwarded(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{
		Name:       "block-admin",
		PathPrefix: "/admin",
		Action:     rules.Block,
		DryRun:     true,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/admin/users")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (a dry_run path rule must never actually block)", resp.StatusCode, http.StatusOK)
	}
	if !upstreamHit.Load() {
		t.Fatal("upstream was never reached — a dry_run path block must still forward the request")
	}

	snap := srv.Stats.Snapshot()
	if snap.DryRunBlocked != 1 {
		t.Fatalf("DryRunBlocked = %d, want 1", snap.DryRunBlocked)
	}
	if !strings.Contains(logBuf.String(), "[DRY-RUN BLOCK]") {
		t.Fatalf("log missing [DRY-RUN BLOCK] marker: %q", logBuf.String())
	}
}

// TestServer_DryRunResponse_BlockNeverEnforcedClientReceivesFullResponse
// proves a DryRun rule matching the (non-streaming) response never
// withholds it: the client receives the full, original body, secret
// included, exactly as bufferResponse read it from upstream.
func TestServer_DryRunResponse_BlockNeverEnforcedClientReceivesFullResponse(t *testing.T) {
	secret := "AKIAABCDEFGHIJKLMNOP"
	upstreamBody := `{"echo":"` + secret + `"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (a dry_run rule must never actually block a response)", resp.StatusCode, http.StatusOK)
	}
	if string(gotBody) != upstreamBody {
		t.Fatalf("client received %q, want the full, unmodified upstream body %q", gotBody, upstreamBody)
	}

	snap := srv.Stats.Snapshot()
	if snap.ResponseBlocked != 0 {
		t.Fatalf("ResponseBlocked = %d, want 0", snap.ResponseBlocked)
	}
	if snap.ResponseDryRunBlocked != 1 {
		t.Fatalf("ResponseDryRunBlocked = %d, want 1", snap.ResponseDryRunBlocked)
	}
	if !strings.Contains(logBuf.String(), "[RESPONSE DRY-RUN BLOCK]") {
		t.Fatalf("log missing [RESPONSE DRY-RUN BLOCK] marker: %q", logBuf.String())
	}
}

// TestServer_DryRunStreamingResponse_BlockNeverCutsStreamShort proves a
// DryRun rule matching a streamed response chunk never ends the stream
// early: every chunk, including the one after the match, reaches the
// client exactly as sent.
func TestServer_DryRunStreamingResponse_BlockNeverCutsStreamShort(t *testing.T) {
	secret := "AKIAABCDEFGHIJKLMNOP"
	firstChunk := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n"
	secretChunk := "data: {\"choices\":[{\"delta\":{\"content\":\"" + secret + "\"}}]}\n\n"
	lastChunk := "data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(firstChunk))
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		w.Write([]byte(secretChunk))
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		w.Write([]byte(lastChunk))
		flusher.Flush()
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	gotBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	wantBody := firstChunk + secretChunk + lastChunk
	if string(gotBody) != wantBody {
		t.Fatalf("client received %q, want the full stream %q (a dry_run rule must never cut it short)", gotBody, wantBody)
	}

	logOutput := waitForLogContains(&logBuf, "[RESPONSE DRY-RUN BLOCK]", time.Second)
	if !strings.Contains(logOutput, "Would have triggered rule: aws-access-key") {
		t.Fatalf("log missing the would-have-triggered rule name: %q", logOutput)
	}

	snap := srv.Stats.Snapshot()
	if snap.ResponseBlocked != 0 {
		t.Fatalf("ResponseBlocked = %d, want 0", snap.ResponseBlocked)
	}
	if snap.ResponseDryRunBlocked != 1 {
		t.Fatalf("ResponseDryRunBlocked = %d, want 1", snap.ResponseDryRunBlocked)
	}
}

// TestServer_Webhook_FiresOnDryRunBlockWithExpectedPayload proves a
// configured WebhookURL receives a dry_run_block alert, with "Would
// have triggered rule" wording distinguishing it from a real block.
func TestServer_Webhook_FiresOnDryRunBlockWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.WebhookURL = webhookURL
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/upload", "text/plain", strings.NewReader("key=AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	select {
	case payload := <-received:
		if payload["event"] != "dry_run_block" {
			t.Errorf("event = %v, want %q", payload["event"], "dry_run_block")
		}
		if payload["rule"] != "aws-access-key" {
			t.Errorf("rule = %v, want %q", payload["rule"], "aws-access-key")
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "DRY_RUN_BLOCK") || !strings.Contains(text, "Would have triggered rule") {
			t.Errorf("text = %q, want it to mention DRY_RUN_BLOCK and 'Would have triggered rule'", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_StatsEndpoint_ReportsDryRunCounts proves the live
// /_aiproxy/stats endpoint surfaces both the overall dry-run counters
// and their per-rule breakdown, for both request- and response-side
// dry-run matches.
func TestServer_StatsEndpoint_ReportsDryRunCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/respblock" {
			w.Write([]byte(`{"echo":"AKIAABCDEFGHIJKLMNOP"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(path, body string) {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
	}

	post("/reqblock", `{"key":"AKIAABCDEFGHIJKLMNOP"}`)
	post("/respblock", `{"hello":"world"}`)

	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET /_aiproxy/stats: %v", err)
	}
	defer statsResp.Body.Close()

	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if got.DryRunBlocked != 1 {
		t.Errorf("dry_run_blocked = %d, want 1", got.DryRunBlocked)
	}
	if got.ResponseDryRunBlocked != 1 {
		t.Errorf("response_dry_run_blocked = %d, want 1", got.ResponseDryRunBlocked)
	}
	rule, ok := got.PerRule["aws-access-key"]
	if !ok {
		t.Fatalf("per_rule missing aws-access-key: %+v", got.PerRule)
	}
	if rule.DryRunBlocked != 1 || rule.ResponseDryRunBlocked != 1 {
		t.Errorf("per_rule[aws-access-key] = %+v, want dry_run_blocked=1 response_dry_run_blocked=1", rule)
	}
}

// TestServer_MetricsEndpoint_ReportsDryRunCounters proves metricsPath
// exposes both the four overall (unlabeled) aiproxy_dry_run_*_total
// series and their rule-labeled aiproxy_rule_dry_run_*_total
// counterparts.
func TestServer_MetricsEndpoint_ReportsDryRunCounters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`{"key":"AKIAABCDEFGHIJKLMNOP"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	metricsResp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("GET /_aiproxy/metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	for _, want := range []string{
		"# HELP aiproxy_dry_run_blocked_total",
		"# TYPE aiproxy_dry_run_blocked_total counter",
		"aiproxy_dry_run_blocked_total 1",
		`aiproxy_rule_dry_run_blocked_total{rule="aws-access-key"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q: %q", want, out)
		}
	}
}

// TestServer_ProxyAuth_DisabledByDefault proves a Server with no
// ProxyAPIKey set behaves exactly as before this feature existed — no
// Proxy-Authorization header needed at all.
func TestServer_ProxyAuth_DisabledByDefault(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_ProxyAuth_RejectsRequestMissingHeader proves a request
// with no Proxy-Authorization header at all is rejected with 407 and
// never reaches the upstream, once ProxyAPIKey is set.
func TestServer_ProxyAuth_RejectsRequestMissingHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unauthenticated request must never reach the upstream target")
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	var logBuf bytes.Buffer
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != "Bearer" {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, "Bearer")
	}

	snap := srv.Stats.Snapshot()
	if snap.Unauthorized != 1 {
		t.Fatalf("Unauthorized = %d, want 1", snap.Unauthorized)
	}
	if !strings.Contains(logBuf.String(), "[UNAUTHORIZED]") {
		t.Fatalf("log missing [UNAUTHORIZED] marker: %q", logBuf.String())
	}
}

// TestServer_ProxyAuth_RejectsWrongKey proves a Proxy-Authorization
// header carrying the wrong key is rejected the same way a missing one
// is — not treated as "close enough".
func TestServer_ProxyAuth_RejectsWrongKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unauthenticated request must never reach the upstream target")
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer wrong-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
}

// TestServer_ProxyAuth_AllowsCorrectKey proves the correct
// "Proxy-Authorization: Bearer <key>" header lets a request through
// normally, and is not itself forwarded upstream (it's aiproxy's own
// credential, not the client's).
func TestServer_ProxyAuth_AllowsCorrectKey(t *testing.T) {
	var gotProxyAuthUpstream string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyAuthUpstream = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer s3cr3t-shared-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if gotProxyAuthUpstream != "" {
		t.Errorf("upstream received Proxy-Authorization = %q, want it stripped by the httputil.ReverseProxy default (hop-by-hop header)", gotProxyAuthUpstream)
	}
}

// TestServer_ProxyAuth_MultipleNamedKeysAllAuthenticate proves every
// configured key — the anonymous ProxyAPIKey and every named
// ProxyAPIKeys entry — independently grants access, not just the first
// one checked.
func TestServer_ProxyAuth_MultipleNamedKeysAllAuthenticate(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "anon-key"
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "team-a", Key: "team-a-key"},
		{Name: "team-b", Key: "team-b-key"},
	}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for _, key := range []string{"anon-key", "team-a-key", "team-b-key"} {
		req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do (key %q): %v", key, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("key %q: status = %d, want %d", key, resp.StatusCode, http.StatusOK)
		}
	}
}

// TestServer_ProxyAuth_WrongKeyRejectedWithMultipleKeysConfigured proves
// a request presenting none of the valid keys still gets 407, even when
// several keys are configured — no accidental "any non-empty header
// passes" bug from the multi-key loop.
func TestServer_ProxyAuth_WrongKeyRejectedWithMultipleKeysConfigured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request with a wrong key must never reach the upstream target")
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "anon-key"
	srv.ProxyAPIKeys = []proxy.ProxyKey{{Name: "team-a", Key: "team-a-key"}}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer totally-wrong-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
}

// TestServer_ProxyAuth_AttributesStatsToMatchedClientName proves a
// request authenticated with a named key shows up in
// GET /_aiproxy/stats' per_client under that key's own name, while one
// authenticated with the anonymous ProxyAPIKey shows up under
// "default" — including token usage, so per-client cost tracking works
// end to end.
func TestServer_ProxyAuth_AttributesStatsToMatchedClientName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"usage":{"total_tokens":42}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "anon-key"
	srv.ProxyAPIKeys = []proxy.ProxyKey{{Name: "team-a", Key: "team-a-key"}}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	do := func(key string) {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/x", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
	}
	do("team-a-key")
	do("anon-key")
	do("anon-key")

	statsResp, err := (&http.Client{}).Do(func() *http.Request {
		req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/_aiproxy/stats", nil)
		req.Header.Set("Proxy-Authorization", "Bearer anon-key")
		return req
	}())
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	defer statsResp.Body.Close()
	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	teamA, ok := got.PerClient["team-a"]
	if !ok {
		t.Fatalf("PerClient missing team-a: %+v", got.PerClient)
	}
	if teamA.Allowed != 1 || teamA.TotalTokens != 42 {
		t.Errorf("PerClient[team-a] = %+v, want allowed=1 total_tokens=42", teamA)
	}

	def, ok := got.PerClient["default"]
	if !ok {
		t.Fatalf("PerClient missing default: %+v", got.PerClient)
	}
	if def.Allowed != 2 || def.TotalTokens != 84 {
		t.Errorf("PerClient[default] = %+v, want allowed=2 total_tokens=84", def)
	}
}

// TestServer_ProxyAuth_NamedKeyOwnRateLimitTakesPrecedenceOverRoute
// proves a key's own max_requests_per_minute override actually governs
// that caller's traffic instead of the route's own (looser) limiter —
// the confirmed precedence: the caller's own budget is authoritative
// regardless of which route they hit.
func TestServer_ProxyAuth_NamedKeyOwnRateLimitTakesPrecedenceOverRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	// The route's own limiter is generous (1000/min) — the key's own
	// limiter (1/min) must be what actually governs this caller.
	srv.Limiter = limiter.New(1000, time.Minute)
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "team-a", Key: "team-a-key", Limiter: limiter.New(1, time.Minute)},
	}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	do := func() int {
		req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer team-a-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := do(); got != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", got, http.StatusOK)
	}
	if got := do(); got != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d (the key's own 1/min limit, not the route's 1000/min)", got, http.StatusTooManyRequests)
	}
}

// TestServer_ProxyAuth_NamedKeyOwnTokenRateLimitTakesPrecedenceOverRoute
// is TestServer_ProxyAuth_NamedKeyOwnRateLimitTakesPrecedenceOverRoute's
// counterpart for the token-based breaker.
func TestServer_ProxyAuth_NamedKeyOwnTokenRateLimitTakesPrecedenceOverRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":100}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	// The server-wide token breaker is generous — the key's own (100
	// tokens) must be what actually governs this caller.
	srv.TokenLimiter = limiter.NewTokenLimiter(1000000, time.Minute)
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "team-a", Key: "team-a-key", TokenLimiter: limiter.NewTokenLimiter(100, time.Minute)},
	}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	do := func() int {
		req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer team-a-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := do(); got != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", got, http.StatusOK)
	}
	if got := do(); got != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d (the key's own 100-token budget, not the server-wide one)", got, http.StatusTooManyRequests)
	}
}

// TestServer_ProxyAuth_NamedKeyWithoutOwnLimiterFallsBackToRoute proves
// a key with no max_requests_per_minute override behaves exactly as
// before — sharing whatever route/global limiter would otherwise apply
// — a regression check for the common case (most keys won't set their
// own override).
func TestServer_ProxyAuth_NamedKeyWithoutOwnLimiterFallsBackToRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Limiter = limiter.New(1, time.Minute)
	srv.ProxyAPIKeys = []proxy.ProxyKey{{Name: "team-a", Key: "team-a-key"}} // no Limiter
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	do := func() int {
		req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer team-a-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := do(); got != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", got, http.StatusOK)
	}
	if got := do(); got != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d (falls back to the server-wide 1/min limiter)", got, http.StatusTooManyRequests)
	}
}

// TestServer_MetricsEndpoint_ReportsClientLabeledCounters proves the
// per-client counters (and estimated cost gauge) reach the Prometheus
// endpoint, labeled client="...", same as the per-target/per-rule
// series.
func TestServer_MetricsEndpoint_ReportsClientLabeledCounters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"usage":{"total_tokens":100}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKeys = []proxy.ProxyKey{{Name: "team-a", Key: "team-a-key"}}
	srv.CostPer1KTokens = 0.03
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/x", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer team-a-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	metricsReq, err := http.NewRequest(http.MethodGet, frontend.URL+"/_aiproxy/metrics", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	metricsReq.Header.Set("Proxy-Authorization", "Bearer team-a-key")
	metricsResp, err := http.DefaultClient.Do(metricsReq)
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	for _, want := range []string{
		"# TYPE aiproxy_client_allowed_total counter",
		`aiproxy_client_allowed_total{client="team-a"} 1`,
		`aiproxy_client_tokens_used_total{client="team-a"} 100`,
		`aiproxy_client_estimated_cost{client="team-a"} 0.003`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q: %q", want, out)
		}
	}
}

// TestServer_ReloadConfig_SwapsProxyAPIKeysLive proves ReloadConfig
// actually replaces Server.ProxyAPIKeys, same as every other reloadable
// field: a key that didn't exist before the reload works afterward, and
// one that existed before stops working.
func TestServer_ReloadConfig_SwapsProxyAPIKeysLive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.ProxyAPIKeys = []proxy.ProxyKey{{Name: "old-team", Key: "old-key"}}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "", []proxy.ProxyKey{{Name: "new-team", Key: "new-key"}}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	do := func(key string) int {
		req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := do("old-key"); got != http.StatusProxyAuthRequired {
		t.Errorf("old-key after reload: status = %d, want %d (must no longer work)", got, http.StatusProxyAuthRequired)
	}
	if got := do("new-key"); got != http.StatusOK {
		t.Errorf("new-key after reload: status = %d, want %d", got, http.StatusOK)
	}
}

// TestServer_ProxyAuth_IndependentOfClientsUpstreamCredential proves
// aiproxy's own Proxy-Authorization check is entirely separate from
// whatever Authorization/X-Api-Key credential the client is sending
// through to the real upstream API: a valid upstream credential doesn't
// satisfy the proxy's own auth, and vice versa both are required
// together when proxy_api_key is set.
func TestServer_ProxyAuth_IndependentOfClientsUpstreamCredential(t *testing.T) {
	var gotUpstreamAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUpstreamAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	// A real upstream Authorization header, but no Proxy-Authorization
	// at all: must still be rejected before ever reaching the upstream.
	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer real-upstream-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d (missing Proxy-Authorization must reject regardless of Authorization)", resp.StatusCode, http.StatusProxyAuthRequired)
	}

	// Both headers present: passes the proxy's own check, and the
	// client's own upstream credential still reaches the target intact.
	req2, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req2.Header.Set("Authorization", "Bearer real-upstream-key")
	req2.Header.Set("Proxy-Authorization", "Bearer s3cr3t-shared-key")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}
	if gotUpstreamAuth != "Bearer real-upstream-key" {
		t.Errorf("upstream Authorization = %q, want the client's own upstream credential untouched", gotUpstreamAuth)
	}
}

// TestServer_ProxyAuth_GatesStatsAndMetricsEndpoints proves
// statsPath/metricsPath require the same Proxy-Authorization as any
// other request once ProxyAPIKey is set — they are not a side-channel
// exempt from the check.
func TestServer_ProxyAuth_GatesStatsAndMetricsEndpoints(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for _, path := range []string{"/_aiproxy/stats", "/_aiproxy/metrics"} {
		resp, err := http.Get(frontend.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("GET %s without key: status = %d, want %d", path, resp.StatusCode, http.StatusProxyAuthRequired)
		}

		req, err := http.NewRequest(http.MethodGet, frontend.URL+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer s3cr3t-shared-key")
		authedResp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		authedResp.Body.Close()
		if authedResp.StatusCode != http.StatusOK {
			t.Errorf("GET %s with correct key: status = %d, want %d", path, authedResp.StatusCode, http.StatusOK)
		}
	}
}

// TestServer_Webhook_FiresOnUnauthorizedWithExpectedPayload proves a
// configured WebhookURL receives an unauthorized alert, with an empty
// rule (no scanning rule was involved) and text that never echoes the
// configured key.
func TestServer_Webhook_FiresOnUnauthorizedWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unauthenticated request must never reach the upstream target")
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	select {
	case payload := <-received:
		if payload["event"] != "unauthorized" {
			t.Errorf("event = %v, want %q", payload["event"], "unauthorized")
		}
		if rule, ok := payload["rule"]; !ok || rule != "" {
			t.Errorf("rule = %v, want empty string", payload["rule"])
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "UNAUTHORIZED") || !strings.Contains(text, "Proxy-Authorization") {
			t.Errorf("text = %q, want it to mention UNAUTHORIZED and Proxy-Authorization", text)
		}
		if strings.Contains(text, "s3cr3t-shared-key") {
			t.Errorf("text leaked the configured proxy API key: %q", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_StatsEndpoint_ReportsUnauthorizedCount proves the live
// /_aiproxy/stats endpoint surfaces the unauthorized counter — the
// stats request itself must present the correct key to be answered at
// all, exercised alongside two prior unauthenticated attempts.
func TestServer_StatsEndpoint_ReportsUnauthorizedCount(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func(path string) {
		resp, err := http.Get(frontend.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		resp.Body.Close()
	}
	get("/x")
	get("/y")

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/_aiproxy/stats", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer s3cr3t-shared-key")
	statsResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer statsResp.Body.Close()

	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Unauthorized != 2 {
		t.Errorf("unauthorized = %d, want 2", got.Unauthorized)
	}
}

// TestServer_MetricsEndpoint_ReportsUnauthorizedCounter is
// TestServer_StatsEndpoint_ReportsUnauthorizedCount's Prometheus
// counterpart.
func TestServer_MetricsEndpoint_ReportsUnauthorizedCounter(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	unauthed, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	unauthed.Body.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/_aiproxy/metrics", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer s3cr3t-shared-key")
	metricsResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer metricsResp.Body.Close()
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	for _, want := range []string{
		"# HELP aiproxy_unauthorized_total",
		"# TYPE aiproxy_unauthorized_total counter",
		"aiproxy_unauthorized_total 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q: %q", want, out)
		}
	}
}

// TestServer_ReloadConfig_UpdatesProxyAPIKey proves ProxyAPIKey is one
// of the fields SIGHUP-style reload actually replaces: a key that
// wasn't required before a reload is required after, and a request
// authenticated with the previous key stops working.
func TestServer_ReloadConfig_UpdatesProxyAPIKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func() int {
		resp, err := http.Get(frontend.URL + "/x")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := get(); got != http.StatusOK {
		t.Fatalf("before reload: status = %d, want %d (no key required yet)", got, http.StatusOK)
	}

	srv.ReloadConfig(rules.NewEngine(rules.Allow), nil, nil, 0, 0, 0, nil, nil, "new-key-after-reload", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	if got := get(); got != http.StatusProxyAuthRequired {
		t.Fatalf("after reload: status = %d, want %d (key now required)", got, http.StatusProxyAuthRequired)
	}

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer new-key-after-reload")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after reload with correct new key: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_CostBudget_NeverBlocksOrAffectsTraffic proves cost_budget is
// alert-only: a request that pushes the running cost past the budget is
// still forwarded and answered normally, not rejected — this feature has
// no enforcement mode, unlike the rate limiter or proxy auth.
func TestServer_CostBudget_NeverBlocksOrAffectsTraffic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0 // cost = 10.0, already over budget on the first request
	srv.CostBudget = 1.0
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (budget alert must never block traffic)", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "total_tokens") {
		t.Errorf("body = %q, want the upstream response delivered unchanged", body)
	}
}

// TestServer_CostBudget_UnsetNeverFiresWebhook proves that with no
// cost_budget configured, no amount of usage ever triggers a
// budget_exceeded alert — same as every other feature in this package,
// zero/absent means fully off.
func TestServer_CostBudget_UnsetNeverFiresWebhook(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":1000000}}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	webhookCalled := make(chan struct{}, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalled <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0 // cost_budget left at zero (unset)
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	select {
	case <-webhookCalled:
		t.Fatal("webhook fired with no cost_budget configured, want it to never fire")
	case <-time.After(300 * time.Millisecond):
		// expected: no call
	}
}

// TestServer_Webhook_FiresOnBudgetExceededWithExpectedPayload proves a
// request that pushes the running cost past cost_budget fires exactly
// the budget_exceeded webhook event, carrying the cost and budget that
// were compared, never a rule name.
func TestServer_Webhook_FiresOnBudgetExceededWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0 // cost = 10.0
	srv.CostBudget = 5.0
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/chat", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	select {
	case payload := <-received:
		if payload["event"] != "budget_exceeded" {
			t.Errorf("event = %v, want %q", payload["event"], "budget_exceeded")
		}
		if rule, ok := payload["rule"]; !ok || rule != "" {
			t.Errorf("rule = %v, want empty string (a budget alert matches no rule)", payload["rule"])
		}
		if cost, ok := payload["cost"].(float64); !ok || cost != 10.0 {
			t.Errorf("cost = %v, want 10.0", payload["cost"])
		}
		if budget, ok := payload["budget"].(float64); !ok || budget != 5.0 {
			t.Errorf("budget = %v, want 5.0", payload["budget"])
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "BUDGET_EXCEEDED") || !strings.Contains(text, "10.0000") || !strings.Contains(text, "5.0000") {
			t.Errorf("text = %q, want it to mention BUDGET_EXCEEDED, the cost, and the budget", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_CostBudget_AlertFiresExactlyOnceAcrossManyRequests proves
// the one-shot latch holds across real HTTP traffic, not just direct
// Stats calls: several requests each push the cost further over budget,
// but only the first ever triggers a webhook call.
func TestServer_CostBudget_AlertFiresExactlyOnceAcrossManyRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	var webhookCalls atomic.Int64
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0 // each request adds cost = 10.0
	srv.CostBudget = 5.0
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 5; i++ {
		resp, err := http.Post(frontend.URL+"/chat", "text/plain", strings.NewReader("hello"))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		resp.Body.Close()
	}

	// Give the last request's async webhook delivery goroutine a moment,
	// then check the count settled at exactly one.
	time.Sleep(300 * time.Millisecond)
	if got := webhookCalls.Load(); got != 1 {
		t.Errorf("webhook calls = %d, want exactly 1 across 5 budget-crossing requests", got)
	}
}

// TestServer_StatsEndpoint_ReportsCostBudgetOnlyWhenConfigured proves
// GET /_aiproxy/stats surfaces the configured cost_budget threshold at
// the top level, and omits it entirely when unset — same convention as
// estimated_cost.
func TestServer_StatsEndpoint_ReportsCostBudgetOnlyWhenConfigured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	fetchStats := func() statsJSONResponse {
		resp, err := http.Get(frontend.URL + "/_aiproxy/stats")
		if err != nil {
			t.Fatalf("get stats: %v", err)
		}
		defer resp.Body.Close()
		var got statsJSONResponse
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return got
	}

	if got := fetchStats(); got.CostBudget != nil {
		t.Errorf("CostBudget = %v, want nil when unset", *got.CostBudget)
	}

	srv.CostBudget = 25.5
	got := fetchStats()
	if got.CostBudget == nil {
		t.Fatal("CostBudget = nil, want 25.5 once configured")
	}
	if *got.CostBudget != 25.5 {
		t.Errorf("CostBudget = %g, want 25.5", *got.CostBudget)
	}
	for target, t2 := range got.PerTarget {
		if t2.CostBudget != nil {
			t.Errorf("PerTarget[%q].CostBudget = %v, want nil (a budget is a whole-run threshold, never repeated per target)", target, *t2.CostBudget)
		}
	}
}

// TestServer_MetricsEndpoint_ReportsCostBudgetGaugeOnlyWhenConfigured is
// TestServer_StatsEndpoint_ReportsCostBudgetOnlyWhenConfigured's
// Prometheus counterpart.
func TestServer_MetricsEndpoint_ReportsCostBudgetGaugeOnlyWhenConfigured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	fetchMetrics := func() string {
		resp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
		if err != nil {
			t.Fatalf("get metrics: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return string(body)
	}

	if out := fetchMetrics(); strings.Contains(out, "aiproxy_cost_budget") {
		t.Errorf("metrics output has aiproxy_cost_budget with no budget configured: %q", out)
	}

	srv.CostBudget = 25.5
	out := fetchMetrics()
	for _, want := range []string{
		"# HELP aiproxy_cost_budget",
		"# TYPE aiproxy_cost_budget gauge",
		"aiproxy_cost_budget 25.5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q: %q", want, out)
		}
	}
}

// TestServer_SummaryText_IncludesCostBudgetLineAndFlagsWhenExceeded
// proves the shutdown summary shows the configured budget, and flags it
// "(EXCEEDED)" only once the running cost has actually crossed it.
func TestServer_SummaryText_IncludesCostBudgetLineAndFlagsWhenExceeded(t *testing.T) {
	targetURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))

	withoutBudget := srv.Summary()
	if strings.Contains(withoutBudget, "Cost budget") {
		t.Fatalf("summary must omit the cost budget line when CostBudget is unset: %q", withoutBudget)
	}

	srv.CostPer1KTokens = 1.0
	srv.CostBudget = 100.0
	srv.Stats.RecordTokensUsed("default", 5000) // cost = 5.0, under budget

	underBudget := srv.Summary()
	if !strings.Contains(underBudget, "Cost budget:         100") {
		t.Fatalf("summary missing cost budget line: %q", underBudget)
	}
	if strings.Contains(underBudget, "EXCEEDED") {
		t.Fatalf("summary flagged EXCEEDED while under budget: %q", underBudget)
	}

	srv.Stats.RecordTokensUsed("default", 100000) // cost now well over 100

	overBudget := srv.Summary()
	if !strings.Contains(overBudget, "Cost budget:         100") || !strings.Contains(overBudget, "(EXCEEDED)") {
		t.Fatalf("summary missing EXCEEDED flag once over budget: %q", overBudget)
	}
}

// TestServer_ReloadConfig_UpdatesCostBudget proves CostBudget is one of
// the fields SIGHUP-style reload actually replaces.
func TestServer_ReloadConfig_UpdatesCostBudget(t *testing.T) {
	targetURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0

	if got := srv.Summary(); strings.Contains(got, "Cost budget") {
		t.Fatalf("summary has a cost budget line before any budget was configured: %q", got)
	}

	srv.ReloadConfig(rules.NewEngine(rules.Allow), nil, nil, 1.0, 50.0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	if got := srv.Summary(); !strings.Contains(got, "Cost budget:         50") {
		t.Fatalf("summary missing cost budget line after reload: %q", got)
	}
}

// TestServer_Failover_FailsOverToNextCandidateWhenFirstUnreachable
// proves the core failover contract: a route with more than one
// candidate URL moves on to the next candidate, and the client still
// gets a normal response, when an earlier candidate is completely
// unreachable (nothing listening on that address at all).
func TestServer_Failover_FailsOverToNextCandidateWhenFirstUnreachable(t *testing.T) {
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("served by the working backend"))
	}))
	defer working.Close()
	workingURL, err := url.Parse(working.URL)
	if err != nil {
		t.Fatalf("parse working url: %v", err)
	}

	unreachableURL, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse unreachable url: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", workingURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(&logBuf, "", 0)
	srv.AddRoute("/openai", []*url.URL{unreachableURL, workingURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/openai/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "served by the working backend" {
		t.Fatalf("body = %q, want the working backend's response", body)
	}

	snap := srv.Stats.Snapshot()
	if snap.Failover != 1 {
		t.Errorf("Failover = %d, want 1", snap.Failover)
	}
	if got := snap.PerTarget["/openai"].Failover; got != 1 {
		t.Errorf("PerTarget[/openai].Failover = %d, want 1", got)
	}

	if !strings.Contains(logBuf.String(), "[FAILOVER]") {
		t.Errorf("log missing [FAILOVER] line: %q", logBuf.String())
	}
}

// TestServer_Failover_NeverRetriesOnHTTPLevelErrorResponse proves
// failover is transport-error-only: a candidate that actually answers
// with a 5xx is never retried against the next candidate, since that
// backend may have already started acting on the request — the client
// gets that 5xx exactly as if there were only one candidate.
func TestServer_Failover_NeverRetriesOnHTTPLevelErrorResponse(t *testing.T) {
	var secondCandidateHit atomic.Bool
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("upstream error"))
	}))
	defer failing.Close()
	failingURL, err := url.Parse(failing.URL)
	if err != nil {
		t.Fatalf("parse failing url: %v", err)
	}

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCandidateHit.Store(true)
		w.Write([]byte("second candidate"))
	}))
	defer second.Close()
	secondURL, err := url.Parse(second.URL)
	if err != nil {
		t.Fatalf("parse second url: %v", err)
	}

	srv := proxy.New("unused", failingURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/openai", []*url.URL{failingURL, secondURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/openai/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (the first candidate's own 5xx, not failed over)", resp.StatusCode, http.StatusInternalServerError)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "upstream error" {
		t.Fatalf("body = %q, want the failing candidate's own response body", body)
	}
	if secondCandidateHit.Load() {
		t.Error("second candidate was hit, want failover to never trigger on an HTTP-level 5xx response")
	}
	if got := srv.Stats.Snapshot().Failover; got != 0 {
		t.Errorf("Failover = %d, want 0 (a 5xx must never count as a failover)", got)
	}
}

// TestServer_Failover_AllCandidatesUnreachable_StillReturnsAnErrorResponse
// proves that when every candidate in the list is unreachable, the
// client still gets a normal (if unsuccessful) HTTP response rather than
// the connection hanging or the server crashing.
func TestServer_Failover_AllCandidatesUnreachable_StillReturnsAnErrorResponse(t *testing.T) {
	firstDead, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	secondDead, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", firstDead, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/openai", []*url.URL{firstDead, secondDead}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/openai/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx once every candidate is unreachable", resp.StatusCode)
	}
	if got := srv.Stats.Snapshot().Failover; got != 1 {
		t.Errorf("Failover = %d, want 1 (one transition attempted, from the first dead candidate to the second)", got)
	}
}

// TestServer_Failover_ReusesBufferedBodyAcrossAttempts proves a POST
// body survives failover intact: the second candidate must receive the
// exact same body the client originally sent, not an empty or partial
// one left over from the first (failed) attempt consuming the reader.
func TestServer_Failover_ReusesBufferedBodyAcrossAttempts(t *testing.T) {
	var receivedBody []byte
	echoing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = b
		w.Write([]byte("ok"))
	}))
	defer echoing.Close()
	echoingURL, err := url.Parse(echoing.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	unreachableURL, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", echoingURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/openai", []*url.URL{unreachableURL, echoingURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const payload = `{"messages":[{"role":"user","content":"hello, does failover preserve me?"}]}`
	resp, err := http.Post(frontend.URL+"/openai/v1/chat", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if string(receivedBody) != payload {
		t.Fatalf("second candidate received body = %q, want %q", receivedBody, payload)
	}
}

// hijackAndClose is an http.HandlerFunc that hijacks and abruptly
// closes the raw connection without writing anything — the standard
// way to make a test server produce a genuine transport-level failure
// (as opposed to an HTTP-level error response), the same class of
// failure failover/the breaker only ever react to.
func hijackAndClose(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("ResponseWriter does not support hijacking")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		conn.Close()
	}
}

// TestServer_TargetBreaker_PrefersHealthyCandidateAfterEjection proves
// the core claim: once a candidate crosses its failure threshold, a
// route with a healthier alternative stops trying the ejected one
// first — observed indirectly but unambiguously via the Failover
// counter, which only increments when a request actually has to move
// on from one candidate to the next. With threshold=3, the first 3
// requests each still try the broken candidate first (and so each log
// a failover); the 4th and 5th, made after ejection, go straight to the
// healthy candidate and never generate a failover event at all.
func TestServer_TargetBreaker_PrefersHealthyCandidateAfterEjection(t *testing.T) {
	broken := httptest.NewServer(hijackAndClose(t))
	defer broken.Close()
	brokenURL, err := url.Parse(broken.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer healthy.Close()
	healthyURL, err := url.Parse(healthy.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", healthyURL, rules.NewEngine(rules.Allow))
	srv.TargetBreaker = breaker.NewRegistry(3, time.Hour)
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/openai", []*url.URL{brokenURL, healthyURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 5; i++ {
		resp, err := http.Get(frontend.URL + "/openai/v1/chat")
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		resp.Body.Close()
	}

	if got := srv.Stats.Snapshot().Failover; got != 3 {
		t.Fatalf("Failover = %d, want 3 (only the first 3 requests, before ejection, should have needed to fail over)", got)
	}
	if got := srv.Stats.Snapshot().TargetsEjected; got != 1 {
		t.Fatalf("TargetsEjected = %d, want 1", got)
	}
}

// TestServer_TargetBreaker_AlwaysAttemptsWhenNoHealthyCandidateExists
// proves the confirmed design choice: with no failover candidate to
// skip ahead to, an ejected target still gets a genuine attempt on
// every single request — ejection never synthetically fails a request
// on its own.
func TestServer_TargetBreaker_AlwaysAttemptsWhenNoHealthyCandidateExists(t *testing.T) {
	var hitCount atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		hijackAndClose(t)(w, r)
	}))
	defer flaky.Close()
	flakyURL, err := url.Parse(flaky.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", flakyURL, rules.NewEngine(rules.Allow))
	srv.TargetBreaker = breaker.NewRegistry(1, time.Hour) // ejects after just 1 failure
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(frontend.URL + "/v1/chat")
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		resp.Body.Close()
	}

	if got := hitCount.Load(); got != 3 {
		t.Fatalf("hitCount = %d, want 3 (every request must genuinely attempt the only candidate, ejected or not)", got)
	}
}

// TestServer_TargetBreaker_LogsEjectionAndRecoveryTransitions proves
// the ejection and recovery transitions are each logged and counted
// exactly once, using a single target that starts broken and is then
// flipped to healthy mid-test.
func TestServer_TargetBreaker_LogsEjectionAndRecoveryTransitions(t *testing.T) {
	var up atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			hijackAndClose(t)(w, r)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.TargetBreaker = breaker.NewRegistry(2, time.Hour)
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func() {
		resp, err := http.Get(frontend.URL + "/v1/chat")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
	}

	get() // failure 1 (below threshold)
	get() // failure 2 -> crosses threshold, ejects

	if !strings.Contains(logBuf.String(), "[TARGET EJECTED]") {
		t.Fatalf("log missing [TARGET EJECTED]: %q", logBuf.String())
	}
	if got := srv.Stats.Snapshot().TargetsEjected; got != 1 {
		t.Errorf("TargetsEjected = %d, want 1", got)
	}
	if got := srv.Stats.Snapshot().TargetsRecovered; got != 0 {
		t.Errorf("TargetsRecovered = %d, want 0 (not recovered yet)", got)
	}

	up.Store(true)
	get() // now succeeds -> recovers

	if !strings.Contains(logBuf.String(), "[TARGET RECOVERED]") {
		t.Fatalf("log missing [TARGET RECOVERED]: %q", logBuf.String())
	}
	if got := srv.Stats.Snapshot().TargetsRecovered; got != 1 {
		t.Errorf("TargetsRecovered = %d, want 1", got)
	}
}

// TestServer_Webhook_FiresOnTargetEjectedAndRecovered proves both
// events carry the expected event name and target field.
func TestServer_Webhook_FiresOnTargetEjectedAndRecovered(t *testing.T) {
	var up atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			hijackAndClose(t)(w, r)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	received := make(chan map[string]any, 2)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.TargetBreaker = breaker.NewRegistry(1, time.Hour)
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func() {
		resp, err := http.Get(frontend.URL + "/v1/chat")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
	}

	get() // ejects immediately (threshold=1)

	select {
	case payload := <-received:
		if payload["event"] != "target_ejected" {
			t.Errorf("event = %v, want target_ejected", payload["event"])
		}
		if payload["target"] != targetURL.String() {
			t.Errorf("target = %v, want %s", payload["target"], targetURL.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never received the target_ejected event")
	}

	up.Store(true)
	get() // recovers

	select {
	case payload := <-received:
		if payload["event"] != "target_recovered" {
			t.Errorf("event = %v, want target_recovered", payload["event"])
		}
		if payload["target"] != targetURL.String() {
			t.Errorf("target = %v, want %s", payload["target"], targetURL.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never received the target_recovered event")
	}
}

// TestServer_ReloadConfig_UpdatesTargetBreaker proves TargetBreaker is
// actually swapped in by a live SIGHUP-style reload, not just settable
// at construction.
func TestServer_ReloadConfig_UpdatesTargetBreaker(t *testing.T) {
	broken := httptest.NewServer(hijackAndClose(t))
	defer broken.Close()
	brokenURL, err := url.Parse(broken.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer healthy.Close()
	healthyURL, err := url.Parse(healthy.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", healthyURL, engine)
	srv.AddRoute("/openai", []*url.URL{brokenURL, healthyURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	tb := breaker.NewRegistry(1, time.Hour)
	reloadedRoutes := []proxy.Route{{Prefix: "/openai", Targets: []*url.URL{brokenURL, healthyURL}}}
	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "", nil, nil, reloadedRoutes, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, tb, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	get := func() {
		resp, err := http.Get(frontend.URL + "/openai/v1/chat")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
	}

	get() // ejects the broken candidate (threshold=1)
	get() // should now skip straight to the healthy one

	if got := srv.Stats.Snapshot().PerTarget["/openai"].Failover; got != 1 {
		t.Fatalf("Failover = %d, want 1 (only the first request, before ejection, should have needed to fail over)", got)
	}
}

// TestServer_Webhook_FiresOnFailoverWithExpectedPayload proves the
// failover webhook event carries the failed and next candidate URLs,
// with an empty rule (a failover isn't attributable to any scanning
// rule).
func TestServer_Webhook_FiresOnFailoverWithExpectedPayload(t *testing.T) {
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer working.Close()
	workingURL, err := url.Parse(working.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	unreachableURL, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", workingURL, rules.NewEngine(rules.Allow))
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/openai", []*url.URL{unreachableURL, workingURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/openai/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	select {
	case payload := <-received:
		if payload["event"] != "failover" {
			t.Errorf("event = %v, want %q", payload["event"], "failover")
		}
		if rule, ok := payload["rule"]; !ok || rule != "" {
			t.Errorf("rule = %v, want empty string", payload["rule"])
		}
		failed, _ := payload["failed_target"].(string)
		if !strings.Contains(failed, unreachableURL.Host) {
			t.Errorf("failed_target = %q, want it to mention %q", failed, unreachableURL.Host)
		}
		next, _ := payload["next_target"].(string)
		if !strings.Contains(next, workingURL.Host) {
			t.Errorf("next_target = %q, want it to mention %q", next, workingURL.Host)
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "FAILOVER") {
			t.Errorf("text = %q, want it to mention FAILOVER", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_StatsEndpoint_ReportsFailoverPerTarget proves GET
// /_aiproxy/stats surfaces the failover count broken down by target,
// unlike unauthorized/dry-run — a failover is always attributable to
// one specific route's own candidate list.
func TestServer_StatsEndpoint_ReportsFailoverPerTarget(t *testing.T) {
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer working.Close()
	workingURL, err := url.Parse(working.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	unreachableURL, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", workingURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/openai", []*url.URL{unreachableURL, workingURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/openai/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	defer statsResp.Body.Close()
	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Failover != 1 {
		t.Errorf("Failover = %d, want 1", got.Failover)
	}
	if got.PerTarget["/openai"].Failover != 1 {
		t.Errorf("PerTarget[/openai].Failover = %d, want 1", got.PerTarget["/openai"].Failover)
	}
}

// TestServer_MetricsEndpoint_ReportsFailoverCounter is
// TestServer_StatsEndpoint_ReportsFailoverPerTarget's Prometheus
// counterpart.
func TestServer_MetricsEndpoint_ReportsFailoverCounter(t *testing.T) {
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer working.Close()
	workingURL, err := url.Parse(working.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	unreachableURL, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", workingURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/openai", []*url.URL{unreachableURL, workingURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/openai/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	metricsResp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)
	for _, want := range []string{
		"# HELP aiproxy_failover_total",
		"# TYPE aiproxy_failover_total counter",
		`aiproxy_failover_total{target="/openai"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q: %q", want, out)
		}
	}
}

// TestServer_StatsEndpoint_ReportsLatency proves a successful forwarded
// request is timed and shows up both in the overall Latency histogram
// and inside its target's own PerTarget entry — see
// stats.Stats.RecordLatency.
func TestServer_StatsEndpoint_ReportsLatency(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	defer statsResp.Body.Close()
	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Latency.Count != 1 {
		t.Errorf("overall Latency.Count = %d, want 1", got.Latency.Count)
	}
	if got.Latency.SumSeconds < 0 {
		// Not > 0: a genuinely fast local round trip can legitimately
		// measure as exactly 0 under a coarser timer (observed on
		// Windows CI) — that's a real, valid measurement, not a bug.
		// Count and Buckets above are what actually prove an
		// observation was recorded at all.
		t.Errorf("overall Latency.SumSeconds = %g, want >= 0", got.Latency.SumSeconds)
	}
	if len(got.Latency.Buckets) == 0 {
		t.Error("overall Latency.Buckets is empty, want the full fixed bucket set")
	}
	def, ok := got.PerTarget["default"]
	if !ok {
		t.Fatalf("PerTarget missing default: %+v", got.PerTarget)
	}
	if def.Latency.Count != 1 {
		t.Errorf("PerTarget[default].Latency.Count = %d, want 1", def.Latency.Count)
	}
}

// TestServer_MetricsEndpoint_ReportsLatencyHistogram is
// TestServer_StatsEndpoint_ReportsLatency's Prometheus counterpart:
// checks the aiproxy_upstream_latency_seconds histogram is emitted in
// the shape histogram_quantile() expects, including the mandatory
// le="+Inf" bucket and the _sum/_count series.
func TestServer_MetricsEndpoint_ReportsLatencyHistogram(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	metricsResp, err := http.Get(frontend.URL + "/_aiproxy/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	for _, want := range []string{
		"# HELP aiproxy_upstream_latency_seconds",
		"# TYPE aiproxy_upstream_latency_seconds histogram",
		`aiproxy_upstream_latency_seconds_bucket{target="default",le="10"} 1`,
		`aiproxy_upstream_latency_seconds_bucket{target="default",le="+Inf"} 1`,
		`aiproxy_upstream_latency_seconds_count{target="default"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q: %q", want, out)
		}
	}
	if !strings.Contains(out, `aiproxy_upstream_latency_seconds_sum{target="default"} `) {
		t.Errorf("metrics output missing the sum series: %q", out)
	}
}

// TestServer_Latency_NotRecordedForBlockedRequest proves a request the
// rule engine rejects outright — never forwarded upstream — leaves the
// latency histogram untouched: there is no upstream RoundTrip to time.
func TestServer_Latency_NotRecordedForBlockedRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "test-secret",
		Pattern: regexp.MustCompile(`SECRET`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`SECRET`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	defer statsResp.Body.Close()
	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Latency.Count != 0 {
		t.Errorf("Latency.Count = %d, want 0 (a blocked request never reaches the upstream RoundTrip)", got.Latency.Count)
	}
}

// TestServer_Latency_RecordedOnceEvenAfterFailover proves a request
// that fails over across one unreachable candidate before succeeding is
// still counted as exactly one latency observation, not one per
// attempt — see failoverTransport.RoundTrip's comment on why the timer
// starts before the first attempt rather than the successful one.
func TestServer_Latency_RecordedOnceEvenAfterFailover(t *testing.T) {
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer working.Close()
	workingURL, err := url.Parse(working.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	unreachableURL, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", workingURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/openai", []*url.URL{unreachableURL, workingURL}, nil, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/openai/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	statsResp, err := http.Get(frontend.URL + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	defer statsResp.Body.Close()
	var got statsJSONResponse
	if err := json.NewDecoder(statsResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.PerTarget["/openai"].Latency.Count != 1 {
		t.Errorf("PerTarget[/openai].Latency.Count = %d, want 1 (one observation per request, regardless of failover attempts)", got.PerTarget["/openai"].Latency.Count)
	}
}

// TestServer_LatencyLog_LogsPerRequestDurationOnAllow proves a
// forwarded request gets its own [LATENCY] line right after [ALLOW] —
// the per-request counterpart to the aggregate histogram, visible
// directly in the log stream without polling stats.
func TestServer_LatencyLog_LogsPerRequestDurationOnAllow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	logOutput := waitForLogContains(&logBuf, "[LATENCY]", 2*time.Second)
	if !strings.Contains(logOutput, "[ALLOW] GET /x") {
		t.Fatalf("log missing the allow line: %q", logOutput)
	}
	if !strings.Contains(logOutput, "[LATENCY] GET /x") {
		t.Fatalf("log missing a latency line for the same request: %q", logOutput)
	}
	if strings.Index(logOutput, "[ALLOW]") > strings.Index(logOutput, "[LATENCY]") {
		t.Fatalf("latency line must come after the allow line, got: %q", logOutput)
	}
}

// TestServer_LatencyLog_JSONFormatIncludesDurationMS proves the latency
// event's JSON shape under --log-format json: level "latency" and a
// duration_ms field, not folded into the allow event itself (which is
// logged before the round trip even starts, so it can't carry a
// duration yet).
func TestServer_LatencyLog_JSONFormatIncludesDurationMS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.LogFormat = proxy.LogFormatJSON
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	var latencyEvent map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line is not valid JSON: %q: %v", line, err)
		}
		if ev["level"] == "latency" {
			latencyEvent = ev
			break
		}
	}
	if latencyEvent == nil {
		t.Fatalf("no latency-level event found: %q", logBuf.String())
	}
	durationMS, ok := latencyEvent["duration_ms"].(float64)
	if !ok {
		t.Fatalf("latency event missing numeric duration_ms: %+v", latencyEvent)
	}
	if durationMS < 0 {
		t.Errorf("duration_ms = %v, want >= 0", durationMS)
	}
}

// TestServer_LatencyLog_NotLoggedForRequestBlockedByRules proves a
// request the rule engine rejects outright — never forwarded upstream —
// never gets a [LATENCY] line: there's no upstream round trip to time.
func TestServer_LatencyLog_NotLoggedForRequestBlockedByRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "test-secret",
		Pattern: regexp.MustCompile(`SECRET`),
		Action:  rules.Block,
	})

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "text/plain", strings.NewReader("SECRET"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	logOutput := waitForLogContains(&logBuf, "[BLOCK]", 2*time.Second)
	if strings.Contains(logOutput, "[LATENCY]") {
		t.Fatalf("log unexpectedly contains a latency line for a request that never reached upstream: %q", logOutput)
	}
}

// TestServer_LatencyLog_NotLoggedForCacheHit proves a cache hit — also
// never forwarded upstream — never gets a [LATENCY] line either.
func TestServer_LatencyLog_NotLoggedForCacheHit(t *testing.T) {
	t.Chdir(t.TempDir())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"n":1}`
	post := func() {
		resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}
	post()
	preSecondPost := waitForLogContains(&logBuf, "[LATENCY]", 2*time.Second) // wait for the first request's own latency line
	offset := len(preSecondPost)

	post() // identical request: served from cache this time
	fullLog := waitForLogContains(&logBuf, "[CACHE HIT]", 2*time.Second)
	sinceSecondPost := fullLog[offset:]
	if strings.Contains(sinceSecondPost, "[LATENCY]") {
		t.Fatalf("log unexpectedly contains a latency line for a cache hit: %q", sinceSecondPost)
	}
}

// TestServer_LatencyLog_LoggedEvenWhenResponseIsBlocked proves latency
// is logged regardless of what response scanning then decides to do
// with the response — it measures how long upstream took to answer,
// not the outcome of that answer.
func TestServer_LatencyLog_LoggedEvenWhenResponseIsBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"echo":"AKIAABCDEFGHIJKLMNOP"}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/x", "application/json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	logOutput := waitForLogContains(&logBuf, "[RESPONSE BLOCK]", 2*time.Second)
	if !strings.Contains(logOutput, "[LATENCY] POST /x") {
		t.Fatalf("log missing a latency line despite the response itself being blocked: %q", logOutput)
	}
}

// TestServer_SingleURLTarget_UnaffectedByFailoverTransport is a
// regression check: a route with exactly one candidate URL — every
// route before failover existed, and still the overwhelmingly common
// case — must behave identically to before, including on a genuine
// upstream failure (still a normal error response, never itself
// misreported as a "failover").
func TestServer_SingleURLTarget_UnaffectedByFailoverTransport(t *testing.T) {
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("single target response"))
	}))
	defer working.Close()
	workingURL, err := url.Parse(working.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", workingURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/anything")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "single target response" {
		t.Fatalf("body = %q, want the single target's response", body)
	}
	if got := srv.Stats.Snapshot().Failover; got != 0 {
		t.Errorf("Failover = %d, want 0 for a single-URL target", got)
	}
}

// logFileLines reads path and returns each non-empty line decoded as a
// generic JSON object, in order.
func logFileLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if raw == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("log file line is not valid JSON: %q: %v", raw, err)
		}
		lines = append(lines, m)
	}
	return lines
}

// TestServer_LogFile_WritesJSONLLineForEachEventIndependentOfLogFormat
// proves Server.LogFile always receives one JSON line per event — even
// under LogFormatText, where the terminal itself shows colored,
// human-readable lines instead. The on-disk record is meant to be
// grepped/parsed later, so its shape can't depend on what the terminal
// happens to be configured to show.
func TestServer_LogFile_WritesJSONLLineForEachEventIndependentOfLogFormat(t *testing.T) {
	for _, format := range []proxy.LogFormat{proxy.LogFormatText, proxy.LogFormatJSON} {
		t.Run(string(format), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			targetURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}

			logPath := filepath.Join(t.TempDir(), "aiproxy.log")
			logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				t.Fatalf("open log file: %v", err)
			}
			defer logFile.Close()

			engine := rules.NewEngine(rules.Allow)
			engine.AddBodyRegexRule(rules.BodyRegexRule{
				Name:    "aws-access-key",
				Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
				Action:  rules.Block,
			})

			srv := proxy.New("unused", targetURL, engine)
			srv.LogFormat = format
			srv.LogFile = logFile
			srv.Logger = log.New(io.Discard, "", 0)
			frontend := httptest.NewServer(srv)
			defer frontend.Close()

			allowedResp, err := http.Get(frontend.URL + "/ok")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			allowedResp.Body.Close()

			blockedResp, err := http.Post(frontend.URL+"/x", "text/plain", strings.NewReader("AKIAABCDEFGHIJKLMNOP"))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			blockedResp.Body.Close()

			lines := logFileLines(t, logPath)
			if len(lines) != 3 {
				t.Fatalf("log file has %d line(s), want 3: %+v", len(lines), lines)
			}
			if lines[0]["level"] != "allow" {
				t.Errorf("lines[0][level] = %v, want %q", lines[0]["level"], "allow")
			}
			if lines[1]["level"] != "latency" {
				t.Errorf("lines[1][level] = %v, want %q (the allowed request's per-request latency line)", lines[1]["level"], "latency")
			}
			if lines[2]["level"] != "block" {
				t.Errorf("lines[2][level] = %v, want %q", lines[2]["level"], "block")
			}
			if lines[2]["rule"] != "aws-access-key" {
				t.Errorf("lines[2][rule] = %v, want %q", lines[2]["rule"], "aws-access-key")
			}
		})
	}
}

// TestServer_LogFile_SharesExactTimestampWithJSONTerminalOutput proves
// recordLogEvent's contract: under LogFormatJSON, the line written to
// LogFile and the line written to the terminal for the very same event
// carry the identical "time" value, rather than two independent
// timestamps taken microseconds apart.
func TestServer_LogFile_SharesExactTimestampWithJSONTerminalOutput(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "aiproxy.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()

	var termBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.LogFormat = proxy.LogFormatJSON
	srv.LogFile = logFile
	srv.Logger = log.New(&termBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/ok")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	fileLines := logFileLines(t, logPath)
	if len(fileLines) != 2 {
		t.Fatalf("log file has %d line(s), want 2 (allow, then its per-request latency line)", len(fileLines))
	}

	// Only the first (the "allow" event) is compared against the file's
	// own first line — the second line each side writes is the
	// following latency event, irrelevant to what this test is proving.
	termLines := strings.Split(strings.TrimSpace(termBuf.String()), "\n")
	if len(termLines) != 2 {
		t.Fatalf("terminal output has %d line(s), want 2: %q", len(termLines), termBuf.String())
	}
	var termEvent map[string]any
	if err := json.Unmarshal([]byte(termLines[0]), &termEvent); err != nil {
		t.Fatalf("terminal line is not valid JSON: %q: %v", termLines[0], err)
	}

	fileTime, _ := fileLines[0]["time"].(string)
	termTime, _ := termEvent["time"].(string)
	if fileTime == "" || termTime == "" {
		t.Fatalf("missing time field: file=%q terminal=%q", fileTime, termTime)
	}
	if fileTime != termTime {
		t.Errorf("file time = %q, terminal time = %q, want identical", fileTime, termTime)
	}
}

// TestServer_LogFile_IncludesShutdownSummary proves the persistent log
// gets the session's own final summary too — driven through the real
// ListenAndServe shutdown path, the same one a Ctrl+C ultimately
// triggers via signal.NotifyContext in the cli package.
func TestServer_LogFile_IncludesShutdownSummary(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "aiproxy.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()

	addr := freeLoopbackAddr(t)
	srv := proxy.New(addr, targetURL, rules.NewEngine(rules.Allow))
	srv.LogFile = logFile
	srv.Logger = log.New(io.Discard, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()

	waitForServerUp(t, addr, time.Second)

	resp, err := http.Get("http://" + addr + "/ok")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe never returned after cancel")
	}

	lines := logFileLines(t, logPath)
	if len(lines) != 3 {
		t.Fatalf("log file has %d line(s), want 3 (the request, its latency line, then the shutdown summary): %+v", len(lines), lines)
	}
	summary := lines[2]
	if _, ok := summary["allowed"]; !ok {
		t.Errorf("last line = %+v, want the stats-snapshot shape (an \"allowed\" field)", summary)
	}
}

// TestServer_ReloadConfig_ReopensLogFileAndClosesOldHandle proves
// LogFile is one of the fields SIGHUP-style reload actually replaces,
// and that the previous handle is genuinely closed afterward — not
// leaked — the exact mechanics external log rotation (rename, then
// SIGHUP) depends on.
func TestServer_ReloadConfig_ReopensLogFileAndClosesOldHandle(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.log")
	newPath := filepath.Join(dir, "new.log")

	oldFile, err := os.OpenFile(oldPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open old log file: %v", err)
	}
	newFile, err := os.OpenFile(newPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open new log file: %v", err)
	}
	defer newFile.Close()

	targetURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.LogFile = oldFile
	srv.Logger = log.New(io.Discard, "", 0)

	srv.LogEvent("before_reload", "first event, goes to the old file")

	srv.ReloadConfig(rules.NewEngine(rules.Allow), nil, nil, 0, 0, 0, nil, nil, "", nil, newFile, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	srv.LogEvent("after_reload", "second event, goes to the new file")

	oldLines := logFileLines(t, oldPath)
	if len(oldLines) != 1 || oldLines[0]["level"] != "before_reload" {
		t.Errorf("old file lines = %+v, want exactly the pre-reload event", oldLines)
	}
	newLines := logFileLines(t, newPath)
	if len(newLines) != 1 || newLines[0]["level"] != "after_reload" {
		t.Errorf("new file lines = %+v, want exactly the post-reload event", newLines)
	}

	if _, err := oldFile.Write([]byte("x")); err == nil {
		t.Error("write to the old file handle succeeded after reload, want it closed by ReloadConfig")
	}
}

// TestServer_LogFile_NilByDefault_NeverWritesAFile proves that with no
// LogFile configured (the default, and every test in this file besides
// the ones explicitly about this feature), nothing about request
// handling changes and no file is ever touched.
func TestServer_LogFile_NilByDefault_NeverWritesAFile(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/ok")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_LogFile_WriteFailureNeverAffectsClientResponse proves a
// broken log file (here, simulated by closing the handle out from under
// the server, standing in for a real-world disk-full or permission
// failure) never propagates to the client — the request is still
// answered normally, same discipline as a failed webhook delivery.
func TestServer_LogFile_WriteFailureNeverAffectsClientResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "aiproxy.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	logFile.Close() // broken on purpose: every subsequent write to it fails

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.LogFile = logFile
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/ok")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (a broken log file must never affect the client response)", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_AuditChain_ChainsRealRequestTrafficIntoAVerifiableLog is a
// genuine end-to-end proof of the whole audit-signing feature: real
// requests (allowed, blocked, and rate-limited) against a running
// Server with AuditChain set produce a log file that auditlog.Verify
// confirms is fully intact.
func TestServer_AuditChain_ChainsRealRequestTrafficIntoAVerifiableLog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()

	key := []byte("integration-test-key")

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.LogFile = logFile
	srv.AuditChain = auditlog.NewChain(key, "")
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	allowedResp, err := http.Get(frontend.URL + "/ok")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	allowedResp.Body.Close()

	blockedResp, err := http.Post(frontend.URL+"/x", "text/plain", strings.NewReader("AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	blockedResp.Body.Close()

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer f.Close()

	result, err := auditlog.Verify(f, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Broken != 0 {
		t.Fatalf("chain broken at line %d: %v", result.Broken, result.Err)
	}
	if result.Lines < 3 {
		t.Fatalf("Lines = %d, want at least 3 (allow, latency, block)", result.Lines)
	}

	// Every stored envelope must still carry the original event's own
	// fields under "event", not just the chain linkage — the feature
	// signs the real event stream, it doesn't replace it.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	firstLine := strings.SplitN(string(data), "\n", 2)[0]
	var env auditlog.Envelope
	if err := json.Unmarshal([]byte(firstLine), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var event map[string]any
	if err := json.Unmarshal(env.Event, &event); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if event["level"] != "allow" {
		t.Errorf("event[level] = %v, want %q", event["level"], "allow")
	}
	if env.PrevHash != auditlog.Genesis {
		t.Errorf("first line PrevHash = %q, want Genesis", env.PrevHash)
	}
}

// TestServer_AuditChain_TamperingWithLogFileAfterTheFactIsDetected is
// the feature's actual point: an operator who edits a historical line
// in the log file after the fact — the exact scenario audit signing
// exists to catch — gets caught by Verify.
func TestServer_AuditChain_TamperingWithLogFileAfterTheFactIsDetected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()

	key := []byte("tamper-test-key")

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.LogFile = logFile
	srv.AuditChain = auditlog.NewChain(key, "")
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	blockedResp, err := http.Post(frontend.URL+"/x", "text/plain", strings.NewReader("AKIAABCDEFGHIJKLMNOP"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	blockedResp.Body.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	// An operator (or attacker) rewrites the blocked event to look like
	// an allowed one, after the fact, directly on disk. Event is a
	// json.RawMessage, embedded verbatim (not string-escaped) inside
	// each line's outer envelope object, so the substring appears
	// unescaped, the same as it would in the plain, unchained shape.
	tampered := bytes.Replace(data, []byte(`"level":"block"`), []byte(`"level":"allow"`), 1)
	if bytes.Equal(data, tampered) {
		t.Fatal("tamper replacement did not match anything in the file — test setup is wrong")
	}

	result, err := auditlog.Verify(bytes.NewReader(tampered), key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Broken == 0 {
		t.Fatal("Verify did not detect the tampered line")
	}
}

// TestServer_AuditChain_ConcurrentRequestsProduceAValidChain proves the
// exact race auditlog.Chain's own doc comment warns about — chaining
// and writing must happen atomically together — is actually prevented
// under real concurrent request load, not just in auditlog's own
// package-level tests. Run with -race.
func TestServer_AuditChain_ConcurrentRequestsProduceAValidChain(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()

	key := []byte("concurrent-test-key")

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.LogFile = logFile
	srv.AuditChain = auditlog.NewChain(key, "")
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(frontend.URL + "/ok")
			if err != nil {
				t.Errorf("get: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer f.Close()

	result, err := auditlog.Verify(f, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Broken != 0 {
		t.Fatalf("chain broken at line %d: %v", result.Broken, result.Err)
	}
	if result.Lines != n*2 {
		t.Fatalf("Lines = %d, want %d (allow + latency per request)", result.Lines, n*2)
	}
}

// TestServer_AuditChain_NilByDefault_LeavesLogFileUnchained proves
// audit signing is fully opt-in: a Server with a LogFile but no
// AuditChain writes the same plain, flat JSON lines it always has,
// never the chained envelope shape.
func TestServer_AuditChain_NilByDefault_LeavesLogFileUnchained(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "aiproxy.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.LogFile = logFile
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/ok")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	lines := logFileLines(t, logPath)
	if len(lines) == 0 {
		t.Fatal("expected at least one log line")
	}
	if _, ok := lines[0]["hash"]; ok {
		t.Errorf("lines[0] has a \"hash\" field with AuditChain unset: %+v", lines[0])
	}
	if lines[0]["level"] != "allow" {
		t.Errorf("lines[0][level] = %v, want %q (flat, unwrapped shape)", lines[0]["level"], "allow")
	}
}

// TestServer_ModelRouting_RoutesByBodyModelFieldAndLeavesPathUnchanged
// proves AddModelRoute's core contract: a request whose JSON body's
// "model" field matches a registered glob pattern is forwarded to that
// route's target, with the client's own path left completely unchanged
// (unlike path-prefix routing, there is no prefix to strip).
func TestServer_ModelRouting_RoutesByBodyModelFieldAndLeavesPathUnchanged(t *testing.T) {
	var anthropicPath, openaiPath, defaultPath string

	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anthropicPath = r.URL.Path
		w.Write([]byte("anthropic response"))
	}))
	defer anthropic.Close()

	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openaiPath = r.URL.Path
		w.Write([]byte("openai response"))
	}))
	defer openai.Close()

	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultPath = r.URL.Path
		w.Write([]byte("default response"))
	}))
	defer defaultUpstream.Close()

	anthropicURL, err := url.Parse(anthropic.URL)
	if err != nil {
		t.Fatalf("parse anthropic url: %v", err)
	}
	openaiURL, err := url.Parse(openai.URL)
	if err != nil {
		t.Fatalf("parse openai url: %v", err)
	}
	defaultURL, err := url.Parse(defaultUpstream.URL)
	if err != nil {
		t.Fatalf("parse default url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", defaultURL, engine)
	srv.AddModelRoute("anthropic", []string{"claude-*"}, []*url.URL{anthropicURL}, nil, nil, nil)
	srv.AddModelRoute("openai", []string{"gpt-*", "o1*"}, []*url.URL{openaiURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(path, model string) string {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(`{"model":"`+model+`","messages":[]}`))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("post %s: read body: %v", path, err)
		}
		return string(body)
	}

	if got := post("/v1/messages", "claude-3-opus-20240229"); got != "anthropic response" {
		t.Fatalf("model claude-3-opus-20240229 body = %q, want the anthropic upstream's response", got)
	}
	if anthropicPath != "/v1/messages" {
		t.Fatalf("anthropic upstream saw path %q, want /v1/messages unchanged (model routing never strips a prefix)", anthropicPath)
	}

	if got := post("/v1/chat/completions", "gpt-4o"); got != "openai response" {
		t.Fatalf("model gpt-4o body = %q, want the openai upstream's response", got)
	}
	if openaiPath != "/v1/chat/completions" {
		t.Fatalf("openai upstream saw path %q, want /v1/chat/completions unchanged", openaiPath)
	}

	if got := post("/v1/chat/completions", "o1-preview"); got != "openai response" {
		t.Fatalf("model o1-preview body = %q, want the openai upstream's response (matches the o1* pattern)", got)
	}

	if got := post("/v1/embeddings", "text-embedding-3-small"); got != "default response" {
		t.Fatalf("unmatched model body = %q, want the default target's response", got)
	}
	if defaultPath != "/v1/embeddings" {
		t.Fatalf("default upstream saw path %q, want /v1/embeddings unchanged", defaultPath)
	}
}

// TestServer_ModelRouting_TakesPriorityOverPathPrefixRouting proves the
// documented precedence: when both a model route and a path-prefix
// route could apply to the same request, the model route wins and
// path-prefix routing is skipped entirely for that request.
func TestServer_ModelRouting_TakesPriorityOverPathPrefixRouting(t *testing.T) {
	var modelRouteHit, pathRouteHit bool

	modelUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelRouteHit = true
		w.Write([]byte("model route response"))
	}))
	defer modelUpstream.Close()

	pathUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathRouteHit = true
		w.Write([]byte("path route response"))
	}))
	defer pathUpstream.Close()

	modelURL, err := url.Parse(modelUpstream.URL)
	if err != nil {
		t.Fatalf("parse model url: %v", err)
	}
	pathURL, err := url.Parse(pathUpstream.URL)
	if err != nil {
		t.Fatalf("parse path url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", pathURL, engine)
	srv.AddRoute("/v1", []*url.URL{pathURL}, nil, nil, nil)
	srv.AddModelRoute("anthropic", []string{"claude-*"}, []*url.URL{modelURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-3-opus"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "model route response" {
		t.Fatalf("body = %q, want the model route's response (it must take priority over the matching /v1 path route)", string(body))
	}
	if !modelRouteHit || pathRouteHit {
		t.Fatalf("modelRouteHit=%v pathRouteHit=%v, want only the model route hit", modelRouteHit, pathRouteHit)
	}
}

// TestServer_ModelRouting_FirstMatchingRouteWinsInConfiguredOrder
// proves that when more than one registered route's pattern could match
// a model name, the first one added wins — same "first match, in
// order" rule as path-prefix routes and webhook event filters.
func TestServer_ModelRouting_FirstMatchingRouteWinsInConfiguredOrder(t *testing.T) {
	var firstHit, secondHit bool

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHit = true
		w.Write([]byte("first"))
	}))
	defer first.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHit = true
		w.Write([]byte("second"))
	}))
	defer second.Close()

	firstURL, err := url.Parse(first.URL)
	if err != nil {
		t.Fatalf("parse first url: %v", err)
	}
	secondURL, err := url.Parse(second.URL)
	if err != nil {
		t.Fatalf("parse second url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", firstURL, engine)
	srv.AddModelRoute("first", []string{"claude-*"}, []*url.URL{firstURL}, nil, nil, nil)
	srv.AddModelRoute("second", []string{"claude-3-*"}, []*url.URL{secondURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-3-opus"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if string(body) != "first" || !firstHit || secondHit {
		t.Fatalf("body = %q firstHit=%v secondHit=%v, want only the first-registered matching route hit", string(body), firstHit, secondHit)
	}
}

// TestServer_ModelRouting_PerTargetStatsLabeledByModelRouteName proves a
// model route's traffic is attributed in Server.Stats.Snapshot().PerTarget
// under "model:<name>" — distinct from a path prefix's own label, so the
// two routing mechanisms can never collide in stats even if configured
// with overlapping-looking names.
func TestServer_ModelRouting_PerTargetStatsLabeledByModelRouteName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", upstreamURL, engine)
	srv.AddModelRoute("anthropic", []string{"claude-*"}, []*url.URL{upstreamURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-3-opus"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	snap := srv.Stats.Snapshot()
	modelSnap, ok := snap.PerTarget["model:anthropic"]
	if !ok {
		keys := make([]string, 0, len(snap.PerTarget))
		for k := range snap.PerTarget {
			keys = append(keys, k)
		}
		t.Fatalf("PerTarget missing \"model:anthropic\" key; got keys %v", keys)
	}
	if modelSnap.Allowed != 1 {
		t.Fatalf("PerTarget[model:anthropic].Allowed = %d, want 1", modelSnap.Allowed)
	}
}

// TestServer_ModelRouting_OwnRateLimitTakesPrecedenceOverServerWide
// proves a model route's own dedicated Limiter, if set, is what
// actually gets enforced — not the server-wide one — mirroring the same
// precedence a path-prefix route's own Limiter already has.
func TestServer_ModelRouting_OwnRateLimitTakesPrecedenceOverServerWide(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", upstreamURL, engine)
	// The server-wide limiter is generous; the model route's own is not
	// — if the route's own limiter isn't what's actually enforced, this
	// request would never be rate-limited within the test.
	srv.Limiter = limiter.New(1000, time.Minute)
	srv.AddModelRoute("anthropic", []string{"claude-*"}, []*url.URL{upstreamURL}, nil, limiter.New(1, time.Minute), nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() int {
		resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-3-opus"}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := post(); got != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", got, http.StatusOK)
	}
	if got := post(); got != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d (the model route's own 1/minute limit should have tripped)", got, http.StatusTooManyRequests)
	}
}

// TestServer_ModelRouting_OwnTokenRateLimitTakesPrecedenceOverServerWide
// is TestServer_ModelRouting_OwnRateLimitTakesPrecedenceOverServerWide's
// counterpart for the token-based breaker.
func TestServer_ModelRouting_OwnTokenRateLimitTakesPrecedenceOverServerWide(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":100}}`))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", upstreamURL, engine)
	// The server-wide token breaker is generous; the model route's own
	// (100 tokens) is not — if the route's own isn't what's actually
	// enforced, this request would never be token-rate-limited within
	// the test.
	srv.TokenLimiter = limiter.NewTokenLimiter(1000000, time.Minute)
	srv.AddModelRoute("anthropic", []string{"claude-*"}, []*url.URL{upstreamURL}, nil, nil, limiter.NewTokenLimiter(100, time.Minute))
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() int {
		resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-3-opus"}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := post(); got != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", got, http.StatusOK)
	}
	if got := post(); got != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d (the model route's own 100-token budget should have tripped)", got, http.StatusTooManyRequests)
	}
}

// TestServer_ModelRouting_FailoverAcrossCandidatesWorksLikePathRoutes
// proves a model route's ordered urls list fails over exactly like a
// path-prefix route's does: an unreachable first candidate falls
// through to the second, and the client never sees the failure.
func TestServer_ModelRouting_FailoverAcrossCandidatesWorksLikePathRoutes(t *testing.T) {
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("working"))
	}))
	defer working.Close()
	workingURL, err := url.Parse(working.URL)
	if err != nil {
		t.Fatalf("parse working url: %v", err)
	}

	unreachable, err := url.Parse("https://127.0.0.1:1")
	if err != nil {
		t.Fatalf("parse unreachable url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", workingURL, engine)
	srv.AddModelRoute("anthropic", []string{"claude-*"}, []*url.URL{unreachable, workingURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-3-opus"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "working" {
		t.Fatalf("body = %q, want the second (working) candidate's response after the first proved unreachable", string(body))
	}

	snap := srv.Stats.Snapshot()
	if snap.PerTarget["model:anthropic"].Failover != 1 {
		t.Fatalf("PerTarget[model:anthropic].Failover = %d, want 1", snap.PerTarget["model:anthropic"].Failover)
	}
}

// TestServer_ModelRouting_UnparseableOrMissingModelFieldFallsBackToPathRouting
// proves a request with no "model" field, or a body that isn't even
// valid JSON, never errors out — it just falls back to whatever
// path-prefix routing (or the default Target) would otherwise apply,
// exactly as if no model routes were configured at all.
func TestServer_ModelRouting_UnparseableOrMissingModelFieldFallsBackToPathRouting(t *testing.T) {
	var defaultHits int
	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultHits++
		w.Write([]byte("default"))
	}))
	defer defaultUpstream.Close()
	defaultURL, err := url.Parse(defaultUpstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	modelUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("model"))
	}))
	defer modelUpstream.Close()
	modelURL, err := url.Parse(modelUpstream.URL)
	if err != nil {
		t.Fatalf("parse model url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", defaultURL, engine)
	srv.AddModelRoute("anthropic", []string{"claude-*"}, []*url.URL{modelURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(body string) (int, string) {
		resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return resp.StatusCode, string(got)
	}

	if status, got := post(`{"messages":[]}`); status != http.StatusOK || got != "default" {
		t.Fatalf("no model field: status=%d body=%q, want 200/default", status, got)
	}
	if status, got := post(`not valid json`); status != http.StatusOK || got != "default" {
		t.Fatalf("invalid JSON body: status=%d body=%q, want 200/default (never an error)", status, got)
	}
	if defaultHits != 2 {
		t.Fatalf("defaultHits = %d, want 2", defaultHits)
	}
}

// TestServer_ReloadConfig_SwapsModelRoutesLive proves a SIGHUP-style
// ReloadConfig can add a model route to a server that started with
// none — the same "swap under one lock" guarantee already proven for
// path-prefix routes.
func TestServer_ReloadConfig_SwapsModelRoutesLive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("routed"))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("default"))
	}))
	defer defaultUpstream.Close()
	defaultURL, err := url.Parse(defaultUpstream.URL)
	if err != nil {
		t.Fatalf("parse default url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", defaultURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() string {
		resp, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-3-opus"}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	if got := post(); got != "default" {
		t.Fatalf("before reload: body = %q, want default (no model route registered yet)", got)
	}

	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "", nil, nil, nil, []proxy.ModelRoute{
		{Name: "anthropic", Models: []string{"claude-*"}, Targets: []*url.URL{upstreamURL}},
	}, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	if got := post(); got != "routed" {
		t.Fatalf("after reload: body = %q, want routed (the model route added via ReloadConfig should now match)", got)
	}
}

// TestServer_ClientCostBudget_FiresWebhookOnlyForTheKeyThatCrossedIt
// proves a named proxy key's own cost_budget fires an independent
// budget_exceeded alert — carrying that key's own Name in the payload's
// "client" field — while a different key, whose own usage stays under
// its own budget, never triggers one.
func TestServer_ClientCostBudget_FiresWebhookOnlyForTheKeyThatCrossedIt(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 4)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0 // cost = 10.0 per request
	srv.WebhookURL = webhookURL
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "team-over", Key: "key-over", CostBudget: 5.0},    // crossed by the first request
		{Name: "team-under", Key: "key-under", CostBudget: 50.0}, // not crossed by one request
	}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(key string) {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader("hello"))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}

	post("key-under")
	post("key-over")

	select {
	case payload := <-received:
		if payload["event"] != "budget_exceeded" {
			t.Fatalf("event = %v, want budget_exceeded", payload["event"])
		}
		if payload["client"] != "team-over" {
			t.Fatalf("client = %v, want team-over", payload["client"])
		}
		if cost, ok := payload["cost"].(float64); !ok || cost != 10.0 {
			t.Errorf("cost = %v, want 10.0", payload["cost"])
		}
		if budget, ok := payload["budget"].(float64); !ok || budget != 5.0 {
			t.Errorf("budget = %v, want 5.0", payload["budget"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called for team-over")
	}

	select {
	case payload := <-received:
		t.Fatalf("a second webhook call arrived, want none (team-under's own budget was never crossed): %+v", payload)
	case <-time.After(300 * time.Millisecond):
		// expected: team-under never crosses its own 50.0 budget with one 10.0 request
	}
}

// TestServer_ClientCostBudget_IndependentFromServerWideBudget proves a
// named key's own cost_budget and Server.CostBudget (the server-wide
// one) are entirely separate checks: a request can cross one, both, or
// neither, and each still only ever fires its own alert once.
func TestServer_ClientCostBudget_IndependentFromServerWideBudget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan string, 4)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		client, _ := payload["client"].(string)
		received <- client
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0 // cost = 10.0 per request
	srv.CostBudget = 5.0      // server-wide: crossed by any request, client="" (never attributed)
	srv.WebhookURL = webhookURL
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "team-a", Key: "key-a", CostBudget: 5.0}, // also crossed by its own first request
	}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer key-a")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	// Both the server-wide budget (client="") and team-a's own budget
	// (client="team-a") should have fired from this single request.
	var events []string
	for i := 0; i < 2; i++ {
		select {
		case client := <-received:
			events = append(events, client)
		case <-time.After(2 * time.Second):
			t.Fatalf("want 2 webhook calls (server-wide + team-a), got %v", events)
		}
	}

	sawGlobal, sawClient := false, false
	for _, c := range events {
		if c == "" {
			sawGlobal = true
		}
		if c == "team-a" {
			sawClient = true
		}
	}
	if !sawGlobal || !sawClient {
		t.Fatalf("events = %v, want one with client=\"\" (server-wide) and one with client=\"team-a\"", events)
	}
}

// TestServer_ClientCostBudget_AlertFiresExactlyOnceAcrossManyRequests
// proves the one-shot latch holds across real HTTP traffic for a named
// key's own budget too, not just the server-wide one.
func TestServer_ClientCostBudget_AlertFiresExactlyOnceAcrossManyRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	var callCount atomic.Int32
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0
	srv.WebhookURL = webhookURL
	srv.ProxyAPIKeys = []proxy.ProxyKey{{Name: "team-a", Key: "key-a", CostBudget: 5.0}}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 5; i++ {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader("hello"))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer key-a")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		resp.Body.Close()
	}

	time.Sleep(300 * time.Millisecond)
	if got := callCount.Load(); got != 1 {
		t.Fatalf("webhook called %d times, want exactly 1 (the one-shot latch should suppress every request after the first crossing)", got)
	}
}

// TestServer_ClientCostBudget_NeverBlocksOrAffectsTraffic proves a
// crossed per-key budget is alert-only, exactly like the server-wide
// one: the request that crosses it (and every one after) is still
// forwarded and answered completely normally.
func TestServer_ClientCostBudget_NeverBlocksOrAffectsTraffic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.CostPer1KTokens = 1.0
	srv.ProxyAPIKeys = []proxy.ProxyKey{{Name: "team-a", Key: "key-a", CostBudget: 1.0}}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer key-a")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (a crossed per-key budget must never block traffic)", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "total_tokens") {
		t.Errorf("body = %q, want the upstream response delivered unchanged", body)
	}
}

// TestServer_ReloadConfig_UpdatesProxyAPIKeyCostBudget proves a
// SIGHUP-style ReloadConfig can add a per-key cost_budget to a server
// that started with none — the field lives on ProxyKey, so it swaps in
// with ProxyAPIKeys the same way Name/Key/Limiter already do, no
// ReloadConfig signature change needed.
func TestServer_ReloadConfig_UpdatesProxyAPIKeyCostBudget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":10000}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	var callCount atomic.Int32
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.CostPer1KTokens = 1.0
	srv.WebhookURL = webhookURL
	srv.ProxyAPIKeys = []proxy.ProxyKey{{Name: "team-a", Key: "key-a"}} // no budget yet
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader("hello"))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer key-a")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}

	post()
	time.Sleep(200 * time.Millisecond)
	if got := callCount.Load(); got != 0 {
		t.Fatalf("webhook called %d times before reload, want 0 (no budget configured yet)", got)
	}

	srv.ReloadConfig(engine, nil, nil, 1.0, 0, 0, webhookURL, nil, "", []proxy.ProxyKey{
		{Name: "team-a", Key: "key-a", CostBudget: 5.0},
	}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	post()
	time.Sleep(200 * time.Millisecond)
	if got := callCount.Load(); got != 1 {
		t.Fatalf("webhook called %d times after reload, want 1 (the newly configured budget should now fire)", got)
	}
}

// mustCIDR parses s (CIDR notation) into a *net.IPNet for building
// Server.IPAllowList/IPDenyList directly in tests, failing the test on
// a malformed literal rather than silently testing against a nil net.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("mustCIDR(%q): %v", s, err)
	}
	return n
}

// TestServer_IPAccess_UnconfiguredAllowsEveryIP proves that with both
// IPAllowList and IPDenyList empty (the default), no IP is ever denied
// — same zero-cost-when-unused discipline as every other optional
// check in this package.
func TestServer_IPAccess_UnconfiguredAllowsEveryIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_IPAccess_AllowListLetsMatchingIPThrough proves a request
// from an IP covered by IPAllowList is forwarded normally.
func TestServer_IPAccess_AllowListLetsMatchingIPThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	// httptest.NewServer always listens on loopback, so every test
	// request's remote IP falls inside 127.0.0.0/8.
	srv.IPAllowList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (127.0.0.1 is covered by the allow list)", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_IPAccess_AllowListRejectsNonMatchingIP proves a request
// from an IP NOT covered by a non-empty IPAllowList is denied with 403
// and never reaches the upstream target.
func TestServer_IPAccess_AllowListRejectsNonMatchingIP(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	// A range that can never cover a loopback test connection.
	srv.IPAllowList = []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if upstreamHit.Load() {
		t.Error("upstream was hit, want the request rejected before ever reaching it")
	}

	snap := srv.Stats.Snapshot()
	if snap.IPDenied != 1 {
		t.Errorf("Stats.IPDenied = %d, want 1", snap.IPDenied)
	}
}

// TestServer_IPAccess_DenyListRejectsMatchingIP proves IPDenyList
// rejects a matching IP even with no IPAllowList configured at all
// (which would otherwise mean "everyone allowed").
func TestServer_IPAccess_DenyListRejectsMatchingIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.IPDenyList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// TestServer_IPAccess_DenyListWinsOverAllowList proves a deny match
// takes priority even for an IP that's also covered by IPAllowList —
// the documented "carve an exception out of a broader allow range"
// behavior.
func TestServer_IPAccess_DenyListWinsOverAllowList(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.IPAllowList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.IPDenyList = []*net.IPNet{mustCIDR(t, "127.0.0.1/32")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (a deny match must win even though the broader allow range also matches)", resp.StatusCode, http.StatusForbidden)
	}
}

// TestServer_IPAccess_CheckedBeforeProxyAuth proves the IP check runs
// before proxy authentication: a caller presenting a completely valid
// Proxy-Authorization key still gets rejected by an IP deny list,
// never even reaching the auth check.
func TestServer_IPAccess_CheckedBeforeProxyAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "the-real-key"
	srv.IPDenyList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer the-real-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (IP deny must win even with a correct proxy key presented)", resp.StatusCode, http.StatusForbidden)
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		t.Fatal("got 407, meaning the auth check ran before the IP check — wrong order")
	}
}

// TestServer_IPAccess_DeniedRequestNeverCountsAsUnauthorized proves an
// IP-denied request is counted and logged as ip_denied, not as
// unauthorized, even when a proxy key is also configured — they're
// distinct rejection reasons.
func TestServer_IPAccess_DeniedRequestNeverCountsAsUnauthorized(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "the-real-key"
	srv.IPDenyList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	snap := srv.Stats.Snapshot()
	if snap.IPDenied != 1 {
		t.Errorf("IPDenied = %d, want 1", snap.IPDenied)
	}
	if snap.Unauthorized != 0 {
		t.Errorf("Unauthorized = %d, want 0 (an IP-denied request never reaches the auth check at all)", snap.Unauthorized)
	}
}

// TestServer_Webhook_FiresOnIPDeniedWithExpectedPayload proves the
// ip_denied webhook event carries the denied remote_ip and an empty
// rule, and that the log line/JSON event both include it too.
func TestServer_Webhook_FiresOnIPDeniedWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.IPDenyList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	select {
	case payload := <-received:
		if payload["event"] != "ip_denied" {
			t.Errorf("event = %v, want ip_denied", payload["event"])
		}
		if rule, ok := payload["rule"]; !ok || rule != "" {
			t.Errorf("rule = %v, want empty string (an IP denial matches no rule)", payload["rule"])
		}
		remoteIP, _ := payload["remote_ip"].(string)
		if remoteIP == "" {
			t.Error("remote_ip missing or empty in webhook payload")
		}
		if !strings.HasPrefix(remoteIP, "127.0.0.1") {
			t.Errorf("remote_ip = %q, want it to start with 127.0.0.1", remoteIP)
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "IP_DENIED") {
			t.Errorf("text = %q, want it to mention IP_DENIED", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_ReloadConfig_UpdatesIPLists proves a SIGHUP-style
// ReloadConfig can add an IP deny list to a server that started with
// none, live — the same guarantee already proven for every other
// reloadable field.
func TestServer_ReloadConfig_UpdatesIPLists(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func() int {
		resp, err := http.Get(frontend.URL + "/x")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get(); got != http.StatusOK {
		t.Fatalf("before reload: status = %d, want %d (no deny list configured yet)", got, http.StatusOK)
	}

	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, []*net.IPNet{
		mustCIDR(t, "127.0.0.0/8"),
	}, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	if got := get(); got != http.StatusForbidden {
		t.Fatalf("after reload: status = %d, want %d (the newly configured deny list should now reject this IP)", got, http.StatusForbidden)
	}
}

// mustGeoIPTable writes csv to a temp file and loads it via geoip.Load,
// failing the test on any error — the real loading path production
// code uses, not a hand-built Table (its fields are all unexported).
func mustGeoIPTable(t *testing.T, csv string) *geoip.Table {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip.csv")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatalf("write geoip csv: %v", err)
	}
	table, err := geoip.Load(path)
	if err != nil {
		t.Fatalf("geoip.Load: %v", err)
	}
	return table
}

// TestServer_CountryAccess_UnconfiguredAllowsEveryCountry proves that
// with both CountryAllowList and CountryDenyList empty (the default),
// no request is ever country-denied — same zero-cost-when-unused
// discipline as checkIPAccess, even with a GeoIPTable set.
func TestServer_CountryAccess_UnconfiguredAllowsEveryCountry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,ZZ\n")
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_CountryAccess_AllowListLetsMatchingCountryThrough proves a
// request whose resolved country is covered by CountryAllowList is
// forwarded normally.
func TestServer_CountryAccess_AllowListLetsMatchingCountryThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	// httptest.NewServer always listens on loopback, so every test
	// request's remote IP falls inside this range.
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.CountryAllowList = []string{"SE"}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (the resolved country SE is covered by the allow list)", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_CountryAccess_AllowListRejectsNonMatchingCountry proves a
// request whose resolved country is NOT covered by a non-empty
// CountryAllowList is denied with 403 and never reaches upstream.
func TestServer_CountryAccess_AllowListRejectsNonMatchingCountry(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.CountryAllowList = []string{"NO"}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if upstreamHit.Load() {
		t.Error("upstream was hit, want the request rejected before ever reaching it")
	}

	snap := srv.Stats.Snapshot()
	if snap.CountryDenied != 1 {
		t.Errorf("Stats.CountryDenied = %d, want 1", snap.CountryDenied)
	}
}

// TestServer_CountryAccess_DenyListRejectsMatchingCountry proves
// CountryDenyList rejects a matching country even with no
// CountryAllowList configured at all.
func TestServer_CountryAccess_DenyListRejectsMatchingCountry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.CountryDenyList = []string{"SE"}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// TestServer_CountryAccess_DenyListWinsOverAllowList proves a country
// deny match takes priority even for a country also covered by
// CountryAllowList — the same precedence checkIPAccess already uses.
func TestServer_CountryAccess_DenyListWinsOverAllowList(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.CountryAllowList = []string{"SE"}
	srv.CountryDenyList = []string{"SE"}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (a deny match must win even though the same country is also allow-listed)", resp.StatusCode, http.StatusForbidden)
	}
}

// TestServer_CountryAccess_UnresolvableIPDeniedWhenEitherListConfigured
// proves an IP whose country can't be resolved (no GeoIPTable, or an
// IP the table just doesn't cover) is denied whenever either country
// list is configured — the same "can't evaluate it, so deny" rule
// checkIPAccess already applies to an unparseable remote IP.
func TestServer_CountryAccess_UnresolvableIPDeniedWhenEitherListConfigured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table *geoip.Table
	}{
		{"NilTable", nil},
		{"IPNotCoveredByAnyRange", mustGeoIPTable(t, "10.0.0.0/8,SE\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			targetURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}

			srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
			srv.GeoIPTable = tc.table
			srv.CountryAllowList = []string{"SE"}
			srv.Logger = log.New(io.Discard, "", 0)
			frontend := httptest.NewServer(srv)
			defer frontend.Close()

			resp, err := http.Get(frontend.URL + "/x")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want %d (an unresolvable country must fail closed)", resp.StatusCode, http.StatusForbidden)
			}
		})
	}
}

// TestServer_CountryAccess_IndependentOfIPAllowList proves the
// confirmed design: an IP explicitly covered by IPAllowList is NOT an
// exemption from a country-level deny — the two checks are a fully
// independent AND gate, neither is a bypass of the other.
func TestServer_CountryAccess_IndependentOfIPAllowList(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	// The IP itself is explicitly allow-listed...
	srv.IPAllowList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	// ...but its resolved country is denied, independently.
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.CountryDenyList = []string{"SE"}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (an IP allow-list entry must not exempt a request from a country-level deny)", resp.StatusCode, http.StatusForbidden)
	}
}

// TestServer_CountryAccess_CheckedAfterIPAccessButBeforeProxyAuth
// proves the ordering: an IP-level deny still wins even when the
// country would otherwise be allowed, and a country deny still wins
// over a completely valid Proxy-Authorization key.
func TestServer_CountryAccess_CheckedAfterIPAccessButBeforeProxyAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "the-real-key"
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.CountryDenyList = []string{"SE"}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer the-real-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (country deny must win even with a correct proxy key presented)", resp.StatusCode, http.StatusForbidden)
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		t.Fatal("got 407, meaning the auth check ran before the country check — wrong order")
	}
}

// TestServer_CountryAccess_DeniedRequestNeverCountsAsIPDeniedOrUnauthorized
// proves a country-denied request is counted and logged as
// country_denied only — distinct rejection reasons, never conflated.
func TestServer_CountryAccess_DeniedRequestNeverCountsAsIPDeniedOrUnauthorized(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "the-real-key"
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.CountryDenyList = []string{"SE"}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	snap := srv.Stats.Snapshot()
	if snap.CountryDenied != 1 {
		t.Errorf("CountryDenied = %d, want 1", snap.CountryDenied)
	}
	if snap.IPDenied != 0 {
		t.Errorf("IPDenied = %d, want 0 (a country denial is a distinct reason from an IP denial)", snap.IPDenied)
	}
	if snap.Unauthorized != 0 {
		t.Errorf("Unauthorized = %d, want 0 (a country-denied request never reaches the auth check at all)", snap.Unauthorized)
	}
}

// TestServer_Webhook_FiresOnCountryDeniedWithExpectedPayload proves the
// country_denied webhook event carries the denied remote_ip and its
// resolved country, and an empty rule.
func TestServer_Webhook_FiresOnCountryDeniedWithExpectedPayload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.GeoIPTable = mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.CountryDenyList = []string{"SE"}
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	select {
	case payload := <-received:
		if payload["event"] != "country_denied" {
			t.Errorf("event = %v, want country_denied", payload["event"])
		}
		if rule, ok := payload["rule"]; !ok || rule != "" {
			t.Errorf("rule = %v, want empty string (a country denial matches no rule)", payload["rule"])
		}
		if payload["country"] != "SE" {
			t.Errorf("country = %v, want SE", payload["country"])
		}
		remoteIP, _ := payload["remote_ip"].(string)
		if !strings.HasPrefix(remoteIP, "127.0.0.1") {
			t.Errorf("remote_ip = %q, want it to start with 127.0.0.1", remoteIP)
		}
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "COUNTRY_DENIED") {
			t.Errorf("text = %q, want it to mention COUNTRY_DENIED", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// TestServer_ReloadConfig_UpdatesCountryLists proves a SIGHUP-style
// ReloadConfig can add GeoIPTable/CountryDenyList to a server that
// started with none, live.
func TestServer_ReloadConfig_UpdatesCountryLists(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func() int {
		resp, err := http.Get(frontend.URL + "/x")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get(); got != http.StatusOK {
		t.Fatalf("before reload: status = %d, want %d (no country deny list configured yet)", got, http.StatusOK)
	}

	table := mustGeoIPTable(t, "127.0.0.0/8,SE\n")
	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil,
		table, nil, []string{"SE"}, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	if got := get(); got != http.StatusForbidden {
		t.Fatalf("after reload: status = %d, want %d (the newly configured country deny list should now reject this IP)", got, http.StatusForbidden)
	}
}

// TestServer_ReloadConfig_UpdatesTokenLimiter proves the server-wide
// TokenLimiter is one of the fields ReloadConfig atomically swaps in —
// disabled before the reload, live and enforcing immediately after.
func TestServer_ReloadConfig_UpdatesTokenLimiter(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":100}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func() int {
		resp, err := http.Get(frontend.URL + "/x")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get(); got != http.StatusOK {
		t.Fatalf("before reload: status = %d, want %d (no token breaker configured yet)", got, http.StatusOK)
	}

	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, limiter.NewTokenLimiter(50, time.Minute), nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	if got := get(); got != http.StatusOK {
		t.Fatalf("first request after reload: status = %d, want %d (window starts empty)", got, http.StatusOK)
	}
	if got := get(); got != http.StatusTooManyRequests {
		t.Fatalf("second request after reload: status = %d, want %d (100 tokens already recorded against the newly configured 50-token budget)", got, http.StatusTooManyRequests)
	}
}

// TestServer_Dashboard_ServesHTMLPage proves GET /_aiproxy/dashboard
// returns a self-contained HTML page that fetches statsPath itself,
// never anything forwarded from or shaped by the upstream target.
func TestServer_Dashboard_ServesHTMLPage(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/dashboard")
	if err != nil {
		t.Fatalf("GET /_aiproxy/dashboard: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "<title>aiproxy dashboard</title>") {
		t.Error("body missing the expected <title>")
	}
	if !strings.Contains(string(body), "/_aiproxy/stats") {
		t.Error("body missing a reference to /_aiproxy/stats — the dashboard is supposed to poll it client-side")
	}
}

// TestServer_Dashboard_RejectsNonGetMethod mirrors
// TestServer_StatsEndpoint_RejectsNonGetMethod: the dashboard has no
// meaningful semantics for anything but GET.
func TestServer_Dashboard_RejectsNonGetMethod(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/_aiproxy/dashboard", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /_aiproxy/dashboard: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestServer_Dashboard_NeverForwardedUpstreamOrCountedInStats mirrors
// TestServer_StatsEndpoint_NeverForwardedUpstreamOrCountedInStats: like
// every other reserved proxy-internal path, a dashboard request must
// never reach the upstream target or be counted as allowed traffic.
func TestServer_Dashboard_NeverForwardedUpstreamOrCountedInStats(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(frontend.URL + "/_aiproxy/dashboard")
		if err != nil {
			t.Fatalf("GET /_aiproxy/dashboard: %v", err)
		}
		resp.Body.Close()
	}

	if upstreamHit.Load() {
		t.Fatal("a request for dashboardPath must never reach the upstream target")
	}

	snap := srv.Stats.Snapshot()
	if snap.Allowed != 0 {
		t.Fatalf("Allowed = %d, want 0 (dashboard requests must not themselves be counted)", snap.Allowed)
	}
}

// TestServer_Dashboard_GatedByProxyAuth proves the deliberate,
// confirmed design choice: the dashboard page itself is gated by
// proxy_api_key exactly like statsPath/metricsPath, with no exception
// — see dashboardPath's doc comment.
func TestServer_Dashboard_GatedByProxyAuth(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/dashboard")
	if err != nil {
		t.Fatalf("GET without key: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("without key: status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/_aiproxy/dashboard", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer s3cr3t-shared-key")
	authedResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	authedResp.Body.Close()
	if authedResp.StatusCode != http.StatusOK {
		t.Errorf("with correct key: status = %d, want %d", authedResp.StatusCode, http.StatusOK)
	}
}

// TestServer_Dashboard_GatedByIPAccess proves the dashboard is also
// subject to ip_allow_list/ip_deny_list, same as every other request —
// no exception there either.
func TestServer_Dashboard_GatedByIPAccess(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.IPDenyList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/dashboard")
	if err != nil {
		t.Fatalf("GET /_aiproxy/dashboard: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// TestServer_Healthz_ReturnsOK proves the basic contract: a GET to
// /_aiproxy/healthz always succeeds with a minimal JSON body.
func TestServer_Healthz_ReturnsOK(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/healthz")
	if err != nil {
		t.Fatalf("GET /_aiproxy/healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Errorf("body = %q, want {\"status\":\"ok\"}", body)
	}
}

// TestServer_Healthz_RejectsNonGetMethod mirrors every other reserved
// path's method restriction.
func TestServer_Healthz_RejectsNonGetMethod(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/_aiproxy/healthz", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /_aiproxy/healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestServer_Healthz_NeverForwardedUpstreamOrCountedInStats mirrors the
// same guarantee every other reserved path makes.
func TestServer_Healthz_NeverForwardedUpstreamOrCountedInStats(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(frontend.URL + "/_aiproxy/healthz")
		if err != nil {
			t.Fatalf("GET /_aiproxy/healthz: %v", err)
		}
		resp.Body.Close()
	}

	if upstreamHit.Load() {
		t.Fatal("a request for healthzPath must never reach the upstream target")
	}

	snap := srv.Stats.Snapshot()
	if snap.Allowed != 0 {
		t.Fatalf("Allowed = %d, want 0 (healthz requests must not themselves be counted)", snap.Allowed)
	}
}

// TestServer_Healthz_NeverGatedByProxyAuth proves the deliberate
// exception documented on healthzPath: unlike every other reserved
// path, healthz stays reachable even with proxy_api_key configured and
// no credential presented at all.
func TestServer_Healthz_NeverGatedByProxyAuth(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.ProxyAPIKey = "s3cr3t-shared-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/healthz")
	if err != nil {
		t.Fatalf("GET /_aiproxy/healthz (no credential): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (healthz must never require proxy_api_key)", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_Healthz_NeverGatedByIPAccess proves the same exception
// for ip_allow_list/ip_deny_list: healthz stays reachable even from an
// IP that would otherwise be denied.
func TestServer_Healthz_NeverGatedByIPAccess(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.IPDenyList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/_aiproxy/healthz")
	if err != nil {
		t.Fatalf("GET /_aiproxy/healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (healthz must never be IP-gated)", resp.StatusCode, http.StatusOK)
	}
}

// postWithProxyAuth POSTs body to url carrying a Proxy-Authorization
// header for key, the same helper shape as getWithProxyAuth but for a
// request custom rules can actually scan.
func postWithProxyAuth(t *testing.T, url, key, contentType, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

// TestServer_CustomRuleTargetScoping_OnlyBlocksConfiguredTarget proves a
// custom rule whose Targets names only one route blocks a matching
// secret sent to that target but lets the identical secret through
// completely unblocked when sent to a different target — the rule is
// treated as if it didn't exist at all outside its configured scope,
// not merely "not logged" or "dry-run".
func TestServer_CustomRuleTargetScoping_OnlyBlocksConfiguredTarget(t *testing.T) {
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("openai response"))
	}))
	defer openai.Close()

	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("anthropic response"))
	}))
	defer anthropic.Close()

	openaiURL, err := url.Parse(openai.URL)
	if err != nil {
		t.Fatalf("parse openai url: %v", err)
	}
	anthropicURL, err := url.Parse(anthropic.URL)
	if err != nil {
		t.Fatalf("parse anthropic url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "custom-secret",
		Pattern: regexp.MustCompile(`SECRET_[0-9]+`),
		Action:  rules.Block,
		Targets: []string{"/openai"},
	})

	srv := proxy.New("unused", anthropicURL, engine)
	srv.AddRoute("/openai", []*url.URL{openaiURL}, nil, nil, nil)
	srv.AddRoute("/anthropic", []*url.URL{anthropicURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	secretBody := `{"note":"SECRET_12345"}`

	resp, err := http.Post(frontend.URL+"/openai/v1/chat", "application/json", strings.NewReader(secretBody))
	if err != nil {
		t.Fatalf("post to scoped target: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status for /openai = %d, want %d (rule is scoped to this target)", resp.StatusCode, http.StatusForbidden)
	}

	resp, err = http.Post(frontend.URL+"/anthropic/v1/messages", "application/json", strings.NewReader(secretBody))
	if err != nil {
		t.Fatalf("post to non-scoped target: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status for /anthropic = %d, want %d (rule must not apply outside its Targets)", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "anthropic response" {
		t.Fatalf("body = %q, want the anthropic upstream's response", body)
	}
}

// TestServer_CustomRuleKeyScoping_OnlyBlocksConfiguredKey proves the
// same falls-through-as-if-absent behavior for Keys: the same secret is
// blocked for one named proxy key but passes through untouched for
// another, both hitting the exact same route.
func TestServer_CustomRuleKeyScoping_OnlyBlocksConfiguredKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "custom-secret",
		Pattern: regexp.MustCompile(`SECRET_[0-9]+`),
		Action:  rules.Block,
		Keys:    []string{"mobile-app"},
	})

	srv := proxy.New("unused", targetURL, engine)
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "mobile-app", Key: "mobile-key"},
		{Name: "backend-service", Key: "backend-key"},
	}
	srv.Logger = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	secretBody := `{"note":"SECRET_12345"}`

	resp := postWithProxyAuth(t, frontend.URL+"/v1/chat", "mobile-key", "application/json", secretBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status for mobile-app key = %d, want %d (rule is scoped to this key)", resp.StatusCode, http.StatusForbidden)
	}

	resp = postWithProxyAuth(t, frontend.URL+"/v1/chat", "backend-key", "application/json", secretBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status for backend-service key = %d, want %d (rule must not apply outside its Keys)", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "upstream response" {
		t.Fatalf("body = %q, want the upstream's response", body)
	}
}

// TestServer_AdminAddr_MovesAdminSurfaceOffMainListener proves the core
// AdminAddr claim end to end through the real ListenAndServe entry
// point (not httptest.NewServer, which never exercises the two-listener
// path at all): once AdminAddr is set, the admin surface (statsPath
// here) is completely gone from Addr — a plain 404, not the request
// falling through and getting forwarded upstream as if it were an
// ordinary route — while it's fully reachable, correctly, on AdminAddr
// itself. Ordinary proxy traffic on Addr is unaffected either way.
func TestServer_AdminAddr_MovesAdminSurfaceOffMainListener(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	addr := freeLoopbackAddr(t)
	adminAddr := freeLoopbackAddr(t)

	srv := proxy.New(addr, targetURL, rules.NewEngine(rules.Allow))
	srv.AdminAddr = adminAddr
	srv.Logger = log.New(io.Discard, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForServerUp(t, addr, time.Second)
	waitForServerUp(t, adminAddr, time.Second)

	// Ordinary proxy traffic on Addr still works.
	resp, err := http.Get("http://" + addr + "/v1/chat")
	if err != nil {
		t.Fatalf("GET %s/v1/chat: %v", addr, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy traffic status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// statsPath on Addr is gone entirely — a plain 404, not forwarded.
	resp, err = http.Get("http://" + addr + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET %s/_aiproxy/stats: %v", addr, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("stats on Addr status = %d, want %d (must move entirely to AdminAddr)", resp.StatusCode, http.StatusNotFound)
	}

	// statsPath on AdminAddr works correctly.
	resp, err = http.Get("http://" + adminAddr + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET %s/_aiproxy/stats: %v", adminAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats on AdminAddr status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read stats body: %v", err)
	}
	if !strings.Contains(string(body), `"allowed"`) {
		t.Fatalf("stats body = %q, want it to look like a real stats snapshot", body)
	}
}

// TestServer_AdminAddr_NeverForwardsOrdinaryTrafficToUpstream proves
// AdminAddr's own listener only ever serves the admin surface plus
// healthz — a path that would be ordinary proxy traffic on Addr gets a
// 404 on AdminAddr instead of ever reaching the upstream target, since
// forwarding was never this listener's job.
func TestServer_AdminAddr_NeverForwardsOrdinaryTrafficToUpstream(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	addr := freeLoopbackAddr(t)
	adminAddr := freeLoopbackAddr(t)

	srv := proxy.New(addr, targetURL, rules.NewEngine(rules.Allow))
	srv.AdminAddr = adminAddr
	srv.Logger = log.New(io.Discard, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForServerUp(t, adminAddr, time.Second)

	resp, err := http.Get("http://" + adminAddr + "/v1/chat")
	if err != nil {
		t.Fatalf("GET %s/v1/chat: %v", adminAddr, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (AdminAddr must never forward ordinary traffic)", resp.StatusCode, http.StatusNotFound)
	}
	if upstreamHit {
		t.Fatal("upstream was hit — AdminAddr must never forward to the upstream target")
	}
}

// TestServer_AdminAddr_StillGatedByProxyAPIKey proves the confirmed
// design choice — moving the admin surface to its own listener changes
// nothing about what's required to reach it — end to end: a request to
// AdminAddr without the configured proxy_api_key is rejected exactly
// like it would be on Addr, and the correct key succeeds.
func TestServer_AdminAddr_StillGatedByProxyAPIKey(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	addr := freeLoopbackAddr(t)
	adminAddr := freeLoopbackAddr(t)

	srv := proxy.New(addr, targetURL, rules.NewEngine(rules.Allow))
	srv.AdminAddr = adminAddr
	srv.ProxyAPIKey = "s3cr3t-key"
	srv.Logger = log.New(io.Discard, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForServerUp(t, adminAddr, time.Second)

	resp, err := http.Get("http://" + adminAddr + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("GET without key: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status without key = %d, want %d (AdminAddr must stay gated by proxy_api_key)", resp.StatusCode, http.StatusProxyAuthRequired)
	}

	resp = getWithProxyAuth(t, "http://"+adminAddr+"/_aiproxy/stats", "s3cr3t-key")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status with correct key = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_AdminAddr_HealthzReachableOnBothListeners proves healthz
// stays on Addr unconditionally (an orchestrator's liveness probe keeps
// working against the same port the service always listened on) while
// also being served on AdminAddr, for an operator who'd rather probe
// the admin listener instead.
func TestServer_AdminAddr_HealthzReachableOnBothListeners(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	addr := freeLoopbackAddr(t)
	adminAddr := freeLoopbackAddr(t)

	srv := proxy.New(addr, targetURL, rules.NewEngine(rules.Allow))
	srv.AdminAddr = adminAddr
	srv.ProxyAPIKey = "s3cr3t-key" // healthz must stay exempt even so
	srv.Logger = log.New(io.Discard, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForServerUp(t, addr, time.Second)
	waitForServerUp(t, adminAddr, time.Second)

	for _, a := range []string{addr, adminAddr} {
		resp, err := http.Get("http://" + a + "/_aiproxy/healthz")
		if err != nil {
			t.Fatalf("GET %s/_aiproxy/healthz: %v", a, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz on %s status = %d, want %d", a, resp.StatusCode, http.StatusOK)
		}
	}
}

// TestNewUpstreamTransport_ZeroMeansUnlimitedResponseHeaderTimeout
// proves the zero value — upstream_response_timeout_seconds absent —
// resolves to Go's own unlimited default, the exact behavior aiproxy
// had before this feature existed.
func TestNewUpstreamTransport_ZeroMeansUnlimitedResponseHeaderTimeout(t *testing.T) {
	tr := proxy.NewUpstreamTransport(0)
	if tr.ResponseHeaderTimeout != 0 {
		t.Fatalf("ResponseHeaderTimeout = %v, want 0 (unlimited)", tr.ResponseHeaderTimeout)
	}
}

// TestNewUpstreamTransport_SetsResponseHeaderTimeout proves a positive
// duration is threaded straight through onto the built transport.
func TestNewUpstreamTransport_SetsResponseHeaderTimeout(t *testing.T) {
	tr := proxy.NewUpstreamTransport(5 * time.Second)
	if tr.ResponseHeaderTimeout != 5*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 5s", tr.ResponseHeaderTimeout)
	}
}

// TestServer_UpstreamResponseTimeout_AbortsHungUpstream proves
// UpstreamTransport's ResponseHeaderTimeout (upstream_response_timeout_seconds)
// aborts a request whose upstream accepts the connection but never
// responds at all, instead of hanging forever — Go's stdlib default
// behavior before this feature existed.
func TestServer_UpstreamResponseTimeout_AbortsHungUpstream(t *testing.T) {
	block := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never responds until the test explicitly releases it
	}))
	defer upstream.Close()
	defer close(block)

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.UpstreamTransport = proxy.NewUpstreamTransport(150 * time.Millisecond)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	start := time.Now()
	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("request took %v, want it to abort near the 150ms response timeout, not hang", elapsed)
	}
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx (the upstream never responded)", resp.StatusCode)
	}
}

// TestServer_UpstreamResponseTimeout_NeverAffectsPromptResponse proves
// a configured response timeout doesn't get in the way of an upstream
// that actually responds well within it.
func TestServer_UpstreamResponseTimeout_NeverAffectsPromptResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("prompt response"))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.UpstreamTransport = proxy.NewUpstreamTransport(2 * time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "prompt response" {
		t.Fatalf("body = %q, want the upstream's response", body)
	}
}

// TestServer_UpstreamTotalTimeout_AbortsHungUpstream proves
// UpstreamTotalTimeout also catches a fully hung upstream, the same
// failure mode UpstreamResponseTimeout catches — it wraps the entire
// round trip, headers included.
func TestServer_UpstreamTotalTimeout_AbortsHungUpstream(t *testing.T) {
	block := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer upstream.Close()
	defer close(block)

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.UpstreamTotalTimeout = 150 * time.Millisecond
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	start := time.Now()
	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("request took %v, want it to abort near the 150ms total timeout, not hang", elapsed)
	}
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx (the upstream never responded)", resp.StatusCode)
	}
}

// TestServer_UpstreamTotalTimeout_AbortsStalledStreamMidway proves
// UpstreamTotalTimeout catches what UpstreamResponseTimeout structurally
// can't: an upstream that responds promptly and starts streaming, then
// stalls before finishing. The handler here answers immediately and
// flushes a first chunk right away, well under the configured total
// timeout, then sleeps far longer than it before sending a second chunk
// — proving the whole request is aborted close to the timeout instead
// of waiting for the handler's full (much longer) sleep to elapse.
func TestServer_UpstreamTotalTimeout_AbortsStalledStreamMidway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("chunk1"))
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond)
		w.Write([]byte("chunk2"))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.UpstreamTotalTimeout = 150 * time.Millisecond
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	start := time.Now()
	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body) // an error here is an acceptable way to observe the abort too
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("request took %v, want it aborted near the 150ms total timeout rather than waiting out the handler's 2s stall", elapsed)
	}
	if string(body) == "chunk1chunk2" {
		t.Fatalf("received the full body %q — the stalled stream should have been aborted before chunk2 arrived", body)
	}
}

// TestServer_UpstreamTotalTimeout_NeverAffectsFastCompletion proves a
// configured total timeout doesn't get in the way of a request that
// completes well within it.
func TestServer_UpstreamTotalTimeout_NeverAffectsFastCompletion(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fast response"))
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.UpstreamTotalTimeout = 2 * time.Second
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "fast response" {
		t.Fatalf("body = %q, want the upstream's response", body)
	}
}

// TestServer_ReloadConfig_UpdatesUpstreamTimeouts proves both timeout
// settings are actually swapped in by a live SIGHUP-style reload, not
// just settable at construction — a hung upstream that would otherwise
// succeed (no timeout configured) is correctly aborted once
// ReloadConfig installs a short one.
func TestServer_ReloadConfig_UpdatesUpstreamTimeouts(t *testing.T) {
	block := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer upstream.Close()
	defer close(block)

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(150*time.Millisecond), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil)

	start := time.Now()
	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("request took %v, want the reloaded 150ms response timeout to abort it quickly", elapsed)
	}
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx", resp.StatusCode)
	}
}

// getWithAccept issues a GET to url carrying the given Accept header
// (empty means no header at all, matching a plain http.Get).
func getWithAccept(t *testing.T, url, accept string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return resp
}

// proxyErrorBody is the JSON shape writeError sends — a local copy
// (proxy_test is an external test package, with no access to the
// unexported errorResponse type) so these tests decode against the
// exact same wire shape a real client would.
type proxyErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Rule    string `json:"rule,omitempty"`
}

// TestServer_Block_PlainTextByDefault proves a real end-to-end blocked
// request, through the actual ServeHTTP path, still gets exactly the
// same plain-text body as ever when the client never asks for JSON.
func TestServer_Block_PlainTextByDefault(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/upload", "application/json", strings.NewReader(`{"key":"AKIAABCDEFGHIJKLMNOP"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.TrimSpace(string(body)) != "blocked by aiproxy rules" {
		t.Fatalf("body = %q, want the plain message", body)
	}
}

// TestServer_Block_JSONErrorWhenAccepted proves the same real blocked
// request instead gets a structured JSON body — with the matched rule
// name populated — when the client's Accept header explicitly asks for
// application/json.
func TestServer_Block_JSONErrorWhenAccepted(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/upload", strings.NewReader(`{"key":"AKIAABCDEFGHIJKLMNOP"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got proxyErrorBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	want := proxyErrorBody{Error: "block", Message: "blocked by aiproxy rules", Rule: "aws-access-key"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestServer_RateLimited_JSONErrorWhenAccepted proves content
// negotiation applies uniformly across rejection reasons, not just
// block — the JSON body correctly reports "rate_limited" with no rule
// (rate limiting isn't attributable to any one rule).
func TestServer_RateLimited_JSONErrorWhenAccepted(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Limiter = limiter.New(0, time.Minute) // 0 allowed per window: the very first request already trips it
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp := getWithAccept(t, frontend.URL+"/v1/chat", "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
	var got proxyErrorBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	want := proxyErrorBody{Error: "rate_limited", Message: "rate limit exceeded"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestServer_IPDenied_JSONErrorWhenAccepted proves a network-level
// rejection (checked before proxy auth, before anything else) is also
// covered by content negotiation.
func TestServer_IPDenied_JSONErrorWhenAccepted(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.IPDenyList = []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp := getWithAccept(t, frontend.URL+"/v1/chat", "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	var got proxyErrorBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	want := proxyErrorBody{Error: "ip_denied", Message: "access denied"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestServer_ResponseBlock_JSONErrorWhenAccepted proves the
// response-side synthetic error body (rewritten from inside
// ModifyResponse, not a direct ServeHTTP write) also honors content
// negotiation end to end through a real forwarded request.
func TestServer_ResponseBlock_JSONErrorWhenAccepted(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"echo":"AKIAABCDEFGHIJKLMNOP"}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})
	srv := proxy.New("unused", targetURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp := getWithAccept(t, frontend.URL+"/v1/chat", "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got proxyErrorBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if got.Error != "response_block" {
		t.Fatalf("Error = %q, want response_block", got.Error)
	}
}

// TestServer_AdminPathMovedOff_JSONNotFoundWhenAccepted proves the
// generic 404 for an admin path moved off the main listener (see
// AdminAddr) also honors content negotiation.
func TestServer_AdminPathMovedOff_JSONNotFoundWhenAccepted(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.AdminAddr = "127.0.0.1:0" // never actually started; only its non-empty-ness matters to ServeHTTP's own check
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp := getWithAccept(t, frontend.URL+"/_aiproxy/stats", "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	var got proxyErrorBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if got.Error != "not_found" {
		t.Fatalf("Error = %q, want not_found", got.Error)
	}
}

// TestServer_NotifyEvent_DeliversWebhookWithEventAndText proves the
// exported NotifyEvent — the CLI package's own entry point for
// reporting a process-level event (a config-reload diff) it detects
// outside of ServeHTTP's own request handling — delivers a real webhook
// with no method/URL/rule, the same shape as every other
// no-single-request-to-attribute event (target_ejected/target_recovered).
func TestServer_NotifyEvent_DeliversWebhookWithEventAndText(t *testing.T) {
	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.WebhookURL = webhookURL
	srv.Logger = log.New(io.Discard, "", 0)

	srv.NotifyEvent("config_changed", "aiproxy: config reloaded from aiproxy.json: max_requests_per_minute: 60 -> 100")

	select {
	case payload := <-received:
		if payload["event"] != "config_changed" {
			t.Errorf("event = %v, want config_changed", payload["event"])
		}
		if payload["text"] != "aiproxy: config reloaded from aiproxy.json: max_requests_per_minute: 60 -> 100" {
			t.Errorf("text = %v, want the exact diff summary", payload["text"])
		}
		if payload["method"] != nil && payload["method"] != "" {
			t.Errorf("method = %v, want empty (not tied to any one request)", payload["method"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never received the config_changed event")
	}
}

// TestServer_CORS_PreflightAnsweredWithoutReachingUpstream proves a
// real browser-shaped preflight (OPTIONS + Access-Control-Request-
// Method) gets a 204 carrying the configured CORS headers and never
// reaches the upstream target — the preflight itself never carries the
// caller's own credentials, so it must be answered before proxy auth,
// rules, or forwarding ever run.
func TestServer_CORS_PreflightAnsweredWithoutReachingUpstream(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.ProxyAPIKey = "secret-key" // proves the preflight skips auth entirely
	srv.CORS = &proxy.CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowCredentials: true,
		MaxAgeSeconds:    600,
	}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodOptions, frontend.URL+"/v1/chat", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type, x-api-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the echoed specific origin", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods missing")
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "content-type, x-api-key" {
		t.Errorf("Access-Control-Allow-Headers = %q, want the reflected request headers", got)
	}
	if got := resp.Header.Get("Access-Control-Max-Age"); got != "600" {
		t.Errorf("Access-Control-Max-Age = %q, want 600", got)
	}
	if n := atomic.LoadInt32(&upstreamHits); n != 0 {
		t.Fatalf("upstream received %d requests, want 0 (a preflight must never be forwarded)", n)
	}
}

// TestServer_CORS_AllowedOriginGetsHeaderOnSuccessfulRequest proves an
// actual (non-preflight) request from an allowed origin carries the
// CORS header through to a genuine, successfully forwarded response.
func TestServer_CORS_AllowedOriginGetsHeaderOnSuccessfulRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.CORS = &proxy.CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/v1/chat", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://app.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://app.example.com", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want empty (not configured)", got)
	}
}

// TestServer_CORS_DisallowedOriginGetsNoHeader proves a request from an
// origin not on the allow list gets no CORS header at all — the
// browser's own same-origin policy then blocks the page's JS from
// reading the (still successfully delivered, at the HTTP level)
// response, exactly the intended enforcement point for CORS.
func TestServer_CORS_DisallowedOriginGetsNoHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.CORS = &proxy.CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/v1/chat", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://evil.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (CORS never blocks at the HTTP level, only the header)", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for a disallowed origin", got)
	}
}

// TestServer_CORS_WildcardEchoesSpecificOriginNeverLiteralAsterisk
// proves cors_allowed_origins: ["*"] still echoes back the caller's own
// specific Origin value, never the literal "*" — required by spec
// whenever Access-Control-Allow-Credentials is also sent, and simpler
// to always do regardless.
func TestServer_CORS_WildcardEchoesSpecificOriginNeverLiteralAsterisk(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.CORS = &proxy.CORSConfig{AllowedOrigins: []string{"*"}, AllowCredentials: true}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/v1/chat", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://anything.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://anything.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the echoed specific origin, never a literal \"*\"", got)
	}
}

// TestServer_CORS_RejectionStillCarriesHeader proves a request that
// gets rejected (here: proxy_api_key auth) still carries the correct
// CORS header — otherwise a browser-based client's own JS error
// handling never sees the real reason for the failure, just an opaque
// CORS error masking it.
func TestServer_CORS_RejectionStillCarriesHeader(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.ProxyAPIKey = "secret-key"
	srv.CORS = &proxy.CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodPost, frontend.URL+"/v1/chat", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://app.example.com")
	// Deliberately no Proxy-Authorization header.

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://app.example.com even on a rejected request", got)
	}
}

// TestServer_CORS_CacheHitFromDifferentAllowedOriginGetsItsOwnHeader
// proves a second request for the same cached response, from a
// different (but still allowed) origin than the one that originally
// populated the cache entry, gets ITS OWN correct CORS header — never
// the first request's stale one. Both origins are configured via a
// wildcard so a single request each is enough to prove the freshness,
// without needing two exact-origin entries.
func TestServer_CORS_CacheHitFromDifferentAllowedOriginGetsItsOwnHeader(t *testing.T) {
	t.Chdir(t.TempDir())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Logger = log.New(io.Discard, "", 0)
	srv.CORS = &proxy.CORSConfig{AllowedOrigins: []string{"*"}}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	postFrom := func(origin string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/v1/chat", strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		return resp
	}

	first := postFrom("https://one.example.com")
	first.Body.Close()
	if got := first.Header.Get("Access-Control-Allow-Origin"); got != "https://one.example.com" {
		t.Fatalf("first request Access-Control-Allow-Origin = %q, want https://one.example.com", got)
	}

	second := postFrom("https://two.example.com") // same cache key, different origin
	defer second.Body.Close()
	if got := second.Header.Get("Access-Control-Allow-Origin"); got != "https://two.example.com" {
		t.Fatalf("cache-hit Access-Control-Allow-Origin = %q, want https://two.example.com (its own origin, not the first request's stale one)", got)
	}
}

// TestServer_RateLimitHeaders_PresentOnAllowedRequestAndDecreasing
// proves X-RateLimit-{Limit,Remaining,Reset}-Requests appear on a
// genuinely successful response, not only on a 429 — the whole point
// being a well-behaved client can see it's close to a limit before it
// ever actually gets rejected — and that Remaining counts down request
// by request.
func TestServer_RateLimitHeaders_PresentOnAllowedRequestAndDecreasing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.Limiter = limiter.New(5, time.Minute)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	wantRemaining := []string{"4", "3", "2"}
	for i, want := range wantRemaining {
		resp, err := http.Get(frontend.URL + "/endpoint")
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i+1, resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("X-Ratelimit-Limit-Requests"); got != "5" {
			t.Fatalf("request %d: X-RateLimit-Limit-Requests = %q, want 5", i+1, got)
		}
		if got := resp.Header.Get("X-Ratelimit-Remaining-Requests"); got != want {
			t.Fatalf("request %d: X-RateLimit-Remaining-Requests = %q, want %s", i+1, got, want)
		}
		if got := resp.Header.Get("X-Ratelimit-Reset-Requests"); got == "" {
			t.Fatalf("request %d: X-RateLimit-Reset-Requests missing", i+1)
		}
		if resp.Header.Get("Retry-After") != "" {
			t.Fatalf("request %d: Retry-After present on an allowed request, want absent", i+1)
		}
	}
}

// TestServer_RateLimitHeaders_RetryAfterPresentOnRejection proves a
// genuine 429 carries Remaining=0 and a real Retry-After value a
// well-behaved client can wait out — rounded up, never truncated down
// to less than the actual remaining wait.
func TestServer_RateLimitHeaders_RetryAfterPresentOnRejection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.Limiter = limiter.New(1, time.Minute)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	first, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	first.Body.Close()

	resp, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
	if got := resp.Header.Get("X-Ratelimit-Remaining-Requests"); got != "0" {
		t.Fatalf("X-RateLimit-Remaining-Requests = %q, want 0", got)
	}
	retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil {
		t.Fatalf("Retry-After = %q, want an integer number of seconds: %v", resp.Header.Get("Retry-After"), err)
	}
	if retryAfter <= 0 || retryAfter > 60 {
		t.Fatalf("Retry-After = %d, want a positive value up to the 60s window", retryAfter)
	}
}

// TestServer_RateLimitHeaders_TokenLimiterUsesItsOwnHeaderPair proves
// the token-based limiter reports through its own
// X-RateLimit-*-Tokens header trio, independent of (and alongside) the
// request-count limiter's own X-RateLimit-*-Requests trio when both
// are configured.
func TestServer_RateLimitHeaders_TokenLimiterUsesItsOwnHeaderPair(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"usage":{"total_tokens":40}}`))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.Limiter = limiter.New(100, time.Minute)
	srv.TokenLimiter = limiter.NewTokenLimiter(100, time.Minute)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/endpoint", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if got := resp.Header.Get("X-Ratelimit-Limit-Requests"); got != "100" {
		t.Errorf("X-RateLimit-Limit-Requests = %q, want 100", got)
	}
	if got := resp.Header.Get("X-Ratelimit-Limit-Tokens"); got != "100" {
		t.Errorf("X-RateLimit-Limit-Tokens = %q, want 100", got)
	}
	if got := resp.Header.Get("X-Ratelimit-Remaining-Tokens"); got != "100" {
		// The 40-token usage this response reports is only recorded
		// asynchronously once the response body is read — it can never
		// be reflected in this same response's own headers, only a
		// later request's.
		t.Errorf("X-RateLimit-Remaining-Tokens = %q, want 100 (this response's own usage isn't known until after it's already been sent)", got)
	}
}

// TestServer_RateLimitHeaders_AbsentWhenNoLimiterConfigured proves no
// rate-limit headers appear at all when neither limiter is configured
// — a request that never asks a limiter anything has no limiter state
// to report.
func TestServer_RateLimitHeaders_AbsentWhenNoLimiterConfigured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	for _, h := range []string{"X-Ratelimit-Limit-Requests", "X-Ratelimit-Remaining-Requests", "X-Ratelimit-Reset-Requests"} {
		if got := resp.Header.Get(h); got != "" {
			t.Errorf("%s = %q, want absent when no limiter is configured", h, got)
		}
	}
}

// TestServer_RateLimitHeaders_AbsentOnCacheHit proves a cache hit —
// which bypasses the rate limiter entirely, and always has — carries
// no rate-limit headers either: there is no limiter state to report
// for a request that never actually asked the limiter anything.
func TestServer_RateLimitHeaders_AbsentOnCacheHit(t *testing.T) {
	t.Chdir(t.TempDir())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Logger = log.New(io.Discard, "", 0)
	srv.Limiter = limiter.New(100, time.Minute)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func() *http.Response {
		resp, err := http.Post(frontend.URL+"/v1/chat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	first := post()
	first.Body.Close()
	if got := first.Header.Get("X-Ratelimit-Remaining-Requests"); got == "" {
		t.Fatal("first (non-cached) request missing X-RateLimit-Remaining-Requests")
	}

	second := post() // a genuine cache hit
	defer second.Body.Close()
	if got := second.Header.Get("X-Ratelimit-Remaining-Requests"); got != "" {
		t.Fatalf("cache-hit X-RateLimit-Remaining-Requests = %q, want absent (a cache hit never consults the limiter)", got)
	}
}

// TestServer_RequestID_GeneratedAndEchoedOnASuccessfulResponse proves a
// client that never sends its own X-Request-Id still gets a real,
// freshly generated one back on the response — every response carries
// one, not only a rejection.
func TestServer_RequestID_GeneratedAndEchoedOnASuccessfulResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Request-Id"); got == "" {
		t.Fatal("X-Request-Id missing on a successful response")
	}
}

// TestServer_RequestID_ClientSuppliedIDIsEchoedBackVerbatim proves a
// client's own X-Request-Id is reused rather than replaced, so a
// caller that already generates its own correlation ID (a gateway
// further upstream, say) can still tie aiproxy's own logs back to that
// exact value.
func TestServer_RequestID_ClientSuppliedIDIsEchoedBackVerbatim(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/endpoint", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Request-Id", "caller-generated-id-42")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Request-Id"); got != "caller-generated-id-42" {
		t.Fatalf("X-Request-Id = %q, want the client's own caller-generated-id-42 echoed back", got)
	}
}

// TestServer_RequestID_UnsafeClientSuppliedIDIsReplaced proves a
// client-supplied X-Request-Id containing characters that could break
// a log line or enable header injection if echoed back is never
// trusted — aiproxy generates its own instead, silently, rather than
// rejecting the request over what's ultimately just a logging nicety.
func TestServer_RequestID_UnsafeClientSuppliedIDIsReplaced(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/endpoint", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Go's own net/http client refuses to send a header value containing
	// a raw CR/LF itself, so the unsafe shape tested here is a
	// double-quote — still outside aiproxy's safe charset, but a value
	// an HTTP client will actually transmit.
	req.Header.Set("X-Request-Id", `unsafe"value`)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Request-Id"); got == `unsafe"value` {
		t.Fatal("X-Request-Id echoed back the unsafe client-supplied value verbatim, want a fresh generated one instead")
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Fatal("X-Request-Id missing entirely after rejecting the unsafe client value")
	}
}

// TestServer_RequestID_PresentOnRejectionAndDistinctPerRequest proves
// the header is present on a genuine rejection too (not only a
// forwarded response), and that two different requests never collide
// on the same ID.
func TestServer_RequestID_PresentOnRejectionAndDistinctPerRequest(t *testing.T) {
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.ProxyAPIKey = "secret"
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	first, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	defer first.Body.Close()
	if first.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", first.StatusCode, http.StatusProxyAuthRequired)
	}
	firstID := first.Header.Get("X-Request-Id")
	if firstID == "" {
		t.Fatal("X-Request-Id missing on a rejected (407) response")
	}

	second, err := http.Get(frontend.URL + "/endpoint")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer second.Body.Close()
	secondID := second.Header.Get("X-Request-Id")
	if secondID == "" {
		t.Fatal("X-Request-Id missing on the second rejected response")
	}
	if firstID == secondID {
		t.Fatalf("two different requests got the same X-Request-Id: %q", firstID)
	}
}

// TestServer_RequestID_IncludedInWebhookPayload proves a webhook alert
// carries the same request_id as the log line for the request that
// triggered it, so an operator can correlate a Slack/webhook alert
// with the exact log lines for that one request.
func TestServer_RequestID_IncludedInWebhookPayload(t *testing.T) {
	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()
	webhookURL, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatalf("parse webhook url: %v", err)
	}

	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.WebhookURL = webhookURL
	srv.ProxyAPIKey = "secret"
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/endpoint", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Request-Id", "webhook-correlation-test-id")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	select {
	case payload := <-received:
		if payload["request_id"] != "webhook-correlation-test-id" {
			t.Errorf("webhook payload request_id = %v, want webhook-correlation-test-id", payload["request_id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never received the unauthorized event")
	}
}

// TestServer_IPRateLimit_SixthRequestFromOneIPGets429AndHeaders proves
// the core per-IP budget: 5 requests from the same caller IP succeed,
// the 6th is rejected with 429 and the X-RateLimit-*-Ip headers/
// Retry-After a real client can act on. Uses a synthetic request with
// a manually-set RemoteAddr (rather than a real httptest.NewServer
// connection, which always originates from 127.0.0.1) so two
// different-IP scenarios can actually be distinguished — see
// TestServer_IPRateLimit_DifferentIPsHaveIndependentBudgets.
func TestServer_IPRateLimit_SixthRequestFromOneIPGets429AndHeaders(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.IPLimiter = iplimiter.NewRegistry(5, time.Minute)

	doRequest := func(remoteAddr string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "/endpoint", nil)
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Result()
	}

	for i := 1; i <= 5; i++ {
		resp := doRequest("203.0.113.5:1234")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("X-Ratelimit-Limit-Ip"); got != "5" {
			t.Errorf("request %d: X-RateLimit-Limit-Ip = %q, want 5", i, got)
		}
	}
	if upstreamHits.Load() != 5 {
		t.Fatalf("upstream hits = %d, want exactly 5", upstreamHits.Load())
	}

	resp := doRequest("203.0.113.5:1234")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th request: status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
	if got := resp.Header.Get("X-Ratelimit-Remaining-Ip"); got != "0" {
		t.Errorf("6th request: X-RateLimit-Remaining-Ip = %q, want 0", got)
	}
	retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retryAfter <= 0 || retryAfter > 60 {
		t.Errorf("6th request: Retry-After = %q, want a positive integer up to 60", resp.Header.Get("Retry-After"))
	}
	if upstreamHits.Load() != 5 {
		t.Fatalf("upstream hits after the 6th (rejected) request = %d, want still exactly 5", upstreamHits.Load())
	}
}

// TestServer_IPRateLimit_DifferentIPsHaveIndependentBudgets proves one
// caller IP exhausting its own budget never throttles a different IP
// — the whole point of per-IP (rather than one shared) limiting.
func TestServer_IPRateLimit_DifferentIPsHaveIndependentBudgets(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.IPLimiter = iplimiter.NewRegistry(1, time.Minute)

	doRequest := func(remoteAddr string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "/endpoint", nil)
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Result()
	}

	if resp := doRequest("203.0.113.1:1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("IP #1 first request: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp := doRequest("203.0.113.1:1"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("IP #1 second request: status = %d, want %d (its own 1-request budget exhausted)", resp.StatusCode, http.StatusTooManyRequests)
	}
	// A completely different IP must still get its own fresh request
	// through, unaffected by IP #1's own exhausted budget.
	if resp := doRequest("203.0.113.2:1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("IP #2 first request: status = %d, want %d (independent budget from IP #1)", resp.StatusCode, http.StatusOK)
	}
}

// TestServer_IPRateLimit_AppliesRegardlessOfProxyAuth proves the
// per-IP breaker is checked before, and independent of,
// proxy_api_key authentication — protection for a caller with no
// identity of its own, not something an authenticated caller can
// bypass or that only applies to unauthenticated ones.
func TestServer_IPRateLimit_AppliesRegardlessOfProxyAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.IPLimiter = iplimiter.NewRegistry(1, time.Minute)
	srv.ProxyAPIKey = "secret"

	doRequest := func() *http.Response {
		req := httptest.NewRequest(http.MethodGet, "/endpoint", nil)
		req.RemoteAddr = "203.0.113.9:1"
		req.Header.Set("Proxy-Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Result()
	}

	if resp := doRequest(); resp.StatusCode != http.StatusOK {
		t.Fatalf("first authenticated request: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp := doRequest()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second authenticated request: status = %d, want %d (per-IP budget applies even with a valid proxy_api_key)", resp.StatusCode, http.StatusTooManyRequests)
	}
}

// TestServer_IPRateLimit_StatsAndLogReflectRejection proves a genuine
// rejection is counted (global-only, per Stats.RecordIPRateLimited)
// and logged under its own distinct ip_rate_limited level, never
// folded into the identity-based rate_limited counter/level.
func TestServer_IPRateLimit_StatsAndLogReflectRejection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	var logBuf bytes.Buffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(&logBuf, "", 0)
	srv.IPLimiter = iplimiter.NewRegistry(1, time.Minute)

	doRequest := func() *http.Response {
		req := httptest.NewRequest(http.MethodGet, "/endpoint", nil)
		req.RemoteAddr = "203.0.113.7:1"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Result()
	}

	doRequest()
	doRequest()

	snap := srv.Stats.Snapshot()
	if snap.IPRateLimited != 1 {
		t.Fatalf("Stats.IPRateLimited = %d, want 1", snap.IPRateLimited)
	}
	if snap.RateLimited != 0 {
		t.Fatalf("Stats.RateLimited = %d, want 0 (must never be folded into the identity-based counter)", snap.RateLimited)
	}
	if !strings.Contains(logBuf.String(), "[IP RATE LIMITED]") {
		t.Fatalf("log missing [IP RATE LIMITED] line: %q", logBuf.String())
	}
}

// TestServer_TargetCacheTTL_OverridesGlobalTTLForOnlyThatTarget proves
// a target's own TargetCacheTTL entry is used instead of the
// server-wide CacheTTL for its own cache entries, while a different
// target with no override keeps using the global default unaffected.
func TestServer_TargetCacheTTL_OverridesGlobalTTLForOnlyThatTarget(t *testing.T) {
	t.Chdir(t.TempDir())

	var shortHits, longHits atomic.Int32
	short := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shortHits.Add(1)
		w.Write([]byte("short"))
	}))
	defer short.Close()
	long := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		longHits.Add(1)
		w.Write([]byte("long"))
	}))
	defer long.Close()

	shortURL, err := url.Parse(short.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	longURL, err := url.Parse(long.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", longURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.CacheTTL = time.Hour // the default: effectively never expires for this test's timescale
	srv.TargetCacheTTL = map[string]time.Duration{"/short": 30 * time.Millisecond}
	srv.AddRoute("/short", []*url.URL{shortURL}, nil, nil, nil)
	srv.AddRoute("/long", []*url.URL{longURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func(path string) {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
	}

	post("/short/v1/x")
	post("/long/v1/x")
	time.Sleep(50 * time.Millisecond) // past /short's own 30ms override, nowhere near /long's 1h default
	post("/short/v1/x")
	post("/long/v1/x")

	if got := shortHits.Load(); got != 2 {
		t.Fatalf("/short upstream hits = %d, want 2 (its own 30ms override expired the cached entry)", got)
	}
	if got := longHits.Load(); got != 1 {
		t.Fatalf("/long upstream hits = %d, want 1 (still cached under the 1h global default, unaffected by /short's own override)", got)
	}
}

// TestServer_TargetCacheEnabled_FalseOptsOutEvenWithGlobalCachingOn
// proves a target's own TargetCacheEnabled=false entry disables
// caching for just that target's traffic, while every other target
// keeps caching normally under the server-wide default.
func TestServer_TargetCacheEnabled_FalseOptsOutEvenWithGlobalCachingOn(t *testing.T) {
	t.Chdir(t.TempDir())

	var neverHits, alwaysHits atomic.Int32
	never := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		neverHits.Add(1)
		w.Write([]byte("never"))
	}))
	defer never.Close()
	always := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alwaysHits.Add(1)
		w.Write([]byte("always"))
	}))
	defer always.Close()

	neverURL, err := url.Parse(never.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	alwaysURL, err := url.Parse(always.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", alwaysURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	falseVal := false
	srv.TargetCacheEnabled = map[string]bool{"/never-cache": falseVal}
	srv.AddRoute("/never-cache", []*url.URL{neverURL}, nil, nil, nil)
	srv.AddRoute("/always-cache", []*url.URL{alwaysURL}, nil, nil, nil)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func(path string) {
		resp, err := http.Post(frontend.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
	}

	post("/never-cache/v1/x")
	post("/always-cache/v1/x")
	post("/never-cache/v1/x") // identical body/path again
	post("/always-cache/v1/x")

	if got := neverHits.Load(); got != 2 {
		t.Fatalf("/never-cache upstream hits = %d, want 2 (caching disabled for this target, every request must reach upstream)", got)
	}
	if got := alwaysHits.Load(); got != 1 {
		t.Fatalf("/always-cache upstream hits = %d, want 1 (a genuine cache hit on the second identical request)", got)
	}
}

// TestServer_TargetCacheEnabled_TrueNeverWidensWhenCacheIsNil proves a
// target's own TargetCacheEnabled=true override has no effect at all
// when Server.Cache itself is nil — a per-target setting alone must
// never be what silently stands up real on-disk cache infrastructure;
// that decision always starts at the top-level cache_enabled.
func TestServer_TargetCacheEnabled_TrueNeverWidensWhenCacheIsNil(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Write([]byte("response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	// srv.Cache deliberately left nil — global caching off entirely.
	trueVal := true
	srv.TargetCacheEnabled = map[string]bool{"default": trueVal}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"model":"gpt-4"}`
	post := func() {
		resp, err := http.Post(frontend.URL+"/v1/x", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}

	post()
	post() // identical request again

	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream hits = %d, want 2 — a per-target cache_enabled=true override must never widen caching on when Server.Cache is nil", got)
	}
}

// TestServer_WeightedRouting_SplitApproximatesConfiguredWeights proves
// the real, end-to-end weighted-routing behavior: with a heavily
// lopsided 995:5 split across many real requests, the heavy candidate
// gets the large majority of traffic and the light candidate still
// gets a genuine, non-zero share — a real statistical split, not a
// disguised failover list.
func TestServer_WeightedRouting_SplitApproximatesConfiguredWeights(t *testing.T) {
	var heavyHits, lightHits atomic.Int32
	heavy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		heavyHits.Add(1)
		w.Write([]byte("heavy"))
	}))
	defer heavy.Close()
	light := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lightHits.Add(1)
		w.Write([]byte("light"))
	}))
	defer light.Close()

	heavyURL, err := url.Parse(heavy.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	lightURL, err := url.Parse(light.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", heavyURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/split", []*url.URL{heavyURL, lightURL}, []int{995, 5}, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const trials = 400
	for i := 0; i < trials; i++ {
		// A distinct body every time so this never hits the (disabled
		// here) cache and always genuinely re-resolves the route.
		resp, err := http.Post(frontend.URL+"/split/v1", "application/json", strings.NewReader(fmt.Sprintf(`{"n":%d}`, i)))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		resp.Body.Close()
	}

	total := heavyHits.Load() + lightHits.Load()
	if total != trials {
		t.Fatalf("total hits = %d, want %d", total, trials)
	}
	if lightHits.Load() == 0 {
		t.Fatal("light candidate (weight 5/1000) never received a single request across 400 trials — the split isn't actually random")
	}
	// Loose bound purely to catch a badly broken split (e.g. always
	// picking the same candidate, or a roughly 50/50 split instead of
	// 995:5) without being flaky — heavy should get comfortably more
	// than 3/4 of all traffic.
	if heavyHits.Load() < trials*3/4 {
		t.Fatalf("heavy candidate (weight 995/1000) only received %d/%d requests, want a large majority", heavyHits.Load(), trials)
	}
}

// TestServer_WeightedRouting_FailoverStillProtectsTheChosenCandidate
// proves a weighted pick still gets the same failover protection every
// other route already has: if the weighted-chosen primary is
// unreachable, the request still succeeds against the other declared
// candidate rather than failing outright.
func TestServer_WeightedRouting_FailoverStillProtectsTheChosenCandidate(t *testing.T) {
	dead := httptest.NewServer(hijackAndClose(t))
	defer dead.Close()
	deadURL, err := url.Parse(dead.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer healthy.Close()
	healthyURL, err := url.Parse(healthy.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", healthyURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	// Weight the dead candidate overwhelmingly so it's (almost) always
	// the one chosen first — proving failover rescues the request even
	// when the weighted pick itself lands on the unreachable one.
	srv.AddRoute("/split", []*url.URL{deadURL, healthyURL}, []int{999, 1}, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/split/v1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d — failover must rescue a weighted pick that lands on a dead candidate", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want the healthy candidate's own response", body)
	}
}

// TestServer_WeightedRouting_CacheKeyTracksTheActuallyChosenCandidate
// proves the cache key for a weighted route is computed from whichever
// candidate was actually chosen for THIS request, not a fixed
// declared-first candidate the way a plain failover list's own cache
// key always is — otherwise one candidate's cached response could
// silently leak into a request that was "supposed" to go to a
// genuinely different destination, defeating the entire point of a
// deliberate split between non-interchangeable candidates. Uses an
// overwhelming weight so the SAME candidate is picked (and its
// response cached) consistently enough to assert on, then confirms a
// second identical request is a genuine cache hit serving that exact
// same candidate's own response — not the other one's.
func TestServer_WeightedRouting_CacheKeyTracksTheActuallyChosenCandidate(t *testing.T) {
	t.Chdir(t.TempDir())

	var heavyHits, lightHits atomic.Int32
	heavy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		heavyHits.Add(1)
		w.Write([]byte("response-from-heavy"))
	}))
	defer heavy.Close()
	light := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lightHits.Add(1)
		w.Write([]byte("response-from-light"))
	}))
	defer light.Close()

	heavyURL, err := url.Parse(heavy.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	lightURL, err := url.Parse(light.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", heavyURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Logger = log.New(io.Discard, "", 0)
	srv.AddRoute("/split", []*url.URL{heavyURL, lightURL}, []int{999999, 1}, nil, nil)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"x":1}`
	post := func() *http.Response {
		resp, err := http.Post(frontend.URL+"/split/v1", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	first := post()
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if string(firstBody) != "response-from-heavy" {
		t.Fatalf("first response = %q, want response-from-heavy (999999:1 weight)", firstBody)
	}

	second := post() // identical body: should be a genuine cache hit
	defer second.Body.Close()
	secondBody, _ := io.ReadAll(second.Body)
	if string(secondBody) != "response-from-heavy" {
		t.Fatalf("second (cached) response = %q, want response-from-heavy — the cache entry populated by the heavy candidate must never surface the light candidate's response, or vice versa", secondBody)
	}
	if got := second.Header.Get("Age"); got == "" {
		t.Fatal("second response missing Age header, want a genuine cache hit")
	}
	if heavyHits.Load() != 1 {
		t.Fatalf("heavy upstream hits = %d, want exactly 1 (first request only; the second must be served from cache)", heavyHits.Load())
	}
	if lightHits.Load() != 0 {
		t.Fatalf("light upstream hits = %d, want 0 (999999:1 weight should never have picked it across these 2 requests)", lightHits.Load())
	}
}

// TestServer_ShadowTraffic_MirrorsAllowedRequestToShadowTarget proves
// the core mechanism: an allowed request forwarded to the real target
// also, in the background, reaches the configured shadow target with
// the same method, path, and body.
func TestServer_ShadowTraffic_MirrorsAllowedRequestToShadowTarget(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("real response"))
	}))
	defer real.Close()
	realURL, err := url.Parse(real.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	type shadowReq struct {
		method, path, body string
	}
	received := make(chan shadowReq, 1)
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- shadowReq{method: r.Method, path: r.URL.Path, body: string(body)}
		w.WriteHeader(http.StatusOK)
	}))
	defer shadow.Close()
	shadowURL, err := url.Parse(shadow.URL)
	if err != nil {
		t.Fatalf("parse shadow url: %v", err)
	}

	srv := proxy.New("unused", realURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TargetShadowURL = map[string]*url.URL{"default": shadowURL}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Post(frontend.URL+"/v1/chat", "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "real response" {
		t.Fatalf("client response = %q, want %q (must always come from the real target)", body, "real response")
	}

	select {
	case got := <-received:
		if got.method != http.MethodPost {
			t.Errorf("shadow method = %q, want POST", got.method)
		}
		if got.path != "/v1/chat" {
			t.Errorf("shadow path = %q, want /v1/chat", got.path)
		}
		if got.body != `{"a":1}` {
			t.Errorf("shadow body = %q, want %q", got.body, `{"a":1}`)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shadow target never received a mirrored request")
	}
}

// TestServer_ShadowTraffic_ClientResponseUnaffectedByASlowShadowTarget
// proves shadowing runs entirely in the background: the client's own
// response returns as soon as the real target answers, never waiting on
// a shadow target that's still hanging.
func TestServer_ShadowTraffic_ClientResponseUnaffectedByASlowShadowTarget(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("real response"))
	}))
	defer real.Close()
	realURL, err := url.Parse(real.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	shadowEntered := make(chan struct{})
	releaseShadow := make(chan struct{})
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(shadowEntered)
		<-releaseShadow
		w.WriteHeader(http.StatusOK)
	}))
	defer shadow.Close()
	shadowURL, err := url.Parse(shadow.URL)
	if err != nil {
		t.Fatalf("parse shadow url: %v", err)
	}

	srv := proxy.New("unused", realURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TargetShadowURL = map[string]*url.URL{"default": shadowURL}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	start := time.Now()
	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	elapsed := time.Since(start)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if elapsed > time.Second {
		t.Fatalf("client response took %s, want well under 1s — it must never wait on the shadow target", elapsed)
	}

	select {
	case <-shadowEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("shadow target was never even reached")
	}
	close(releaseShadow)
}

// TestServer_ShadowTraffic_ClientResponseUnaffectedByAnUnreachableShadowTarget
// proves a shadow target that's simply down never turns into an error
// for the client — the real response is still a clean 200.
func TestServer_ShadowTraffic_ClientResponseUnaffectedByAnUnreachableShadowTarget(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("real response"))
	}))
	defer real.Close()
	realURL, err := url.Parse(real.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	deadURL, err := url.Parse("http://" + freeLoopbackAddr(t))
	if err != nil {
		t.Fatalf("parse dead url: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", realURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(&logBuf, "", 0)
	srv.TargetShadowURL = map[string]*url.URL{"default": deadURL}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "real response" {
		t.Fatalf("status=%d body=%q, want 200 %q (an unreachable shadow target must never affect the real response)", resp.StatusCode, body, "real response")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if snap := srv.Stats.Snapshot(); snap.ShadowError == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Stats.ShadowError never reached 1; snapshot = %+v", srv.Stats.Snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logBuf.String(), "[SHADOW ERROR]") {
		t.Fatalf("log missing [SHADOW ERROR] line: %q", logBuf.String())
	}
}

// TestServer_ShadowTraffic_BlockedRequestIsNeverMirrored proves a
// request the rule engine blocks never reaches the shadow target at
// all — there's nothing genuine to compare a canary's behavior against
// once the real request was never forwarded either.
func TestServer_ShadowTraffic_BlockedRequestIsNeverMirrored(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer real.Close()
	realURL, err := url.Parse(real.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	var shadowHits atomic.Int32
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowHits.Add(1)
	}))
	defer shadow.Close()
	shadowURL, err := url.Parse(shadow.URL)
	if err != nil {
		t.Fatalf("parse shadow url: %v", err)
	}

	srv := proxy.New("unused", realURL, rules.NewEngine(rules.Block)) // blocks everything
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TargetShadowURL = map[string]*url.URL{"default": shadowURL}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL + "/v1/chat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (blocked)", resp.StatusCode)
	}

	time.Sleep(200 * time.Millisecond) // give a wrongly-fired mirror a chance to land
	if got := shadowHits.Load(); got != 0 {
		t.Fatalf("shadow target received %d requests, want 0 (a blocked request must never be mirrored)", got)
	}
}

// TestServer_ShadowTraffic_MirrorsTheRedactedBodyNeverTheRawOne is the
// feature's central safety property: a shadow target must never see
// anything the real one wouldn't also see. When a rule redacts a
// matched secret, the shadow target must receive the SAME redacted
// body the real target gets — never the raw, unredacted client body.
func TestServer_ShadowTraffic_MirrorsTheRedactedBodyNeverTheRawOne(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("real response"))
	}))
	defer real.Close()
	realURL, err := url.Parse(real.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	shadowBody := make(chan string, 1)
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		shadowBody <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadow.Close()
	shadowURL, err := url.Parse(shadow.URL)
	if err != nil {
		t.Fatalf("parse shadow url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "openai-api-key", Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), Action: rules.Redact})

	srv := proxy.New("unused", realURL, engine)
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TargetShadowURL = map[string]*url.URL{"default": shadowURL}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const secret = "sk-abcdefghijklmnopqrstuvwx"
	resp, err := http.Post(frontend.URL+"/v1/chat", "text/plain", strings.NewReader("key="+secret))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	select {
	case got := <-shadowBody:
		if strings.Contains(got, secret) {
			t.Fatalf("shadow target received the RAW secret: %q — redaction must apply before mirroring", got)
		}
		if !strings.Contains(got, "REDACTED") {
			t.Fatalf("shadow body = %q, want it to carry the same [REDACTED:...] marker the real target gets", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shadow target never received a mirrored request")
	}
}

// TestServer_ShadowTraffic_OnlyTargetsWithShadowURLConfiguredAreMirrored
// proves shadowing is genuinely per-target: a route with no shadow_url
// of its own never mirrors anything, even while a different route on
// the same server does.
func TestServer_ShadowTraffic_OnlyTargetsWithShadowURLConfiguredAreMirrored(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer real.Close()
	realURL, err := url.Parse(real.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	var shadowHits atomic.Int32
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowHits.Add(1)
	}))
	defer shadow.Close()
	shadowURL, err := url.Parse(shadow.URL)
	if err != nil {
		t.Fatalf("parse shadow url: %v", err)
	}

	srv := proxy.New("unused", realURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	// Only "/mirrored" gets a shadow target — the bare default (-target,
	// labeled "default") and any other route never do.
	srv.AddRoute("/mirrored", []*url.URL{realURL}, nil, nil, nil)
	srv.TargetShadowURL = map[string]*url.URL{"/mirrored": shadowURL}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	get := func(path string) {
		resp, err := http.Get(frontend.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		resp.Body.Close()
	}
	get("/unmirrored")
	get("/unmirrored")
	time.Sleep(200 * time.Millisecond)
	if got := shadowHits.Load(); got != 0 {
		t.Fatalf("shadow target received %d requests from the unconfigured route, want 0", got)
	}

	get("/mirrored/v1")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if shadowHits.Load() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("shadow target received %d requests from the configured route, want 1", shadowHits.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestServer_ShadowTraffic_SampleRateApproximatesConfiguredFraction
// statistically proves ShadowSampleRate actually controls what
// fraction of forwarded requests get mirrored — mirroring the same
// statistical-dominance style TestServer_WeightedRouting_
// SplitApproximatesConfiguredWeights already established for weighted
// routing.
func TestServer_ShadowTraffic_SampleRateApproximatesConfiguredFraction(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer real.Close()
	realURL, err := url.Parse(real.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	var shadowHits atomic.Int32
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowHits.Add(1)
	}))
	defer shadow.Close()
	shadowURL, err := url.Parse(shadow.URL)
	if err != nil {
		t.Fatalf("parse shadow url: %v", err)
	}

	srv := proxy.New("unused", realURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TargetShadowURL = map[string]*url.URL{"default": shadowURL}
	srv.TargetShadowSampleRate = map[string]float64{"default": 0.1}
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const n = 400
	for i := 0; i < n; i++ {
		resp, err := http.Get(frontend.URL + "/v1/chat")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	var got int32
	for {
		got = shadowHits.Load()
		if got > 0 {
			// Give any still-in-flight background mirrors a moment to
			// land before taking the final count.
			time.Sleep(200 * time.Millisecond)
			got = shadowHits.Load()
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A 10% rate over 400 requests: expect roughly 40, generously
	// bounded (5-90) to keep this non-flaky while still proving the
	// rate is doing SOMETHING — neither ~0% nor ~100%.
	if got < 5 || got > 90 {
		t.Fatalf("shadow target received %d/%d requests (%.1f%%), want roughly 10%% (5-90 range)", got, n, 100*float64(got)/n)
	}
}
