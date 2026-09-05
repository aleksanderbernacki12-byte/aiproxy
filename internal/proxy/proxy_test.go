package proxy_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/limiter"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

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
