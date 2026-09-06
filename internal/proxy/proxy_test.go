package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/cache"
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
	if _, hit, err := c.Get(key); err != nil {
		t.Fatalf("cache.Get: %v", err)
	} else if hit {
		t.Fatal("an aborted stream must never be cached, but a cache entry was found")
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
	srv.AddRoute("/openai", openaiURL, nil)
	srv.AddRoute("/anthropic", anthropicURL, nil)
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
	srv.AddRoute("/openai", openaiURL, nil)
	srv.AddRoute("/anthropic", anthropicURL, nil)
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
	srv.AddRoute("/openai", openaiURL, nil)
	srv.AddRoute("/anthropic", anthropicURL, nil)
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
	if !strings.Contains(summary, "[/openai] allowed=1 blocked=1 redacted=0 rate-limited=0 cache-hits=0 tokens=10 cost=0.0002") {
		t.Fatalf("Summary() missing correct /openai line: %q", summary)
	}
	if !strings.Contains(summary, "[/anthropic] allowed=1 blocked=0 redacted=0 rate-limited=0 cache-hits=0 tokens=30 cost=0.0006") {
		t.Fatalf("Summary() missing correct /anthropic line: %q", summary)
	}
	if !strings.Contains(summary, "[default] allowed=1 blocked=0 redacted=0 rate-limited=0 cache-hits=0 tokens=0 cost=0.0000") {
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

// statsJSONResponse mirrors the wire shape served at GET /_aiproxy/stats,
// for tests to decode into.
type statsJSONResponse struct {
	Allowed       int64                        `json:"allowed"`
	Blocked       int64                        `json:"blocked"`
	Redacted      int64                        `json:"redacted"`
	RateLimited   int64                        `json:"rate_limited"`
	CacheHits     int64                        `json:"cache_hits"`
	TotalTokens   int64                        `json:"total_tokens"`
	EstimatedCost *float64                     `json:"estimated_cost,omitempty"`
	PerTarget     map[string]statsJSONResponse `json:"per_target,omitempty"`
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
	srv.AddRoute("/other", otherURL, nil)
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
	srv.AddRoute("/strict", strictURL, limiter.New(1, time.Minute))
	srv.AddRoute("/shared", sharedURL, nil) // no override: shares srv.Limiter
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
	srv.AddRoute("/limited", targetURL, limiter.New(1, time.Minute))
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
	Time    string `json:"time"`
	Level   string `json:"level"`
	Method  string `json:"method,omitempty"`
	URL     string `json:"url,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Tokens  int    `json:"tokens,omitempty"`
	Message string `json:"message,omitempty"`
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

	wantLevels := []string{"allow", "usage", "block", "rate_limited", "cache_hit"}
	if len(events) != len(wantLevels) {
		t.Fatalf("got %d log events, want %d: %+v", len(events), len(wantLevels), events)
	}
	for i, want := range wantLevels {
		if events[i].Level != want {
			t.Errorf("event %d level = %q, want %q (all events: %+v)", i, events[i].Level, want, events)
		}
	}
	if events[1].Tokens != 7 {
		t.Errorf("usage event tokens = %d, want 7", events[1].Tokens)
	}
	if events[2].Rule != "test-secret" {
		t.Errorf("block event rule = %q, want test-secret", events[2].Rule)
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
	if len(rawLines) != 2 {
		t.Fatalf("got %d log lines, want 2 (the allow event, then the summary): %q", len(rawLines), rawLines)
	}

	var summary statsJSONResponse
	if err := json.Unmarshal([]byte(rawLines[1]), &summary); err != nil {
		t.Fatalf("summary line is not valid JSON: %q: %v", rawLines[1], err)
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
	srv.ReloadConfig(allowAll, nil, nil, 0.05, []proxy.Route{
		{Prefix: "/other", Target: otherURL, Limiter: strictLimiter},
	})

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
			srv.ReloadConfig(rules.NewEngine(action), limiter.New(1000, time.Minute), nil, 0, nil)
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

	var ev jsonLogLine
	if err := json.Unmarshal(bytes.TrimSpace(logBuf.Bytes()), &ev); err != nil {
		t.Fatalf("log line is not valid JSON: %q: %v", logBuf.String(), err)
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
