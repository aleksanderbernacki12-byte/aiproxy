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

	srv.Stats.RecordTokensUsed(2500)

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
	srv.AddRoute("/openai", openaiURL)
	srv.AddRoute("/anthropic", anthropicURL)
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
	srv.AddRoute("/openai", openaiURL)
	srv.AddRoute("/anthropic", anthropicURL)
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
