package proxy_test

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
	"aiproxy/internal/semcache"
)

func newSemanticCacheTestServer(t *testing.T, upstream *httptest.Server, threshold float64) (*proxy.Server, *httptest.Server) {
	t.Helper()
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
	srv.SemanticIndex = semcache.NewIndex(semcache.DefaultIndexSize)
	srv.SemanticCacheThreshold = threshold
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	t.Cleanup(frontend.Close)
	t.Cleanup(upstream.Close)
	return srv, frontend
}

func countingUpstream(hits *atomic.Int32, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(body))
	}))
}

func TestServer_SemanticCache_RephrasedPromptServedFromSimilarEntry(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "Stockholm is the capital of Sweden.")
	_, frontend := newSemanticCacheTestServer(t, upstream, 0.5)

	first, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Can you tell me what the capital of Sweden is"}]}`))
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()

	second, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Could you tell me what the capital of Sweden is"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	secondBody, _ := io.ReadAll(second.Body)
	second.Body.Close()

	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1 (second request should have been served from the semantic match)", hits.Load())
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("bodies differ: %q vs %q", firstBody, secondBody)
	}
	if got := second.Header.Get("X-Semantic-Cache-Hit"); got != "true" {
		t.Fatalf("X-Semantic-Cache-Hit = %q, want \"true\"", got)
	}
	if got := second.Header.Get("X-Semantic-Cache-Similarity"); got == "" {
		t.Fatal("expected X-Semantic-Cache-Similarity to be set")
	}
	if got := first.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("first (genuine miss) response should not carry X-Semantic-Cache-Hit, got %q", got)
	}
}

func TestServer_SemanticCache_DifferentTopicNeverMatches(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	_, frontend := newSemanticCacheTestServer(t, upstream, 0.5)

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Explain how photosynthesis works in plants"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (unrelated prompts must never coalesce)", hits.Load())
	}
	if got := resp.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit header, got %q", got)
	}
}

func TestServer_SemanticCache_ThresholdTooHighRejectsNearMiss(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	// threshold 0.99 is high enough that even a close rewording won't
	// reach it, given real word-level shingle overlap.
	_, frontend := newSemanticCacheTestServer(t, upstream, 0.99)

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Can you tell me what the capital of Sweden is"}]}`))
	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Could you tell me what the capital of Sweden is"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (threshold 0.99 should reject this near-miss)", hits.Load())
	}
	if got := resp.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit header, got %q", got)
	}
}

func TestServer_SemanticCache_StaleIndexEntryFallsThroughToFreshForward(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	srv, frontend := newSemanticCacheTestServer(t, upstream, 0.5)
	srv.CacheTTL = 50 * time.Millisecond

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Can you tell me what the capital of Sweden is"}]}`))
	time.Sleep(150 * time.Millisecond) // let the real cache entry's TTL expire

	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Could you tell me what the capital of Sweden is"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (a stale index entry must fall through to a fresh forward, not error)", hits.Load())
	}
	if got := resp.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit header for a stale candidate, got %q", got)
	}
}

func TestServer_SemanticCache_DisabledBehavesAsBeforeRegression(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c // SemanticIndex left nil: semantic caching disabled
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()
	defer upstream.Close()

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"what's the capital of sweden"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (semantic caching disabled, both requests must forward independently)", hits.Load())
	}
	if got := resp.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit header when disabled, got %q", got)
	}
}

func TestServer_SemanticCache_StatsAndLog(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	srv, frontend := newSemanticCacheTestServer(t, upstream, 0.5)

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Can you tell me what the capital of Sweden is"}]}`))
	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Could you tell me what the capital of Sweden is"}]}`))

	if n := srv.Stats.Snapshot().SemanticCacheHits; n != 1 {
		t.Fatalf("stats SemanticCacheHits = %d, want 1", n)
	}
}

func TestServer_SemanticCache_ReloadConfigHotSwapsThresholdAndEnablement(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c // starts with semantic caching disabled
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()
	defer upstream.Close()

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Can you tell me what the capital of Sweden is"}]}`))
	beforeReload, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Could you tell me what the capital of Sweden is"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits before reload = %d, want 2 (disabled)", hits.Load())
	}
	if got := beforeReload.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit before reload, got %q", got)
	}

	idx := semcache.NewIndex(semcache.DefaultIndexSize)
	srv.ReloadConfig(srv.Engine, nil, c, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil, false, nil, nil, idx, 0.5)

	// Deliberately a different prompt pair from the pre-reload requests
	// above (Norway, not Sweden): the exact-match cache (srv.Cache) is
	// the same instance across ReloadConfig and already holds entries
	// for the Sweden pair from before, so reusing it here would produce
	// an exact-cache hit that never touches the semantic path at all —
	// the very thing this test exists to exercise.
	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Can you tell me what the capital of Norway is"}]}`))
	afterReload, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Could you tell me what the capital of Norway is"}]}`))
	if err != nil {
		t.Fatalf("fourth request: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("upstream hits after reload = %d, want 3 (only the third request should be a genuine miss; the fourth should be a semantic hit)", hits.Load())
	}
	if got := afterReload.Header.Get("X-Semantic-Cache-Hit"); got != "true" {
		t.Fatalf("expected a semantic cache hit after reload enabled it, got header %q", got)
	}
}
