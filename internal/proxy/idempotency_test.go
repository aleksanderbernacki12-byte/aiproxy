package proxy_test

import (
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
	"aiproxy/internal/idempotency"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

// TestServer_Idempotency_ReplaysSecondRequestWithSameKeyAndBody proves
// the core mechanism: a retry carrying the same Idempotency-Key and the
// same body gets back the exact same response without ever reaching
// the upstream target a second time.
func TestServer_Idempotency_ReplaysSecondRequestWithSameKeyAndBody(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Write([]byte("original response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() *http.Response {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Idempotency-Key", "retry-abc")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	first := post()
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if string(firstBody) != "original response" {
		t.Fatalf("first response = %q, want %q", firstBody, "original response")
	}

	second := post()
	defer second.Body.Close()
	secondBody, _ := io.ReadAll(second.Body)
	if string(secondBody) != "original response" {
		t.Fatalf("second (replayed) response = %q, want %q", secondBody, "original response")
	}
	if got := second.Header.Get("Idempotency-Replayed"); got != "true" {
		t.Fatalf("Idempotency-Replayed header = %q, want %q", got, "true")
	}
	if got := first.Header.Get("Idempotency-Replayed"); got != "" {
		t.Fatalf("first response carried Idempotency-Replayed = %q, want empty (it was never a replay)", got)
	}

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want 1 (the retry must never reach it)", got)
	}
}

// TestServer_Idempotency_ConflictOnSameKeyDifferentBody proves reusing
// an idempotency key for a genuinely different request body is rejected
// rather than either replaying the wrong response or silently
// forwarding a second, different one.
func TestServer_Idempotency_ConflictOnSameKeyDifferentBody(t *testing.T) {
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
	srv.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(body string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Idempotency-Key", "retry-xyz")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	first := post(`{"n":1}`)
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.StatusCode)
	}

	conflict := post(`{"n":2}`)
	defer conflict.Body.Close()
	if conflict.StatusCode != http.StatusConflict {
		t.Fatalf("conflicting request status = %d, want %d", conflict.StatusCode, http.StatusConflict)
	}

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want 1 (the conflicting body must never be forwarded)", got)
	}
}

// TestServer_Idempotency_ConcurrentRetryWaitsForFirstThenReplays is the
// feature's central value proposition: a retry that arrives while the
// first attempt is still in flight must never trigger a second upstream
// call — it waits for the first to finish and gets the identical
// response.
func TestServer_Idempotency_ConcurrentRetryWaitsForFirstThenReplays(t *testing.T) {
	var upstreamHits atomic.Int32
	upstreamEntered := make(chan struct{})
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		close(upstreamEntered)
		<-releaseUpstream
		w.Write([]byte("the one true response"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Idempotency = idempotency.NewRegistry(time.Minute, 5*time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(`{"n":1}`))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Idempotency-Key", "concurrent-retry")
		return http.DefaultClient.Do(req)
	}

	firstDone := make(chan *http.Response, 1)
	go func() {
		resp, err := post()
		if err != nil {
			t.Errorf("first post: %v", err)
			return
		}
		firstDone <- resp
	}()
	<-upstreamEntered // the first request is now genuinely in flight

	secondDone := make(chan *http.Response, 1)
	go func() {
		resp, err := post()
		if err != nil {
			t.Errorf("second post: %v", err)
			return
		}
		secondDone <- resp
	}()
	time.Sleep(100 * time.Millisecond) // give the second request a real chance to reach and start waiting in Claim

	close(releaseUpstream)

	var bodies []string
	for i := 0; i < 2; i++ {
		select {
		case resp := <-firstDone:
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodies = append(bodies, string(body))
		case resp := <-secondDone:
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodies = append(bodies, string(body))
		case <-time.After(5 * time.Second):
			t.Fatal("a concurrent request never completed")
		}
	}

	for _, b := range bodies {
		if b != "the one true response" {
			t.Fatalf("got response body %q, want %q", b, "the one true response")
		}
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want exactly 1 (the second, concurrent retry must never trigger its own forward)", got)
	}
}

// TestServer_Idempotency_DifferentClientsWithSameKeyAreIndependent
// proves idempotency records are scoped per authenticated client: two
// different proxy_api_keys using the exact same Idempotency-Key value
// never conflict with or replay each other's response.
func TestServer_Idempotency_DifferentClientsWithSameKeyAreIndependent(t *testing.T) {
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
	srv.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "client-a", Key: "key-a"},
		{Name: "client-b", Key: "key-b"},
	}
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(proxyKey string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Idempotency-Key", "shared-key-value")
		req.Header.Set("Proxy-Authorization", "Bearer "+proxyKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	a := post("key-a")
	a.Body.Close()
	if a.StatusCode != http.StatusOK {
		t.Fatalf("client-a status = %d, want 200", a.StatusCode)
	}

	b := post("key-b")
	defer b.Body.Close()
	if b.StatusCode != http.StatusOK {
		t.Fatalf("client-b status = %d, want 200 (a different client's own record must never conflict)", b.StatusCode)
	}
	if got := b.Header.Get("Idempotency-Replayed"); got != "" {
		t.Fatalf("client-b's response was a replay of client-a's, want its own genuine forward")
	}

	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream received %d requests, want 2 (each client's own first use of the key)", got)
	}
}

// TestServer_Idempotency_BlockedRequestReleasesClaimForRetry proves a
// request that never reaches a real upstream answer (blocked by a
// rule) doesn't leave its idempotency key permanently stuck — a retry
// with the same key and body is evaluated fresh rather than replaying
// a rejection forever.
func TestServer_Idempotency_BlockedRequestReleasesClaimForRetry(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Write([]byte("finally allowed"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Block)) // blocks everything, for now
	srv.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() *http.Response {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Idempotency-Key", "retry-after-block")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	blocked := post()
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("first (blocked) status = %d, want 403", blocked.StatusCode)
	}

	srv.Engine = rules.NewEngine(rules.Allow) // now allow everything
	retry := post()
	defer retry.Body.Close()
	body, _ := io.ReadAll(retry.Body)
	if retry.StatusCode != http.StatusOK || string(body) != "finally allowed" {
		t.Fatalf("retry status=%d body=%q, want 200 %q (a blocked request must never permanently claim its key)", retry.StatusCode, body, "finally allowed")
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want 1 (only the retry, once actually allowed)", got)
	}
}

// TestServer_Idempotency_MissingOrDisabledMeansNormalBehavior proves
// this feature never activates unless both Server.Idempotency is
// configured AND the client actually sends the header — the same
// "zero/absent means fully off" discipline every other feature here
// has.
func TestServer_Idempotency_MissingOrDisabledMeansNormalBehavior(t *testing.T) {
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
	srv.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	// Idempotency is configured, but no header is sent: two otherwise
	// identical requests must both genuinely reach the upstream.
	for i := 0; i < 2; i++ {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		resp.Body.Close()
	}
	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream received %d requests, want 2 (no Idempotency-Key header sent, so no dedup should apply)", got)
	}
}

// TestServer_Idempotency_StatsAndLogReflectReplayAndConflict proves
// each outcome is counted and logged distinctly.
func TestServer_Idempotency_StatsAndLogReflectReplayAndConflict(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func(key, body string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	post("key1", `{"n":1}`).Body.Close()
	post("key1", `{"n":1}`).Body.Close() // replay
	post("key1", `{"n":2}`).Body.Close() // conflict

	snap := srv.Stats.Snapshot()
	if snap.IdempotencyReplayed != 1 {
		t.Fatalf("Stats.IdempotencyReplayed = %d, want 1", snap.IdempotencyReplayed)
	}
	if snap.IdempotencyConflicts != 1 {
		t.Fatalf("Stats.IdempotencyConflicts = %d, want 1", snap.IdempotencyConflicts)
	}
	if !strings.Contains(logBuf.String(), "[IDEMPOTENCY REPLAY]") {
		t.Fatalf("log missing [IDEMPOTENCY REPLAY] line: %q", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "[IDEMPOTENCY CONFLICT]") {
		t.Fatalf("log missing [IDEMPOTENCY CONFLICT] line: %q", logBuf.String())
	}
}

// TestServer_Idempotency_CacheHitIsAlsoStoredForReplay proves a
// response served from the on-disk cache still completes the
// idempotency claim — otherwise a concurrent retry racing a cache hit
// could be told to forward on its own (Own again, after an incorrectly
// abandoned claim) instead of correctly replaying, or a strict test of
// this integration point would see the claim wrongly Released.
func TestServer_Idempotency_CacheHitIsAlsoStoredForReplay(t *testing.T) {
	t.Chdir(t.TempDir())

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Write([]byte("cacheable response"))
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

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const body = `{"n":1}`
	postWithKey := func(key string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	// Populate the cache (no idempotency key needed for this one).
	warm, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("warm post: %v", err)
	}
	warm.Body.Close()
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits after warm-up = %d, want 1", got)
	}

	// This request has its own, brand-new idempotency key and hits the
	// now-warm cache — it must still complete (Store) that key's own
	// claim, not just serve the cached bytes and leave the claim
	// dangling.
	first := postWithKey("cache-then-idem")
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if string(firstBody) != "cacheable response" {
		t.Fatalf("first response = %q, want %q", firstBody, "cacheable response")
	}
	if got := first.Header.Get("Age"); got == "" {
		t.Fatal("first response missing Age header, want a genuine cache hit")
	}

	// A second use of the SAME idempotency key must now be a genuine
	// idempotency Replay (not just another independent cache hit) —
	// proven by the marker header only Replay ever sets.
	second := postWithKey("cache-then-idem")
	defer second.Body.Close()
	if got := second.Header.Get("Idempotency-Replayed"); got != "true" {
		t.Fatalf("Idempotency-Replayed = %q, want %q (the cache-hit path must complete the idempotency claim too)", got, "true")
	}

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests total, want 1 (everything after the warm-up came from cache/idempotency)", got)
	}
}

// TestServer_ReloadConfig_UpdatesIdempotency proves Idempotency is
// actually swapped in by a live SIGHUP-style reload, not just settable
// at construction.
func TestServer_ReloadConfig_UpdatesIdempotency(t *testing.T) {
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

	post := func() *http.Response {
		req, err := http.NewRequest(http.MethodPost, frontend.URL+"/chat", strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Idempotency-Key", "reload-test")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	before := post() // idempotency off: no replay marker
	before.Body.Close()
	if got := before.Header.Get("Idempotency-Replayed"); got != "" {
		t.Fatalf("before reload: Idempotency-Replayed = %q, want empty", got)
	}

	reg := idempotency.NewRegistry(time.Minute, time.Second)
	srv.ReloadConfig(srv.Engine, nil, nil, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil, false, reg, nil, nil, 0)

	post().Body.Close() // populate the record post-reload
	after := post()
	defer after.Body.Close()
	if got := after.Header.Get("Idempotency-Replayed"); got != "true" {
		t.Fatalf("after reload: Idempotency-Replayed = %q, want %q (Idempotency must be live)", got, "true")
	}
}
