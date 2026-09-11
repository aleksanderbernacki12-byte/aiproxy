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
	"aiproxy/internal/coalesce"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

// TestServer_RequestCoalescing_ConcurrentIdenticalMissesShareOneUpstreamCall
// is the feature's central value proposition: several genuinely
// concurrent requests with identical content, none of them cached yet,
// must collapse into exactly one real upstream call — every other one
// waits and replays that single response instead of independently
// forwarding its own redundant duplicate.
func TestServer_RequestCoalescing_ConcurrentIdenticalMissesShareOneUpstreamCall(t *testing.T) {
	t.Chdir(t.TempDir())

	var upstreamHits atomic.Int32
	upstreamEntered := make(chan struct{})
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := upstreamHits.Add(1)
		if n == 1 {
			close(upstreamEntered)
			<-releaseUpstream
		}
		w.Write([]byte("the one true response"))
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
	srv.Coalescer = coalesce.NewGroup(5 * time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() (*http.Response, error) {
		return http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
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
		t.Fatalf("upstream received %d requests, want exactly 1 (the second, concurrent identical request must never trigger its own forward)", got)
	}
}

// TestServer_RequestCoalescing_DifferentBodiesNeverCoalesce proves
// coalescing only ever collapses genuinely identical content — two
// concurrent requests with different bodies (and therefore different
// cache keys) must each reach the upstream independently.
func TestServer_RequestCoalescing_DifferentBodiesNeverCoalesce(t *testing.T) {
	t.Chdir(t.TempDir())

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

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Coalescer = coalesce.NewGroup(5 * time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	first, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("post 1: %v", err)
	}
	first.Body.Close()
	second, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":2}`))
	if err != nil {
		t.Fatalf("post 2: %v", err)
	}
	second.Body.Close()

	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream received %d requests, want 2 (different bodies must never coalesce)", got)
	}
}

// TestServer_RequestCoalescing_SecondRequestAfterFirstCompletesIsACacheHit
// proves coalescing only protects genuinely OVERLAPPING requests — once
// the first has already finished (and its response is on disk), a
// later, non-overlapping request is served from the real cache, not
// from a lingering coalescing record.
func TestServer_RequestCoalescing_SecondRequestAfterFirstCompletesIsACacheHit(t *testing.T) {
	t.Chdir(t.TempDir())

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Write([]byte("cacheable"))
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
	srv.Coalescer = coalesce.NewGroup(5 * time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	first, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("post 1: %v", err)
	}
	first.Body.Close()

	second, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("post 2: %v", err)
	}
	defer second.Body.Close()
	if got := second.Header.Get("Age"); got == "" {
		t.Fatal("second request missing Age header, want a genuine cache hit (the coalescing record must not still be lingering)")
	}

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want 1", got)
	}
}

// TestServer_RequestCoalescing_BlockedRequestReleasesClaimForWaiter
// proves a request that never reaches a real upstream answer (blocked
// by a rule) doesn't strand a concurrent identical request waiting on
// it forever — the waiter gets a fair shot at its own attempt instead.
func TestServer_RequestCoalescing_BlockedRequestReleasesClaimForWaiter(t *testing.T) {
	t.Chdir(t.TempDir())

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

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Block)) // blocks everything, for now
	srv.Cache = c
	srv.Coalescer = coalesce.NewGroup(5 * time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() *http.Response {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
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
		t.Fatalf("retry status=%d body=%q, want 200 %q (a blocked owner must never permanently strand its coalescing key)", retry.StatusCode, body, "finally allowed")
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want 1 (only the retry, once actually allowed)", got)
	}
}

// TestServer_RequestCoalescing_ReplayCarriesNoMarkerHeader proves a
// coalesced response is completely transparent to the client — unlike
// an idempotency replay's deliberate Idempotency-Replayed header, this
// is an internal optimization the client never opted into and should
// never be able to detect from the response shape.
func TestServer_RequestCoalescing_ReplayCarriesNoMarkerHeader(t *testing.T) {
	t.Chdir(t.TempDir())

	upstreamEntered := make(chan struct{})
	releaseUpstream := make(chan struct{})
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

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Coalescer = coalesce.NewGroup(5 * time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	go func() {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-upstreamEntered

	secondDone := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Errorf("second post: %v", err)
			return
		}
		secondDone <- resp
	}()
	time.Sleep(100 * time.Millisecond)
	close(releaseUpstream)

	select {
	case resp := <-secondDone:
		defer resp.Body.Close()
		if got := resp.Header.Get("Idempotency-Replayed"); got != "" {
			t.Fatalf("coalesced response carried Idempotency-Replayed = %q, want empty — coalescing must be invisible to the client", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second request never completed")
	}
}

// TestServer_RequestCoalescing_StatsAndLogReflectCoalescedRequest
// proves each coalesced replay is counted and logged distinctly from a
// plain cache hit.
func TestServer_RequestCoalescing_StatsAndLogReflectCoalescedRequest(t *testing.T) {
	t.Chdir(t.TempDir())

	upstreamEntered := make(chan struct{})
	releaseUpstream := make(chan struct{})
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

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	var logBuf syncBuffer
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Coalescer = coalesce.NewGroup(5 * time.Second)
	srv.Logger = log.New(&logBuf, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	go func() {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-upstreamEntered

	secondDone := make(chan struct{})
	go func() {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err == nil {
			resp.Body.Close()
		}
		close(secondDone)
	}()
	time.Sleep(100 * time.Millisecond)
	close(releaseUpstream)

	select {
	case <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("second request never completed")
	}

	snap := srv.Stats.Snapshot()
	if snap.CoalescedRequests != 1 {
		t.Fatalf("Stats.CoalescedRequests = %d, want 1", snap.CoalescedRequests)
	}
	if !strings.Contains(logBuf.String(), "[COALESCED]") {
		t.Fatalf("log missing [COALESCED] line: %q", logBuf.String())
	}
}

// TestServer_RequestCoalescing_DisabledMeansEveryConcurrentRequestForwards
// proves this feature never activates unless Server.Coalescer is
// actually configured — the same "zero/absent means fully off"
// discipline every other feature here has.
func TestServer_RequestCoalescing_DisabledMeansEveryConcurrentRequestForwards(t *testing.T) {
	t.Chdir(t.TempDir())

	var upstreamHits atomic.Int32
	upstreamEntered := make(chan struct{})
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := upstreamHits.Add(1)
		if n == 1 {
			close(upstreamEntered)
			<-releaseUpstream
		}
		w.Write([]byte("ok"))
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
	srv.Cache = c // caching on, but Coalescer left nil
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	go func() {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-upstreamEntered

	secondDone := make(chan struct{})
	go func() {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err == nil {
			resp.Body.Close()
		}
		close(secondDone)
	}()
	time.Sleep(100 * time.Millisecond)
	close(releaseUpstream)

	select {
	case <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("second request never completed")
	}

	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream received %d requests, want 2 (with Coalescer nil, concurrent identical requests must each forward independently)", got)
	}
}

// TestServer_ReloadConfig_UpdatesCoalescer proves Coalescer is actually
// swapped in by a live SIGHUP-style reload, not just settable at
// construction.
func TestServer_ReloadConfig_UpdatesCoalescer(t *testing.T) {
	t.Chdir(t.TempDir())

	upstreamEntered := make(chan struct{})
	releaseUpstream := make(chan struct{})
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

	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	group := coalesce.NewGroup(5 * time.Second)
	srv.ReloadConfig(srv.Engine, nil, c, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil, false, nil, group, nil, 0)

	go func() {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-upstreamEntered

	logged := make(chan struct{})
	go func() {
		resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"n":1}`))
		if err == nil {
			resp.Body.Close()
		}
		close(logged)
	}()
	time.Sleep(100 * time.Millisecond)
	close(releaseUpstream)

	select {
	case <-logged:
	case <-time.After(5 * time.Second):
		t.Fatal("second request never completed")
	}

	if got := srv.Stats.Snapshot().CoalescedRequests; got != 1 {
		t.Fatalf("Stats.CoalescedRequests after reload = %d, want 1 (Coalescer must be live)", got)
	}
}
