package proxy_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/idempotency"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestLimits_OversizedBufferedResponseIsRejectedAndNotCached(t *testing.T) {
	t.Chdir(t.TempDir())
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":"`+strings.Repeat("x", 4096)+`"}`)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.MaxResponseBodyBytes = 1024
	c, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	s.Cache = c

	for attempt := 1; attempt <= 2; attempt++ {
		req := httptest.NewRequest("POST", "/chat", strings.NewReader(`{"p":1}`))
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "upstream_response_too_large") {
			t.Fatalf("attempt %d: status=%d body=%q, want 502 upstream_response_too_large", attempt, rec.Code, rec.Body.String())
		}
	}
	if upstreamHits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (an oversized response must never be cached)", upstreamHits.Load())
	}
	if n := s.Stats.Snapshot().UpstreamResponseTooLarge; n != 2 {
		t.Fatalf("UpstreamResponseTooLarge = %d, want 2", n)
	}
}

func TestLimits_IdempotencyAtCapacityReturns503(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	defer close(release)
	target, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	s.Idempotency.MaxEntries = 1

	go func() {
		req := httptest.NewRequest("POST", "/a", strings.NewReader(`{}`))
		req.Header.Set("Idempotency-Key", "first")
		s.ServeHTTP(httptest.NewRecorder(), req)
	}()
	<-entered

	req := httptest.NewRequest("POST", "/a", strings.NewReader(`{}`))
	req.Header.Set("Idempotency-Key", "second")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "idempotency_capacity") {
		t.Fatalf("status=%d body=%q, want 503 idempotency_capacity", rec.Code, rec.Body.String())
	}
	if n := s.Stats.Snapshot().IdempotencyFull; n != 1 {
		t.Fatalf("IdempotencyFull = %d, want 1", n)
	}
}

func TestLimits_WebhookDeliveriesUseABoundedQueue(t *testing.T) {
	release := make(chan struct{})
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer hook.Close()
	defer close(release)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{Name: "deny", PathPrefix: "/deny", Action: rules.Block})
	s := proxy.New("unused", target, engine)
	s.Logger = log.New(io.Discard, "", 0)
	hookURL, _ := url.Parse(hook.URL)
	s.WebhookURL = hookURL

	before := runtime.NumGoroutine()
	for i := 0; i < 400; i++ {
		s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/deny", nil))
	}
	if n := s.Stats.Snapshot().WebhookDropped; n < 100 {
		t.Fatalf("WebhookDropped = %d, want at least 100 of 400 with a queue of 256 and a stalled endpoint", n)
	}
	if grown := runtime.NumGoroutine() - before; grown > 50 {
		t.Fatalf("goroutines grew by %d for 400 webhook deliveries, want a bounded worker pool", grown)
	}
}

func TestLimits_ConcurrencyCapRejectsWithServiceUnavailable(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.MaxConcurrentRequests = 1

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest("GET", "/held", nil))
		done <- rec.Code
	}()
	<-entered

	req := httptest.NewRequest("GET", "/second", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "too_many_concurrent_requests") {
		t.Fatalf("status=%d body=%q, want 503 too_many_concurrent_requests", rec.Code, rec.Body.String())
	}
	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("held request status = %d, want 200", code)
	}
	if n := s.Stats.Snapshot().ConcurrencyRejected; n != 1 {
		t.Fatalf("ConcurrencyRejected = %d, want 1", n)
	}
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/after", nil))
	if rec.Code == http.StatusServiceUnavailable {
		t.Fatal("a request after the held one finished was still rejected: the in-flight count leaked")
	}
}
