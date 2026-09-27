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
