package proxy

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"aiproxy/internal/breaker"
	"aiproxy/internal/rules"
)

func TestAllCandidateTargets_DeduplicatesAcrossTargetAndRoutes(t *testing.T) {
	a, err := url.Parse("https://a.example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	b, err := url.Parse("https://b.example.com")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	s := New("unused", a, rules.NewEngine(rules.Allow))
	s.AddRoute("/openai", []*url.URL{a, b}, nil, nil, nil)
	s.AddModelRoute("claude", []string{"claude-*"}, []*url.URL{b}, nil, nil, nil)

	got := s.allCandidateTargets()
	if len(got) != 2 {
		t.Fatalf("allCandidateTargets() = %v, want exactly 2 deduplicated entries", got)
	}
	seen := map[string]bool{}
	for _, u := range got {
		seen[u.String()] = true
	}
	if !seen[a.String()] || !seen[b.String()] {
		t.Fatalf("allCandidateTargets() = %v, want both a and b present", got)
	}
}

func TestProbeTarget_SuccessRecordsBreakerSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	s := New("unused", targetURL, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	tb := breaker.NewRegistry(1, time.Hour)
	tb.RecordFailure(targetURL.String()) // pre-eject it

	client := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	s.probeTarget(client, "", targetURL, tb)

	if tb.IsEjected(targetURL.String()) {
		t.Fatal("target still ejected after a successful probe, want recovered")
	}
}

func TestProbeTarget_AnyStatusCodeCountsAsHealthy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // a real HTTP response, just not a 2xx
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	s := New("unused", targetURL, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	tb := breaker.NewRegistry(1, time.Hour)
	tb.RecordFailure(targetURL.String())

	client := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	s.probeTarget(client, "", targetURL, tb)

	if tb.IsEjected(targetURL.String()) {
		t.Fatal("a completed HTTP exchange (even 404) must count as healthy, regardless of status code")
	}
}

func TestProbeTarget_TransportFailureRecordsBreakerFailure(t *testing.T) {
	upstream := httptest.NewServer(hijackAndCloseForHealthCheckTest(t))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	s := New("unused", targetURL, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	tb := breaker.NewRegistry(1, time.Hour)

	client := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	s.probeTarget(client, "", targetURL, tb)

	if !tb.IsEjected(targetURL.String()) {
		t.Fatal("a genuine transport-level failure must record a breaker failure")
	}
}

func TestProbeTarget_CustomPathOverridesProbedPath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL + "/v1")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	s := New("unused", targetURL, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	tb := breaker.NewRegistry(1, time.Hour)

	client := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	s.probeTarget(client, "/health", targetURL, tb)

	if gotPath != "/health" {
		t.Fatalf("probed path = %q, want /health (configured path overrides the target's own)", gotPath)
	}
}

func TestProbeTarget_EmptyPathProbesTargetsOwnPathUnchanged(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL + "/v1")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	s := New("unused", targetURL, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	tb := breaker.NewRegistry(1, time.Hour)

	client := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	s.probeTarget(client, "", targetURL, tb)

	if gotPath != "/v1" {
		t.Fatalf("probed path = %q, want /v1 (the target's own configured path, unchanged)", gotPath)
	}
}

func TestRunHealthChecks_EjectsDeadTargetProactivelyWithoutAnyRealRequest(t *testing.T) {
	dead := httptest.NewServer(hijackAndCloseForHealthCheckTest(t))
	defer dead.Close()
	deadURL, err := url.Parse(dead.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	healthyURL, err := url.Parse("https://healthy.example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	s := New("unused", healthyURL, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.TargetBreaker = breaker.NewRegistry(1, time.Hour)
	s.HealthCheckInterval = 20 * time.Millisecond
	s.AddRoute("/openai", []*url.URL{healthyURL, deadURL}, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runHealthChecks(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.TargetBreaker.IsEjected(deadURL.String()) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dead target was never ejected by a background health check, despite no real request ever being sent")
}

func TestRunHealthChecks_StopsPromptlyOnContextCancel(t *testing.T) {
	targetURL, err := url.Parse("https://unused.example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	s := New("unused", targetURL, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	// HealthCheckInterval left at zero (disabled): runHealthChecks must
	// still respond to cancellation promptly rather than blocking on its
	// own idle-poll wait.

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runHealthChecks(ctx)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runHealthChecks did not return promptly after its context was cancelled")
	}
}

// hijackAndCloseForHealthCheckTest mirrors proxy_test.go's own
// hijackAndClose helper (an internal package test can't reach an
// external package's unexported test helper) — hijacks and abruptly
// closes the raw connection, the standard way to produce a genuine
// transport-level failure rather than an HTTP-level error response.
func hijackAndCloseForHealthCheckTest(t *testing.T) http.HandlerFunc {
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
