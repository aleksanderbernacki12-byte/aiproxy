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

	"aiproxy/internal/idempotency"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

// idempotencyTestServer counts upstream executions behind a proxy with
// idempotency enabled and no proxy authentication.
func idempotencyTestServer(t *testing.T) (*proxy.Server, *atomic.Int32) {
	t.Helper()
	var executions atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executions.Add(1)
		io.WriteString(w, r.Method+" "+r.URL.RequestURI())
	}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	return s, &executions
}

func idempotentCall(s *proxy.Server, method, target, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(`{"op":1}`))
	req.Header.Set("Idempotency-Key", "shared-key")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestIdempotency_ReusedKeyForDifferentOperationConflicts(t *testing.T) {
	cases := []struct{ name, firstMethod, firstTarget, secondMethod, secondTarget string }{
		{"different path", "POST", "/a", "POST", "/b"},
		{"different method", "POST", "/a", "PUT", "/a"},
		{"different query", "POST", "/a?x=1", "POST", "/a?x=2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, executions := idempotencyTestServer(t)
			idempotentCall(s, tc.firstMethod, tc.firstTarget, "")
			got := idempotentCall(s, tc.secondMethod, tc.secondTarget, "")
			if got.Code != http.StatusConflict {
				t.Fatalf("status = %d body=%q, want 409", got.Code, got.Body.String())
			}
			if executions.Load() != 1 {
				t.Fatalf("upstream executions = %d, want 1", executions.Load())
			}
		})
	}
}

func TestIdempotency_IdenticalRequestStillReplays(t *testing.T) {
	s, executions := idempotencyTestServer(t)
	idempotentCall(s, "POST", "/a?x=1", "")
	got := idempotentCall(s, "POST", "/a?x=1", "")
	if got.Header().Get("Idempotency-Replayed") != "true" || executions.Load() != 1 {
		t.Fatalf("replayed=%q executions=%d, want true and 1", got.Header().Get("Idempotency-Replayed"), executions.Load())
	}
}

func TestIdempotency_DifferentUpstreamCredentialsNeverShareRecords(t *testing.T) {
	s, executions := idempotencyTestServer(t)
	alice := idempotentCall(s, "POST", "/a", "Bearer alice")
	bob := idempotentCall(s, "POST", "/a", "Bearer bob")
	if alice.Code != http.StatusOK || bob.Code != http.StatusOK {
		t.Fatalf("status alice=%d bob=%d, want 200 both", alice.Code, bob.Code)
	}
	if bob.Header().Get("Idempotency-Replayed") == "true" || executions.Load() != 2 {
		t.Fatalf("bob replayed=%q executions=%d, want no replay and 2", bob.Header().Get("Idempotency-Replayed"), executions.Load())
	}
}

// brokenAfterReceiving reads the full request, counts it as executed,
// then drops the connection before any response: the upstream acted,
// but the proxy only sees a transport error.
func brokenAfterReceiving(t *testing.T, executions *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		executions.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	}))
	t.Cleanup(server.Close)
	return server
}

func failoverTestServer(t *testing.T, first *url.URL, executions *atomic.Int32) *proxy.Server {
	t.Helper()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executions.Add(1)
		io.WriteString(w, "served by second")
	}))
	t.Cleanup(second.Close)
	secondURL, _ := url.Parse(second.URL)
	s := proxy.New("unused", secondURL, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.AddRoute("/route", []*url.URL{first, secondURL}, nil, nil, nil)
	return s
}

func TestFailover_UnsafeRequestReceivedByUpstreamIsNotRetried(t *testing.T) {
	var executions atomic.Int32
	firstURL, _ := url.Parse(brokenAfterReceiving(t, &executions).URL)
	s := failoverTestServer(t, firstURL, &executions)
	req := httptest.NewRequest("POST", "/route/execute", strings.NewReader(`{"op":1}`))
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if executions.Load() != 1 {
		t.Fatalf("executions = %d, want 1", executions.Load())
	}
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "upstream_outcome_unknown") {
		t.Fatalf("status=%d body=%q, want 502 upstream_outcome_unknown", rec.Code, rec.Body.String())
	}
	if n := s.Stats.Snapshot().UpstreamOutcomeUnknown; n != 1 {
		t.Fatalf("UpstreamOutcomeUnknown = %d, want 1", n)
	}
}

func TestFailover_SafeRequestReceivedByUpstreamStillFailsOver(t *testing.T) {
	var executions atomic.Int32
	firstURL, _ := url.Parse(brokenAfterReceiving(t, &executions).URL)
	s := failoverTestServer(t, firstURL, &executions)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/route/items", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "served by second" {
		t.Fatalf("status=%d body=%q, want 200 from second", rec.Code, rec.Body.String())
	}
}

func TestFailover_UnsafeRequestToUnreachableUpstreamStillFailsOver(t *testing.T) {
	var executions atomic.Int32
	unreachable, _ := url.Parse("http://" + freeLoopbackAddr(t))
	s := failoverTestServer(t, unreachable, &executions)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("POST", "/route/execute", strings.NewReader(`{"op":1}`)))
	if rec.Code != http.StatusOK || executions.Load() != 1 {
		t.Fatalf("status=%d executions=%d, want 200 and 1", rec.Code, executions.Load())
	}
}

func TestFailover_WebhookPayloadMasksTargetURLs(t *testing.T) {
	payloads := make(chan string, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		payloads <- string(body)
	}))
	defer hook.Close()
	var executions atomic.Int32
	unreachable, _ := url.Parse("http://" + freeLoopbackAddr(t) + "/?key=FAKE_PRIVATE_VALUE")
	s := failoverTestServer(t, unreachable, &executions)
	hookURL, _ := url.Parse(hook.URL)
	s.WebhookURL = hookURL
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/route/items", nil))
	select {
	case payload := <-payloads:
		if strings.Contains(payload, "FAKE_PRIVATE_VALUE") {
			t.Fatalf("failover webhook leaked target URL: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no failover webhook delivered")
	}
}
