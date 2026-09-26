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
