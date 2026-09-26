// Package proxy_test: this file keeps the security review's own named
// findings permanently greppable by their original names, even though
// Tasks 2, 5, 6, and 8 already added equivalent coverage under different
// helper names. The overlap is intentional, not duplicate cruft — see
// docs/reviews/2026-09-12-v0.74.1-system-review.md and
// docs/reviews/2026-09-12-v0.74.1-repro/review_findings_test.go.txt for the
// findings these tests are named after.
package proxy_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/idempotency"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
	"aiproxy/internal/semcache"
)

func reviewServer(t *testing.T, handler http.HandlerFunc) *proxy.Server {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	return s
}

func reviewCache(t *testing.T, s *proxy.Server) {
	t.Helper()
	t.Chdir(t.TempDir())
	c, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	s.Cache = c
}

func TestReview_CacheMustIsolateCredentials(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "private response for "+r.Header.Get("Authorization"))
	})
	reviewCache(t, s)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "alice", Key: "alice-proxy"}, {Name: "bob", Key: "bob-proxy"}}
	a := partitionCall(s, "GET", "/account", "", map[string]string{"Proxy-Authorization": "Bearer alice-proxy", "Authorization": "Bearer alice-upstream"})
	b := partitionCall(s, "GET", "/account", "", map[string]string{"Proxy-Authorization": "Bearer bob-proxy", "Authorization": "Bearer bob-upstream"})
	if a.Code != 200 || b.Code != 200 {
		t.Fatalf("unexpected status %d/%d", a.Code, b.Code)
	}
	if strings.Contains(b.Body.String(), "alice-upstream") {
		t.Fatalf("Bob received Alice's cached response: %q", b.Body.String())
	}
}

func TestReview_CacheMustEnforceClientRules(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "allowed answer") })
	reviewCache(t, s)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "alice", Key: "alice-proxy"}, {Name: "bob", Key: "bob-proxy"}}
	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "bob-restriction", Pattern: regexp.MustCompile("restricted"), Action: rules.Block, Keys: []string{"bob"}})
	partitionCall(s, "POST", "/chat", "restricted", map[string]string{"Proxy-Authorization": "Bearer alice-proxy"})
	b := partitionCall(s, "POST", "/chat", "restricted", map[string]string{"Proxy-Authorization": "Bearer bob-proxy"})
	if b.Code != 403 {
		t.Fatalf("Bob bypassed key-scoped block through cache: status %d, body %q", b.Code, b.Body.String())
	}
}

func TestReview_SemanticCacheMustRespectModelAndStream(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); fmt.Fprint(w, string(b)) })
	reviewCache(t, s)
	s.SemanticIndex = semcache.NewIndex(100, 100)
	s.SemanticCacheThreshold = 0.99
	a := `{"model":"model-a","stream":false,"messages":[{"role":"user","content":"Explain the capital of Sweden"}]}`
	b := `{"model":"model-b","stream":true,"messages":[{"role":"user","content":"Explain the capital of Sweden"}]}`
	partitionCall(s, "POST", "/chat", a, nil)
	got := partitionCall(s, "POST", "/chat", b, nil)
	if got.Header().Get("X-Semantic-Cache-Hit") == "true" {
		t.Fatalf("model-b stream request replayed model-a non-stream response: %s", got.Body.String())
	}
}

func TestReview_ClientKeyMustNotControlDrain(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	// Required to exercise the fail-closed path: with no admin key
	// configured at all, checkAdminAuth intentionally falls back to
	// checkProxyAuth (Task 8's backward-compatible default), so an
	// ordinary client key would reach drain by design, not by bug.
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "POST", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer client-key"})
	if got.Code == 200 {
		t.Fatalf("ordinary proxy client can initiate global drain: %s", got.Body.String())
	}
}

func TestReview_QueryCredentialsMustNotEnterLogs(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	var buf bytes.Buffer
	s.Logger = log.New(&buf, "", 0)
	req := httptest.NewRequest("GET", "/chat?api_key=FAKE_PRIVATE_VALUE", nil)
	s.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(buf.String(), "FAKE_PRIVATE_VALUE") {
		t.Fatalf("query credential logged verbatim: %q", buf.String())
	}
}

func TestReview_BlockedResponseMustStillAccountForUsage(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answer":"SECRET_A","usage":{"total_tokens":123}}`)
	})
	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "fake-secret", Pattern: regexp.MustCompile("SECRET_A"), Action: rules.Block})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("POST", "/chat", strings.NewReader(`{"prompt":"hello"}`)))
	if rec.Code != 403 {
		t.Fatalf("expected blocked response, got %d", rec.Code)
	}
	if n := s.Stats.Snapshot().TotalTokens; n != 123 {
		t.Fatalf("upstream used 123 tokens, but blocked response recorded %d", n)
	}
}

func TestReview_IdempotencyMustRespectOperation(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.Method+" "+r.URL.Path) })
	s.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	call := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Header.Set("Idempotency-Key", "same-key")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}
	call("POST", "/operation-a")
	got := call("DELETE", "/operation-b")
	if got.Header().Get("Idempotency-Replayed") == "true" {
		t.Fatalf("DELETE /operation-b received unrelated replay: %q", got.Body.String())
	}
}

func TestReview_FailoverMustNotAssumeTransportErrorMeansUnprocessed(t *testing.T) {
	var executions atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		executions.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	}))
	t.Cleanup(first.Close)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { executions.Add(1); fmt.Fprint(w, "ok") }))
	t.Cleanup(second.Close)
	u1, _ := url.Parse(first.URL)
	u2, _ := url.Parse(second.URL)
	s := proxy.New("unused", u1, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.AddRoute("/route", []*url.URL{u1, u2}, nil, nil, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("POST", "/route/execute", strings.NewReader(`{"operation":"test"}`)))
	if executions.Load() > 1 {
		t.Fatalf("one POST executed by %d upstreams after connection closed post-processing, status=%d", executions.Load(), rec.Code)
	}
}
