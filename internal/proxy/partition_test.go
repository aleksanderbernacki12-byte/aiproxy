package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"aiproxy/internal/cache"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func partitionTestServer(t *testing.T, handler http.HandlerFunc) *proxy.Server {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	t.Chdir(t.TempDir())
	c, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	s.Cache = c
	return s
}

func partitionCall(s *proxy.Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestCache_IsolatesByUpstreamCredential_NoProxyKeysConfigured(t *testing.T) {
	// Regression for review finding #1: even with NO proxy_api_key(s)
	// configured at all (auth.label == "" for every caller), two
	// different callers presenting two different personal upstream
	// credentials must never share a cache entry.
	var hits atomic.Int32
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "private response for "+r.Header.Get("Authorization"))
	})
	a := partitionCall(s, "GET", "/account", "", map[string]string{"Authorization": "Bearer alice-upstream"})
	b := partitionCall(s, "GET", "/account", "", map[string]string{"Authorization": "Bearer bob-upstream"})
	if a.Code != 200 || b.Code != 200 {
		t.Fatalf("unexpected status %d/%d", a.Code, b.Code)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected upstream to be called twice (no cache sharing), got %d", hits.Load())
	}
	if strings.Contains(b.Body.String(), "alice-upstream") {
		t.Fatalf("caller with a different upstream credential received the other caller's cached response: %q", b.Body.String())
	}
	if !strings.Contains(b.Body.String(), "bob-upstream") {
		t.Fatalf("caller b should have received its own upstream response containing its own credential, got %q", b.Body.String())
	}
}

func TestCache_SameCredentialStillHits(t *testing.T) {
	// Sanity check the fix isn't a blanket cache-bust: the SAME caller
	// (same auth.label, same upstream credential) must still get a real
	// cache hit on a repeat request.
	var calls atomic.Int32
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "answer")
	})
	headers := map[string]string{"Authorization": "Bearer alice-upstream"}
	partitionCall(s, "GET", "/account", "", headers)
	second := partitionCall(s, "GET", "/account", "", headers)
	if second.Header().Get("Age") == "" {
		t.Fatalf("expected second identical call to be a cache hit (Age header set), got status %d body %q", second.Code, second.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("expected upstream to be called exactly once, got %d", calls.Load())
	}
}

func TestCache_IsolatesByProxyKeyLabel_SameUpstreamCredential(t *testing.T) {
	// Regression for review finding #1's other dimension: two callers
	// authenticated with two DIFFERENT configured proxy keys (so two
	// different auth.label values), but presenting the very same (or no)
	// upstream credential, must never share a cache entry either —
	// auth.label alone must be enough to partition them.
	var hits atomic.Int32
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprintf(w, "response #%d", hits.Load())
	})
	s.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "alice", Key: "alice-proxy-key"},
		{Name: "bob", Key: "bob-proxy-key"},
	}
	a := partitionCall(s, "GET", "/account", "", map[string]string{"Proxy-Authorization": "Bearer alice-proxy-key"})
	b := partitionCall(s, "GET", "/account", "", map[string]string{"Proxy-Authorization": "Bearer bob-proxy-key"})
	if a.Code != 200 || b.Code != 200 {
		t.Fatalf("unexpected status %d/%d", a.Code, b.Code)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected upstream to be called twice (no cache sharing across proxy-key labels), got %d", hits.Load())
	}
	if a.Body.String() == b.Body.String() {
		t.Fatalf("callers with different proxy-key labels received the same cached response: %q", a.Body.String())
	}
}
