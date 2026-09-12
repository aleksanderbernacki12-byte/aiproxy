package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aiproxy/internal/cache"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func partitionTestServer(t *testing.T, handler http.HandlerFunc) *proxy.Server {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
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
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "private response for "+r.Header.Get("Authorization"))
	})
	a := partitionCall(s, "GET", "/account", "", map[string]string{"Authorization": "Bearer alice-upstream"})
	b := partitionCall(s, "GET", "/account", "", map[string]string{"Authorization": "Bearer bob-upstream"})
	if a.Code != 200 || b.Code != 200 {
		t.Fatalf("unexpected status %d/%d", a.Code, b.Code)
	}
	if strings.Contains(b.Body.String(), "alice-upstream") {
		t.Fatalf("caller with a different upstream credential received the other caller's cached response: %q", b.Body.String())
	}
}

func TestCache_SameCredentialStillHits(t *testing.T) {
	// Sanity check the fix isn't a blanket cache-bust: the SAME caller
	// (same auth.label, same upstream credential) must still get a real
	// cache hit on a repeat request.
	calls := 0
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, "answer")
	})
	headers := map[string]string{"Authorization": "Bearer alice-upstream"}
	partitionCall(s, "GET", "/account", "", headers)
	second := partitionCall(s, "GET", "/account", "", headers)
	if second.Header().Get("Age") == "" {
		t.Fatalf("expected second identical call to be a cache hit (Age header set), got status %d body %q", second.Code, second.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected upstream to be called exactly once, got %d", calls)
	}
}
