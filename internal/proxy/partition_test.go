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
	"aiproxy/internal/semcache"
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

func TestCache_IsolatesByAzureAndGoogleAuthHeaders(t *testing.T) {
	// Regression proving the Api-Key (Azure OpenAI) and X-Goog-Api-Key
	// (Google Vertex/Gemini) additions to partitionIdentity's hashed
	// header set actually isolate callers: before they were added, two
	// callers using different Azure or Google credentials shared one
	// partition.
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "private response for "+r.Header.Get("Api-Key")+r.Header.Get("X-Goog-Api-Key"))
	})
	partitionCall(s, "GET", "/account", "", map[string]string{"Api-Key": "alice-azure"})
	b := partitionCall(s, "GET", "/account", "", map[string]string{"Api-Key": "bob-azure"})
	if strings.Contains(b.Body.String(), "alice-azure") {
		t.Fatalf("different Api-Key values shared a cache entry: %q", b.Body.String())
	}

	partitionCall(s, "GET", "/account", "", map[string]string{"X-Goog-Api-Key": "alice-google"})
	d := partitionCall(s, "GET", "/account", "", map[string]string{"X-Goog-Api-Key": "bob-google"})
	if strings.Contains(d.Body.String(), "alice-google") {
		t.Fatalf("different X-Goog-Api-Key values shared a cache entry: %q", d.Body.String())
	}
}

func TestCache_IsolatesByProxyKeyLabel_SameUpstreamCredential(t *testing.T) {
	// Two different configured proxy keys must never share a cache
	// entry — proven here via their differing Proxy-Authorization
	// header value, since auth.label's own independent contribution
	// isn't separately observable in this test (both keys' raw headers
	// already differ, so partitionIdentity would isolate them by header
	// value alone even if auth.label were removed from the hash). There
	// is no way to make two real proxy keys share a Proxy-Authorization
	// header, so isolating auth.label's contribution specifically can't
	// be tested at this level — an inherent limitation of testing here,
	// not a gap in the fix.
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

func TestSemanticCache_IsolatesByUpstreamCredential(t *testing.T) {
	// Regression for review finding #1 applied to the semantic cache
	// specifically: a REPHRASED prompt (so the exact-match cache can't
	// contribute — only a real semantic-similarity hit could serve it)
	// from a different upstream credential must never receive the
	// first caller's cached response, and must get its own real answer
	// from upstream instead.
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprint(w, "answer to: "+string(b)+" for "+r.Header.Get("Authorization"))
	})
	s.SemanticIndex = semcache.NewIndex(100)
	s.SemanticCacheThreshold = 0.5
	first := `{"messages":[{"role":"user","content":"Explain the capital of Sweden"}]}`
	second := `{"messages":[{"role":"user","content":"What is the capital city of Sweden"}]}`
	partitionCall(s, "POST", "/chat", first, map[string]string{"Authorization": "Bearer alice-upstream"})
	got := partitionCall(s, "POST", "/chat", second, map[string]string{"Authorization": "Bearer bob-upstream"})
	if got.Header().Get("X-Semantic-Cache-Hit") == "true" {
		t.Fatalf("different upstream credential received a semantic cache hit meant for another caller: %s", got.Body.String())
	}
	if !strings.Contains(got.Body.String(), "bob-upstream") {
		t.Fatalf("expected bob to receive his own real answer, got: %s", got.Body.String())
	}
}

func TestSemanticCache_IsolatesByDestinationPath(t *testing.T) {
	// Regression for the endpoint/path dimension of review finding #3:
	// two different destination paths behind the same target (e.g. two
	// Azure OpenAI deployments, which put the model name in the URL
	// path rather than the request body) must never share a semantic
	// cache hit, even with byte-identical bodies and the same caller.
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "answer from "+r.URL.Path)
	})
	s.SemanticIndex = semcache.NewIndex(100)
	s.SemanticCacheThreshold = 0.5
	body := `{"messages":[{"role":"user","content":"Explain the capital of Sweden"}]}`
	partitionCall(s, "POST", "/openai/deployments/gpt-4o-prod/chat/completions", body, nil)
	got := partitionCall(s, "POST", "/openai/deployments/gpt-35-cheap/chat/completions", body, nil)
	if got.Header().Get("X-Semantic-Cache-Hit") == "true" {
		t.Fatalf("different destination path received a semantic cache hit meant for a different deployment: %s", got.Body.String())
	}
}
