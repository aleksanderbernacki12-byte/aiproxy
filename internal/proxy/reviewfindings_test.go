package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"aiproxy/internal/cache"
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
	s.SemanticIndex = semcache.NewIndex(100)
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
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "POST", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer client-key"})
	if got.Code == 200 {
		t.Fatalf("ordinary proxy client can initiate global drain: %s", got.Body.String())
	}
}
