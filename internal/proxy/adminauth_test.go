package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func adminAuthTestServer(t *testing.T) *proxy.Server {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	return s
}

func TestAdminAuth_OrdinaryProxyKeyCannotReachDrain(t *testing.T) {
	s := adminAuthTestServer(t)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "POST", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer client-key"})
	if got.Code == 200 {
		t.Fatalf("ordinary proxy client key reached /_aiproxy/drain: %s", got.Body.String())
	}
}

func TestAdminAuth_AdminKeyCanReachDrain(t *testing.T) {
	s := adminAuthTestServer(t)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "GET", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer admin-secret"})
	if got.Code != 200 {
		t.Fatalf("admin key rejected from /_aiproxy/drain: status=%d body=%q", got.Code, got.Body.String())
	}
}

func TestAdminAuth_AdminKeyCannotReachOrdinaryProxyTraffic(t *testing.T) {
	// An admin key is not a proxy key: it must not be usable to send
	// ordinary proxied traffic when proxy_api_key(s) are configured.
	s := adminAuthTestServer(t)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "GET", "/chat", "", map[string]string{"Proxy-Authorization": "Bearer admin-secret"})
	if got.Code == 200 {
		t.Fatalf("admin key was accepted for ordinary proxy traffic: %s", got.Body.String())
	}
}

func TestAdminAuth_NoAdminKeyConfigured_OrdinaryProxyKeyStillWorksForAdminPaths(t *testing.T) {
	// Backward compatibility: a deployment that hasn't adopted
	// admin_api_key/admin_api_keys yet keeps today's behavior.
	s := adminAuthTestServer(t)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	got := partitionCall(s, "GET", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer client-key"})
	if got.Code != 200 {
		t.Fatalf("expected backward-compatible admin access with no admin key configured, got status=%d body=%q", got.Code, got.Body.String())
	}
}
