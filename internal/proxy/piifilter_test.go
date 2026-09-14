package proxy_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"aiproxy/internal/cache"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestPIIFilter_RedactsOnlyForwardedBodyAfterRouting(t *testing.T) {
	var defaultHits atomic.Int32
	defaultURL := contractUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		defaultHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	var forwarded string
	modelURL := contractUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		forwarded = string(body)
		w.WriteHeader(http.StatusNoContent)
	})

	srv := proxy.New("unused", defaultURL, rules.NewEngine(rules.Allow))
	srv.AddModelRoute("chat", []string{"chat-*"}, []*url.URL{modelURL}, nil, nil, nil)
	frontend := contractFrontend(t, srv)
	requestBody := `{"model":"chat-small","prompt":"Maila anna@example.com eller använd 900101-0017"}`
	response, err := frontend.Client().Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.StatusCode)
	}
	if defaultHits.Load() != 0 {
		t.Fatal("PII filtering changed model-route selection")
	}
	want := `{"model":"chat-small","prompt":"Maila [REDACTED_EMAIL] eller använd [REDACTED_SSN]"}`
	if forwarded != want {
		t.Fatalf("forwarded body = %q, want %q", forwarded, want)
	}
}

func TestPIIFilter_PreservesOriginalCacheIdentity(t *testing.T) {
	t.Chdir(t.TempDir())
	var upstreamHits atomic.Int32
	target := contractUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	})
	cch, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	srv.Cache = cch
	frontend := contractFrontend(t, srv)

	post := func(email string) *http.Response {
		t.Helper()
		body := `{"prompt":"` + email + `"}`
		response, err := frontend.Client().Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	for _, email := range []string{"alice@example.com", "bob@example.com"} {
		response := post(email)
		response.Body.Close()
	}
	cached := post("alice@example.com")
	defer cached.Body.Close()
	if cached.Header.Get("Age") == "" {
		t.Fatal("repeated original request was not served from cache")
	}
	if upstreamHits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2; distinct original PII must retain distinct cache keys", upstreamHits.Load())
	}
}
