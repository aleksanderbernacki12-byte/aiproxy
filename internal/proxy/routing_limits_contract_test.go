package proxy_test

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/limiter"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func contractUpstream(t *testing.T, handler http.HandlerFunc) *url.URL {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func contractFrontend(t *testing.T, srv *proxy.Server) *httptest.Server {
	t.Helper()
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	frontend.Client().Timeout = 10 * time.Second
	t.Cleanup(frontend.Close)
	return frontend
}

func TestRoutingContract_SelectionPreservesForwardedRequest(t *testing.T) {
	type observed struct {
		Target, Method, Path, Query, Body, APIKey string
	}
	upstream := func(label string) *url.URL {
		return contractUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(observed{label, r.Method, r.URL.Path, r.URL.RawQuery, string(body), r.Header.Get("X-Api-Key")})
		})
	}
	defaultURL, pathURL, modelURL := upstream("default"), upstream("path"), upstream("model")
	srv := proxy.New("unused", defaultURL, rules.NewEngine(rules.Allow))
	srv.AddRoute("/api", []*url.URL{pathURL}, nil, nil, nil)
	srv.AddModelRoute("chat", []string{"chat-*"}, []*url.URL{modelURL}, nil, nil, nil)
	frontend := contractFrontend(t, srv)
	const query = "tag=a&tag=b&encoded=a%2Fb"
	cases := []struct {
		name, path, body, wantTarget, wantPath string
	}{
		{"model overrides path", "/api/v1/messages", `{"model":"chat-small","prompt":"hello"}`, "model", "/api/v1/messages"},
		{"model overrides default", "/v1/messages", `{"model":"chat-large"}`, "model", "/v1/messages"},
		{"unmatched model uses path", "/api/v1/messages", `{"model":"other"}`, "path", "/v1/messages"},
		{"missing model uses path", "/api/v1/messages", `{"prompt":"hello"}`, "path", "/v1/messages"},
		{"non-string model uses path", "/api/v1/messages", `{"model":7}`, "path", "/v1/messages"},
		{"unparseable body uses path", "/api/v1/messages", `not-json`, "path", "/v1/messages"},
		{"exact prefix forwards root", "/api", `{}`, "path", "/"},
		{"unmatched path uses default", "/elsewhere", `{}`, "default", "/elsewhere"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPatch, frontend.URL+tc.path+"?"+query, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Api-Key", "synthetic-upstream-key")
			resp, err := frontend.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			var got observed
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			want := observed{tc.wantTarget, http.MethodPatch, tc.wantPath, query, tc.body, "synthetic-upstream-key"}
			if got != want {
				t.Fatalf("forwarded = %+v, want %+v", got, want)
			}
		})
	}
}

func TestRoutingContract_ConcurrentClientQuotasSpanPathAndModelRoutes(t *testing.T) {
	var upstreamHits atomic.Int32
	target := contractUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		io.WriteString(w, "ok")
	})
	srv := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	global, pathLimit, modelLimit := limiter.New(1, time.Hour), limiter.New(1, time.Hour), limiter.New(1, time.Hour)
	srv.Limiter = global
	srv.AddRoute("/api", []*url.URL{target}, nil, pathLimit, nil)
	srv.AddModelRoute("chat", []string{"chat-*"}, []*url.URL{target}, nil, modelLimit, nil)
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "alice", Key: "alice-key", Limiter: limiter.New(5, time.Hour)},
		{Name: "bob", Key: "bob-key", Limiter: limiter.New(7, time.Hour)},
	}
	frontend := contractFrontend(t, srv)
	const attempts = 24
	start := make(chan struct{})
	var allowed [2]atomic.Int32
	var rejected [2]atomic.Int32
	var wg sync.WaitGroup
	for client, quota := range []int{5, 7} {
		for attempt := 0; attempt < attempts; attempt++ {
			wg.Add(1)
			go func(client, quota, attempt int) {
				defer wg.Done()
				<-start
				body := `{}`
				if attempt%2 == 0 {
					body = `{"model":"chat-small"}`
				}
				req, err := http.NewRequest(http.MethodPost, frontend.URL+"/api/messages", strings.NewReader(body))
				if err != nil {
					t.Error(err)
					return
				}
				req.Header.Set("Proxy-Authorization", "Bearer "+[]string{"alice-key", "bob-key"}[client])
				resp, err := frontend.Client().Do(req)
				if err != nil {
					t.Error(err)
					return
				}
				defer resp.Body.Close()
				if _, err := io.Copy(io.Discard, resp.Body); err != nil {
					t.Error(err)
				}
				if got := resp.Header.Get("X-RateLimit-Limit-Requests"); got != strconv.Itoa(quota) {
					t.Errorf("client %d limit header = %q, want %d", client, got, quota)
				}
				switch resp.StatusCode {
				case http.StatusOK:
					allowed[client].Add(1)
				case http.StatusTooManyRequests:
					rejected[client].Add(1)
					if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || n <= 0 {
						t.Errorf("invalid Retry-After: %q", resp.Header.Get("Retry-After"))
					}
				default:
					t.Errorf("unexpected status: %d", resp.StatusCode)
				}
			}(client, quota, attempt)
		}
	}
	close(start)
	wg.Wait()
	for client, quota := range []int32{5, 7} {
		if allowed[client].Load() != quota || rejected[client].Load() != attempts-quota {
			t.Errorf("client %d allowed/rejected = %d/%d, want %d/%d", client, allowed[client].Load(), rejected[client].Load(), quota, attempts-quota)
		}
	}
	if got := upstreamHits.Load(); got != 12 {
		t.Errorf("upstream calls = %d, want exactly 12", got)
	}
	for name, l := range map[string]*limiter.Limiter{"global": global, "path": pathLimit, "model": modelLimit} {
		if _, remaining, _ := l.Info(); remaining != 1 {
			t.Errorf("%s quota consumed despite client override", name)
		}
	}
	if got := srv.Stats.Snapshot().RateLimited; got != 2*attempts-12 {
		t.Errorf("rate-limited count = %d, want %d", got, 2*attempts-12)
	}
}

func TestRoutingContract_TokenBudgetFollowsClientAcrossRoutes(t *testing.T) {
	var upstreamHits atomic.Int32
	target := contractUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"usage":{"total_tokens":6}}`)
	})
	srv := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	exhausted := limiter.NewTokenLimiter(1, time.Hour)
	exhausted.Add(1)
	srv.TokenLimiter = exhausted
	srv.AddRoute("/api", []*url.URL{target}, nil, nil, exhausted)
	srv.AddModelRoute("chat", []string{"chat-*"}, []*url.URL{target}, nil, nil, exhausted)
	srv.ProxyAPIKeys = []proxy.ProxyKey{
		{Name: "alice", Key: "alice-key", TokenLimiter: limiter.NewTokenLimiter(10, time.Hour)},
		{Name: "bob", Key: "bob-key", TokenLimiter: limiter.NewTokenLimiter(10, time.Hour)},
	}
	frontend := contractFrontend(t, srv)
	for _, key := range []string{"alice-key", "bob-key"} {
		for attempt, body := range []string{`{}`, `{"model":"chat-small"}`, `{}`, `{"model":"chat-small"}`} {
			req, err := http.NewRequest(http.MethodPost, frontend.URL+"/api/messages", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Proxy-Authorization", "Bearer "+key)
			resp, err := frontend.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			want := http.StatusOK
			if attempt >= 2 {
				want = http.StatusTooManyRequests
			}
			if resp.StatusCode != want || resp.Header.Get("X-RateLimit-Limit-Tokens") != "10" {
				t.Fatalf("%s attempt %d: status/limit = %d/%q, want %d/10", key, attempt+1, resp.StatusCode, resp.Header.Get("X-RateLimit-Limit-Tokens"), want)
			}
		}
	}
	snap := srv.Stats.Snapshot()
	if upstreamHits.Load() != 4 || snap.TotalTokens != 24 || snap.TokenRateLimited != 4 || snap.RateLimited != 0 {
		t.Fatalf("hits/tokens/token-rejections/request-rejections = %d/%d/%d/%d, want 4/24/4/0", upstreamHits.Load(), snap.TotalTokens, snap.TokenRateLimited, snap.RateLimited)
	}
}
