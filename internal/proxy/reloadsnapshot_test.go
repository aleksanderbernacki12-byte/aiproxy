package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/idempotency"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestReload_LogWritesNeverHitAClosedFile(t *testing.T) {
	dir := t.TempDir()
	openLog := func(i int) (*os.File, string) {
		path := filepath.Join(dir, fmt.Sprintf("%d.log", i))
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("open log file: %v", err)
		}
		return f, path
	}

	targetURL, _ := url.Parse("https://example.com")
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	var logged syncBuffer
	srv.Logger = log.New(&logged, "", 0)
	first, firstPath := openLog(0)
	srv.LogFile = first
	paths := []string{firstPath}

	const writers, writesEach, reloads = 4, 500, 50
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < writesEach; i++ {
				srv.LogEvent("tick", "x")
			}
		}()
	}
	var last *os.File
	for i := 1; i <= reloads; i++ {
		f, path := openLog(i)
		paths = append(paths, path)
		last = f
		srv.ReloadConfig(proxy.RuntimeConfig{Engine: rules.NewEngine(rules.Allow), LogFile: f, UpstreamTransport: proxy.NewUpstreamTransport(0)})
	}
	wg.Wait()
	defer last.Close()

	if strings.Contains(logged.String(), "write failed") {
		t.Errorf("a log write hit a closed file:\n%s", logged.String())
	}
	total := 0
	for _, path := range paths {
		total += len(logFileLines(t, path))
	}
	if total != writers*writesEach {
		t.Errorf("log lines across all files = %d, want %d", total, writers*writesEach)
	}
}

// TestReload_InFlightRequestKeepsItsConfig reloads while a request is
// waiting on the upstream: the in-flight request must finish on the
// engine and idempotency registry it started with (review finding #14),
// while the next request sees the new configuration.
func TestReload_InFlightRequestKeepsItsConfig(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	targetURL, _ := url.Parse(upstream.URL)

	registryA := idempotency.NewRegistry(time.Minute, time.Second)
	registryB := idempotency.NewRegistry(time.Minute, time.Second)
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Idempotency = registryA
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	post := func() (int, string, string) {
		req, _ := http.NewRequest(http.MethodPost, frontend.URL+"/v1/x", strings.NewReader(`{"n":1}`))
		req.Header.Set("Idempotency-Key", "k1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("post: %v", err)
			return 0, "", ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), resp.Header.Get("Idempotency-Replayed")
	}

	type result struct {
		status int
		body   string
	}
	inFlight := make(chan result, 1)
	go func() {
		status, body, _ := post()
		inFlight <- result{status, body}
	}()
	<-entered

	srv.ReloadConfig(proxy.RuntimeConfig{
		Engine:            rules.NewEngine(rules.Block),
		Idempotency:       registryB,
		UpstreamTransport: proxy.NewUpstreamTransport(0),
	})
	close(release)

	got := <-inFlight
	if got.status != http.StatusOK || got.body != `{"ok":true}` {
		t.Fatalf("in-flight request = %d %q, want 200 {\"ok\":true} from the pre-reload config", got.status, got.body)
	}
	if n := registryB.Len(); n != 0 {
		t.Errorf("new registry has %d entries, want 0: the in-flight request leaked into it", n)
	}

	if status, _, _ := post(); status != http.StatusForbidden {
		t.Errorf("request after reload = %d, want 403 from the new Block engine", status)
	}

	srv.ReloadConfig(proxy.RuntimeConfig{
		Engine:            rules.NewEngine(rules.Allow),
		Idempotency:       registryA,
		UpstreamTransport: proxy.NewUpstreamTransport(0),
	})
	status, body, replayed := post()
	if status != http.StatusOK || body != `{"ok":true}` || replayed != "true" {
		t.Errorf("replay from the original registry = %d %q replayed=%q, want the stored response: the in-flight request must complete its entry in the registry it claimed", status, body, replayed)
	}
}

// TestReload_ConcurrentWithTrafficAndCacheClear reloads with a fresh
// cache and idempotency registry while requests and admin cache clears
// run concurrently; under -race this proves the snapshot hand-over has
// no data races and never breaks a request.
func TestReload_ConcurrentWithTrafficAndCacheClear(t *testing.T) {
	t.Chdir(t.TempDir())
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	targetURL, _ := url.Parse(upstream.URL)

	newCache := func() *cache.Cache {
		c, err := cache.New()
		if err != nil {
			t.Fatalf("cache.New: %v", err)
		}
		return c
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = newCache()
	srv.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	const clients, requestsEach, reloads = 8, 100, 50
	var wg sync.WaitGroup
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < requestsEach; i++ {
				var req *http.Request
				if i%2 == 0 {
					req, _ = http.NewRequest(http.MethodGet, frontend.URL+"/v1/models", nil)
				} else {
					req, _ = http.NewRequest(http.MethodPost, frontend.URL+"/v1/x", strings.NewReader(fmt.Sprintf(`{"c":%d,"i":%d}`, c, i)))
					req.Header.Set("Idempotency-Key", fmt.Sprintf("k-%d-%d", c, i))
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Errorf("request: %v", err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status = %d, want 200", resp.StatusCode)
				}
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < reloads; i++ {
			srv.ReloadConfig(proxy.RuntimeConfig{
				Engine:            rules.NewEngine(rules.Allow),
				Cache:             newCache(),
				Idempotency:       idempotency.NewRegistry(time.Minute, time.Second),
				UpstreamTransport: proxy.NewUpstreamTransport(0),
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < reloads; i++ {
			resp, err := http.Post(frontend.URL+"/_aiproxy/cache/clear", "", nil)
			if err != nil {
				t.Errorf("cache clear: %v", err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	wg.Wait()
}
