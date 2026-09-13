package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/coalesce"
	"aiproxy/internal/idempotency"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestReplayPolicy_ExactCacheHit_BlockedByRuleAddedAfterCaching(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "the answer contains FUTURE_SECRET")
	}))
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

	// First call: no block rule yet, gets cached normally.
	first := partitionCall(s, "GET", "/chat", "", nil)
	if first.Code != 200 {
		t.Fatalf("expected first call to succeed, got %d: %s", first.Code, first.Body.String())
	}

	// A block rule is added AFTER the response was already cached —
	// simulating a config reload that tightens policy.
	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "future-secret", Pattern: regexp.MustCompile("FUTURE_SECRET"), Action: rules.Block})

	second := partitionCall(s, "GET", "/chat", "", nil)
	if second.Code == 200 {
		t.Fatalf("cached response bypassed a rule added after it was cached: status=%d body=%q", second.Code, second.Body.String())
	}
}

func TestReplayPolicy_Coalescing_BlockedByCurrentRules(t *testing.T) {
	release := make(chan struct{})
	var served atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		served.Add(1)
		fmt.Fprint(w, "contains COALESCE_SECRET")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	// The block rule for the response body exists from the start here —
	// this specifically proves coalesced replay (not just exact cache)
	// re-checks current rules, since a coalesced Replay branch never
	// even calls bufferResponse's own live check.
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "coalesce-secret", Pattern: regexp.MustCompile("COALESCE_SECRET"), Action: rules.Block})
	s := proxy.New("unused", u, engine)
	s.Logger = log.New(io.Discard, "", 0)
	s.Coalescer = coalesce.NewGroup(5 * time.Second)

	done := make(chan *httptest.ResponseRecorder, 2)
	go func() { done <- partitionCall(s, "GET", "/chat", "", nil) }()
	time.Sleep(50 * time.Millisecond) // let the first request claim Own before the second arrives
	go func() { done <- partitionCall(s, "GET", "/chat", "", nil) }()
	time.Sleep(50 * time.Millisecond) // let the second request start waiting (coalesce.Claim) before releasing upstream
	close(release)

	r1, r2 := <-done, <-done
	for _, r := range []*httptest.ResponseRecorder{r1, r2} {
		if r.Code == 200 {
			t.Fatalf("a request (owner or coalesced replay) received a blocked body: status=%d body=%q", r.Code, r.Body.String())
		}
	}
}

func TestReplayPolicy_IdempotencyReplay_BlockedWithoutReForwardingUpstream(t *testing.T) {
	var executions atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executions.Add(1)
		fmt.Fprint(w, "contains IDEMPOTENT_SECRET")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)

	headers := map[string]string{"Idempotency-Key": "op-1"}
	first := partitionCall(s, "POST", "/charge", `{}`, headers)
	if first.Code != 200 {
		t.Fatalf("expected first call to succeed, got %d", first.Code)
	}
	if executions.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream execution after first call, got %d", executions.Load())
	}

	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "idempotent-secret", Pattern: regexp.MustCompile("IDEMPOTENT_SECRET"), Action: rules.Block})

	second := partitionCall(s, "POST", "/charge", `{}`, headers)
	if second.Code == 200 {
		t.Fatalf("idempotency replay bypassed a rule added after the original call: status=%d", second.Code)
	}
	if executions.Load() != 1 {
		t.Fatalf("a policy-rejected idempotency replay re-forwarded the request upstream: %d total executions (a real charge operation must never run twice)", executions.Load())
	}
}
