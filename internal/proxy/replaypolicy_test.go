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
		fmt.Fprint(w, "shared answer")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	// Scoped to "/beta" only — the owner's own request lands on the
	// default target ("default"), out of this rule's scope, and
	// succeeds; only the coalesced waiter's request (routed to
	// "/beta", the SAME upstream, sharing the same coalescing key
	// since cache.Key hashes the resolved destination, not the route
	// label) is in scope. Only checkReplayPolicy's own re-check can
	// catch that — the owner's live check was for a different scope
	// entirely and would never have blocked this.
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "beta-secret", Pattern: regexp.MustCompile("SHARED"), Action: rules.Block, Targets: []string{"/beta"}})
	s := proxy.New("unused", u, engine)
	s.Logger = log.New(io.Discard, "", 0)
	t.Chdir(t.TempDir())
	c, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	s.Cache = c
	s.Coalescer = coalesce.NewGroup(5 * time.Second)
	s.AddRoute("/beta", []*url.URL{u}, nil, nil, nil)

	done := make(chan *httptest.ResponseRecorder, 2)
	go func() { done <- partitionCall(s, "GET", "/", "SHARED content", nil) }()
	time.Sleep(50 * time.Millisecond)
	go func() { done <- partitionCall(s, "GET", "/beta", "SHARED content", nil) }()
	time.Sleep(50 * time.Millisecond)
	close(release)

	owner, waiter := <-done, <-done
	if owner.Code != 200 {
		t.Fatalf("owner (out of the rule's scope) should have succeeded, got %d: %s", owner.Code, owner.Body.String())
	}
	if waiter.Code == 200 {
		t.Fatalf("coalesced waiter received a response its own route-scoped rule should have blocked: status=%d body=%q", waiter.Code, waiter.Body.String())
	}
	if served.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream call (real coalescing), got %d — the two requests may not share a coalescing key", served.Load())
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

func TestReplayPolicy_ExactCacheHit_BlockedByRequestSideRuleAddedAfterCaching(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "allowed answer")
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

	// First call: no request-side rule yet, gets cached normally. The
	// upstream response itself is completely benign — this proves the
	// re-check is catching the REQUEST content, not the response.
	first := partitionCall(s, "POST", "/chat", "restricted content", nil)
	if first.Code != 200 {
		t.Fatalf("expected first call to succeed, got %d: %s", first.Code, first.Body.String())
	}

	// A request-side block rule is added AFTER the response was cached.
	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "restricted-request", Pattern: regexp.MustCompile("restricted"), Action: rules.Block})

	second := partitionCall(s, "POST", "/chat", "restricted content", nil)
	if second.Code == 200 {
		t.Fatalf("cached response bypassed a REQUEST-side rule added after it was cached: status=%d body=%q", second.Code, second.Body.String())
	}
}
