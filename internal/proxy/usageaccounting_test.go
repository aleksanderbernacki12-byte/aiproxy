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
	"time"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestUsage_RedactRuleInsideUsageObjectStillCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answer":"hi","usage":{"total_tokens":77}}`)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "numbers", Pattern: regexp.MustCompile(`\b77\b`), Action: rules.Redact})
	s := proxy.New("unused", target, engine)
	s.Logger = log.New(io.Discard, "", 0)
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/chat", strings.NewReader(`{"prompt":"x"}`)))
	if n := s.Stats.Snapshot().TotalTokens; n != 77 {
		t.Fatalf("TotalTokens = %d, want 77", n)
	}
}

func TestUsage_StreamBlockedOnEventCarryingUsageStillCountsIt(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11}}}\n\n")
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "data: {\"type\":\"message_delta\",\"delta\":{\"text\":\"AKIAABCDEFGHIJKLMNOP\"},\"usage\":{\"output_tokens\":5}}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "aws-access-key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Action: rules.Block})
	s := proxy.New("unused", target, engine)
	s.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(s)
	defer frontend.Close()
	response, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats.Snapshot().TotalTokens != 16 {
		if time.Now().After(deadline) {
			t.Fatalf("TotalTokens = %d, want 16 (11 delivered + 5 in the blocked event)", s.Stats.Snapshot().TotalTokens)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
