package proxy_test

import (
	"io"
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

type capturingComplianceRecorder struct {
	events chan proxy.ComplianceEvent
	panic  bool
}

func (r *capturingComplianceRecorder) RecordAsync(event proxy.ComplianceEvent) bool {
	if r.panic {
		panic("synthetic recorder panic")
	}
	r.events <- event
	return true
}

func TestComplianceRecorderCapturesRawExchangeAfterLocalRedaction(t *testing.T) {
	upstreamRequest := make(chan []byte, 1)
	upstreamHeaders := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamRequest <- body
		upstreamHeaders <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"result":"TOPSECRET","usage":{"total_tokens":17}}`)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "response-secret", Pattern: regexp.MustCompile("TOPSECRET"), Action: rules.Redact})
	recorder := &capturingComplianceRecorder{events: make(chan proxy.ComplianceEvent, 1)}
	server := proxy.New("unused", target, engine)
	server.ComplianceRecorder = recorder
	frontend := httptest.NewServer(server)
	defer frontend.Close()

	request, err := http.NewRequest(http.MethodPost, frontend.URL+"/v1/chat", strings.NewReader(`{"model":"gpt-4o","prompt":"alice@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Aiproxy-Client-Id", "employee-42")
	request.Header.Set("X-Aiproxy-Application-Id", "legal-assistant")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	clientBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(clientBody), "TOPSECRET") {
		t.Fatal("response policy did not redact the client-facing body")
	}
	if got := string(<-upstreamRequest); !strings.Contains(got, "[REDACTED_EMAIL]") || strings.Contains(got, "alice@example.com") {
		t.Fatalf("upstream request = %q, want locally PII-redacted body", got)
	}
	forwardedHeaders := <-upstreamHeaders
	if forwardedHeaders.Get("X-Aiproxy-Client-Id") != "" || forwardedHeaders.Get("X-Aiproxy-Application-Id") != "" {
		t.Fatal("internal compliance identity headers reached the upstream")
	}

	select {
	case event := <-recorder.events:
		if event.ClientID != "employee-42" || event.ApplicationID != "legal-assistant" {
			t.Fatalf("identity = %q/%q", event.ClientID, event.ApplicationID)
		}
		if !strings.Contains(string(event.RequestBody), "alice@example.com") {
			t.Fatal("vault snapshot did not retain the original request")
		}
		if !strings.Contains(string(event.ResponseBody), "TOPSECRET") {
			t.Fatal("vault snapshot did not retain the original upstream response")
		}
		if event.Routing["model"] != "gpt-4o" {
			t.Fatalf("routing model = %#v", event.Routing["model"])
		}
		if !event.ComplianceFlags["pii_detected"] || !event.ComplianceFlags["pii_redacted"] || !event.ComplianceFlags["response_policy_redacted"] {
			t.Fatalf("compliance flags = %#v", event.ComplianceFlags)
		}
		if event.Metrics["total_tokens"] != 17 || event.Metrics["status_code"] != http.StatusCreated {
			t.Fatalf("metrics = %#v", event.Metrics)
		}
		if len(event.EventID) != 36 || event.Timestamp.IsZero() {
			t.Fatalf("event identity = %q at %s", event.EventID, event.Timestamp)
		}
	case <-time.After(time.Second):
		t.Fatal("completed exchange was not submitted to compliance recorder")
	}
}

func TestComplianceRecorderPanicDoesNotFailLLMTraffic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	server := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	server.ComplianceRecorder = &capturingComplianceRecorder{panic: true}
	frontend := httptest.NewServer(server)
	defer frontend.Close()

	response, err := http.Post(frontend.URL, "application/json", strings.NewReader(`{"model":"gpt-4o"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
}

func TestComplianceRecorderCapturesRawStreamingResponse(t *testing.T) {
	const rawStream = "data: {\"delta\":\"TOPSECRET\"}\n\ndata: [DONE]\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, rawStream)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "response-secret", Pattern: regexp.MustCompile("TOPSECRET"), Action: rules.Redact})
	recorder := &capturingComplianceRecorder{events: make(chan proxy.ComplianceEvent, 1)}
	server := proxy.New("unused", target, engine)
	server.ComplianceRecorder = recorder
	frontend := httptest.NewServer(server)
	defer frontend.Close()

	response, err := http.Post(frontend.URL, "application/json", strings.NewReader(`{"model":"gpt-4o"}`))
	if err != nil {
		t.Fatal(err)
	}
	clientBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if strings.Contains(string(clientBody), "TOPSECRET") {
		t.Fatal("stream secret reached the client")
	}
	select {
	case event := <-recorder.events:
		if string(event.ResponseBody) != rawStream {
			t.Fatalf("raw stream = %q, want %q", event.ResponseBody, rawStream)
		}
		if !event.ComplianceFlags["response_policy_redacted"] || event.Metrics["response_complete"] != true {
			t.Fatalf("stream evidence = flags %#v metrics %#v", event.ComplianceFlags, event.Metrics)
		}
	case <-time.After(time.Second):
		t.Fatal("stream exchange was not submitted")
	}
}
