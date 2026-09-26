package proxy_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

const leakedValue = "FAKE_PRIVATE_VALUE"

func TestLogSafety_JSONLogFormatHasNoQueryValue(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	var buf bytes.Buffer
	s.Logger = log.New(&buf, "", 0)
	s.LogFormat = proxy.LogFormatJSON
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/chat?api_key="+leakedValue, nil))
	if strings.Contains(buf.String(), leakedValue) {
		t.Fatalf("JSON log contains query value: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "api_key=REDACTED") {
		t.Fatalf("JSON log lost the masked key: %s", buf.String())
	}
}

func TestLogSafety_BlockWebhookPayloadHasNoQueryValue(t *testing.T) {
	payloads := make(chan string, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		payloads <- string(body)
	}))
	defer hook.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{Name: "deny-chat", PathPrefix: "/chat", Action: rules.Block})
	s := proxy.New("unused", target, engine)
	s.Logger = log.New(io.Discard, "", 0)
	hookURL, _ := url.Parse(hook.URL)
	s.WebhookURL = hookURL
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/chat?api_key="+leakedValue, nil))
	select {
	case payload := <-payloads:
		if strings.Contains(payload, leakedValue) {
			t.Fatalf("webhook payload contains query value: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no webhook delivered")
	}
}

func TestLogSafety_ComplianceEventCarriesMaskedURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	recorder := &capturingComplianceRecorder{events: make(chan proxy.ComplianceEvent, 1)}
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.ComplianceRecorder = recorder
	frontend := httptest.NewServer(s)
	defer frontend.Close()
	request, _ := http.NewRequest(http.MethodPost, frontend.URL+"/v1/chat?api_key="+leakedValue, strings.NewReader(`{"prompt":"hi"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Aiproxy-Client-Id", "employee-42")
	request.Header.Set("X-Aiproxy-Application-Id", "legal-assistant")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	select {
	case event := <-recorder.events:
		if strings.Contains(event.RequestURL, leakedValue) || !strings.Contains(event.RequestURL, "api_key=REDACTED") {
			t.Fatalf("compliance RequestURL = %q", event.RequestURL)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no compliance event recorded")
	}
}
