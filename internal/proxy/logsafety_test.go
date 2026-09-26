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

func TestLogSafety_UnreachableUpstreamLogsNoQueryValueAndReturns502(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL, _ := url.Parse(dead.URL)
	dead.Close()
	s := proxy.New("unused", deadURL, rules.NewEngine(rules.Allow))
	var buf bytes.Buffer
	s.Logger = log.New(&buf, "", 0)
	var stdBuf bytes.Buffer
	log.SetOutput(&stdBuf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, httptest.NewRequest("GET", "/chat?api_key="+leakedValue, nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", recorder.Code)
	}
	if strings.Contains(buf.String()+stdBuf.String(), leakedValue) {
		t.Fatalf("upstream error leaked query value: server=%q std=%q", buf.String(), stdBuf.String())
	}
	if !strings.Contains(buf.String(), "aiproxy: upstream:") {
		t.Fatalf("upstream error not logged through server logger: %q", buf.String())
	}
}

func TestLogSafety_WebhookDeliveryErrorOmitsURL(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadHook, _ := url.Parse(dead.URL + "/services/T000/B000/" + leakedValue + "?token=" + leakedValue)
	dead.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{Name: "deny-chat", PathPrefix: "/chat", Action: rules.Block})
	s := proxy.New("unused", target, engine)
	var buf syncBuffer
	s.Logger = log.New(&buf, "", 0)
	s.WebhookURL = deadHook
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/chat", nil))
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "delivery failed") {
		if time.Now().After(deadline) {
			t.Fatalf("no webhook delivery error logged: %q", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(buf.String(), leakedValue) {
		t.Fatalf("webhook error leaked its URL: %q", buf.String())
	}
}
