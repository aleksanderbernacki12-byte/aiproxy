package proxy

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"aiproxy/internal/rules"
)

func logURLTestServer() *Server {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "path-key", Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{8,}`), Action: rules.Block})
	target, _ := url.Parse("http://upstream.invalid")
	return New("unused", target, engine)
}

func TestLogSafeURL(t *testing.T) {
	s := logURLTestServer()
	cases := []struct{ name, in, want string }{
		{"relative path and query", "/chat?api_key=FAKE&model=gpt", "/chat?api_key=REDACTED&model=REDACTED"},
		{"userinfo and fragment dropped", "https://user:pass@host.example/v1?x=1#frag", "https://host.example/v1?x=REDACTED"},
		{"empty value stays empty", "/v1?flag=&k=v", "/v1?flag=&k=REDACTED"},
		{"repeated key keeps both", "/v1?k=a&k=b", "/v1?k=REDACTED&k=REDACTED"},
		{"path secret masked", "/bot/sk-ABCDEFGH1234/send", "/bot/[REDACTED:path-key]/send"},
		{"no query untouched", "/v1/chat/completions", "/v1/chat/completions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			before := u.String()
			if got := s.logSafeURL(u); got != tc.want {
				t.Fatalf("logSafeURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if u.String() != before {
				t.Fatalf("logSafeURL mutated its input: %q -> %q", before, u.String())
			}
		})
	}
	if got := s.logSafeURL(nil); got != "" {
		t.Fatalf("logSafeURL(nil) = %q, want empty", got)
	}
}

func TestLogSafeRawURL(t *testing.T) {
	s := logURLTestServer()
	if got := s.logSafeRawURL("https://gen.example/v1?key=FAKE"); got != "https://gen.example/v1?key=REDACTED" {
		t.Fatalf("logSafeRawURL = %q", got)
	}
	if got := s.logSafeRawURL("http://[::1:bad"); got != "[unparseable URL]" {
		t.Fatalf("logSafeRawURL(unparseable) = %q", got)
	}
}

func TestLogSafeError(t *testing.T) {
	s := logURLTestServer()
	err := &url.Error{Op: "Post", URL: "https://up.example/chat?api_key=FAKE", Err: errors.New("connection refused")}
	got := s.logSafeError(err)
	if strings.Contains(got, "FAKE") || !strings.Contains(got, "Post") || !strings.Contains(got, "connection refused") {
		t.Fatalf("logSafeError = %q", got)
	}
	plain := errors.New("plain failure")
	if got := s.logSafeError(plain); got != "plain failure" {
		t.Fatalf("logSafeError(plain) = %q", got)
	}
	if got := s.logSafeError(nil); got != "" {
		t.Fatalf("logSafeError(nil) = %q", got)
	}
}

func TestLogSafety_BreakerAndShadowLogsMaskConfiguredURLs(t *testing.T) {
	s := logURLTestServer()
	var buf strings.Builder
	s.Logger = log.New(&buf, "", 0)
	s.logTargetEjected(s.logSafeRawURL("https://gen.example/v1?key=FAKE_PRIVATE_VALUE"))
	shadow, _ := url.Parse("http://127.0.0.1:1")
	s.mirrorToShadow(shadow, "POST", "/chat", "api_key=FAKE_PRIVATE_VALUE", http.Header{}, nil, "default", "req-1")
	if strings.Contains(buf.String(), "FAKE_PRIVATE_VALUE") {
		t.Fatalf("breaker/shadow log leaked: %q", buf.String())
	}
}
