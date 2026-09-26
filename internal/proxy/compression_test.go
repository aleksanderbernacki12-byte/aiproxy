package proxy_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

const awsKey = "AKIAABCDEFGHIJKLMNOP"

func gzipBytes(t *testing.T, plain string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	io.WriteString(writer, plain)
	writer.Close()
	return buf.Bytes()
}

// compressibleWith pads s so gzip really compresses it (tiny inputs are
// stored uncompressed, which would leave the secret visible and make a
// test pass for the wrong reason).
func compressibleWith(s string) string {
	return strings.Repeat("lorem ipsum dolor ", 200) + s
}

func blockingEngine() *rules.Engine {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "aws", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Action: rules.Block})
	return engine
}

// gzipUpstream answers with a gzip body only when the proxy itself asked
// for gzip, like a real provider, and records what it was sent.
func gzipUpstream(t *testing.T, plain string, seen *http.Header, body *[]byte) *url.URL {
	t.Helper()
	compressed := gzipBytes(t, plain)
	if bytes.Contains(compressed, []byte(awsKey)) {
		t.Fatal("test setup: secret visible in compressed bytes")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = r.Header.Clone()
		}
		if body != nil {
			*body, _ = io.ReadAll(r.Body)
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(compressed)
			return
		}
		io.WriteString(w, plain)
	}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	return target
}

func TestCompression_GzipResponseIsScannedDecompressed(t *testing.T) {
	target := gzipUpstream(t, `{"answer":"`+compressibleWith(awsKey)+`"}`, nil, nil)
	s := proxy.New("unused", target, blockingEngine())
	s.Logger = log.New(io.Discard, "", 0)
	req := httptest.NewRequest("POST", "/chat", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (secret in gzip response must be blocked)", rec.Code)
	}
}

func TestCompression_GzipResponseUsageIsCounted(t *testing.T) {
	target := gzipUpstream(t, `{"answer":"`+compressibleWith("ok")+`","usage":{"total_tokens":42}}`, nil, nil)
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	req := httptest.NewRequest("POST", "/chat", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("client got Content-Encoding %q, want a plain body", rec.Header().Get("Content-Encoding"))
	}
	if n := s.Stats.Snapshot().TotalTokens; n != 42 {
		t.Fatalf("TotalTokens = %d, want 42", n)
	}
}

func TestCompression_GzipRequestBodyIsScannedAndForwardedPlain(t *testing.T) {
	var seen http.Header
	var forwarded []byte
	target := gzipUpstream(t, `{"ok":true}`, &seen, &forwarded)
	s := proxy.New("unused", target, blockingEngine())
	s.Logger = log.New(io.Discard, "", 0)

	blocked := httptest.NewRequest("POST", "/chat", bytes.NewReader(gzipBytes(t, compressibleWith(awsKey))))
	blocked.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, blocked)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a secret inside a gzip request body", rec.Code)
	}

	plain := compressibleWith("hello")
	allowed := httptest.NewRequest("POST", "/chat", bytes.NewReader(gzipBytes(t, plain)))
	allowed.Header.Set("Content-Encoding", "gzip")
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, allowed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if string(forwarded) != plain || seen.Get("Content-Encoding") != "" {
		t.Fatalf("upstream got Content-Encoding=%q body len %d, want plain body without encoding", seen.Get("Content-Encoding"), len(forwarded))
	}
}

func TestCompression_UnsupportedRequestEncodingIsRejected(t *testing.T) {
	target := gzipUpstream(t, `{"ok":true}`, nil, nil)
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	req := httptest.NewRequest("POST", "/chat", strings.NewReader("opaque"))
	req.Header.Set("Content-Encoding", "br")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType || !strings.Contains(rec.Body.String(), "unsupported_content_encoding") {
		t.Fatalf("status=%d body=%q, want 415 unsupported_content_encoding", rec.Code, rec.Body.String())
	}
}
