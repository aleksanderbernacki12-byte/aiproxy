package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestAcceptsJSON(t *testing.T) {
	cases := []struct {
		name   string
		accept string
		want   bool
	}{
		{"no header", "", false},
		{"exact match", "application/json", true},
		{"exact match case-insensitive", "Application/JSON", true},
		{"wildcard only, curl's own default", "*/*", false},
		{"application wildcard only", "application/*", false},
		{"explicit among multiple offered types", "text/html,application/json;q=0.9,*/*;q=0.8", true},
		{"zero quality explicitly rejects it", "application/json;q=0", false},
		{"zero quality with extra spaces", "application/json ; q=0", false},
		{"nonzero quality still counts", "application/json;q=0.5", true},
		{"unrelated type only", "text/plain", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.accept != "" {
				req.Header.Set("Accept", c.accept)
			}
			if got := acceptsJSON(req); got != c.want {
				t.Errorf("acceptsJSON(%q) = %v, want %v", c.accept, got, c.want)
			}
		})
	}
}

// TestWriteError_PlainTextByDefault proves a request with no Accept
// header — or one that never explicitly names application/json — gets
// exactly the same plain-text body aiproxy has always produced, the
// core backward-compatibility guarantee of this feature.
func TestWriteError_PlainTextByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	writeError(w, req, http.StatusForbidden, "block", "blocked by aiproxy rules", "aws-access-key")

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "blocked by aiproxy rules" {
		t.Fatalf("body = %q, want the plain message", got)
	}
}

// TestWriteError_JSONWhenAccepted proves a client that explicitly asks
// for JSON gets the structured body instead, with every field
// populated correctly.
func TestWriteError_JSONWhenAccepted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	writeError(w, req, http.StatusForbidden, "block", "blocked by aiproxy rules", "aws-access-key")

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got errorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v (%s)", err, w.Body.String())
	}
	want := errorResponse{Error: "block", Message: "blocked by aiproxy rules", Rule: "aws-access-key"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestWriteError_OmitsRuleFieldWhenEmpty proves an empty rule (every
// rejection reason except a block) is left out of the JSON body
// entirely, not sent as an empty string.
func TestWriteError_OmitsRuleFieldWhenEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	writeError(w, req, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded", "")

	if strings.Contains(w.Body.String(), `"rule"`) {
		t.Fatalf("body = %q, want no \"rule\" key when rule is empty (omitempty)", w.Body.String())
	}
}

// TestWriteResponseBlockedBody_JSONWhenRequestAcceptsIt proves the
// response-side synthetic error body (built from resp.Request, not a
// direct http.Request the caller already has) honors content
// negotiation exactly like writeError.
func TestWriteResponseBlockedBody_JSONWhenRequestAcceptsIt(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	resp := &http.Response{Request: req, Header: make(http.Header)}

	writeResponseBlockedBody(resp, "response blocked by aiproxy rules")

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var got errorResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body is not valid JSON: %v (%s)", err, body)
	}
	if got.Error != "response_block" || got.Message != "response blocked by aiproxy rules" {
		t.Fatalf("got %+v", got)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length header = %q, want %d", got, len(body))
	}
}

// TestWriteResponseBlockedBody_PlainTextByDefault proves the default,
// pre-existing plain-text behavior is unchanged for a request that
// never asked for JSON — including the Content-Type now being
// correctly set for the first time (a latent pre-existing gap fixed
// incidentally while adding this feature).
func TestWriteResponseBlockedBody_PlainTextByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := &http.Response{Request: req, Header: make(http.Header)}

	writeResponseBlockedBody(resp, "response blocked by aiproxy rules")

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "response blocked by aiproxy rules" {
		t.Fatalf("body = %q, want the plain message", body)
	}
}
