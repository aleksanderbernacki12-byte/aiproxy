package proxy

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var uuidLikeRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestGenerateRequestID_ProducesUUIDv4Shape(t *testing.T) {
	id := generateRequestID()
	if !uuidLikeRE.MatchString(id) {
		t.Fatalf("generateRequestID() = %q, want UUIDv4-shaped 8-4-4-4-12 hex", id)
	}
	if id[14] != '4' {
		t.Errorf("generateRequestID() = %q, want version nibble 4 at index 14", id)
	}
	variant := id[19]
	if variant != '8' && variant != '9' && variant != 'a' && variant != 'b' {
		t.Errorf("generateRequestID() = %q, want RFC 4122 variant nibble (8/9/a/b) at index 19", id)
	}
}

func TestGenerateRequestID_NeverRepeatsAcrossManyCalls(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := generateRequestID()
		if seen[id] {
			t.Fatalf("generateRequestID() produced a duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestValidRequestID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want bool
	}{
		{"uuid shape", "550e8400-e29b-41d4-a716-446655440000", true},
		{"simple alnum", "abc123", true},
		{"underscore and dot", "req_id.v1", true},
		{"empty", "", true}, // validity itself doesn't special-case empty; resolveRequestID does
		{"too long but otherwise valid chars", strings.Repeat("a", maxRequestIDLen+1), false},
		{"contains space", "abc 123", false},
		{"contains CRLF", "abc\r\ninjected", false},
		{"contains quote", `abc"def`, false},
		{"contains slash", "abc/def", false},
		{"contains unicode", "abc日本語", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validRequestID(c.id); got != c.want {
				t.Errorf("validRequestID(%q) = %v, want %v", c.id, got, c.want)
			}
		})
	}
}

func TestValidRequestID_ExactlyMaxLengthOfSafeCharsIsValid(t *testing.T) {
	id := ""
	for i := 0; i < maxRequestIDLen; i++ {
		id += "a"
	}
	if !validRequestID(id) {
		t.Errorf("validRequestID with exactly maxRequestIDLen safe characters = false, want true")
	}
	if validRequestID(id + "a") {
		t.Errorf("validRequestID one character over maxRequestIDLen = true, want false")
	}
}

func TestResolveRequestID_ReusesValidClientSuppliedID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(requestIDHeader, "client-supplied-id-123")

	got := resolveRequestID(r)
	if got != "client-supplied-id-123" {
		t.Errorf("resolveRequestID() = %q, want the client's own valid ID echoed back verbatim", got)
	}
}

func TestResolveRequestID_GeneratesFreshIDWhenHeaderAbsent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	got := resolveRequestID(r)
	if !uuidLikeRE.MatchString(got) {
		t.Errorf("resolveRequestID() with no header = %q, want a freshly generated UUID-shaped ID", got)
	}
}

func TestResolveRequestID_GeneratesFreshIDWhenClientHeaderIsUnsafe(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(requestIDHeader, "not a safe\r\nid")

	got := resolveRequestID(r)
	if got == "not a safe\r\nid" {
		t.Fatal("resolveRequestID() echoed back an unsafe client-supplied value verbatim, want a fresh generated one instead")
	}
	if !uuidLikeRE.MatchString(got) {
		t.Errorf("resolveRequestID() with an unsafe header = %q, want a freshly generated UUID-shaped ID", got)
	}
}

func TestResolveRequestID_GeneratesFreshIDWhenClientHeaderIsEmpty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(requestIDHeader, "")

	got := resolveRequestID(r)
	if !uuidLikeRE.MatchString(got) {
		t.Errorf("resolveRequestID() with an empty header = %q, want a freshly generated UUID-shaped ID", got)
	}
}
