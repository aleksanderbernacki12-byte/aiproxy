package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSConfig_AllowedOrigin(t *testing.T) {
	cases := []struct {
		name   string
		cors   *CORSConfig
		origin string
		want   string
		wantOK bool
	}{
		{"exact match", &CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}, "https://app.example.com", "https://app.example.com", true},
		{"no match", &CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}, "https://evil.example.com", "", false},
		{"empty origin header never matches", &CORSConfig{AllowedOrigins: []string{"*"}}, "", "", false},
		{"wildcard echoes specific origin, never literal *", &CORSConfig{AllowedOrigins: []string{"*"}}, "https://anything.example.com", "https://anything.example.com", true},
		{"one of several configured origins", &CORSConfig{AllowedOrigins: []string{"https://a.example.com", "https://b.example.com"}}, "https://b.example.com", "https://b.example.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := c.cors.allowedOrigin(c.origin)
			if ok != c.wantOK || got != c.want {
				t.Errorf("allowedOrigin(%q) = (%q, %v), want (%q, %v)", c.origin, got, ok, c.want, c.wantOK)
			}
		})
	}
}

func TestApplyCORSHeaders(t *testing.T) {
	t.Run("nil cors leaves header untouched", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Origin", "https://app.example.com")
		h := make(http.Header)
		applyCORSHeaders(nil, h, r)
		if len(h) != 0 {
			t.Errorf("header = %v, want empty", h)
		}
	})

	t.Run("disallowed origin leaves header untouched", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Origin", "https://evil.example.com")
		h := make(http.Header)
		applyCORSHeaders(cors, h, r)
		if len(h) != 0 {
			t.Errorf("header = %v, want empty", h)
		}
	})

	t.Run("allowed origin sets Allow-Origin and Vary, no credentials by default", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Origin", "https://app.example.com")
		h := make(http.Header)
		applyCORSHeaders(cors, h, r)
		if got := h.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
			t.Errorf("Access-Control-Allow-Origin = %q, want https://app.example.com", got)
		}
		if got := h.Get("Vary"); got != "Origin" {
			t.Errorf("Vary = %q, want Origin", got)
		}
		if got := h.Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want empty", got)
		}
	})

	t.Run("AllowCredentials sets the credentials header", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"https://app.example.com"}, AllowCredentials: true}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Origin", "https://app.example.com")
		h := make(http.Header)
		applyCORSHeaders(cors, h, r)
		if got := h.Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
		}
	})

	t.Run("calling twice stays idempotent, no duplicate Vary", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Origin", "https://app.example.com")
		h := make(http.Header)
		applyCORSHeaders(cors, h, r)
		applyCORSHeaders(cors, h, r)
		if got := h.Values("Vary"); len(got) != 1 {
			t.Errorf("Vary = %v, want exactly one entry", got)
		}
		if got := h.Values("Access-Control-Allow-Origin"); len(got) != 1 {
			t.Errorf("Access-Control-Allow-Origin = %v, want exactly one entry", got)
		}
	})
}

func TestCORSPreflightRequest(t *testing.T) {
	cases := []struct {
		name   string
		method string
		acrm   string
		want   bool
	}{
		{"real preflight", http.MethodOptions, "POST", true},
		{"OPTIONS without Access-Control-Request-Method is not a preflight", http.MethodOptions, "", false},
		{"POST with Access-Control-Request-Method is still not OPTIONS", http.MethodPost, "POST", false},
		{"plain GET", http.MethodGet, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, "/", nil)
			if c.acrm != "" {
				r.Header.Set("Access-Control-Request-Method", c.acrm)
			}
			if got := corsPreflightRequest(r); got != c.want {
				t.Errorf("corsPreflightRequest() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestHandleCORSPreflight(t *testing.T) {
	t.Run("default methods when unset", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"*"}}
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		handleCORSPreflight(cors, w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
		}
		if got := w.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, PUT, PATCH, DELETE, OPTIONS" {
			t.Errorf("Access-Control-Allow-Methods = %q, want the default set", got)
		}
	})

	t.Run("configured methods override the default", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET", "POST"}}
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		handleCORSPreflight(cors, w, r)
		if got := w.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST" {
			t.Errorf("Access-Control-Allow-Methods = %q, want GET, POST", got)
		}
	})

	t.Run("reflects requested headers when none configured", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"*"}}
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "x-api-key, content-type")
		w := httptest.NewRecorder()
		handleCORSPreflight(cors, w, r)
		if got := w.Header().Get("Access-Control-Allow-Headers"); got != "x-api-key, content-type" {
			t.Errorf("Access-Control-Allow-Headers = %q, want the reflected request headers", got)
		}
	})

	t.Run("configured headers override reflection", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"*"}, AllowedHeaders: []string{"Content-Type"}}
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "x-api-key, content-type")
		w := httptest.NewRecorder()
		handleCORSPreflight(cors, w, r)
		if got := w.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type" {
			t.Errorf("Access-Control-Allow-Headers = %q, want the configured Content-Type", got)
		}
	})

	t.Run("MaxAgeSeconds omitted when zero", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"*"}}
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		handleCORSPreflight(cors, w, r)
		if got := w.Header().Get("Access-Control-Max-Age"); got != "" {
			t.Errorf("Access-Control-Max-Age = %q, want empty", got)
		}
	})

	t.Run("MaxAgeSeconds set when configured", func(t *testing.T) {
		cors := &CORSConfig{AllowedOrigins: []string{"*"}, MaxAgeSeconds: 3600}
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		handleCORSPreflight(cors, w, r)
		if got := w.Header().Get("Access-Control-Max-Age"); got != "3600" {
			t.Errorf("Access-Control-Max-Age = %q, want 3600", got)
		}
	})
}
