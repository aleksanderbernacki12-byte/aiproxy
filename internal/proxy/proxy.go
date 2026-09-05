// Package proxy implements the network interception layer: a reverse
// proxy built on Go's standard net/http and net/http/httputil. It
// terminates plaintext HTTP on localhost, buffers each request body in
// memory so the rules.Engine can inspect it in cleartext, and forwards
// allowed requests over a new HTTPS connection to a fixed target.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/limiter"
	"aiproxy/internal/rules"
)

// ANSI escape codes for structured, color-coded proxy logging. These are
// the standard terminal codes understood by virtually every terminal
// emulator; no external logging framework is used.
const (
	ansiReset     = "\x1b[0m"
	ansiGreen     = "\x1b[32m"
	ansiBrightRed = "\x1b[91m"
	ansiYellow    = "\x1b[33m"
	ansiBlue      = "\x1b[34m"
	ansiPurple    = "\x1b[35m"
)

// llmUsageResponse is a minimal, proxy-internal shape for pulling a token
// usage count out of an LLM provider's JSON response body. Every other
// field in the response is ignored.
type llmUsageResponse struct {
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

// requestContextKey is the context key used to carry per-request data
// (the client-facing method/URL, and the cache key) from ServeHTTP
// through to ModifyResponse. The method/URL travel this way so usage
// logging matches the same format as the ALLOW/BLOCK/CIRCUIT BREAKER
// lines rather than the rewritten, absolute upstream URL; the cache key
// travels this way so ModifyResponse can store the response under the
// exact same key ServeHTTP already checked for a hit.
type requestContextKey struct{}

type requestContextInfo struct {
	method   string
	url      string
	cacheKey string
}

// Server is a reverse proxy that evaluates every request's body against
// a rules.Engine before forwarding it to Target over HTTPS.
type Server struct {
	Addr    string
	Target  *url.URL
	Engine  *rules.Engine
	Logger  *log.Logger
	Limiter *limiter.Limiter // nil disables the circuit breaker
	Cache   *cache.Cache     // nil disables the response cache

	reverseProxy *httputil.ReverseProxy
	httpServer   *http.Server
}

// New creates a Server that listens on addr, forwards allowed requests to
// target over HTTPS, and enforces engine on every request.
func New(addr string, target *url.URL, engine *rules.Engine) *Server {
	s := &Server{
		Addr:   addr,
		Target: target,
		Engine: engine,
		Logger: log.Default(),
	}

	s.reverseProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
		},
		ModifyResponse: s.modifyResponse,
	}

	return s
}

// ServeHTTP implements http.Handler. It reads the full request body into
// memory so the rule engine can inspect it in cleartext, evaluates the
// request, and either blocks it or restores the body and forwards it
// intact to Target over HTTPS.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The cache is checked before rules and the rate limiter: a cache hit
	// never touches either, and never reaches the upstream target.
	var cacheKey string
	if s.Cache != nil {
		cacheKey = cache.Key(r.Method, s.Target.ResolveReference(r.URL).String(), body)
		if cached, hit, err := s.Cache.Get(cacheKey); err == nil && hit {
			defer cached.Body.Close()
			copyHeader(w.Header(), cached.Header)
			w.WriteHeader(cached.StatusCode)
			io.Copy(w, cached.Body)
			s.logCacheHit(r.Method, r.URL.String())
			return
		}
	}

	action, ruleName, err := s.Engine.Evaluate(rules.Request{
		Method: r.Method,
		URL:    r.URL.String(),
		Body:   body,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if action == rules.Block {
		// The matched secret itself must never reach the log, only the
		// static rule name that identifies which pattern triggered it.
		s.logBlock(r.Method, r.URL.String(), ruleName)
		http.Error(w, "blocked by aiproxy rules", http.StatusForbidden)
		return
	}

	if s.Limiter != nil && !s.Limiter.Allow() {
		s.logRateLimited(r.Method, r.URL.String())
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	s.logAllow(r.Method, r.URL.String())

	// Carry the client-facing method/URL and the cache key through to
	// modifyResponse via the request context: by the time ModifyResponse
	// runs, the request it sees has already been rewritten to the
	// absolute upstream URL, and it needs the exact same cache key
	// ServeHTTP already checked for a hit in order to store a miss.
	reqCtx := requestContextInfo{method: r.Method, url: r.URL.String(), cacheKey: cacheKey}
	r = r.WithContext(context.WithValue(r.Context(), requestContextKey{}, reqCtx))

	s.reverseProxy.ServeHTTP(w, r)
}

// modifyResponse is httputil.ReverseProxy's response hook. It reads the
// full upstream response body into memory so it can look for an LLM-style
// token usage payload and, if caching is enabled, store the response for
// future identical requests. It immediately restores the body so the
// client still receives it intact — whether or not the body turned out
// to be parseable JSON.
func (s *Server) modifyResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		// Unlike a JSON parse failure, a body we couldn't even fully read
		// means there is nothing intact left to hand the client; let
		// ReverseProxy's normal error handling take over.
		return err
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

	reqCtx, _ := resp.Request.Context().Value(requestContextKey{}).(requestContextInfo)

	var usage llmUsageResponse
	if err := json.Unmarshal(body, &usage); err == nil && usage.Usage.TotalTokens > 0 {
		s.logUsage(reqCtx.method, reqCtx.url, usage.Usage.TotalTokens)
	}

	if s.Cache != nil && resp.StatusCode == http.StatusOK && reqCtx.cacheKey != "" {
		// httputil.DumpResponse drains and then restores resp.Body itself,
		// so the client still receives the body intact afterwards.
		if err := s.Cache.Set(reqCtx.cacheKey, resp); err != nil {
			s.logf("aiproxy: cache: failed to store response: %v", err)
		}
	}

	return nil
}

func (s *Server) logAllow(method, reqURL string) {
	s.logf("%s[ALLOW] %s %s%s", ansiGreen, method, reqURL, ansiReset)
}

func (s *Server) logBlock(method, reqURL, ruleName string) {
	s.logf("%s[BLOCK] %s %s - Triggered rule: %s%s", ansiBrightRed, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logRateLimited(method, reqURL string) {
	s.logf("%s[CIRCUIT BREAKER] %s %s - Rate limit exceeded%s", ansiYellow, method, reqURL, ansiReset)
}

func (s *Server) logUsage(method, reqURL string, totalTokens int) {
	s.logf("%s[USAGE] %s %s - Tokens used: %d%s", ansiBlue, method, reqURL, totalTokens, ansiReset)
}

func (s *Server) logCacheHit(method, reqURL string) {
	s.logf("%s[CACHE HIT] %s %s%s", ansiPurple, method, reqURL, ansiReset)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

// ListenAndServe starts the proxy and blocks until ctx is cancelled or a
// fatal server error occurs.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.httpServer = &http.Server{
		Addr:    s.Addr,
		Handler: s,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("proxy: %w", err)
	}
}
