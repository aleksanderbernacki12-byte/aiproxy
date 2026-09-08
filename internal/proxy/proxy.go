// Package proxy implements the network interception layer: a reverse
// proxy built on Go's standard net/http and net/http/httputil. It
// terminates plaintext HTTP on localhost, buffers each request body in
// memory so the rules.Engine can inspect it in cleartext, and forwards
// allowed requests over a new HTTPS connection to a fixed target.
package proxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/limiter"
	"aiproxy/internal/rules"
	"aiproxy/internal/stats"
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
	ansiCyan      = "\x1b[36m"
	ansiGray      = "\x1b[90m"
)

// usageFields is the shape of a "usage" object as different providers
// report it: OpenAI-style chat completion APIs report a single
// total_tokens; Anthropic's Messages API instead splits the same idea
// into input_tokens and output_tokens, with no total_tokens field at
// all.
type usageFields struct {
	TotalTokens  int `json:"total_tokens"`
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// total reports usageFields' combined token count: total_tokens
// directly when present, otherwise input_tokens+output_tokens — counted
// as soon as either is nonzero, even before the other has been seen,
// since Anthropic's own streamed events each report only one of the
// two (see extractTotalTokens).
func (u usageFields) total() (int, bool) {
	if u.TotalTokens > 0 {
		return u.TotalTokens, true
	}
	if u.InputTokens > 0 || u.OutputTokens > 0 {
		return u.InputTokens + u.OutputTokens, true
	}
	return 0, false
}

// llmUsageResponse is a minimal, proxy-internal shape for pulling a
// token usage count out of an LLM provider's JSON response body, or one
// SSE chunk of one. Usage covers every shape seen at the top level
// (an OpenAI chat completion, or Anthropic's message_delta stream
// event); Message covers Anthropic's message_start event, whose usage
// is nested one level deeper inside "message" instead. Every other
// field in the response is ignored.
type llmUsageResponse struct {
	Usage   usageFields `json:"usage"`
	Message *struct {
		Usage usageFields `json:"usage"`
	} `json:"message"`
}

// requestContextKey is the context key used to carry per-request data
// (the client-facing method/URL, the cache key, and the resolved route)
// from ServeHTTP through to ModifyResponse and Rewrite. The method/URL
// travel this way so usage logging matches the same format as the
// ALLOW/BLOCK/CIRCUIT BREAKER lines rather than the rewritten, absolute
// upstream URL; the cache key travels this way so ModifyResponse can
// store the response under the exact same key ServeHTTP already checked
// for a hit; the resolved route travels this way so Rewrite forwards to
// the exact target that key was computed against, instead of resolving
// routing a second time and risking the two disagreeing.
type requestContextKey struct{}

type requestContextInfo struct {
	method      string
	url         string
	cacheKey    string
	target      *url.URL
	forwardPath string
	targetLabel string
}

// route is one path-prefix-to-upstream mapping for multi-target routing.
// limiter is nil unless this route was given its own dedicated rate
// limit, in which case it applies instead of the server-wide Limiter for
// this route's traffic only.
type route struct {
	prefix  string
	target  *url.URL
	limiter *limiter.Limiter
}

// statsPath is a reserved, proxy-internal path: a GET request to it never
// reaches any upstream target. It is handled directly by ServeHTTP, ahead
// of caching, rules, and the rate limiter, so it stays reachable for
// monitoring a long-running proxy even while those are actively blocking
// or throttling other traffic.
const statsPath = "/_aiproxy/stats"

// metricsPath is a second reserved, proxy-internal path alongside
// statsPath: the same counters, in Prometheus's text exposition format,
// for scraping instead of polling statsPath. It deliberately isn't the
// ecosystem's usual bare "/metrics" — aiproxy forwards to an arbitrary
// upstream, which (unlike statsPath's own collision risk) could easily
// be a self-hosted LLM gateway that already serves its own metrics at
// that exact path. Point a Prometheus scrape config at this one with
// "metrics_path: /_aiproxy/metrics" instead.
const metricsPath = "/_aiproxy/metrics"

// headerScanExcludes lists, in lowercase, the header names never handed
// to the rule engine for scanning — see filterHeadersForScanning. These
// are exactly the headers a client legitimately uses to authenticate to
// the proxied upstream LLM API on every single request: Anthropic's
// "x-api-key", the generic bearer-token "Authorization" convention (also
// how OpenAI and Vertex AI are authenticated), and its
// "Proxy-Authorization" analogue. Scanning them against the same
// low-false-positive secret patterns built to catch a *leaked* key would
// flag every legitimate authenticated request, since the credential is
// deliberately shaped exactly like what those patterns are built to
// detect.
var headerScanExcludes = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
}

// filterHeadersForScanning returns a copy of header with every name in
// headerScanExcludes removed, for passing to rules.Request.Headers.
func filterHeadersForScanning(header http.Header) map[string][]string {
	filtered := make(map[string][]string, len(header))
	for name, values := range header {
		if headerScanExcludes[strings.ToLower(name)] {
			continue
		}
		filtered[name] = values
	}
	return filtered
}

// DefaultMaxBodyBytes is the request body size limit applied whenever
// Server.MaxBodyBytes is zero or negative. 10 MiB comfortably covers a
// normal LLM chat/completion payload, including a reasonably sized
// embedded image or document, while still bounding the worst case:
// every request body is fully buffered in memory before the rule
// engine can inspect it, so an unbounded size is a real
// memory-exhaustion risk for a proxy whose whole job is inspecting
// untrusted client traffic.
const DefaultMaxBodyBytes = 10 << 20 // 10 MiB

// Server is a reverse proxy that evaluates every request's body against
// a rules.Engine before forwarding it to Target over HTTPS. Additional
// path-prefix routes (see AddRoute) can send matching requests to other
// upstreams instead; Target is always the fallback for anything that
// doesn't match one of those.
//
// Engine, Limiter, Cache, CostPer1KTokens, and the route table added via
// AddRoute are safe to set directly before the server starts serving
// (that's how every constructor caller and test in this codebase already
// sets them up). Once ServeHTTP is live, changing any of them requires
// ReloadConfig instead, which swaps all of them together under a lock —
// the mutex below exists only to make that later swap race-free against
// concurrent requests; it is never involved in the single-threaded setup
// path.
type Server struct {
	Addr   string
	Target *url.URL
	Logger *log.Logger
	Stats  *stats.Stats // always present; counts every request outcome

	// LogFormat selects how every log line below is rendered. The zero
	// value behaves as LogFormatText, so existing callers that never set
	// it see no change in behavior.
	LogFormat LogFormat

	// mu guards every field below it against a concurrent ReloadConfig.
	mu              sync.RWMutex
	Engine          *rules.Engine
	Limiter         *limiter.Limiter // nil disables the circuit breaker
	Cache           *cache.Cache     // nil disables the response cache
	CostPer1KTokens float64          // zero omits the shutdown summary's cost line
	routes          []route

	// CostBudget, if greater than zero, is a threshold in the same units
	// as CostPer1KTokens; once the running total cost reaches or passes
	// it, ServeHTTP logs and webhook-alerts a budget_exceeded event once
	// — see stats.Stats.CrossedBudget. It never blocks or otherwise
	// changes how a request is handled. Zero (the default) disables the
	// check entirely.
	CostBudget float64

	// MaxBodyBytes caps how large a request body ServeHTTP will buffer in
	// memory before rejecting it with a 413. Unlike every other field
	// above, zero (or negative) does not mean "disabled" — it means
	// DefaultMaxBodyBytes applies instead, since a reverse proxy that
	// buffers every request body fully in memory before it can be
	// inspected must never expose an actually-unbounded size by default.
	MaxBodyBytes int64

	// WebhookURL, if non-nil, is POSTed a JSON alert every time a rule
	// blocks or redacts a request, or the rate limiter rejects one — see
	// notifyWebhook. nil (the default) disables alerting entirely.
	WebhookURL *url.URL

	// ProxyAPIKey, if non-empty, requires every request — including
	// GET /_aiproxy/stats and /_aiproxy/metrics — to present it as a
	// "Proxy-Authorization: Bearer <key>" header before ServeHTTP does
	// anything else with it; see checkProxyAuth. Empty (the default)
	// disables the check entirely.
	ProxyAPIKey string

	reverseProxy *httputil.ReverseProxy
	httpServer   *http.Server
}

// LogFormat selects Server's log output shape.
type LogFormat string

const (
	// LogFormatText is the default: colored, human-readable lines like
	// "[ALLOW] GET /endpoint".
	LogFormatText LogFormat = "text"

	// LogFormatJSON emits one JSON object per line instead — including
	// the shutdown summary — so the whole log stream is safe to pipe
	// into a log aggregator or `jq`, with no stray non-JSON lines mixed
	// in. Callers using this format should also strip any timestamp
	// prefix from Logger (e.g. log.New(w, "", 0)): the JSON payload
	// already carries its own "time" field, and a prepended prefix would
	// break every line's JSON.
	LogFormatJSON LogFormat = "json"
)

// logEvent is the shape of one line logged under LogFormatJSON.
type logEvent struct {
	Time   string `json:"time"`
	Level  string `json:"level"`
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Tokens int    `json:"tokens,omitempty"`

	// Cost and Budget are only set on a budget_exceeded event: the
	// running total cost at the moment it was logged, and the
	// cost_budget threshold it crossed.
	Cost    float64 `json:"cost,omitempty"`
	Budget  float64 `json:"budget,omitempty"`
	Message string  `json:"message,omitempty"`
}

// New creates a Server that listens on addr, forwards allowed requests to
// target over HTTPS by default, and enforces engine on every request.
func New(addr string, target *url.URL, engine *rules.Engine) *Server {
	s := &Server{
		Addr:   addr,
		Target: target,
		Engine: engine,
		Logger: log.Default(),
		Stats:  stats.New(),
	}

	s.reverseProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// ServeHTTP already resolved routing once (to compute the
			// cache key) and stashed the result in the context that
			// r.Clone carries through to pr.In; reuse it verbatim so
			// forwarding can never disagree with what was cache-keyed.
			reqCtx, _ := pr.In.Context().Value(requestContextKey{}).(requestContextInfo)
			target := reqCtx.target
			if target == nil {
				target = s.Target
			}
			pr.Out.URL.Path = reqCtx.forwardPath
			pr.Out.URL.RawPath = ""
			pr.SetURL(target)
		},
		ModifyResponse: s.modifyResponse,
		// Flush every write immediately instead of buffering. Without
		// this, a streamed LLM response would sit in a buffer until it
		// was large enough (or the connection closed) before the client
		// saw anything, defeating the point of streaming.
		FlushInterval: -1,
	}

	return s
}

// AddRoute registers a path-prefix route: any request whose path starts
// with prefix is forwarded to target instead of the default Target, with
// the matched prefix stripped from the forwarded path (a request to
// prefix "/openai" and path "/openai/v1/chat" forwards to target's host
// with path "/v1/chat"). Routes are checked in the order they were
// added; the first matching prefix wins, so add more specific prefixes
// before more general ones if they could overlap.
//
// lim, if non-nil, gives this route its own dedicated rate limit instead
// of sharing the server-wide Limiter with every other target — heavy
// traffic to one provider then can't throttle the others. Pass nil for a
// route that should just share whatever Limiter (if any) the server is
// configured with, same as every route did before per-target limits
// existed.
func (s *Server) AddRoute(prefix string, target *url.URL, lim *limiter.Limiter) {
	s.routes = append(s.routes, route{prefix: prefix, target: target, limiter: lim})
}

// resolveRoute matches path against the registered routes and returns
// the target to forward to along with the path to forward it as (the
// matched prefix stripped, if any route matched), a label identifying
// the target for the per-target stats breakdown (the matched prefix, or
// "default" for the fallback Target), and the rate limiter that applies
// to this request: the matched route's own limiter if it has one,
// otherwise the server-wide Limiter (nil if that is unset too, meaning
// no limiting at all). It falls back to the default Target, unmodified
// path, when nothing matches.
func (s *Server) resolveRoute(path string) (target *url.URL, forwardPath string, targetLabel string, lim *limiter.Limiter) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.routes {
		if strings.HasPrefix(path, r.prefix) {
			stripped := strings.TrimPrefix(path, r.prefix)
			if !strings.HasPrefix(stripped, "/") {
				stripped = "/" + stripped
			}
			effectiveLimiter := r.limiter
			if effectiveLimiter == nil {
				effectiveLimiter = s.Limiter
			}
			return r.target, stripped, r.prefix, effectiveLimiter
		}
	}
	return s.Target, path, "default", s.Limiter
}

// getEngine, getCache, getCostPer1KTokens, and getWebhookURL are small
// locked accessors for the fields ReloadConfig can change at runtime,
// used everywhere they're read outside of resolveRoute (which takes the
// same lock itself, for Limiter and the route table).
func (s *Server) getEngine() *rules.Engine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Engine
}

func (s *Server) getCache() *cache.Cache {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Cache
}

func (s *Server) getCostPer1KTokens() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CostPer1KTokens
}

func (s *Server) getCostBudget() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CostBudget
}

func (s *Server) getMaxBodyBytes() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.MaxBodyBytes <= 0 {
		return DefaultMaxBodyBytes
	}
	return s.MaxBodyBytes
}

func (s *Server) getWebhookURL() *url.URL {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.WebhookURL
}

func (s *Server) getProxyAPIKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ProxyAPIKey
}

// Route describes one path-prefix-to-upstream mapping for ReloadConfig,
// mirroring what AddRoute registers before the server starts serving.
type Route struct {
	Prefix string
	Target *url.URL
	// Limiter, if non-nil, gives this route its own dedicated rate
	// limit instead of sharing whatever Limiter ReloadConfig sets.
	Limiter *limiter.Limiter
}

// ReloadConfig atomically replaces the engine, rate limiter, cache,
// cost-per-1K-tokens rate, cost budget, max request body size, webhook
// alert URL, proxy API key, and target routes — e.g. after re-reading
// aiproxy.json on SIGHUP. All of them change together under one lock, so
// a request in flight never observes a torn mix of old and new
// configuration; a request takes effect from the moment it's accepted,
// so anything already being handled keeps running against whatever
// configuration it started with. Pass nil for limiter/cache/webhookURL
// to disable them, matching how the corresponding field would be set at
// startup; pass "" for proxyAPIKey to disable the auth check; pass zero
// for costBudget to disable the budget check, or maxBodyBytes to fall
// back to DefaultMaxBodyBytes, same as leaving Server.MaxBodyBytes
// unset.
func (s *Server) ReloadConfig(engine *rules.Engine, lim *limiter.Limiter, cch *cache.Cache, costPer1KTokens, costBudget float64, maxBodyBytes int64, webhookURL *url.URL, proxyAPIKey string, routes []Route) {
	newRoutes := make([]route, len(routes))
	for i, r := range routes {
		newRoutes[i] = route{prefix: r.Prefix, target: r.Target, limiter: r.Limiter}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.Engine = engine
	s.Limiter = lim
	s.Cache = cch
	s.CostPer1KTokens = costPer1KTokens
	s.CostBudget = costBudget
	s.MaxBodyBytes = maxBodyBytes
	s.WebhookURL = webhookURL
	s.ProxyAPIKey = proxyAPIKey
	s.routes = newRoutes
}

// LogEvent logs a one-off, non-request-scoped message from outside the
// proxy package — e.g. the CLI's SIGHUP reload handler reporting success
// or failure — through the same LogFormat-aware machinery as every other
// log line, so it can never break the "every line is valid JSON"
// guarantee under LogFormatJSON.
func (s *Server) LogEvent(level, message string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: level, Message: message})
		return
	}
	s.logf("%s", message)
}

// proxyAuthScheme is the credential scheme checkProxyAuth expects in the
// Proxy-Authorization header, matching how every LLM API in this
// project's own examples presents a bearer credential.
const proxyAuthScheme = "Bearer "

// checkProxyAuth reports whether r is allowed to use the proxy at all:
// true if Server.ProxyAPIKey is unset (the check is disabled), or if r
// carries a "Proxy-Authorization: Bearer <key>" header whose key exactly
// matches, compared in constant time so a wrong guess can't be narrowed
// down by response timing the way a plain == comparison could leak.
func (s *Server) checkProxyAuth(r *http.Request) bool {
	want := s.getProxyAPIKey()
	if want == "" {
		return true
	}
	got := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(got, proxyAuthScheme) {
		return false
	}
	got = strings.TrimPrefix(got, proxyAuthScheme)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ServeHTTP implements http.Handler. It reads the full request body into
// memory (rejecting it with a 413 past MaxBodyBytes, before any of it is
// buffered) so the rule engine can inspect it in cleartext, evaluates
// the request, and either blocks it or restores the body and forwards
// it intact to the resolved target (Target by default, or a
// path-prefix route added via AddRoute) over HTTPS.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.checkProxyAuth(r) {
		// Checked before statsPath/metricsPath too — an API key, once
		// configured, gates the whole proxy, monitoring endpoints
		// included, not just traffic actually forwarded upstream.
		s.Stats.RecordUnauthorized()
		s.logUnauthorized(r.Method, r.URL.String())
		s.notifyWebhook("unauthorized", r.Method, r.URL.String(), "")
		w.Header().Set("Proxy-Authenticate", strings.TrimSpace(proxyAuthScheme))
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.URL.Path == statsPath {
		s.serveStats(w, r)
		return
	}
	if r.URL.Path == metricsPath {
		s.serveMetrics(w, r)
		return
	}

	limitedBody := http.MaxBytesReader(w, r.Body, s.getMaxBodyBytes())
	body, err := io.ReadAll(limitedBody)
	limitedBody.Close()
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Resolved once so the cache key (below) and the actual forwarding
	// (in Rewrite, via the request context set further down) can never
	// disagree about which target and path this request maps to.
	target, forwardPath, targetLabel, effectiveLimiter := s.resolveRoute(r.URL.Path)

	// The cache is checked before rules and the rate limiter: a cache hit
	// never touches either, and never reaches the upstream target. The
	// key is computed from the body as received, before any redaction —
	// two different secrets that happen to redact to the same
	// placeholder are still cached separately, which only ever costs an
	// extra upstream call, never an incorrect one.
	var cacheKey string
	if cch := s.getCache(); cch != nil {
		destURL := &url.URL{Path: forwardPath, RawQuery: r.URL.RawQuery}
		cacheKey = cache.Key(r.Method, target.ResolveReference(destURL).String(), body)
		if cached, hit, err := cch.Get(cacheKey); err == nil && hit {
			defer cached.Body.Close()
			copyHeader(w.Header(), cached.Header)
			w.WriteHeader(cached.StatusCode)
			io.Copy(w, cached.Body)
			s.Stats.RecordCacheHit(targetLabel)
			s.logCacheHit(r.Method, r.URL.String())
			return
		}
	}

	action, ruleName, evaluatedBody, evaluatedHeaders, dryRunHits, err := s.getEngine().Evaluate(rules.Request{
		Method:  r.Method,
		URL:     r.URL.String(),
		Body:    body,
		Headers: filterHeadersForScanning(r.Header),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.handleRequestDryRunHits(dryRunHits, r.Method, r.URL.String())
	if action == rules.Block {
		// The matched secret itself must never reach the log, only the
		// static rule name that identifies which pattern triggered it.
		s.Stats.RecordBlock(targetLabel, ruleName)
		s.logBlock(r.Method, r.URL.String(), ruleName)
		s.notifyWebhook("block", r.Method, r.URL.String(), ruleName)
		http.Error(w, "blocked by aiproxy rules", http.StatusForbidden)
		return
	}

	if effectiveLimiter != nil && !effectiveLimiter.Allow() {
		s.Stats.RecordRateLimited(targetLabel)
		s.logRateLimited(r.Method, r.URL.String())
		s.notifyWebhook("rate_limited", r.Method, r.URL.String(), "")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// evaluatedBody and evaluatedHeaders are body/r.Header unchanged
	// unless action is Redact, in which case whichever of the two the
	// match was actually found in has the matched secret masked out —
	// forwarded either way, so the client's request only ever fails on
	// Block above. Headers are merged back by name rather than replacing
	// r.Header wholesale, since evaluatedHeaders only ever covers the
	// subset filterHeadersForScanning handed to the engine.
	r.Body = io.NopCloser(bytes.NewReader(evaluatedBody))
	r.ContentLength = int64(len(evaluatedBody))
	for name, values := range evaluatedHeaders {
		r.Header[name] = values
	}
	if action == rules.Redact {
		s.Stats.RecordRedact(targetLabel, ruleName)
		s.logRedact(r.Method, r.URL.String(), ruleName)
		s.notifyWebhook("redact", r.Method, r.URL.String(), ruleName)
	} else {
		s.Stats.RecordAllow(targetLabel)
		s.logAllow(r.Method, r.URL.String())
	}

	// Carry the client-facing method/URL, the cache key, and the resolved
	// route through to Rewrite and modifyResponse via the request
	// context: by the time those run, the request has already been
	// rewritten to the absolute upstream URL, and they need the exact
	// same target/cache key ServeHTTP already resolved and checked.
	reqCtx := requestContextInfo{
		method:      r.Method,
		url:         r.URL.String(),
		cacheKey:    cacheKey,
		target:      target,
		forwardPath: forwardPath,
		targetLabel: targetLabel,
	}
	r = r.WithContext(context.WithValue(r.Context(), requestContextKey{}, reqCtx))

	s.reverseProxy.ServeHTTP(w, r)
}

// modifyResponse is httputil.ReverseProxy's response hook. Most JSON API
// responses are handled by bufferResponse, which reads the whole body
// into memory up front. A response advertised as text/event-stream (the
// format LLM chat APIs use for streaming completions) instead goes
// through streamResponse, which lets ReverseProxy copy each chunk to the
// client as it arrives — usage extraction and caching still happen, but
// only once the stream has finished, from an accumulated copy, so
// streaming is never delayed by our own inspection of it.
func (s *Server) modifyResponse(resp *http.Response) error {
	reqCtx, _ := resp.Request.Context().Value(requestContextKey{}).(requestContextInfo)

	if isEventStream(resp) {
		s.streamResponse(resp, reqCtx)
		return nil
	}
	return s.bufferResponse(resp, reqCtx)
}

// isEventStream reports whether resp is advertised as an SSE stream.
func isEventStream(resp *http.Response) bool {
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return mediaType == "text/event-stream"
}

// bufferResponse reads the full response body into memory, scans it for
// a leaked secret the same way an outgoing request is scanned (guarding
// against the model echoing one back — a prompt injection, or an
// upstream error message reflecting request data — not just what the
// client sent going out), looks for an LLM-style token usage payload,
// and, if caching is enabled, stores the response for future identical
// requests.
func (s *Server) bufferResponse(resp *http.Response, reqCtx requestContextInfo) error {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		// Unlike a JSON parse failure, a body we couldn't even fully read
		// means there is nothing intact left to hand the client; let
		// ReverseProxy's normal error handling take over.
		return err
	}

	action, ruleName, scannedBody, dryRunHits := s.getEngine().EvaluateResponse(body)
	s.handleResponseDryRunHits(dryRunHits, reqCtx.method, reqCtx.url)
	if action == rules.Block {
		s.Stats.RecordResponseBlock(reqCtx.targetLabel, ruleName)
		s.logResponseBlock(reqCtx.method, reqCtx.url, ruleName)
		s.notifyWebhook("response_block", reqCtx.method, reqCtx.url, ruleName)
		msg := []byte("response blocked by aiproxy rules")
		resp.StatusCode = http.StatusForbidden
		resp.Status = http.StatusText(http.StatusForbidden)
		resp.Header.Set("Content-Length", strconv.Itoa(len(msg)))
		resp.ContentLength = int64(len(msg))
		resp.Body = io.NopCloser(bytes.NewReader(msg))
		return nil
	}
	if action == rules.Redact {
		s.Stats.RecordResponseRedact(reqCtx.targetLabel, ruleName)
		s.logResponseRedact(reqCtx.method, reqCtx.url, ruleName)
		s.notifyWebhook("response_redact", reqCtx.method, reqCtx.url, ruleName)
		body = scannedBody
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

	if cch := s.getCache(); cch != nil && resp.StatusCode == http.StatusOK && reqCtx.cacheKey != "" {
		// httputil.DumpResponse drains and then restores resp.Body itself,
		// so the client still receives the body intact afterwards. This
		// runs before the usage log line so a durable cache write is
		// never left pending behind an already-visible log line.
		if err := cch.Set(reqCtx.cacheKey, resp); err != nil {
			s.logError("aiproxy: cache: failed to store response: %v", err)
		}
	}

	s.logUsageFromBody(reqCtx, body)

	return nil
}

// streamResponse wraps resp.Body in a streamTee so ReverseProxy's own
// copy loop streams each chunk to the client immediately, exactly as it
// arrives from upstream — except a chunk streamTee's engine catches a
// secret in is redacted (or, for a Block-actioned rule, withheld,
// ending the stream) before ever reaching that copy loop — while the
// (post-scan) bytes are accumulated on the side. Once the stream ends,
// ReverseProxy closes the body, which triggers usage extraction and —
// for a clean, complete stream on a 200 response — a cache write, both
// from the accumulated copy.
func (s *Server) streamResponse(resp *http.Response, reqCtx requestContextInfo) {
	statusCode := resp.StatusCode
	header := resp.Header

	tee := &streamTee{
		src:    resp.Body,
		engine: s.getEngine(),
		onRedact: func(ruleName string) {
			s.Stats.RecordResponseRedact(reqCtx.targetLabel, ruleName)
			s.logResponseRedact(reqCtx.method, reqCtx.url, ruleName)
			s.notifyWebhook("response_redact", reqCtx.method, reqCtx.url, ruleName)
		},
		onBlock: func(ruleName string) {
			s.Stats.RecordResponseBlock(reqCtx.targetLabel, ruleName)
			s.logResponseBlock(reqCtx.method, reqCtx.url, ruleName)
			s.notifyWebhook("response_block", reqCtx.method, reqCtx.url, ruleName)
		},
		onDryRun: func(hits []rules.DryRunMatch) {
			s.handleResponseDryRunHits(hits, reqCtx.method, reqCtx.url)
		},
	}
	tee.onComplete = func(data []byte, cleanEOF bool) {
		// Cache first, log second: a caller that observes the log
		// line (e.g. a test synchronizing on it) can then rely on the
		// cache write having already landed. A stream a Block rule cut
		// short is never cached, same as any other incomplete stream:
		// cleanEOF is false for it too (see streamTee.Read).
		if cch := s.getCache(); cleanEOF && cch != nil && statusCode == http.StatusOK && reqCtx.cacheKey != "" {
			s.writeStreamToCache(cch, reqCtx.cacheKey, statusCode, header, data)
		}
		s.logUsageFromBody(reqCtx, data)
	}
	resp.Body = tee
}

// writeStreamToCache stores a completed stream's accumulated bytes under
// key in cch. A stream that was cut short (client disconnect, upstream
// error) must never reach here: a future "hit" would silently replay a
// truncated response as if it were complete.
func (s *Server) writeStreamToCache(cch *cache.Cache, key string, statusCode int, header http.Header, data []byte) {
	cached := &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(data)),
	}
	if err := cch.Set(key, cached); err != nil {
		s.logError("aiproxy: cache: failed to store response: %v", err)
	}
}

// errResponseBlocked is returned by streamTee.Read once a Block-actioned
// rule matches a streamed response chunk: ReverseProxy's copy loop ends
// on this error rather than a clean EOF, so the connection reads as
// broken instead of as a normal, complete response. This distinction
// matters because a streaming response's 200 status and headers are
// already committed to the client before the first byte of its body is
// even read — by the time a Block match can be detected, some of the
// response may already be on its way to the client, so there is no way
// to withdraw it the way a non-streaming Block (see bufferResponse) can
// swap in a clean 403 before anything is sent. Ending the connection
// abnormally at least keeps a truncated-but-silent stream from being
// mistaken for a short but complete answer.
var errResponseBlocked = errors.New("aiproxy: response blocked by rule")

// streamTee lets a streaming response body be read normally (so
// ReverseProxy can copy it straight through to the client) while every
// byte is also scanned for a leaked secret before being handed back —
// one accumulated batch at a time, split on the standard SSE event
// boundary ("\n\n"), so a match is (almost always) caught within
// whatever text delta it actually arrived in, without buffering the
// whole response the way bufferResponse does for a non-streaming reply.
// engine nil disables scanning entirely (chunks pass through untouched,
// same as before response scanning existed); onRedact/onBlock/onDryRun,
// if set, fire synchronously — once per matching batch, in real time as
// it's found — rather than being deferred to onComplete, which instead
// runs exactly once, when the stream is closed, with the full
// accumulated (post-scan) data and whether the stream ended cleanly.
//
// A secret split exactly across two batches is a known limitation:
// each is scanned independently, the same trade-off documented for the
// jwt/off built-in rule and for redacting a Bedrock-signed request body
// elsewhere in this project — real-world text deltas are practically
// always more than a couple of bytes, so this only matters in a
// pathological worst case.
type streamTee struct {
	src    io.ReadCloser
	engine *rules.Engine

	tmp     [32 * 1024]byte
	pending bytes.Buffer // raw bytes read but not yet a complete batch
	out     bytes.Buffer // processed bytes still owed to Read's caller
	buf     bytes.Buffer // full accumulated (post-scan) data, for onComplete

	blocked bool

	onRedact   func(ruleName string)
	onBlock    func(ruleName string)
	onDryRun   func(hits []rules.DryRunMatch)
	onComplete func(data []byte, cleanEOF bool)
	cleanEOF   bool
	once       sync.Once
}

func (t *streamTee) Read(p []byte) (int, error) {
	for t.out.Len() == 0 && !t.blocked {
		n, err := t.src.Read(t.tmp[:])
		if n > 0 {
			t.pending.Write(t.tmp[:n])
			t.processCompleteBatch()
		}
		if t.blocked {
			// A Block match found in the bytes just read overrides
			// whatever err src.Read returned alongside them, even
			// io.EOF: per the io.Reader contract, a reader is allowed to
			// return its final bytes together with io.EOF in the same
			// call, and treating that as a clean end here would let a
			// blocked stream slip through indistinguishable from a
			// normal one (and, e.g., get cached).
			break
		}
		if err != nil {
			if err == io.EOF {
				t.cleanEOF = true
				t.processRemainder()
			}
			if t.out.Len() == 0 {
				return 0, err
			}
			break
		}
	}

	if t.out.Len() > 0 {
		return t.out.Read(p)
	}
	return 0, errResponseBlocked
}

// processCompleteBatch scans t.pending up through its last SSE event
// boundary, if any, and leaves whatever comes after that boundary (a
// still-incomplete trailing event) in t.pending for a future Read.
func (t *streamTee) processCompleteBatch() {
	data := t.pending.Bytes()
	idx := bytes.LastIndex(data, []byte("\n\n"))
	if idx == -1 {
		return
	}
	boundary := idx + 2
	t.scan(data[:boundary])
	remainder := append([]byte(nil), data[boundary:]...)
	t.pending.Reset()
	t.pending.Write(remainder)
}

// processRemainder flushes whatever is left in t.pending once the
// source has reached EOF: there is no more data ever coming to
// complete a trailing partial event, so it is scanned and forwarded
// as-is now rather than silently dropped.
func (t *streamTee) processRemainder() {
	if t.pending.Len() == 0 {
		return
	}
	t.scan(t.pending.Bytes())
	t.pending.Reset()
}

// scan runs engine (if any) against one batch of streamed bytes and
// appends the result to t.out and t.buf — redacted in place for a
// Redact match, or, for a Block match, not appended at all: t.blocked
// is set instead, so Read ends the stream once whatever is already in
// t.out has been handed back.
func (t *streamTee) scan(batch []byte) {
	if t.blocked {
		return
	}
	if t.engine == nil {
		t.out.Write(batch)
		t.buf.Write(batch)
		return
	}

	action, ruleName, scanned, dryRunHits := t.engine.EvaluateResponse(batch)
	if len(dryRunHits) > 0 && t.onDryRun != nil {
		t.onDryRun(dryRunHits)
	}
	switch action {
	case rules.Block:
		t.blocked = true
		if t.onBlock != nil {
			t.onBlock(ruleName)
		}
	case rules.Redact:
		t.out.Write(scanned)
		t.buf.Write(scanned)
		if t.onRedact != nil {
			t.onRedact(ruleName)
		}
	default:
		t.out.Write(batch)
		t.buf.Write(batch)
	}
}

func (t *streamTee) Close() error {
	err := t.src.Close()
	t.once.Do(func() {
		if t.onComplete != nil {
			t.onComplete(t.buf.Bytes(), t.cleanEOF)
		}
	})
	return err
}

// extractTotalTokens looks for a token usage count in body. It handles
// both a plain JSON response and an SSE stream of "data: {...}" events,
// across two different provider shapes: OpenAI-style APIs report a
// running total_tokens, with the final streamed chunk before
// "data: [DONE]" carrying the grand total, so the last positive value
// found wins. Anthropic's Messages API instead splits the count across
// two different events — input_tokens in message_start's nested
// message.usage, output_tokens in message_delta's top-level usage — so
// streaming separately accumulates the best input and output counts
// seen across every chunk and sums them once nothing reported an
// explicit total_tokens directly.
func extractTotalTokens(body []byte) int {
	if tokens, ok := tryUnmarshalUsage(body); ok {
		return tokens
	}

	var bestTotal, input, output int
	sawTotal, sawInput, sawOutput := false, false, false

	for _, line := range bytes.Split(body, []byte("\n")) {
		payload, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:"))
		if !ok {
			continue
		}
		payload = bytes.TrimSpace(payload)
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}

		var chunk llmUsageResponse
		if err := json.Unmarshal(payload, &chunk); err != nil {
			continue
		}
		if chunk.Usage.TotalTokens > 0 {
			bestTotal, sawTotal = chunk.Usage.TotalTokens, true
		}
		if chunk.Usage.InputTokens > 0 {
			input, sawInput = chunk.Usage.InputTokens, true
		}
		if chunk.Usage.OutputTokens > 0 {
			output, sawOutput = chunk.Usage.OutputTokens, true
		}
		if chunk.Message != nil {
			if chunk.Message.Usage.InputTokens > 0 {
				input, sawInput = chunk.Message.Usage.InputTokens, true
			}
			if chunk.Message.Usage.OutputTokens > 0 {
				output, sawOutput = chunk.Message.Usage.OutputTokens, true
			}
		}
	}

	if sawTotal {
		return bestTotal
	}
	if sawInput || sawOutput {
		return input + output
	}
	return 0
}

func tryUnmarshalUsage(data []byte) (int, bool) {
	var usage llmUsageResponse
	if err := json.Unmarshal(data, &usage); err != nil {
		return 0, false
	}
	return usage.Usage.total()
}

func (s *Server) logUsageFromBody(reqCtx requestContextInfo, body []byte) {
	if tokens := extractTotalTokens(body); tokens > 0 {
		s.Stats.RecordTokensUsed(reqCtx.targetLabel, tokens)
		s.logUsage(reqCtx.method, reqCtx.url, tokens)
		if cost, crossed := s.Stats.CrossedBudget(s.getCostPer1KTokens(), s.getCostBudget()); crossed {
			s.logBudgetExceeded(reqCtx.method, reqCtx.url, cost, s.getCostBudget())
			s.notifyBudgetWebhook(reqCtx.method, reqCtx.url, cost, s.getCostBudget())
		}
	}
}

func (s *Server) logAllow(method, reqURL string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "allow", Method: method, URL: reqURL})
		return
	}
	s.logf("%s[ALLOW] %s %s%s", ansiGreen, method, reqURL, ansiReset)
}

func (s *Server) logBlock(method, reqURL, ruleName string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "block", Method: method, URL: reqURL, Rule: ruleName})
		return
	}
	s.logf("%s[BLOCK] %s %s - Triggered rule: %s%s", ansiBrightRed, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logRateLimited(method, reqURL string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "rate_limited", Method: method, URL: reqURL})
		return
	}
	s.logf("%s[CIRCUIT BREAKER] %s %s - Rate limit exceeded%s", ansiYellow, method, reqURL, ansiReset)
}

func (s *Server) logUnauthorized(method, reqURL string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "unauthorized", Method: method, URL: reqURL})
		return
	}
	s.logf("%s[UNAUTHORIZED] %s %s - Missing or invalid Proxy-Authorization%s", ansiBrightRed, method, reqURL, ansiReset)
}

func (s *Server) logBudgetExceeded(method, reqURL string, cost, budget float64) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "budget_exceeded", Method: method, URL: reqURL, Cost: cost, Budget: budget})
		return
	}
	s.logf("%s[BUDGET EXCEEDED] %s %s - Estimated cost %.4f exceeds budget %.4f%s", ansiYellow, method, reqURL, cost, budget, ansiReset)
}

func (s *Server) logUsage(method, reqURL string, totalTokens int) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "usage", Method: method, URL: reqURL, Tokens: totalTokens})
		return
	}
	s.logf("%s[USAGE] %s %s - Tokens used: %d%s", ansiBlue, method, reqURL, totalTokens, ansiReset)
}

func (s *Server) logCacheHit(method, reqURL string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "cache_hit", Method: method, URL: reqURL})
		return
	}
	s.logf("%s[CACHE HIT] %s %s%s", ansiPurple, method, reqURL, ansiReset)
}

func (s *Server) logRedact(method, reqURL, ruleName string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "redact", Method: method, URL: reqURL, Rule: ruleName})
		return
	}
	s.logf("%s[REDACT] %s %s - Triggered rule: %s%s", ansiCyan, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logResponseBlock(method, reqURL, ruleName string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "response_block", Method: method, URL: reqURL, Rule: ruleName})
		return
	}
	s.logf("%s[RESPONSE BLOCK] %s %s - Triggered rule: %s%s", ansiBrightRed, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logResponseRedact(method, reqURL, ruleName string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "response_redact", Method: method, URL: reqURL, Rule: ruleName})
		return
	}
	s.logf("%s[RESPONSE REDACT] %s %s - Triggered rule: %s%s", ansiCyan, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logDryRunBlock(method, reqURL, ruleName string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "dry_run_block", Method: method, URL: reqURL, Rule: ruleName})
		return
	}
	s.logf("%s[DRY-RUN BLOCK] %s %s - Would have triggered rule: %s%s", ansiGray, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logDryRunRedact(method, reqURL, ruleName string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "dry_run_redact", Method: method, URL: reqURL, Rule: ruleName})
		return
	}
	s.logf("%s[DRY-RUN REDACT] %s %s - Would have triggered rule: %s%s", ansiGray, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logResponseDryRunBlock(method, reqURL, ruleName string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "response_dry_run_block", Method: method, URL: reqURL, Rule: ruleName})
		return
	}
	s.logf("%s[RESPONSE DRY-RUN BLOCK] %s %s - Would have triggered rule: %s%s", ansiGray, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logResponseDryRunRedact(method, reqURL, ruleName string) {
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "response_dry_run_redact", Method: method, URL: reqURL, Rule: ruleName})
		return
	}
	s.logf("%s[RESPONSE DRY-RUN REDACT] %s %s - Would have triggered rule: %s%s", ansiGray, method, reqURL, ruleName, ansiReset)
}

// handleRequestDryRunHits logs, stats-records, and webhook-alerts every
// dry-run rule that matched a request (see rules.DryRunMatch) — nothing
// happens if hits is empty. Called unconditionally, alongside whatever
// the request's actual (non-dry-run) outcome turns out to be, since a
// dry-run match never changes that outcome.
func (s *Server) handleRequestDryRunHits(hits []rules.DryRunMatch, method, reqURL string) {
	for _, h := range hits {
		switch h.Action {
		case rules.Block:
			s.Stats.RecordDryRunBlock(h.RuleName)
			s.logDryRunBlock(method, reqURL, h.RuleName)
			s.notifyWebhook("dry_run_block", method, reqURL, h.RuleName)
		case rules.Redact:
			s.Stats.RecordDryRunRedact(h.RuleName)
			s.logDryRunRedact(method, reqURL, h.RuleName)
			s.notifyWebhook("dry_run_redact", method, reqURL, h.RuleName)
		}
	}
}

// handleResponseDryRunHits is handleRequestDryRunHits' counterpart for a
// dry-run rule matching an upstream response instead of the client's
// request — used by both the non-streaming (bufferResponse) and
// streaming (streamTee) response paths.
func (s *Server) handleResponseDryRunHits(hits []rules.DryRunMatch, method, reqURL string) {
	for _, h := range hits {
		switch h.Action {
		case rules.Block:
			s.Stats.RecordResponseDryRunBlock(h.RuleName)
			s.logResponseDryRunBlock(method, reqURL, h.RuleName)
			s.notifyWebhook("response_dry_run_block", method, reqURL, h.RuleName)
		case rules.Redact:
			s.Stats.RecordResponseDryRunRedact(h.RuleName)
			s.logResponseDryRunRedact(method, reqURL, h.RuleName)
			s.notifyWebhook("response_dry_run_redact", method, reqURL, h.RuleName)
		}
	}
}

// webhookClient is a dedicated HTTP client for webhook deliveries, kept
// separate from the reverse proxy's own upstream connections and given a
// short, fixed timeout: a slow or hanging alert endpoint must never be
// allowed to pile up goroutines or affect the client-facing request path
// it's reporting on.
var webhookClient = &http.Client{Timeout: 5 * time.Second}

// webhookAlert is the JSON body POSTed to Server.WebhookURL for every
// block, redact, rate_limited, unauthorized, budget_exceeded, or
// dry-run event (dry_run_block, dry_run_redact, response_dry_run_block,
// response_dry_run_redact). Text alone is enough for a Slack incoming
// webhook (which reads exactly that field and ignores the rest); the
// remaining fields serve a generic JSON webhook consumer that wants the
// event structured instead of parsed back out of a sentence. Like every
// other log line in this package, it carries the rule name that
// matched, never the matched secret itself; Rule is empty for a
// rate_limited, unauthorized, or budget_exceeded event, since none of
// those is attributable to any one rule. Cost and Budget are set only
// for budget_exceeded, omitted (via omitempty on the pointer) for every
// other event.
type webhookAlert struct {
	Text   string   `json:"text"`
	Event  string   `json:"event"`
	Method string   `json:"method"`
	URL    string   `json:"url"`
	Rule   string   `json:"rule"`
	Time   string   `json:"time"`
	Cost   *float64 `json:"cost,omitempty"`
	Budget *float64 `json:"budget,omitempty"`
}

// deliverWebhookPayload marshals payload and POSTs it to Server.WebhookURL
// on its own goroutine, if configured — shared by notifyWebhook and
// notifyBudgetWebhook so the actual delivery mechanics (timeout, error
// logging, no retry) live in exactly one place. A slow or unreachable
// webhook endpoint never delays the client's actual request — the
// request has already been decided and logged by the time this runs. A
// delivery failure (or a non-2xx response) is logged as an internal
// error and otherwise ignored: there is no retry, and it never changes
// the outcome of the request that triggered it.
func (s *Server) deliverWebhookPayload(payload webhookAlert) {
	webhookURL := s.getWebhookURL()
	if webhookURL == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		// payload is always this one fixed, plain shape, so this should
		// never actually happen — mirrors logEventJSON's own fallback.
		s.logError("aiproxy: webhook: failed to encode alert: %v", err)
		return
	}

	go func() {
		resp, err := webhookClient.Post(webhookURL.String(), "application/json", bytes.NewReader(data))
		if err != nil {
			s.logError("aiproxy: webhook: delivery failed: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			s.logError("aiproxy: webhook: endpoint returned status %d", resp.StatusCode)
		}
	}()
}

// notifyWebhook builds and delivers a webhookAlert for a block, redact,
// rate_limited, unauthorized, or dry-run event. ruleName is the matched
// rule's name for every event except rate_limited and unauthorized, both
// "" (neither is attributable to any one rule) — a dry-run event's Text
// says "Would have triggered rule" instead of "Triggered rule", since
// nothing was actually enforced.
func (s *Server) notifyWebhook(event, method, reqURL, ruleName string) {
	var text string
	switch {
	case event == "rate_limited":
		text = fmt.Sprintf("[%s] %s %s - Rate limit exceeded", strings.ToUpper(event), method, reqURL)
	case event == "unauthorized":
		text = fmt.Sprintf("[%s] %s %s - Missing or invalid Proxy-Authorization", strings.ToUpper(event), method, reqURL)
	case strings.Contains(event, "dry_run"):
		text = fmt.Sprintf("[%s] %s %s - Would have triggered rule: %s", strings.ToUpper(event), method, reqURL, ruleName)
	default:
		text = fmt.Sprintf("[%s] %s %s - Triggered rule: %s", strings.ToUpper(event), method, reqURL, ruleName)
	}
	s.deliverWebhookPayload(webhookAlert{
		Text:   text,
		Event:  event,
		Method: method,
		URL:    reqURL,
		Rule:   ruleName,
		Time:   time.Now().UTC().Format(time.RFC3339),
	})
}

// notifyBudgetWebhook builds and delivers a webhookAlert for the
// budget_exceeded event — kept separate from notifyWebhook rather than
// overloading its signature, since this is the only event carrying a
// cost and a budget instead of a rule name.
func (s *Server) notifyBudgetWebhook(method, reqURL string, cost, budget float64) {
	text := fmt.Sprintf("[BUDGET_EXCEEDED] %s %s - Estimated cost %.4f exceeds budget %.4f", method, reqURL, cost, budget)
	s.deliverWebhookPayload(webhookAlert{
		Text:   text,
		Event:  "budget_exceeded",
		Method: method,
		URL:    reqURL,
		Time:   time.Now().UTC().Format(time.RFC3339),
		Cost:   &cost,
		Budget: &budget,
	})
}

// logEventJSON marshals ev (stamping the current time) and logs it as a
// single line, for LogFormatJSON.
func (s *Server) logEventJSON(ev logEvent) {
	ev.Time = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(ev)
	if err != nil {
		// ev is always one of a few fixed, plain shapes, so this should
		// never actually happen — but silently dropping the event would
		// be worse than a slightly malformed fallback line.
		s.logf(`{"level":"error","message":%q}`, err.Error())
		return
	}
	s.logf("%s", data)
}

// logError logs an internal, non-request-scoped problem (e.g. a failed
// cache write) — as a JSON line under LogFormatJSON, so it never breaks
// the guarantee that every line in that mode is valid JSON, or as a
// plain line otherwise.
func (s *Server) logError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(logEvent{Level: "error", Message: msg})
		return
	}
	s.logf("%s", msg)
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

// statsSnapshotJSON is the wire shape served at statsPath: the same
// counts as stats.Snapshot, plus an estimated cost — computed here, at
// request time, rather than stored on the snapshot itself, since pricing
// is a proxy-level concern (CostPer1KTokens) that the stats package has
// no notion of.
type statsSnapshotJSON struct {
	Allowed          int64 `json:"allowed"`
	Blocked          int64 `json:"blocked"`
	Redacted         int64 `json:"redacted"`
	RateLimited      int64 `json:"rate_limited"`
	CacheHits        int64 `json:"cache_hits"`
	TotalTokens      int64 `json:"total_tokens"`
	ResponseBlocked  int64 `json:"response_blocked"`
	ResponseRedacted int64 `json:"response_redacted"`

	// DryRunBlocked, DryRunRedacted, ResponseDryRunBlocked, and
	// ResponseDryRunRedacted are only meaningful at the top level —
	// dry-run activity is never broken down per target (see
	// stats.Stats.RecordDryRunBlock), so these are always 0 inside
	// per_target.
	DryRunBlocked          int64 `json:"dry_run_blocked"`
	DryRunRedacted         int64 `json:"dry_run_redacted"`
	ResponseDryRunBlocked  int64 `json:"response_dry_run_blocked"`
	ResponseDryRunRedacted int64 `json:"response_dry_run_redacted"`

	// Unauthorized is likewise only meaningful at the top level, and
	// always 0 inside per_target — a rejected request never gets far
	// enough to resolve a target.
	Unauthorized int64 `json:"unauthorized"`

	EstimatedCost *float64                      `json:"estimated_cost,omitempty"`
	PerTarget     map[string]statsSnapshotJSON  `json:"per_target,omitempty"`
	PerRule       map[string]stats.RuleSnapshot `json:"per_rule,omitempty"`

	// CostBudget is the configured cost_budget threshold, included only
	// when it's set. Unlike EstimatedCost, it's never repeated inside
	// PerTarget — a budget is a single whole-proxy-run threshold, not
	// something each target has its own copy of — so toStatsSnapshotJSON
	// never sets it; only the top-level caller (serveStats, logSummary)
	// does, once, after building the rest of the payload.
	CostBudget *float64 `json:"cost_budget,omitempty"`
}

func toStatsSnapshotJSON(snap stats.Snapshot, costPer1KTokens float64) statsSnapshotJSON {
	out := statsSnapshotJSON{
		Allowed:                snap.Allowed,
		Blocked:                snap.Blocked,
		Redacted:               snap.Redacted,
		RateLimited:            snap.RateLimited,
		CacheHits:              snap.CacheHits,
		TotalTokens:            snap.TotalTokens,
		ResponseBlocked:        snap.ResponseBlocked,
		ResponseRedacted:       snap.ResponseRedacted,
		DryRunBlocked:          snap.DryRunBlocked,
		DryRunRedacted:         snap.DryRunRedacted,
		ResponseDryRunBlocked:  snap.ResponseDryRunBlocked,
		ResponseDryRunRedacted: snap.ResponseDryRunRedacted,
		Unauthorized:           snap.Unauthorized,
	}
	if costPer1KTokens > 0 {
		cost := snap.EstimatedCost(costPer1KTokens)
		out.EstimatedCost = &cost
	}
	if len(snap.PerTarget) > 0 {
		out.PerTarget = make(map[string]statsSnapshotJSON, len(snap.PerTarget))
		for name, t := range snap.PerTarget {
			out.PerTarget[name] = toStatsSnapshotJSON(t, costPer1KTokens)
		}
	}
	if len(snap.PerRule) > 0 {
		out.PerRule = snap.PerRule
	}
	return out
}

// withCostBudget sets out.CostBudget when budget is configured — split
// out of toStatsSnapshotJSON so it only ever runs once, on the top-level
// payload, never recursed into PerTarget; see statsSnapshotJSON.CostBudget.
func withCostBudget(out statsSnapshotJSON, budget float64) statsSnapshotJSON {
	if budget > 0 {
		out.CostBudget = &budget
	}
	return out
}

// serveStats answers statsPath with the current Stats snapshot as JSON,
// letting a long-running proxy be monitored without waiting for Ctrl+C.
// It never touches rules, the rate limiter, or the cache, and is never
// itself counted in Stats — it isn't a proxied request.
func (s *Server) serveStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	payload := withCostBudget(toStatsSnapshotJSON(s.Stats.Snapshot(), s.getCostPer1KTokens()), s.getCostBudget())
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logError("aiproxy: stats: failed to encode response: %v", err)
	}
}

// promCounters lists the counters every metricsPath series is built
// from: one line pairs a metric name/help text with the stats.Snapshot
// field it reads.
var promCounters = []struct {
	name string
	help string
	get  func(stats.Snapshot) int64
}{
	{"aiproxy_requests_allowed_total", "Total number of requests allowed and forwarded to the upstream target.", func(s stats.Snapshot) int64 { return s.Allowed }},
	{"aiproxy_requests_blocked_total", "Total number of requests blocked by a rule.", func(s stats.Snapshot) int64 { return s.Blocked }},
	{"aiproxy_requests_redacted_total", "Total number of requests forwarded with a matched secret redacted.", func(s stats.Snapshot) int64 { return s.Redacted }},
	{"aiproxy_requests_rate_limited_total", "Total number of requests rejected by the rate limiter.", func(s stats.Snapshot) int64 { return s.RateLimited }},
	{"aiproxy_cache_hits_total", "Total number of requests served from the local response cache.", func(s stats.Snapshot) int64 { return s.CacheHits }},
	{"aiproxy_tokens_used_total", "Total number of tokens reported in upstream response usage fields.", func(s stats.Snapshot) int64 { return s.TotalTokens }},
	{"aiproxy_responses_blocked_total", "Total number of upstream responses withheld from the client by a rule.", func(s stats.Snapshot) int64 { return s.ResponseBlocked }},
	{"aiproxy_responses_redacted_total", "Total number of upstream responses forwarded with a matched secret redacted.", func(s stats.Snapshot) int64 { return s.ResponseRedacted }},
}

// promRuleCounters mirrors promCounters for the per-rule breakdown:
// which named rule (built-in, custom, or path) is actually responsible
// for a block/redact, independent of which target it happened on. There
// is no rule-labeled equivalent of allowed/rate-limited/cache-hits/
// tokens, since stats.RuleSnapshot only tracks the four outcomes a rule
// match can directly cause.
var promRuleCounters = []struct {
	name string
	help string
	get  func(stats.RuleSnapshot) int64
}{
	{"aiproxy_rule_blocked_total", "Total number of requests blocked by this rule.", func(r stats.RuleSnapshot) int64 { return r.Blocked }},
	{"aiproxy_rule_redacted_total", "Total number of requests redacted by this rule.", func(r stats.RuleSnapshot) int64 { return r.Redacted }},
	{"aiproxy_rule_response_blocked_total", "Total number of upstream responses blocked by this rule.", func(r stats.RuleSnapshot) int64 { return r.ResponseBlocked }},
	{"aiproxy_rule_response_redacted_total", "Total number of upstream responses redacted by this rule.", func(r stats.RuleSnapshot) int64 { return r.ResponseRedacted }},
	{"aiproxy_rule_dry_run_blocked_total", "Total number of requests this dry_run rule would have blocked.", func(r stats.RuleSnapshot) int64 { return r.DryRunBlocked }},
	{"aiproxy_rule_dry_run_redacted_total", "Total number of requests this dry_run rule would have redacted.", func(r stats.RuleSnapshot) int64 { return r.DryRunRedacted }},
	{"aiproxy_rule_dry_run_response_blocked_total", "Total number of upstream responses this dry_run rule would have blocked.", func(r stats.RuleSnapshot) int64 { return r.ResponseDryRunBlocked }},
	{"aiproxy_rule_dry_run_response_redacted_total", "Total number of upstream responses this dry_run rule would have redacted.", func(r stats.RuleSnapshot) int64 { return r.ResponseDryRunRedacted }},
}

// promDryRunCounters lists the four overall (never per-target) dry-run
// counters — see stats.Stats.RecordDryRunBlock for why dry-run activity
// isn't tracked per target the way every other counter is.
var promDryRunCounters = []struct {
	name string
	help string
	get  func(stats.Snapshot) int64
}{
	{"aiproxy_dry_run_blocked_total", "Total number of requests a dry_run rule would have blocked.", func(s stats.Snapshot) int64 { return s.DryRunBlocked }},
	{"aiproxy_dry_run_redacted_total", "Total number of requests a dry_run rule would have redacted.", func(s stats.Snapshot) int64 { return s.DryRunRedacted }},
	{"aiproxy_dry_run_response_blocked_total", "Total number of upstream responses a dry_run rule would have blocked.", func(s stats.Snapshot) int64 { return s.ResponseDryRunBlocked }},
	{"aiproxy_dry_run_response_redacted_total", "Total number of upstream responses a dry_run rule would have redacted.", func(s stats.Snapshot) int64 { return s.ResponseDryRunRedacted }},
}

// promLabelValue escapes a label value per the Prometheus text
// exposition format: backslash, double quote, and newline are the only
// characters that need it.
func promLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// writePromMetrics writes one line per target for every counter in
// promCounters, each labeled target="<name>" — deliberately with no
// separate unlabeled "grand total" series alongside them, since that
// would just be sum(aiproxy_requests_allowed_total) by another name and
// Prometheus users already expect to compute it that way. per_target is
// always walked in full and never suppressed for a single-target run,
// same reasoning as the JSON stats endpoint: a metrics scrape needs a
// structurally predictable shape every time, not a human-friendly
// summary. targets are sorted for a stable scrape-to-scrape diff.
func writePromMetrics(w io.Writer, snap stats.Snapshot, costPer1KTokens, costBudget float64) {
	names := make([]string, 0, len(snap.PerTarget))
	for name := range snap.PerTarget {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, c := range promCounters {
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
		for _, name := range names {
			fmt.Fprintf(w, "%s{target=%q} %d\n", c.name, promLabelValue(name), c.get(snap.PerTarget[name]))
		}
	}

	if costPer1KTokens > 0 {
		fmt.Fprintln(w, "# HELP aiproxy_estimated_cost Estimated cost of tokens used so far, at the configured cost_per_1k_tokens rate.")
		fmt.Fprintln(w, "# TYPE aiproxy_estimated_cost counter")
		for _, name := range names {
			t := snap.PerTarget[name]
			fmt.Fprintf(w, "aiproxy_estimated_cost{target=%q} %g\n", promLabelValue(name), t.EstimatedCost(costPer1KTokens))
		}
	}

	ruleNames := make([]string, 0, len(snap.PerRule))
	for name := range snap.PerRule {
		ruleNames = append(ruleNames, name)
	}
	sort.Strings(ruleNames)

	for _, c := range promRuleCounters {
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
		for _, name := range ruleNames {
			fmt.Fprintf(w, "%s{rule=%q} %d\n", c.name, promLabelValue(name), c.get(snap.PerRule[name]))
		}
	}

	for _, c := range promDryRunCounters {
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
		fmt.Fprintf(w, "%s %d\n", c.name, c.get(snap))
	}

	// Unlabeled, same reasoning as promDryRunCounters: a rejected
	// request never gets far enough to resolve a target to label it
	// with.
	fmt.Fprintln(w, "# HELP aiproxy_unauthorized_total Total number of requests rejected for a missing or invalid Proxy-Authorization header.")
	fmt.Fprintln(w, "# TYPE aiproxy_unauthorized_total counter")
	fmt.Fprintf(w, "aiproxy_unauthorized_total %d\n", snap.Unauthorized)

	// Unlabeled too, but for a different reason than the series above: a
	// gauge, not a counter (the configured value doesn't accumulate),
	// and a single whole-proxy-run threshold rather than something with
	// a per-target or per-rule breakdown to begin with. Omitted entirely
	// when cost_budget isn't set, same as aiproxy_estimated_cost.
	if costBudget > 0 {
		fmt.Fprintln(w, "# HELP aiproxy_cost_budget Configured cost_budget threshold, in the same units as aiproxy_estimated_cost.")
		fmt.Fprintln(w, "# TYPE aiproxy_cost_budget gauge")
		fmt.Fprintf(w, "aiproxy_cost_budget %g\n", costBudget)
	}
}

// serveMetrics answers metricsPath with the current Stats snapshot in
// Prometheus's text exposition format. Like serveStats, it never
// touches rules, the rate limiter, or the cache, and a scrape is never
// itself counted in Stats.
func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writePromMetrics(w, s.Stats.Snapshot(), s.getCostPer1KTokens(), s.getCostBudget())
}

// Summary renders the current stats snapshot as the same block of text
// printed on shutdown, appending an estimated cost line only when
// CostPer1KTokens has been configured, and a cost budget line — flagged
// "(EXCEEDED)" once crossed — only when CostBudget has been configured.
func (s *Server) Summary() string {
	cost := s.getCostPer1KTokens()
	budget := s.getCostBudget()
	snap := s.Stats.Snapshot()
	summary := snap.String()
	if cost > 0 {
		summary += fmt.Sprintf("\nEstimated cost:      %.4f (at %g/1K tokens)", snap.EstimatedCost(cost), cost)
	}
	if budget > 0 {
		line := fmt.Sprintf("\nCost budget:         %.4f", budget)
		if snap.EstimatedCost(cost) >= budget {
			line += " (EXCEEDED)"
		}
		summary += line
	}
	if breakdown := snap.PerTargetString(cost); breakdown != "" {
		summary += "\n" + breakdown
	}
	if breakdown := snap.PerRuleString(); breakdown != "" {
		summary += "\n" + breakdown
	}
	return summary
}

// logSummary logs the shutdown summary in whichever LogFormat is
// configured: Summary()'s multi-line text block for LogFormatText, or
// the same data as a single JSON line (the same shape GET /_aiproxy/stats
// serves) for LogFormatJSON — a multi-line block would otherwise break
// the guarantee that every line is valid JSON in that mode.
func (s *Server) logSummary() {
	if s.LogFormat == LogFormatJSON {
		payload := withCostBudget(toStatsSnapshotJSON(s.Stats.Snapshot(), s.getCostPer1KTokens()), s.getCostBudget())
		data, err := json.Marshal(payload)
		if err != nil {
			s.logError("aiproxy: summary: failed to encode: %v", err)
			return
		}
		s.logf("%s", data)
		return
	}
	s.logf("%s", s.Summary())
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
		err := s.httpServer.Shutdown(shutdownCtx)
		s.logSummary()
		return err
	case err := <-errCh:
		return fmt.Errorf("proxy: %w", err)
	}
}
