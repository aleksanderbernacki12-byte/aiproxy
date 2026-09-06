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
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
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
// ReloadConfig instead, which swaps all five together under a lock — the
// mutex below exists only to make that later swap race-free against
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
	Time    string `json:"time"`
	Level   string `json:"level"`
	Method  string `json:"method,omitempty"`
	URL     string `json:"url,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Tokens  int    `json:"tokens,omitempty"`
	Message string `json:"message,omitempty"`
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

// getEngine, getCache, and getCostPer1KTokens are small locked accessors
// for the fields ReloadConfig can change at runtime, used everywhere
// they're read outside of resolveRoute (which takes the same lock
// itself, for Limiter and the route table).
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
// cost-per-1K-tokens rate, and target routes — e.g. after re-reading
// aiproxy.json on SIGHUP. All five change together under one lock, so a
// request in flight never observes a torn mix of old and new
// configuration; a request takes effect from the moment it's accepted,
// so anything already being handled keeps running against whatever
// configuration it started with. Pass nil for limiter/cache to disable
// them, matching how the corresponding field would be set at startup.
func (s *Server) ReloadConfig(engine *rules.Engine, lim *limiter.Limiter, cch *cache.Cache, costPer1KTokens float64, routes []Route) {
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

// ServeHTTP implements http.Handler. It reads the full request body into
// memory so the rule engine can inspect it in cleartext, evaluates the
// request, and either blocks it or restores the body and forwards it
// intact to the resolved target (Target by default, or a path-prefix
// route added via AddRoute) over HTTPS.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == statsPath {
		s.serveStats(w, r)
		return
	}

	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
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

	action, ruleName, evaluatedBody, err := s.getEngine().Evaluate(rules.Request{
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
		s.Stats.RecordBlock(targetLabel)
		s.logBlock(r.Method, r.URL.String(), ruleName)
		http.Error(w, "blocked by aiproxy rules", http.StatusForbidden)
		return
	}

	if effectiveLimiter != nil && !effectiveLimiter.Allow() {
		s.Stats.RecordRateLimited(targetLabel)
		s.logRateLimited(r.Method, r.URL.String())
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// evaluatedBody is body unchanged unless action is Redact, in which
	// case it has the matched secret masked out — forwarded either way,
	// so the client's request only ever fails on Block above.
	r.Body = io.NopCloser(bytes.NewReader(evaluatedBody))
	r.ContentLength = int64(len(evaluatedBody))
	if action == rules.Redact {
		s.Stats.RecordRedact(targetLabel)
		s.logRedact(r.Method, r.URL.String(), ruleName)
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

// bufferResponse reads the full response body into memory so it can look
// for an LLM-style token usage payload and, if caching is enabled, store
// the response for future identical requests. It immediately restores
// the body so the client still receives it intact — whether or not the
// body turned out to be parseable JSON.
func (s *Server) bufferResponse(resp *http.Response, reqCtx requestContextInfo) error {
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
// arrives from upstream, while a copy of every byte is accumulated on
// the side. Once the stream ends, ReverseProxy closes the body, which
// triggers usage extraction and — for a clean, complete stream on a 200
// response — a cache write, both from the accumulated copy.
func (s *Server) streamResponse(resp *http.Response, reqCtx requestContextInfo) {
	statusCode := resp.StatusCode
	header := resp.Header

	resp.Body = &streamTee{
		src: resp.Body,
		onComplete: func(data []byte, cleanEOF bool) {
			// Cache first, log second: a caller that observes the log
			// line (e.g. a test synchronizing on it) can then rely on the
			// cache write having already landed.
			if cch := s.getCache(); cleanEOF && cch != nil && statusCode == http.StatusOK && reqCtx.cacheKey != "" {
				s.writeStreamToCache(cch, reqCtx.cacheKey, statusCode, header, data)
			}
			s.logUsageFromBody(reqCtx, data)
		},
	}
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

// streamTee lets a streaming response body be read normally (so
// ReverseProxy can copy it straight through to the client) while every
// byte read is also captured. onComplete runs exactly once, when the
// stream is closed, with the full accumulated data and whether the
// stream ended cleanly (io.EOF) rather than by some other read error.
type streamTee struct {
	src        io.ReadCloser
	buf        bytes.Buffer
	cleanEOF   bool
	onComplete func(data []byte, cleanEOF bool)
	once       sync.Once
}

func (t *streamTee) Read(p []byte) (int, error) {
	n, err := t.src.Read(p)
	if n > 0 {
		t.buf.Write(p[:n])
	}
	if err == io.EOF {
		t.cleanEOF = true
	}
	return n, err
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

// extractTotalTokens looks for a usage.total_tokens field in body. It
// handles both a plain JSON response and an SSE stream of "data: {...}"
// events (as OpenAI-style streaming chat completions send when usage
// reporting is requested), returning the last positive value found —
// streamed usage arrives in the final chunk before "data: [DONE]".
func extractTotalTokens(body []byte) int {
	if tokens, ok := tryUnmarshalUsage(body); ok {
		return tokens
	}

	best := 0
	for _, line := range bytes.Split(body, []byte("\n")) {
		payload, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:"))
		if !ok {
			continue
		}
		payload = bytes.TrimSpace(payload)
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		if tokens, ok := tryUnmarshalUsage(payload); ok {
			best = tokens
		}
	}
	return best
}

func tryUnmarshalUsage(data []byte) (int, bool) {
	var usage llmUsageResponse
	if err := json.Unmarshal(data, &usage); err != nil || usage.Usage.TotalTokens <= 0 {
		return 0, false
	}
	return usage.Usage.TotalTokens, true
}

func (s *Server) logUsageFromBody(reqCtx requestContextInfo, body []byte) {
	if tokens := extractTotalTokens(body); tokens > 0 {
		s.Stats.RecordTokensUsed(reqCtx.targetLabel, tokens)
		s.logUsage(reqCtx.method, reqCtx.url, tokens)
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
	Allowed       int64                        `json:"allowed"`
	Blocked       int64                        `json:"blocked"`
	Redacted      int64                        `json:"redacted"`
	RateLimited   int64                        `json:"rate_limited"`
	CacheHits     int64                        `json:"cache_hits"`
	TotalTokens   int64                        `json:"total_tokens"`
	EstimatedCost *float64                     `json:"estimated_cost,omitempty"`
	PerTarget     map[string]statsSnapshotJSON `json:"per_target,omitempty"`
}

func toStatsSnapshotJSON(snap stats.Snapshot, costPer1KTokens float64) statsSnapshotJSON {
	out := statsSnapshotJSON{
		Allowed:     snap.Allowed,
		Blocked:     snap.Blocked,
		Redacted:    snap.Redacted,
		RateLimited: snap.RateLimited,
		CacheHits:   snap.CacheHits,
		TotalTokens: snap.TotalTokens,
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
	payload := toStatsSnapshotJSON(s.Stats.Snapshot(), s.getCostPer1KTokens())
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logError("aiproxy: stats: failed to encode response: %v", err)
	}
}

// Summary renders the current stats snapshot as the same block of text
// printed on shutdown, appending an estimated cost line only when
// CostPer1KTokens has been configured.
func (s *Server) Summary() string {
	cost := s.getCostPer1KTokens()
	snap := s.Stats.Snapshot()
	summary := snap.String()
	if cost > 0 {
		summary += fmt.Sprintf("\nEstimated cost:      %.4f (at %g/1K tokens)", snap.EstimatedCost(cost), cost)
	}
	if breakdown := snap.PerTargetString(cost); breakdown != "" {
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
		payload := toStatsSnapshotJSON(s.Stats.Snapshot(), s.getCostPer1KTokens())
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
