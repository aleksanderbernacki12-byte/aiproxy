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
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"aiproxy/internal/anomaly"
	"aiproxy/internal/auditlog"
	"aiproxy/internal/breaker"
	"aiproxy/internal/cache"
	"aiproxy/internal/geoip"
	"aiproxy/internal/limiter"
	"aiproxy/internal/rules"
	"aiproxy/internal/stats"
)

// ANSI escape codes for structured, color-coded proxy logging. These are
// the standard terminal codes understood by virtually every terminal
// emulator; no external logging framework is used.
const (
	ansiReset        = "\x1b[0m"
	ansiGreen        = "\x1b[32m"
	ansiBrightRed    = "\x1b[91m"
	ansiYellow       = "\x1b[33m"
	ansiBlue         = "\x1b[34m"
	ansiPurple       = "\x1b[35m"
	ansiCyan         = "\x1b[36m"
	ansiGray         = "\x1b[90m"
	ansiBrightYellow = "\x1b[93m"
	ansiDim          = "\x1b[2m"
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
	targets     []*url.URL
	forwardPath string
	targetLabel string

	// clientLabel is the authenticated proxy key's attribution label —
	// "default" for the anonymous Server.ProxyAPIKey, a named
	// Server.ProxyAPIKeys entry's Name, or "" when no key is configured
	// at all — carried through to modifyResponse so token usage
	// extracted from the response can be attributed the same way
	// requests already are; see checkProxyAuth/clientAuth.
	clientLabel string

	// clientCostBudget is the authenticated key's own CostBudget (zero
	// if it has none, or if clientLabel is "" or "default" — the
	// anonymous top-level ProxyAPIKey has no per-key fields to source
	// one from) — carried through to logUsageFromBody the same way
	// clientLabel is, for stats.Stats.CrossedClientBudget.
	clientCostBudget float64

	// tokenLimiter is the effective token-based rate limiter for this
	// request (the authenticated key's own, else the resolved route's,
	// else the server-wide one — see ServeHTTP), carried through to
	// logUsageFromBody so its Add can record this request's actual
	// usage the moment it's known, from the upstream response. nil
	// means no token-based breaker applies to this request at all.
	tokenLimiter *limiter.TokenLimiter

	// latency, if non-nil, is written by failoverTransport.RoundTrip the
	// moment a response actually comes back (successfully, from
	// whichever candidate) and read back by modifyResponse to log a
	// per-request latency line — a pointer, not a plain field, so the
	// same allocation set up in ServeHTTP is shared with whatever
	// modifyResponse later reads through resp.Request's (identical)
	// context, rather than each holding its own independent copy of the
	// (still-zero, at ServeHTTP's point) value.
	latency *time.Duration
}

// route is one path-prefix-to-upstream mapping for multi-target routing.
// targets is always non-empty; more than one entry means the route
// fails over across them in order — see failoverTransport. limiter is
// nil unless this route was given its own dedicated rate limit, in
// which case it applies instead of the server-wide Limiter for this
// route's traffic only.
type route struct {
	prefix       string
	targets      []*url.URL
	limiter      *limiter.Limiter
	tokenLimiter *limiter.TokenLimiter
}

// modelRoute is one model-name-to-upstream mapping for content-based
// routing (see resolveModelRoute). targets and limiter behave exactly
// like route's fields; models is a non-empty list of path.Match glob
// patterns checked, in order, against the request body's "model" field.
type modelRoute struct {
	name         string
	models       []string
	targets      []*url.URL
	limiter      *limiter.Limiter
	tokenLimiter *limiter.TokenLimiter
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

// cacheClearPath is a third reserved, proxy-internal path: a POST here
// deletes every entry from the response cache right now, without a
// restart — the manual counterpart to cache_ttl_seconds' automatic
// expiry, and the only way to evict anything at all when no TTL is
// configured. POST, not GET like statsPath/metricsPath, since this one
// actually mutates state rather than just reading it.
const cacheClearPath = "/_aiproxy/cache/clear"

// dashboardPath is a fourth reserved, proxy-internal path: a GET here
// returns a small, self-contained HTML page that polls statsPath in
// the browser and renders it as a live-updating table, for a
// zero-setup visual glance at a running proxy without building any
// separate tooling. Gated by IP allow/deny lists and proxy
// authentication exactly like statsPath/metricsPath — no exception:
// this page's own background fetch to statsPath from the browser is
// subject to the exact same check, so in a proxy_api_key-gated setup a
// browser (which can't attach a custom header to a plain navigation)
// simply can't load usable data here — curl or the Prometheus endpoint
// remain the answer for that case. Confirmed via a real browser
// (Chromium): a 407 response is actually worse than "can't attach the
// header" — the browser intercepts it at the network stack itself,
// since that status is conventionally reserved for the browser's own
// configured forward proxy rather than an origin server's own
// response, so fetch() never even delivers a Response object for it,
// just a generic network failure. The dashboard's own error handling
// accounts for this. See serveDashboard, dashboard.go.
const dashboardPath = "/_aiproxy/dashboard"

// healthzPath is a fifth reserved, proxy-internal path — and the one
// deliberate exception to every other reserved path's rule: it is
// NEVER gated by ip_allow_list/ip_deny_list or proxy_api_key, checked
// before even those. Every other reserved path (statsPath, metricsPath,
// dashboardPath, cacheClearPath) is fully gated because it exposes real
// operational data (token counts, rule/client names, cache contents);
// healthzPath exposes nothing at all beyond "this process accepted the
// TCP connection and its HTTP server is responsive" — information a
// caller already has the instant the connection itself succeeds or
// fails, auth or no auth. That's also exactly the plain liveness/
// readiness signal a Docker HEALTHCHECK or Kubernetes httpGet probe
// needs, and neither can generally attach a Proxy-Authorization header
// or be restricted to an allow-listed IP without real orchestration
// friction — gating this path would make container health checks
// either impossible or require punching a hole in ip_allow_list
// specifically for the orchestrator, which is strictly worse. Always
// reports healthy: it never depends on --target/a model route's
// upstream being reachable (that's what failover/the circuit breaker
// exist to handle gracefully, not something aiproxy's own liveness
// should flap on) or on any other configured dependency. Never counted
// in Stats or logged, same as every other reserved path — but unlike
// them, deliberately silent even in that sense, since health probes
// fire far more often than a human would ever want in a log stream.
const healthzPath = "/_aiproxy/healthz"

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
	mu      sync.RWMutex
	Engine  *rules.Engine
	Limiter *limiter.Limiter // nil disables the circuit breaker

	// TokenLimiter is a second, orthogonal circuit breaker keyed on
	// upstream response tokens actually used within a rolling minute,
	// instead of Limiter's plain request count — see
	// limiter.TokenLimiter. nil disables it entirely. Resolved with the
	// same precedence as Limiter: a route/model route's own TokenLimiter
	// (if any) or a ProxyKey's own (if any, taking priority over both)
	// override this server-wide one for their own traffic.
	TokenLimiter *limiter.TokenLimiter

	// AnomalyDetector, if non-nil, flags a named client (see
	// clientAuth.label) whose current minute's request count has
	// reached its own configured multiple of that client's own recent
	// baseline — a relative complement to Limiter/TokenLimiter's fixed,
	// absolute thresholds. nil (the default, whenever
	// anomaly_multiplier isn't configured) skips this check entirely.
	// Server-wide only, unlike Limiter/TokenLimiter: a caller's own
	// traffic pattern isn't a function of which route it happened to
	// hit, so there's no per-route/per-key override to resolve here.
	AnomalyDetector *anomaly.Registry

	// AnomalyDryRun, if true, makes AnomalyDetector only report what it
	// would have done (log, webhook, stats) without actually rejecting
	// anything — the same escape hatch a custom rule's own DryRun
	// gives, since a statistical threshold is inherently more prone to
	// a false positive than an exact pattern match.
	AnomalyDryRun bool

	// UpstreamTransport performs the actual dial/TLS/request/response
	// round trip to whichever upstream candidate failoverTransport hands
	// it — built via NewUpstreamTransport from a clone of
	// http.DefaultTransport (preserving its connection pooling, dialer,
	// and TLS defaults) with only ResponseHeaderTimeout overridden. Set
	// once at construction (see New) and swappable via ReloadConfig like
	// every other field above; failoverTransport reads it fresh on every
	// RoundTrip rather than capturing it once, so a reload's new timeout
	// takes effect starting with the very next request. Never nil.
	UpstreamTransport *http.Transport

	// UpstreamTotalTimeout, if greater than zero, caps a forwarded
	// request's entire round trip — connecting, headers, and reading the
	// complete response or stream, across every failover candidate tried
	// for it — at this duration, via a context.WithTimeout wrapping the
	// request passed to UpstreamTransport. Unlike
	// UpstreamTransport.ResponseHeaderTimeout, this can cut off a
	// legitimately long-running streaming completion that's actively
	// sending data — see UpstreamTotalTimeoutSeconds's doc comment in the
	// config package for the full tradeoff. Zero (the default) means no
	// limit.
	UpstreamTotalTimeout time.Duration

	// TargetBreaker, if non-nil, tracks each candidate upstream URL's own
	// consecutive transport-level failures and, once one crosses its
	// configured threshold, temporarily deprioritizes it in favor of a
	// healthier candidate — see the breaker package and
	// failoverTransport.RoundTrip. It never refuses to genuinely attempt
	// an ejected target when there's no healthier candidate to try
	// instead (a single-target route, or every candidate currently
	// ejected) — ejection only ever helps skip ahead to a better option
	// when one exists. nil (the default, whenever
	// target_ejection_threshold isn't configured) disables this
	// entirely, the exact behavior aiproxy had before this feature
	// existed.
	TargetBreaker *breaker.Registry

	Cache           *cache.Cache // nil disables the response cache
	CostPer1KTokens float64      // zero omits the shutdown summary's cost line
	routes          []route
	modelRoutes     []modelRoute

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

	// Webhooks lists additional webhook destinations beyond WebhookURL,
	// each with its own optional filter of which event names it wants —
	// see deliverWebhookPayload and WebhookTarget.matches. WebhookURL, if
	// set, is still notified of every event exactly as before this field
	// existed; entries here are additional, useful for routing a
	// specific event (e.g. budget_exceeded) to a different destination
	// than the general block/redact stream. nil/empty (the default)
	// means WebhookURL alone is the only destination.
	Webhooks []WebhookTarget

	// IPAllowList, if non-empty, restricts which client IPs may reach
	// the proxy at all — checked before ProxyAPIKey or anything else,
	// as the very first thing ServeHTTP does; see checkIPAccess. A deny
	// match in IPDenyList always wins over an allow match here. Empty
	// (the default) means every source IP is allowed, unless
	// IPDenyList itself denies it.
	IPAllowList []*net.IPNet

	// IPDenyList unconditionally rejects any request whose remote IP
	// matches an entry here, regardless of IPAllowList — see
	// checkIPAccess. Empty (the default) denies nothing.
	IPDenyList []*net.IPNet

	// GeoIPTable resolves a client IP to its country code, for
	// CountryAllowList/CountryDenyList — nil (the default, whenever
	// geoip_ranges_file isn't configured) skips the country check
	// entirely, same zero-cost-when-unused discipline as IPAllowList/
	// IPDenyList both being empty.
	GeoIPTable *geoip.Table

	// CountryAllowList/CountryDenyList restrict which client countries
	// may reach the proxy, resolved via GeoIPTable — checked right
	// after IPAllowList/IPDenyList, independently of it: a request
	// must pass both checks; see checkCountryAccess.
	CountryAllowList []string
	CountryDenyList  []string

	// ProxyAPIKey, if non-empty, requires every request — including
	// GET /_aiproxy/stats and /_aiproxy/metrics — to present it as a
	// "Proxy-Authorization: Bearer <key>" header before ServeHTTP does
	// anything else with it; see checkProxyAuth. Empty (the default)
	// disables the check entirely.
	ProxyAPIKey string

	// ProxyAPIKeys lists additional named keys beyond ProxyAPIKey, each
	// checked the same constant-time way. A request authenticated with
	// one of these is attributed, in stats and logs, to that key's Name
	// instead of ProxyAPIKey's anonymous "default" label — see
	// checkProxyAuth and clientAuth. A key with its own Limiter takes
	// precedence over whatever route or the server-wide Limiter would
	// otherwise apply for that request: a caller's own budget is
	// authoritative regardless of which route they hit. nil/empty (the
	// default) means ProxyAPIKey alone (if set) is the only key.
	ProxyAPIKeys []ProxyKey

	// TLSCertFile and TLSKeyFile, if both set, make ListenAndServe
	// terminate TLS itself — a PEM certificate and private key file,
	// loaded once at startup — instead of listening on plain HTTP.
	// Relevant when aiproxy needs to be reachable directly over a
	// network rather than only from localhost or a same-host sidecar,
	// where plain HTTP is normally fine. Both empty (the default) means
	// plain HTTP, unchanged from before this feature existed; the cli
	// package's flag parsing rejects setting exactly one without the
	// other before either ever reaches here. Not hot-reloadable via
	// SIGHUP — unlike every other tunable in this struct, rebinding a
	// listener's TLS configuration live is a meaningfully different (and
	// riskier) operation than swapping the fields ReloadConfig already
	// covers, and a renewed certificate on disk needs a process restart
	// to take effect, the same limitation a plain `http.Server` has.
	TLSCertFile string
	TLSKeyFile  string

	// AdminAddr, if non-empty, moves the whole admin surface — statsPath,
	// metricsPath, dashboardPath, cacheClearPath — onto a second listener
	// bound to this address instead of Addr: ListenAndServe starts a
	// second http.Server for it, serving nothing but that surface (see
	// adminMux), gated by exactly the same IPAllowList/IPDenyList/
	// CountryAllowList/CountryDenyList/ProxyAPIKey checks as ever —
	// moving where the admin surface is reachable from doesn't change
	// what's required to reach it. healthzPath is deliberately NOT moved:
	// it stays reachable on Addr unconditionally (an orchestrator's
	// liveness probe targets the same port the service actually listens
	// on) and is additionally served on AdminAddr too, for an operator
	// who'd rather probe the admin listener instead. Once AdminAddr is
	// set, Addr no longer serves the admin surface at all — a request for
	// one of those paths there gets a plain 404, never silently forwarded
	// upstream, since these paths were always reserved specifically to
	// never collide with a real upstream route. Empty (the default) means
	// everything is served on Addr alone, unchanged from before this
	// field existed. CLI-only, not hot-reloadable via SIGHUP — same
	// reasoning as TLSCertFile/TLSKeyFile: binding a second listener is a
	// process-level operation a live config swap was never meant to
	// cover.
	AdminAddr string

	// LogFile, if non-nil, is an open, append-mode file every log event
	// (including the shutdown summary) is also written to as one JSON
	// line, independent of LogFormat — see recordLogEvent. Opening,
	// reopening on reload, and closing the previous handle are the
	// caller's responsibility (see the cli package's openLogFile); a
	// write failure is reported once via logError and otherwise ignored,
	// same discipline as a webhook delivery failure.
	LogFile *os.File

	// logFileMu serializes writes to LogFile — separate from mu (which
	// guards ReloadConfig's swaps) because this lock is held only for
	// the duration of a single append, from any request-handling
	// goroutine, far more often than a reload ever runs.
	logFileMu sync.Mutex

	// AuditChain, if non-nil, HMAC-chains every line appended to
	// LogFile — see auditlog.Chain — so a later edit, deletion, or
	// reordering of historical lines is detectable with `aiproxy
	// verify-log` and the same key. Set once at startup from
	// -audit-log-key-file (see the cli package) and never touched by
	// ReloadConfig: changing the signing key live is a meaningfully
	// different, riskier operation than the atomic field swaps
	// ReloadConfig already does for everything else, the same
	// reasoning as TLSCertFile/TLSKeyFile above. appendToLogFile calls
	// Chain.Wrap itself, while holding logFileMu — Chain is not safe
	// for concurrent use on its own (see its doc comment), so chaining
	// and the write it produces must happen inside the same critical
	// section.
	AuditChain *auditlog.Chain

	reverseProxy    *httputil.ReverseProxy
	httpServer      *http.Server
	adminHTTPServer *http.Server
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
	Cost   float64 `json:"cost,omitempty"`
	Budget float64 `json:"budget,omitempty"`

	// Client is set on a budget_exceeded event fired by a named proxy
	// key's own cost_budget (see stats.Stats.CrossedClientBudget) —
	// empty for the server-wide cost_budget's own budget_exceeded
	// event, which isn't attributable to any one caller — and always
	// set on an anomaly_detected event, which is never attributable to
	// anything else.
	Client string `json:"client,omitempty"`

	// Rate and Baseline are only set on an anomaly_detected event: the
	// flagged client's own current window's request count, and the
	// established baseline (an exponential moving average of its own
	// past per-minute counts) it was compared against — see the
	// anomaly package. Baseline is a pointer, not a plain float64: a
	// client whose very first window was genuinely idle (0 requests)
	// can have a real, meaningful baseline of exactly 0 — the same
	// "don't let omitempty eat a real zero" reasoning as
	// DurationMS on the latency event.
	Rate     int      `json:"rate,omitempty"`
	Baseline *float64 `json:"baseline,omitempty"`

	// RemoteIP is only set on an ip_denied or country_denied event: the
	// request's own r.RemoteAddr, denied by checkIPAccess/
	// checkCountryAccess before anything else about the request
	// (including proxy auth) was even evaluated.
	RemoteIP string `json:"remote_ip,omitempty"`

	// Country is only set on a country_denied event: the resolved
	// country code RemoteIP was denied for, or empty when it couldn't
	// be resolved at all (still a deny — see checkCountryAccess).
	Country string `json:"country,omitempty"`

	// FailedTarget and NextTarget are only set on a failover event: the
	// candidate URL that just turned out to be unreachable, and the one
	// being tried next.
	FailedTarget string `json:"failed_target,omitempty"`
	NextTarget   string `json:"next_target,omitempty"`

	// Target is only set on a target_ejected or target_recovered event:
	// the one candidate upstream URL that just crossed its
	// consecutive-failure threshold, or recovered afterward — see the
	// breaker package. A separate field from FailedTarget/NextTarget
	// (rather than reusing FailedTarget) since "failed" would be a
	// misleading label on a target_recovered event.
	Target string `json:"target,omitempty"`

	// DurationMS is only set on a latency event: how long, in
	// milliseconds, the upstream took to respond to this one request —
	// see logLatency. Distinct from the aggregate histogram at
	// /_aiproxy/metrics/GET /_aiproxy/stats: this is the same
	// measurement, but attributable to one specific request in the log
	// stream, so a single slow call is visible without polling stats. A
	// pointer, not a plain int64: a genuinely fast local request can
	// round down to 0ms, and that's a real, meaningful measurement, not
	// the same thing as the field being absent — omitempty on a bare
	// int64 would incorrectly drop it in exactly that case.
	DurationMS *int64 `json:"duration_ms,omitempty"`

	// AgeSeconds and Stale are only set on a cache_hit event: how many
	// seconds old the served entry was (see cache.Cache.Get), and
	// whether that age had already crossed cache.Cache.IsStale's warning
	// threshold — never a reason to treat the hit as a miss, purely
	// informational, the same "still genuinely served" semantics
	// IsStale's own doc comment describes. AgeSeconds is a pointer, not
	// a plain int, for the same reason DurationMS is: an entry served
	// the instant after being cached has a real, meaningful age of
	// exactly 0, not the same thing as the field being absent.
	AgeSeconds *int `json:"age_seconds,omitempty"`
	Stale      bool `json:"stale,omitempty"`

	Message string `json:"message,omitempty"`
}

// New creates a Server that listens on addr, forwards allowed requests to
// target over HTTPS by default, and enforces engine on every request.
func New(addr string, target *url.URL, engine *rules.Engine) *Server {
	s := &Server{
		Addr:              addr,
		Target:            target,
		Engine:            engine,
		Logger:            log.Default(),
		Stats:             stats.New(),
		UpstreamTransport: NewUpstreamTransport(0),
	}

	s.reverseProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// ServeHTTP already resolved routing once (to compute the
			// cache key) and stashed the result in the context that
			// r.Clone carries through to pr.In; reuse it verbatim so
			// forwarding can never disagree with what was cache-keyed.
			// The rewrite always points at the first (primary) candidate
			// — failoverTransport is what tries the rest, further down
			// the pipeline, if that one turns out to be unreachable.
			reqCtx, _ := pr.In.Context().Value(requestContextKey{}).(requestContextInfo)
			target := s.Target
			if len(reqCtx.targets) > 0 {
				target = reqCtx.targets[0]
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
		Transport:     &failoverTransport{server: s},
	}

	return s
}

// failoverTransport wraps a base http.RoundTripper to retry a request
// against each of the resolved route's candidate target URLs in order
// (see requestContextInfo.targets), stopping at the first one that
// returns any response at all. It only retries on a transport-level
// failure — a dial/TLS/timeout error meaning the candidate was never
// actually reached — never on an HTTP-level error response (a 5xx): by
// the time a backend has responded at all, it may already have started
// acting on the request, and blindly replaying that against a different
// backend risks a duplicate side effect (a duplicate, possibly billed,
// LLM call being the textbook case for this proxy). A single-candidate
// target — every route before this feature existed, and still the
// overwhelmingly common case — costs nothing extra: the loop just runs
// once, exactly as ReverseProxy would have called base directly.
type failoverTransport struct {
	server *Server
}

// cancelOnCloseBody wraps a response body so closing it also cancels an
// associated context.CancelFunc — how failoverTransport releases the
// per-request context.WithTimeout backing UpstreamTotalTimeout as soon
// as the caller is done with the response, rather than only when the
// timeout itself eventually fires. Safe to call cancel more than once
// (context.CancelFunc always is), so an early transport-level error
// path calling it directly and this Close both firing is never a
// problem.
type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelOnCloseBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}

func (t *failoverTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqCtx, _ := req.Context().Value(requestContextKey{}).(requestContextInfo)
	candidates := reqCtx.targets
	start := time.Now()

	base, totalTimeout := t.server.getUpstreamConfig()
	var cancel context.CancelFunc
	if totalTimeout > 0 {
		var ctx context.Context
		ctx, cancel = context.WithTimeout(req.Context(), totalTimeout)
		req = req.WithContext(ctx)
	}
	// wrapBody ties cancel's lifetime to the response body the caller
	// actually reads and closes, so the context.WithTimeout backing
	// UpstreamTotalTimeout keeps running (and can still abort a stalled
	// read) for exactly as long as the body is open — never longer.
	wrapBody := func(resp *http.Response) *http.Response {
		if cancel != nil {
			resp.Body = cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}
		}
		return resp
	}

	tb := t.server.getTargetBreaker()

	if len(candidates) <= 1 {
		resp, err := base.RoundTrip(req)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			if tb != nil && len(candidates) == 1 {
				t.recordBreakerFailure(tb, candidates[0].String())
			}
			return nil, err
		}
		if tb != nil && len(candidates) == 1 {
			t.recordBreakerSuccess(tb, candidates[0].String())
		}
		t.recordLatency(reqCtx, time.Since(start))
		return wrapBody(resp), nil
	}

	orderedCandidates := candidates
	if tb != nil {
		orderedCandidates = healthOrdered(candidates, tb)
	}

	var lastErr error
	for i, candidate := range orderedCandidates {
		attempt := req
		if i > 0 || candidate != candidates[0] {
			// Either a later attempt (already needed a rebuilt URL/body
			// before failover existed at all), or breaker reordering
			// promoted a different candidate ahead of the one Rewrite
			// already pointed req at — either way, req's current URL no
			// longer matches the candidate this attempt is actually for.
			attempt = req.Clone(req.Context())
			attempt.URL = &url.URL{
				Scheme:   candidate.Scheme,
				Host:     candidate.Host,
				Path:     req.URL.Path,
				RawPath:  req.URL.RawPath,
				RawQuery: req.URL.RawQuery,
			}
			attempt.Host = candidate.Host
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					if cancel != nil {
						cancel()
					}
					return nil, err
				}
				attempt.Body = body
			}
		}

		resp, err := base.RoundTrip(attempt)
		if err == nil {
			if tb != nil {
				t.recordBreakerSuccess(tb, candidate.String())
			}
			// Deliberately timed from the very first attempt, not just
			// this successful one: retry time spent on an earlier
			// unreachable candidate is real latency the client
			// experienced for this request, and hiding it would make a
			// flaky target's histogram look healthier than it is.
			t.recordLatency(reqCtx, time.Since(start))
			return wrapBody(resp), nil
		}
		if tb != nil {
			t.recordBreakerFailure(tb, candidate.String())
		}
		lastErr = err

		if i+1 < len(orderedCandidates) {
			next := orderedCandidates[i+1]
			t.server.Stats.RecordFailover(reqCtx.targetLabel)
			t.server.logFailover(reqCtx.method, reqCtx.url, candidate.String(), next.String())
			t.server.notifyFailoverWebhook(reqCtx.method, reqCtx.url, candidate.String(), next.String())
		}
	}
	if cancel != nil {
		cancel()
	}
	return nil, lastErr
}

// healthOrdered returns candidates reordered so every currently
// non-ejected one comes first (preserving their original relative
// order), followed by every currently ejected one (also in original
// relative order) — never dropping a candidate, just deprioritizing a
// known-bad one in favor of trying a healthier one first. When every
// candidate is currently healthy, or every candidate is currently
// ejected, the original slice is returned unchanged: ejection only ever
// helps skip ahead to a better candidate, never stops a request from
// being genuinely attempted when there's no better option.
func healthOrdered(candidates []*url.URL, tb *breaker.Registry) []*url.URL {
	healthy := make([]*url.URL, 0, len(candidates))
	ejected := make([]*url.URL, 0, len(candidates))
	for _, c := range candidates {
		if tb.IsEjected(c.String()) {
			ejected = append(ejected, c)
		} else {
			healthy = append(healthy, c)
		}
	}
	if len(healthy) == 0 || len(ejected) == 0 {
		return candidates
	}
	return append(healthy, ejected...)
}

// recordBreakerFailure records a transport-level failure against
// target in tb and, exactly on the transition into ejected, reports it
// — a log line, a stats counter, and a webhook alert — the same
// single-fire-on-transition treatment every other breaker-like event in
// this package gets (see e.g. logAnomalyDetected).
func (t *failoverTransport) recordBreakerFailure(tb *breaker.Registry, target string) {
	if tb.RecordFailure(target) {
		t.server.Stats.RecordTargetEjected()
		t.server.logTargetEjected(target)
		t.server.notifyTargetEjectedWebhook(target)
	}
}

// recordBreakerSuccess records a success against target in tb and,
// exactly on the transition out of ejected, reports its recovery.
func (t *failoverTransport) recordBreakerSuccess(tb *breaker.Registry, target string) {
	if tb.RecordSuccess(target) {
		t.server.Stats.RecordTargetRecovered()
		t.server.logTargetRecovered(target)
		t.server.notifyTargetRecoveredWebhook(target)
	}
}

// recordLatency records d in both places a successful RoundTrip's
// timing needs to reach: the aggregate Stats histogram, and — via
// reqCtx.latency, if ServeHTTP set it up — the specific request's own
// context, for modifyResponse to log as a per-request line afterward.
func (t *failoverTransport) recordLatency(reqCtx requestContextInfo, d time.Duration) {
	t.server.Stats.RecordLatency(reqCtx.targetLabel, d)
	if reqCtx.latency != nil {
		*reqCtx.latency = d
	}
}

// AddRoute registers a path-prefix route: any request whose path starts
// with prefix is forwarded to the first URL in targets instead of the
// default Target, with the matched prefix stripped from the forwarded
// path (a request to prefix "/openai" and path "/openai/v1/chat"
// forwards with path "/v1/chat"). targets must be non-empty; a second
// (or later) entry is only ever used as a failover candidate, tried in
// order, if an earlier one is unreachable — see failoverTransport.
// Routes are checked in the order they were added; the first matching
// prefix wins, so add more specific prefixes before more general ones
// if they could overlap.
//
// lim, if non-nil, gives this route its own dedicated rate limit instead
// of sharing the server-wide Limiter with every other target — heavy
// traffic to one provider then can't throttle the others. Pass nil for a
// route that should just share whatever Limiter (if any) the server is
// configured with, same as every route did before per-target limits
// existed. tokenLim behaves the same way for TokenLimiter.
func (s *Server) AddRoute(prefix string, targets []*url.URL, lim *limiter.Limiter, tokenLim *limiter.TokenLimiter) {
	s.routes = append(s.routes, route{prefix: prefix, targets: targets, limiter: lim, tokenLimiter: tokenLim})
}

// resolveRoute matches path against the registered routes and returns
// the ordered list of candidate targets to forward to (always
// non-empty; more than one entry means failover across them) along with
// the path to forward it as (the matched prefix stripped, if any route
// matched), a label identifying the target for the per-target stats
// breakdown (the matched prefix, or "default" for the fallback Target),
// and the rate limiters that apply to this request: the matched route's
// own limiter/tokenLimiter if it has them, otherwise the server-wide
// Limiter/TokenLimiter (nil if those are unset too, meaning no limiting
// at all). It falls back to a single-element list holding the default
// Target, unmodified path, when nothing matches.
func (s *Server) resolveRoute(path string) (targets []*url.URL, forwardPath string, targetLabel string, lim *limiter.Limiter, tokenLim *limiter.TokenLimiter) {
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
			effectiveTokenLimiter := r.tokenLimiter
			if effectiveTokenLimiter == nil {
				effectiveTokenLimiter = s.TokenLimiter
			}
			return r.targets, stripped, r.prefix, effectiveLimiter, effectiveTokenLimiter
		}
	}
	return []*url.URL{s.Target}, path, "default", s.Limiter, s.TokenLimiter
}

// AddModelRoute registers a content-based route: any request whose
// body's top-level "model" field matches one of models (path.Match glob
// syntax) is forwarded to the first URL in targets instead, with the
// request's own path left completely unchanged — unlike AddRoute, there
// is no prefix to strip, since a model route is about *which* upstream
// gets the traffic, not *which URL space* the client used to ask for
// it. name identifies this route in stats/logs, prefixed with "model:"
// to keep it visually and collision-free distinct from a path prefix's
// own label. See resolveModelRoute for matching order and precedence
// over path-prefix routes. tokenLim behaves like AddRoute's own
// parameter of the same name.
func (s *Server) AddModelRoute(name string, models []string, targets []*url.URL, lim *limiter.Limiter, tokenLim *limiter.TokenLimiter) {
	s.modelRoutes = append(s.modelRoutes, modelRoute{name: name, models: models, targets: targets, limiter: lim, tokenLimiter: tokenLim})
}

// modelField pulls just the top-level "model" string out of a request
// body for resolveModelRoute — every other field is ignored, and a body
// that isn't a JSON object (or has no "model" field) simply resolves to
// an empty string, never an error.
type modelField struct {
	Model string `json:"model"`
}

// resolveModelRoute checks body's "model" field against every
// registered model route, in the order they were added, and returns the
// first match's candidate targets, stats/log label ("model:" plus the
// route's own name), and rate limiter. matched is false — and every
// other return value is a zero value — when no model route is
// registered at all, the body has no (or an unparseable) "model" field,
// or no registered route's patterns match it; the caller falls back to
// resolveRoute(path) in that case. Checked before path-prefix routing:
// a model route represents a deliberate, explicit routing decision by
// the operator, so when one is configured and matches, it takes
// priority over whatever path the client happened to use.
func (s *Server) resolveModelRoute(body []byte) (targets []*url.URL, label string, lim *limiter.Limiter, tokenLim *limiter.TokenLimiter, matched bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.modelRoutes) == 0 {
		return nil, "", nil, nil, false
	}

	var mf modelField
	if err := json.Unmarshal(body, &mf); err != nil || mf.Model == "" {
		return nil, "", nil, nil, false
	}

	for _, r := range s.modelRoutes {
		for _, pattern := range r.models {
			if ok, err := path.Match(pattern, mf.Model); err == nil && ok {
				return r.targets, "model:" + r.name, r.limiter, r.tokenLimiter, true
			}
		}
	}
	return nil, "", nil, nil, false
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

func (s *Server) getWebhooks() []WebhookTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Webhooks
}

// getProxyAPIKeys returns both ProxyAPIKey and ProxyAPIKeys under one
// lock, for checkProxyAuth.
func (s *Server) getProxyAPIKeys() (string, []ProxyKey) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ProxyAPIKey, s.ProxyAPIKeys
}

// getIPLists returns both IPAllowList and IPDenyList under one lock,
// for checkIPAccess.
func (s *Server) getIPLists() ([]*net.IPNet, []*net.IPNet) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.IPAllowList, s.IPDenyList
}

// clientIP extracts and parses the remote TCP peer's IP address from
// r.RemoteAddr — deliberately never a client-supplied header like
// X-Forwarded-For, which any caller could set to whatever value they
// want, defeating an IP allow/deny list entirely. Returns nil if
// RemoteAddr is empty or doesn't contain a parseable IP address (this
// package's own tests, and any real net/http server, always set a
// well-formed "host:port"; the plain-host fallback below only matters
// for a RemoteAddr set without a port, e.g. in a synthetic *http.Request
// built by hand).
func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// checkIPAccess reports whether r's remote IP is allowed to reach the
// proxy at all — the first check ServeHTTP makes, before proxy
// authentication or anything else. A match in IPDenyList always wins,
// even for an IP also covered by IPAllowList (useful for carving an
// exception out of a broader allow range). If IPAllowList is non-empty,
// the IP must match one of its entries too. Both lists empty (the
// default) means every IP is allowed, without even trying to parse
// RemoteAddr — the same zero-cost-when-unused discipline as every other
// optional check in this package. An IP that fails to parse is denied
// whenever either list is configured, since there's no way to evaluate
// it against either one.
func (s *Server) checkIPAccess(r *http.Request) bool {
	allow, deny := s.getIPLists()
	if len(allow) == 0 && len(deny) == 0 {
		return true
	}

	ip := clientIP(r)
	if ip == nil {
		return false
	}

	for _, n := range deny {
		if n.Contains(ip) {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, n := range allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// getGeoIPConfig returns GeoIPTable, CountryAllowList, and
// CountryDenyList under one lock, for checkCountryAccess.
func (s *Server) getGeoIPConfig() (*geoip.Table, []string, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.GeoIPTable, s.CountryAllowList, s.CountryDenyList
}

// getAnomalyConfig returns AnomalyDetector and AnomalyDryRun under one
// lock, for ServeHTTP's anomaly check.
func (s *Server) getAnomalyConfig() (*anomaly.Registry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AnomalyDetector, s.AnomalyDryRun
}

// getUpstreamConfig returns UpstreamTransport and UpstreamTotalTimeout
// under one lock, for failoverTransport.RoundTrip.
func (s *Server) getUpstreamConfig() (*http.Transport, time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.UpstreamTransport, s.UpstreamTotalTimeout
}

// getTargetBreaker returns TargetBreaker under lock, for
// failoverTransport.RoundTrip.
func (s *Server) getTargetBreaker() *breaker.Registry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.TargetBreaker
}

// NewUpstreamTransport builds the *http.Transport used for every
// forwarded request: a clone of http.DefaultTransport — preserving its
// connection pooling, dialer, and TLS defaults — with
// ResponseHeaderTimeout set to responseTimeout. Zero means unlimited,
// Go's own stdlib default and the behavior aiproxy has always had.
func NewUpstreamTransport(responseTimeout time.Duration) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = responseTimeout
	return t
}

// checkCountryAccess reports whether r's remote IP's resolved country
// is allowed to reach the proxy, and that resolved country (empty when
// it couldn't be resolved at all) for the caller to log — checked
// right after checkIPAccess, independently of it (see
// CountryAllowList's doc comment: a request must pass both checks,
// neither is an exemption from the other). Both lists empty (the
// default) means every country is allowed, without even resolving
// RemoteAddr's country — same zero-cost-when-unused discipline as
// checkIPAccess. A country deny match always wins, even for a country
// also covered by CountryAllowList, the same precedence checkIPAccess
// already uses between IPDenyList and IPAllowList. An IP whose country
// can't be resolved at all (nil GeoIPTable, an unparseable remote IP,
// or simply not covered by any range in the table) is denied whenever
// either list is configured, since there's no way to evaluate it
// against either one.
func (s *Server) checkCountryAccess(r *http.Request) (bool, string) {
	table, allow, deny := s.getGeoIPConfig()
	if len(allow) == 0 && len(deny) == 0 {
		return true, ""
	}

	var country string
	if table != nil {
		if ip := clientIP(r); ip != nil {
			country, _ = table.Country(ip)
		}
	}
	if country == "" {
		return false, ""
	}

	for _, c := range deny {
		if c == country {
			return false, country
		}
	}
	if len(allow) == 0 {
		return true, country
	}
	for _, c := range allow {
		if c == country {
			return true, country
		}
	}
	return false, country
}

func (s *Server) getLogFile() *os.File {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LogFile
}

// Route describes one path-prefix-to-upstream mapping for ReloadConfig,
// mirroring what AddRoute registers before the server starts serving.
// Targets must be non-empty; more than one entry means failover across
// them in order — see failoverTransport.
type Route struct {
	Prefix  string
	Targets []*url.URL
	// Limiter, if non-nil, gives this route its own dedicated rate
	// limit instead of sharing whatever Limiter ReloadConfig sets.
	Limiter *limiter.Limiter
	// TokenLimiter, if non-nil, gives this route its own dedicated
	// token-based rate limit instead of sharing whatever TokenLimiter
	// ReloadConfig sets.
	TokenLimiter *limiter.TokenLimiter
}

// ModelRoute describes one model-name-to-upstream mapping for
// ReloadConfig, mirroring what AddModelRoute registers before the
// server starts serving. Targets must be non-empty; Models must be
// non-empty. See resolveModelRoute for matching order and precedence
// over Route's path-prefix matching.
type ModelRoute struct {
	Name    string
	Models  []string
	Targets []*url.URL
	// Limiter, if non-nil, gives this route its own dedicated rate
	// limit instead of sharing whatever Limiter ReloadConfig sets.
	Limiter *limiter.Limiter
	// TokenLimiter, if non-nil, gives this route its own dedicated
	// token-based rate limit instead of sharing whatever TokenLimiter
	// ReloadConfig sets.
	TokenLimiter *limiter.TokenLimiter
}

// ReloadConfig atomically replaces the engine, rate limiter, cache,
// cost-per-1K-tokens rate, cost budget, max request body size, webhook
// alert URL, additional webhook destinations, proxy API key, additional
// named proxy keys, log file, path-prefix routes, model routes, and IP
// allow/deny lists — e.g. after re-reading aiproxy.json on SIGHUP. All
// of them change together under one lock,
// so a request in flight never observes a torn mix of old and new
// configuration; a request takes effect from the moment it's accepted,
// so anything already being handled keeps running against whatever
// configuration it started with. Pass nil for
// limiter/cache/webhookURL/webhooks/proxyAPIKeys/logFile to disable
// them, matching how the corresponding field would be set at startup;
// pass "" for proxyAPIKey to disable the anonymous key; pass zero for
// costBudget to disable the budget check, or maxBodyBytes to fall back
// to DefaultMaxBodyBytes, same as leaving Server.MaxBodyBytes unset.
//
// logFile is always swapped in, even if the caller reopened the exact
// same path — the caller (the cli package's reloadConfig) is expected
// to open a fresh handle on every call regardless, which is exactly
// what makes SIGHUP-driven log rotation work: a tool like logrotate
// renames the current file out of the way and signals the process, and
// the next reload's fresh handle creates a new file at that same path.
// The old handle, if any, is closed after the swap — never left open —
// so a long-running proxy reloaded repeatedly never leaks descriptors.
//
// tokenLim replaces the server-wide TokenLimiter the same way lim
// replaces Limiter; pass nil to disable it. Appended as the last
// parameter, after every field that existed before the token-based
// breaker did, rather than alongside lim, purely to keep every existing
// positional call site's argument order intact.
//
// geoIPTable/countryAllowList/countryDenyList replace GeoIPTable/
// CountryAllowList/CountryDenyList the same way ipAllowList/ipDenyList
// replace IPAllowList/IPDenyList; pass nil for geoIPTable and
// nil/empty for the two lists to disable country-based access control
// entirely. Also appended at the very end, same reasoning as tokenLim.
//
// anomalyDetector/anomalyDryRun replace AnomalyDetector/AnomalyDryRun
// wholesale — like lim/tokenLim, a reload always swaps in a brand new
// *anomaly.Registry (see cli.buildLiveConfig) rather than trying to
// preserve any client's already-accumulated baseline, the same
// cold-state-on-reload behavior Limiter/TokenLimiter already have.
// Pass nil for anomalyDetector to disable the breaker entirely. Also
// appended at the very end, same reasoning as tokenLim/geoIPTable.
//
// upstreamTransport/upstreamTotalTimeout replace UpstreamTransport/
// UpstreamTotalTimeout wholesale — upstreamTransport must never be nil
// (see NewUpstreamTransport; cli.buildLiveConfig always builds one, even
// when upstream_response_timeout_seconds is absent). Also appended at
// the very end, same reasoning as tokenLim/geoIPTable/anomalyDetector.
//
// targetBreaker replaces TargetBreaker wholesale — like anomalyDetector,
// a reload always swaps in a brand new *breaker.Registry (see
// cli.buildLiveConfig) rather than trying to preserve any target's
// already-accumulated failure/ejection state. Pass nil to disable
// target ejection entirely. Also appended at the very end, same
// reasoning as every other field above.
func (s *Server) ReloadConfig(engine *rules.Engine, lim *limiter.Limiter, cch *cache.Cache, costPer1KTokens, costBudget float64, maxBodyBytes int64, webhookURL *url.URL, webhooks []WebhookTarget, proxyAPIKey string, proxyAPIKeys []ProxyKey, logFile *os.File, routes []Route, modelRoutes []ModelRoute, ipAllowList, ipDenyList []*net.IPNet, tokenLim *limiter.TokenLimiter, geoIPTable *geoip.Table, countryAllowList, countryDenyList []string, anomalyDetector *anomaly.Registry, anomalyDryRun bool, upstreamTransport *http.Transport, upstreamTotalTimeout time.Duration, targetBreaker *breaker.Registry) {
	newRoutes := make([]route, len(routes))
	for i, r := range routes {
		newRoutes[i] = route{prefix: r.Prefix, targets: r.Targets, limiter: r.Limiter, tokenLimiter: r.TokenLimiter}
	}
	newModelRoutes := make([]modelRoute, len(modelRoutes))
	for i, r := range modelRoutes {
		newModelRoutes[i] = modelRoute{name: r.Name, models: r.Models, targets: r.Targets, limiter: r.Limiter, tokenLimiter: r.TokenLimiter}
	}

	s.mu.Lock()
	oldLogFile := s.LogFile
	s.Engine = engine
	s.Limiter = lim
	s.TokenLimiter = tokenLim
	s.Cache = cch
	s.CostPer1KTokens = costPer1KTokens
	s.CostBudget = costBudget
	s.MaxBodyBytes = maxBodyBytes
	s.WebhookURL = webhookURL
	s.Webhooks = webhooks
	s.ProxyAPIKey = proxyAPIKey
	s.ProxyAPIKeys = proxyAPIKeys
	s.LogFile = logFile
	s.routes = newRoutes
	s.modelRoutes = newModelRoutes
	s.IPAllowList = ipAllowList
	s.IPDenyList = ipDenyList
	s.GeoIPTable = geoIPTable
	s.CountryAllowList = countryAllowList
	s.CountryDenyList = countryDenyList
	s.AnomalyDetector = anomalyDetector
	s.AnomalyDryRun = anomalyDryRun
	s.UpstreamTransport = upstreamTransport
	s.UpstreamTotalTimeout = upstreamTotalTimeout
	s.TargetBreaker = targetBreaker
	s.mu.Unlock()

	if oldLogFile != nil {
		oldLogFile.Close()
	}
}

// LogEvent logs a one-off, non-request-scoped message from outside the
// proxy package — e.g. the CLI's SIGHUP reload handler reporting success
// or failure — through the same LogFormat-aware machinery as every other
// log line, so it can never break the "every line is valid JSON"
// guarantee under LogFormatJSON.
func (s *Server) LogEvent(level, message string) {
	ev := s.recordLogEvent(logEvent{Level: level, Message: message})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s", message)
}

// NotifyEvent delivers a minimal webhook alert for a one-off,
// non-request-scoped event from outside the proxy package — e.g. the
// CLI's SIGHUP reload handler reporting exactly what changed. No
// method/URL/rule, the same shape already used internally for an event
// with no one client request to attribute (see
// notifyTargetEjectedWebhook) — text becomes the payload's Text field
// verbatim. Exported for the same reason LogEvent already is.
func (s *Server) NotifyEvent(event, text string) {
	s.deliverWebhookPayload(webhookAlert{
		Text:  text,
		Event: event,
		Time:  time.Now().UTC().Format(time.RFC3339),
	})
}

// proxyAuthScheme is the credential scheme checkProxyAuth expects in the
// Proxy-Authorization header, matching how every LLM API in this
// project's own examples presents a bearer credential.
const proxyAuthScheme = "Bearer "

// ProxyKey is one resolved additional named entry in Server.ProxyAPIKeys.
type ProxyKey struct {
	// Name identifies this key in stats, logs, and webhook payloads —
	// never the key itself. Never "default", reserved for the anonymous
	// Server.ProxyAPIKey.
	Name string
	Key  string

	// Limiter, if non-nil, is this key's own dedicated rate limit,
	// checked instead of whatever route or the server-wide Limiter
	// would otherwise apply for a request authenticated with it.
	Limiter *limiter.Limiter

	// TokenLimiter, if non-nil, is this key's own dedicated token-based
	// rate limit, checked instead of whatever route or the server-wide
	// TokenLimiter would otherwise apply for a request authenticated
	// with it — same precedence Limiter already has.
	TokenLimiter *limiter.TokenLimiter

	// CostBudget, if greater than zero, is this key's own cost
	// threshold — see stats.Stats.CrossedClientBudget. Fires
	// independently of Server.CostBudget (the server-wide one) and of
	// every other key's own budget.
	CostBudget float64
}

// clientAuth is checkProxyAuth's result: which key (if any) matched,
// for attributing the request in stats/logs, and that key's own rate
// limit override, if it has one. The zero value means either the check
// is disabled entirely (no keys configured at all) or — impossible to
// tell apart from label alone, which is fine, since both cases mean
// "nothing to attribute" — never actually returned alongside ok=false.
type clientAuth struct {
	// label is "default" for the anonymous Server.ProxyAPIKey, a named
	// ProxyKey's Name, or "" when the auth check is disabled entirely
	// (nothing to attribute a request to).
	label        string
	limiter      *limiter.Limiter
	tokenLimiter *limiter.TokenLimiter
	costBudget   float64
}

// checkProxyAuth reports whether r is allowed to use the proxy at all,
// and if so, which key (if any) it authenticated with. True with a
// zero clientAuth if neither Server.ProxyAPIKey nor Server.ProxyAPIKeys
// is set (the check is disabled). Otherwise r must carry a
// "Proxy-Authorization: Bearer <key>" header matching Server.ProxyAPIKey
// or one of Server.ProxyAPIKeys — each compared in constant time so a
// wrong guess can't be narrowed down by response timing the way a plain
// == comparison could leak; checking multiple keys in a loop only ever
// reveals "how many keys are configured" to a caller who doesn't
// already hold a valid one, never anything about their guess.
func (s *Server) checkProxyAuth(r *http.Request) (clientAuth, bool) {
	proxyAPIKey, proxyAPIKeys := s.getProxyAPIKeys()
	if proxyAPIKey == "" && len(proxyAPIKeys) == 0 {
		return clientAuth{}, true
	}

	got := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(got, proxyAuthScheme) {
		return clientAuth{}, false
	}
	got = strings.TrimPrefix(got, proxyAuthScheme)
	gotBytes := []byte(got)

	if proxyAPIKey != "" && subtle.ConstantTimeCompare(gotBytes, []byte(proxyAPIKey)) == 1 {
		return clientAuth{label: "default"}, true
	}
	for _, k := range proxyAPIKeys {
		if subtle.ConstantTimeCompare(gotBytes, []byte(k.Key)) == 1 {
			return clientAuth{label: k.Name, limiter: k.Limiter, tokenLimiter: k.TokenLimiter, costBudget: k.CostBudget}, true
		}
	}
	return clientAuth{}, false
}

// errorResponse is the JSON body writeError sends when the client's
// Accept header explicitly asks for it — see acceptsJSON. Error is a
// stable, machine-readable identifier using the exact same vocabulary
// as every event name already used in log lines, webhook payloads, and
// stats (e.g. "block", "rate_limited", "unauthorized") rather than
// something invented specifically for this JSON shape. Message is the
// same human-readable text the plain-text body has always carried.
// Rule is set only on a "block" rejection — the matched rule's name,
// never the secret it matched.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Rule    string `json:"rule,omitempty"`
}

// acceptsJSON reports whether r's Accept header explicitly lists
// application/json with a non-zero quality value — not simply because a
// wildcard like "*/*" (curl's own default, sent even with no -H at all)
// or "application/*" would technically also match it. A plain curl
// request keeps getting the same plain-text error body it always has;
// a client that explicitly asks for JSON — virtually every JSON REST
// client, including every LLM provider SDK this proxy fronts — gets the
// new structured body instead. This is deliberately narrower than full
// RFC 7231 content negotiation (no wildcard matching, no comparing
// specificity against other offered types): the only question that
// matters here is "did this caller affirmatively ask for JSON," not
// "would JSON technically satisfy what it said it'd accept."
func acceptsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, entry := range strings.Split(accept, ",") {
		mediaType, params, _ := strings.Cut(strings.TrimSpace(entry), ";")
		if !strings.EqualFold(strings.TrimSpace(mediaType), "application/json") {
			continue
		}
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
			if ok && strings.EqualFold(strings.TrimSpace(name), "q") {
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
					q = parsed
				}
			}
		}
		if q > 0 {
			return true
		}
	}
	return false
}

// writeError writes message as the body of an HTTP error response with
// statusCode, in whichever format r's Accept header actually asked for
// — see acceptsJSON. code and rule become errorResponse's Error/Rule
// fields under JSON negotiation; under plain text, only message is ever
// sent, exactly as http.Error has always behaved.
func writeError(w http.ResponseWriter, r *http.Request, statusCode int, code, message, rule string) {
	if acceptsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(errorResponse{Error: code, Message: message, Rule: rule})
		return
	}
	http.Error(w, message, statusCode)
}

// writeResponseBlockedBody rewrites resp in place into a synthetic 403
// error body for a response-side rule match, with the same content
// negotiation as writeError (see acceptsJSON) — using resp.Request
// (Rewrite only ever changes the URL/Host, never the client's own
// headers, so this is still the original Accept header) since a
// ModifyResponse callback has no direct handle on the client-facing
// *http.Request the way ServeHTTP's own writeError calls do. Also fixes
// a latent pre-existing gap while it's here: the prior plain-text-only
// version never reset Content-Type at all, silently leaving whatever
// the real (now-replaced) upstream response body's Content-Type had
// been.
func writeResponseBlockedBody(resp *http.Response, message string) {
	var body []byte
	contentType := "text/plain; charset=utf-8"
	if resp.Request != nil && acceptsJSON(resp.Request) {
		encoded, err := json.Marshal(errorResponse{Error: "response_block", Message: message})
		if err == nil {
			body = encoded
			contentType = "application/json; charset=utf-8"
		}
	}
	if body == nil {
		body = []byte(message)
	}
	resp.StatusCode = http.StatusForbidden
	resp.Status = http.StatusText(http.StatusForbidden)
	resp.Header.Set("Content-Type", contentType)
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.ContentLength = int64(len(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
}

// ServeHTTP implements http.Handler. It reads the full request body into
// memory (rejecting it with a 413 past MaxBodyBytes, before any of it is
// buffered) so the rule engine can inspect it in cleartext, evaluates
// the request, and either blocks it or restores the body and forwards
// it intact to the resolved target (Target by default, or a
// path-prefix route added via AddRoute) over HTTPS.
// isReservedAdminPath reports whether path is one of the admin surface's
// reserved paths that AdminAddr, once set, moves off of Addr entirely —
// every reserved path except healthzPath, which always stays on Addr
// too regardless of AdminAddr (see AdminAddr's doc comment).
func isReservedAdminPath(path string) bool {
	switch path {
	case statsPath, metricsPath, dashboardPath, cacheClearPath:
		return true
	default:
		return false
	}
}

// checkNetworkAndAuthAccess runs the three independent gates every
// request — whether ordinary proxy traffic or a request for the admin
// surface — must pass before anything else happens: the IP allow/deny
// list, the GeoIP country allow/deny list, and proxy_api_key
// authentication, in that order, responding and returning ok=false at
// the first one that rejects the request. Shared by ServeHTTP and
// adminMux.ServeHTTP so a request for the admin surface is gated
// identically whether it arrives on Addr (AdminAddr unset) or on
// AdminAddr's own listener — moving where the admin surface is
// reachable from was never meant to change what's required to reach it.
func (s *Server) checkNetworkAndAuthAccess(w http.ResponseWriter, r *http.Request) (clientAuth, bool) {
	if !s.checkIPAccess(r) {
		// Checked before even proxy authentication: a network-level
		// access decision is more foundational than an application-level
		// credential check, and should reject a completely unknown
		// source before it can so much as present a key.
		s.Stats.RecordIPDenied()
		s.logIPDenied(r.RemoteAddr, r.Method, r.URL.String())
		s.notifyIPDeniedWebhook(r.RemoteAddr, r.Method, r.URL.String())
		writeError(w, r, http.StatusForbidden, "ip_denied", "access denied", "")
		return clientAuth{}, false
	}
	if allowed, country := s.checkCountryAccess(r); !allowed {
		// Checked right after checkIPAccess, for the same reason — a
		// network-level access decision before any application-level
		// credential check — but as a fully independent gate: neither
		// this nor checkIPAccess is an exemption from the other, see
		// CountryAllowList's doc comment.
		s.Stats.RecordCountryDenied()
		s.logCountryDenied(r.RemoteAddr, country, r.Method, r.URL.String())
		s.notifyCountryDeniedWebhook(r.RemoteAddr, country, r.Method, r.URL.String())
		writeError(w, r, http.StatusForbidden, "country_denied", "access denied", "")
		return clientAuth{}, false
	}

	auth, ok := s.checkProxyAuth(r)
	if !ok {
		// Checked before statsPath/metricsPath too — an API key, once
		// configured, gates the whole proxy, monitoring endpoints
		// included, not just traffic actually forwarded upstream.
		s.Stats.RecordUnauthorized()
		s.logUnauthorized(r.Method, r.URL.String())
		s.notifyWebhook("unauthorized", r.Method, r.URL.String(), "")
		w.Header().Set("Proxy-Authenticate", strings.TrimSpace(proxyAuthScheme))
		writeError(w, r, http.StatusProxyAuthRequired, "unauthorized", "proxy authentication required", "")
		return clientAuth{}, false
	}
	return auth, true
}

// adminMux is AdminAddr's own http.Handler, when configured: it serves
// nothing but healthzPath and the admin surface (statsPath, metricsPath,
// dashboardPath, cacheClearPath), gated by exactly the same checks as
// Addr applies to them (see checkNetworkAndAuthAccess) — it never
// forwards to the upstream target, since that was never this listener's
// job to begin with.
type adminMux struct {
	server *Server
}

func (h adminMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := h.server
	if r.URL.Path == healthzPath {
		s.serveHealthz(w, r)
		return
	}
	if _, ok := s.checkNetworkAndAuthAccess(w, r); !ok {
		return
	}
	switch r.URL.Path {
	case statsPath:
		s.serveStats(w, r)
	case metricsPath:
		s.serveMetrics(w, r)
	case dashboardPath:
		s.serveDashboard(w, r)
	case cacheClearPath:
		s.serveCacheClear(w, r)
	default:
		writeError(w, r, http.StatusNotFound, "not_found", "404 page not found", "")
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == healthzPath {
		// See healthzPath's doc comment: deliberately checked before
		// even the IP allow/deny list, since it's the one reserved path
		// with no exception's worth of information to protect.
		s.serveHealthz(w, r)
		return
	}
	if s.AdminAddr != "" && isReservedAdminPath(r.URL.Path) {
		// The admin surface has moved to its own listener (see
		// AdminAddr's doc comment) — Addr must never forward one of
		// these paths upstream as if it were an ordinary route, since
		// "reserved" always meant exactly that.
		writeError(w, r, http.StatusNotFound, "not_found", "404 page not found", "")
		return
	}

	auth, ok := s.checkNetworkAndAuthAccess(w, r)
	if !ok {
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
	if r.URL.Path == dashboardPath {
		s.serveDashboard(w, r)
		return
	}
	if r.URL.Path == cacheClearPath {
		s.serveCacheClear(w, r)
		return
	}

	limitedBody := http.MaxBytesReader(w, r.Body, s.getMaxBodyBytes())
	body, err := io.ReadAll(limitedBody)
	limitedBody.Close()
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large", "")
			return
		}
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error(), "")
		return
	}

	// Resolved once so the cache key (below) and the actual forwarding
	// (in Rewrite, via the request context set further down) can never
	// disagree about which target and path this request maps to. targets
	// is always non-empty; when it holds more than one candidate (a
	// failover route), the cache key is still computed against only the
	// first (primary) one — a stable identity for the route regardless of
	// which candidate actually ends up serving any one request.
	//
	// A model route, if configured and matched, takes priority over
	// path-prefix routing entirely — see resolveModelRoute — and forwards
	// with the client's own path unchanged, since there's no prefix to
	// strip.
	var targets []*url.URL
	var forwardPath, targetLabel string
	var effectiveLimiter *limiter.Limiter
	var effectiveTokenLimiter *limiter.TokenLimiter
	if mTargets, mLabel, mLimiter, mTokenLimiter, matched := s.resolveModelRoute(body); matched {
		targets, forwardPath, targetLabel, effectiveLimiter, effectiveTokenLimiter = mTargets, r.URL.Path, mLabel, mLimiter, mTokenLimiter
	} else {
		targets, forwardPath, targetLabel, effectiveLimiter, effectiveTokenLimiter = s.resolveRoute(r.URL.Path)
	}
	if auth.limiter != nil {
		// The authenticated key's own rate limit is authoritative for
		// this caller regardless of which route they hit — takes
		// precedence over both the route's own limiter and the
		// server-wide one.
		effectiveLimiter = auth.limiter
	}
	if auth.tokenLimiter != nil {
		effectiveTokenLimiter = auth.tokenLimiter
	}

	// The cache is checked before rules and the rate limiter: a cache hit
	// never touches either, and never reaches the upstream target. The
	// key is computed from the body as received, before any redaction —
	// two different secrets that happen to redact to the same
	// placeholder are still cached separately, which only ever costs an
	// extra upstream call, never an incorrect one.
	var cacheKey string
	if cch := s.getCache(); cch != nil {
		destURL := &url.URL{Path: forwardPath, RawQuery: r.URL.RawQuery}
		cacheKey = cache.Key(r.Method, targets[0].ResolveReference(destURL).String(), body)
		if cached, hit, age, err := cch.Get(cacheKey); err == nil && hit {
			defer cached.Body.Close()
			copyHeader(w.Header(), cached.Header)
			// Set after copyHeader, so this always wins over whatever
			// Age (if any) the original upstream response itself might
			// have carried — that value described a different cache's
			// own staleness, not aiproxy's.
			w.Header().Set("Age", strconv.Itoa(int(age.Seconds())))
			stale := cch.IsStale(age)
			w.WriteHeader(cached.StatusCode)
			io.Copy(w, cached.Body)
			s.Stats.RecordCacheHit(targetLabel)
			if stale {
				s.Stats.RecordStaleCacheHit(targetLabel)
			}
			s.logCacheHit(r.Method, r.URL.String(), age, stale)
			return
		}
	}

	action, ruleName, evaluatedBody, evaluatedHeaders, dryRunHits, err := s.getEngine().Evaluate(rules.Request{
		Method:  r.Method,
		URL:     r.URL.String(),
		Body:    body,
		Headers: filterHeadersForScanning(r.Header),
		Target:  targetLabel,
		Key:     auth.label,
	})
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error(), "")
		return
	}
	s.handleRequestDryRunHits(dryRunHits, r.Method, r.URL.String())
	if action == rules.Block {
		// The matched secret itself must never reach the log, only the
		// static rule name that identifies which pattern triggered it.
		s.Stats.RecordBlock(targetLabel, ruleName)
		s.Stats.RecordClientBlock(auth.label)
		s.logBlock(r.Method, r.URL.String(), ruleName)
		s.notifyWebhook("block", r.Method, r.URL.String(), ruleName)
		writeError(w, r, http.StatusForbidden, "block", "blocked by aiproxy rules", ruleName)
		return
	}

	if effectiveLimiter != nil && !effectiveLimiter.Allow() {
		s.Stats.RecordRateLimited(targetLabel)
		s.Stats.RecordClientRateLimited(auth.label)
		s.logRateLimited(r.Method, r.URL.String())
		s.notifyWebhook("rate_limited", r.Method, r.URL.String(), "")
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded", "")
		return
	}

	// A second, independent breaker: effectiveTokenLimiter.Allow() only
	// peeks at usage already recorded for this window (see
	// limiter.TokenLimiter) — the actual token cost of *this* request
	// isn't known until its response comes back, so it can never be
	// checked against the budget before forwarding, only after, via
	// logUsageFromBody's Add call once reqCtx carries this same limiter
	// through to modifyResponse.
	if effectiveTokenLimiter != nil && !effectiveTokenLimiter.Allow() {
		s.Stats.RecordTokenRateLimited(targetLabel)
		s.Stats.RecordClientTokenRateLimited(auth.label)
		s.logTokenRateLimited(r.Method, r.URL.String())
		s.notifyWebhook("token_rate_limited", r.Method, r.URL.String(), "")
		writeError(w, r, http.StatusTooManyRequests, "token_rate_limited", "token rate limit exceeded", "")
		return
	}

	// A third, independent breaker, unlike Limiter/TokenLimiter keyed
	// on this one client's own recent baseline rather than a fixed
	// threshold — see anomaly.Registry. No-ops entirely for an
	// unidentified caller (auth.label == "" whenever no
	// proxy_api_key/proxy_api_keys is configured at all), since
	// there's no notion of "this caller's own baseline" without one.
	if anomalyDetector, anomalyDryRun := s.getAnomalyConfig(); anomalyDetector != nil {
		if anomalous, currentCount, baseline := anomalyDetector.Check(auth.label); anomalous {
			s.Stats.RecordAnomalyDetected()
			s.Stats.RecordClientAnomalyDetected(auth.label)
			s.logAnomalyDetected(auth.label, r.Method, r.URL.String(), currentCount, baseline)
			s.notifyAnomalyWebhook(auth.label, r.Method, r.URL.String(), currentCount, baseline)
			if !anomalyDryRun {
				writeError(w, r, http.StatusTooManyRequests, "anomaly_detected", "anomalous traffic pattern detected", "")
				return
			}
		}
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
	// GetBody lets failoverTransport re-read the same already-buffered
	// body for a second (or later) candidate after an earlier one turns
	// out to be unreachable — evaluatedBody is captured by value here, so
	// every call returns a fresh reader over the same bytes.
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(evaluatedBody)), nil
	}
	for name, values := range evaluatedHeaders {
		r.Header[name] = values
	}
	if action == rules.Redact {
		s.Stats.RecordRedact(targetLabel, ruleName)
		s.Stats.RecordClientRedact(auth.label)
		s.logRedact(r.Method, r.URL.String(), ruleName)
		s.notifyWebhook("redact", r.Method, r.URL.String(), ruleName)
	} else {
		s.Stats.RecordAllow(targetLabel)
		s.Stats.RecordClientAllow(auth.label)
		s.logAllow(r.Method, r.URL.String())
	}

	// Carry the client-facing method/URL, the cache key, and the resolved
	// route through to Rewrite and modifyResponse via the request
	// context: by the time those run, the request has already been
	// rewritten to the absolute upstream URL, and they need the exact
	// same target/cache key ServeHTTP already resolved and checked.
	reqCtx := requestContextInfo{
		method:           r.Method,
		url:              r.URL.String(),
		cacheKey:         cacheKey,
		targets:          targets,
		forwardPath:      forwardPath,
		targetLabel:      targetLabel,
		clientLabel:      auth.label,
		clientCostBudget: auth.costBudget,
		tokenLimiter:     effectiveTokenLimiter,
		latency:          new(time.Duration),
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

	// Logged here, common to both the streaming and buffered paths below,
	// and unconditionally — regardless of what the response scanning
	// further down decides to do with the response (forward, redact,
	// block): latency measures how long upstream took to answer, not
	// what aiproxy did with the answer. reqCtx.latency is only nil for a
	// requestContextInfo built outside ServeHTTP's normal path (e.g. a
	// zero-valued one from a failed type assertion in a test), never in
	// real traffic — failoverTransport.RoundTrip always sets it by the
	// time modifyResponse can even be reached.
	if reqCtx.latency != nil {
		s.logLatency(reqCtx.method, reqCtx.url, *reqCtx.latency)
	}

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

	action, ruleName, scannedBody, dryRunHits := s.getEngine().EvaluateResponse(body, reqCtx.targetLabel, reqCtx.clientLabel)
	s.handleResponseDryRunHits(dryRunHits, reqCtx.method, reqCtx.url)
	if action == rules.Block {
		s.Stats.RecordResponseBlock(reqCtx.targetLabel, ruleName)
		s.logResponseBlock(reqCtx.method, reqCtx.url, ruleName)
		s.notifyWebhook("response_block", reqCtx.method, reqCtx.url, ruleName)
		writeResponseBlockedBody(resp, "response blocked by aiproxy rules")
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
		target: reqCtx.targetLabel,
		key:    reqCtx.clientLabel,
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
	target string
	key    string

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

	action, ruleName, scanned, dryRunHits := t.engine.EvaluateResponse(batch, t.target, t.key)
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
		// Records this request's actual cost against whatever token
		// breaker applied to it — see effectiveTokenLimiter in ServeHTTP
		// and limiter.TokenLimiter.Allow's own doc comment for why this
		// can only happen now, after the fact, never before forwarding.
		if reqCtx.tokenLimiter != nil {
			reqCtx.tokenLimiter.Add(tokens)
		}
		s.Stats.RecordTokensUsed(reqCtx.targetLabel, tokens)
		s.Stats.RecordClientTokensUsed(reqCtx.clientLabel, tokens)
		s.logUsage(reqCtx.method, reqCtx.url, tokens)
		if cost, crossed := s.Stats.CrossedBudget(s.getCostPer1KTokens(), s.getCostBudget()); crossed {
			s.logBudgetExceeded(reqCtx.method, reqCtx.url, cost, s.getCostBudget())
			s.notifyBudgetWebhook(reqCtx.method, reqCtx.url, cost, s.getCostBudget())
		}
		if cost, crossed := s.Stats.CrossedClientBudget(reqCtx.clientLabel, s.getCostPer1KTokens(), reqCtx.clientCostBudget); crossed {
			s.logClientBudgetExceeded(reqCtx.method, reqCtx.url, reqCtx.clientLabel, cost, reqCtx.clientCostBudget)
			s.notifyClientBudgetWebhook(reqCtx.method, reqCtx.url, reqCtx.clientLabel, cost, reqCtx.clientCostBudget)
		}
	}
}

func (s *Server) logAllow(method, reqURL string) {
	ev := s.recordLogEvent(logEvent{Level: "allow", Method: method, URL: reqURL})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[ALLOW] %s %s%s", ansiGreen, method, reqURL, ansiReset)
}

func (s *Server) logBlock(method, reqURL, ruleName string) {
	ev := s.recordLogEvent(logEvent{Level: "block", Method: method, URL: reqURL, Rule: ruleName})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[BLOCK] %s %s - Triggered rule: %s%s", ansiBrightRed, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logRateLimited(method, reqURL string) {
	ev := s.recordLogEvent(logEvent{Level: "rate_limited", Method: method, URL: reqURL})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[CIRCUIT BREAKER] %s %s - Rate limit exceeded%s", ansiYellow, method, reqURL, ansiReset)
}

// logTokenRateLimited is logRateLimited's counterpart for the
// token-based breaker — see limiter.TokenLimiter. Kept as its own Level
// ("token_rate_limited", not "rate_limited") so the two are
// distinguishable in a JSON log stream or GET /_aiproxy/stats, the same
// way ip_denied is kept separate from unauthorized.
func (s *Server) logTokenRateLimited(method, reqURL string) {
	ev := s.recordLogEvent(logEvent{Level: "token_rate_limited", Method: method, URL: reqURL})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[TOKEN LIMIT] %s %s - Token rate limit exceeded%s", ansiYellow, method, reqURL, ansiReset)
}

func (s *Server) logUnauthorized(method, reqURL string) {
	ev := s.recordLogEvent(logEvent{Level: "unauthorized", Method: method, URL: reqURL})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[UNAUTHORIZED] %s %s - Missing or invalid Proxy-Authorization%s", ansiBrightRed, method, reqURL, ansiReset)
}

func (s *Server) logIPDenied(remoteIP, method, reqURL string) {
	ev := s.recordLogEvent(logEvent{Level: "ip_denied", Method: method, URL: reqURL, RemoteIP: remoteIP})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[IP DENIED] %s %s - %s not in ip_allow_list, or in ip_deny_list%s", ansiBrightRed, method, reqURL, remoteIP, ansiReset)
}

func (s *Server) logCountryDenied(remoteIP, country, method, reqURL string) {
	ev := s.recordLogEvent(logEvent{Level: "country_denied", Method: method, URL: reqURL, RemoteIP: remoteIP, Country: country})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	label := country
	if label == "" {
		label = "unresolved"
	}
	s.logf("%s[COUNTRY DENIED] %s %s - %s (%s) not in country_allow_list, or in country_deny_list%s", ansiBrightRed, method, reqURL, remoteIP, label, ansiReset)
}

func (s *Server) logBudgetExceeded(method, reqURL string, cost, budget float64) {
	ev := s.recordLogEvent(logEvent{Level: "budget_exceeded", Method: method, URL: reqURL, Cost: cost, Budget: budget})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[BUDGET EXCEEDED] %s %s - Estimated cost %.4f exceeds budget %.4f%s", ansiYellow, method, reqURL, cost, budget, ansiReset)
}

// logClientBudgetExceeded is logBudgetExceeded's per-client counterpart
// — see stats.Stats.CrossedClientBudget. Kept as its own method, not a
// client-aware branch inside logBudgetExceeded, since the two fire from
// independent CrossedBudget/CrossedClientBudget checks and can both
// fire for the very same request.
func (s *Server) logClientBudgetExceeded(method, reqURL, client string, cost, budget float64) {
	ev := s.recordLogEvent(logEvent{Level: "budget_exceeded", Method: method, URL: reqURL, Client: client, Cost: cost, Budget: budget})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[BUDGET EXCEEDED] %s %s - client %s: estimated cost %.4f exceeds budget %.4f%s", ansiYellow, method, reqURL, client, cost, budget, ansiReset)
}

// logAnomalyDetected logs a client's request rate spiking past its own
// baseline — see anomaly.Registry. currentCount/baseline are always
// real, meaningful numbers here (Check only ever reports anomalous
// alongside them), never zero-valued placeholders.
func (s *Server) logAnomalyDetected(client, method, reqURL string, currentCount int, baseline float64) {
	ev := s.recordLogEvent(logEvent{Level: "anomaly_detected", Method: method, URL: reqURL, Client: client, Rate: currentCount, Baseline: &baseline})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[ANOMALY] %s %s - client %s: %d requests this minute vs. baseline %.1f%s", ansiYellow, method, reqURL, client, currentCount, baseline, ansiReset)
}

func (s *Server) logFailover(method, reqURL, failedTarget, nextTarget string) {
	ev := s.recordLogEvent(logEvent{Level: "failover", Method: method, URL: reqURL, FailedTarget: failedTarget, NextTarget: nextTarget})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[FAILOVER] %s %s - %s unreachable, trying %s%s", ansiBrightYellow, method, reqURL, failedTarget, nextTarget, ansiReset)
}

// logTargetEjected logs one candidate upstream URL crossing its
// consecutive-failure threshold — see breaker.Registry.RecordFailure.
// Fires exactly once per ejection, not on every subsequent failure
// while still in cooldown — see failoverTransport.recordBreakerFailure.
// No method/URL: unlike failover, this isn't tied to any one client
// request — a target can be ejected by any request that happened to hit
// it, and the target itself is the whole story.
func (s *Server) logTargetEjected(target string) {
	ev := s.recordLogEvent(logEvent{Level: "target_ejected", Target: target})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[TARGET EJECTED] %s temporarily deprioritized after repeated failures%s", ansiBrightRed, target, ansiReset)
}

// logTargetRecovered logs one candidate upstream URL succeeding again
// after having been ejected — see breaker.Registry.RecordSuccess.
func (s *Server) logTargetRecovered(target string) {
	ev := s.recordLogEvent(logEvent{Level: "target_recovered", Target: target})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[TARGET RECOVERED] %s%s", ansiGreen, target, ansiReset)
}

// logLatency logs how long the upstream took to respond to one specific
// request — the per-request counterpart to Stats.RecordLatency's
// aggregate histogram, so a single slow call shows up directly in the
// log stream (terminal or JSONL) instead of only being visible by
// polling /_aiproxy/stats or /_aiproxy/metrics. Fired for every request
// that actually reached the upstream and got a response back —
// regardless of whether that response then goes on to be blocked,
// redacted, or forwarded as-is; latency measures how long upstream took
// to answer, independent of what aiproxy decides to do with the answer.
func (s *Server) logLatency(method, reqURL string, d time.Duration) {
	ms := d.Milliseconds()
	ev := s.recordLogEvent(logEvent{Level: "latency", Method: method, URL: reqURL, DurationMS: &ms})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[LATENCY] %s %s - %dms%s", ansiDim, method, reqURL, ms, ansiReset)
}

func (s *Server) logUsage(method, reqURL string, totalTokens int) {
	ev := s.recordLogEvent(logEvent{Level: "usage", Method: method, URL: reqURL, Tokens: totalTokens})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[USAGE] %s %s - Tokens used: %d%s", ansiBlue, method, reqURL, totalTokens, ansiReset)
}

// logCacheHit logs a request served from cache — age is how old the
// served entry was (see cache.Cache.Get), and stale reports whether
// that age had already crossed cache.Cache.IsStale's warning threshold,
// rendered as a visually distinct log line (yellow instead of the usual
// purple) so an operator watching the log stream notices a cache that's
// due for a refresh without needing to poll /_aiproxy/stats.
func (s *Server) logCacheHit(method, reqURL string, age time.Duration, stale bool) {
	ageSeconds := int(age.Seconds())
	ev := s.recordLogEvent(logEvent{Level: "cache_hit", Method: method, URL: reqURL, AgeSeconds: &ageSeconds, Stale: stale})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	if stale {
		s.logf("%s[CACHE HIT - STALE] %s %s - age %ds%s", ansiYellow, method, reqURL, ageSeconds, ansiReset)
		return
	}
	s.logf("%s[CACHE HIT] %s %s - age %ds%s", ansiPurple, method, reqURL, ageSeconds, ansiReset)
}

func (s *Server) logRedact(method, reqURL, ruleName string) {
	ev := s.recordLogEvent(logEvent{Level: "redact", Method: method, URL: reqURL, Rule: ruleName})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[REDACT] %s %s - Triggered rule: %s%s", ansiCyan, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logResponseBlock(method, reqURL, ruleName string) {
	ev := s.recordLogEvent(logEvent{Level: "response_block", Method: method, URL: reqURL, Rule: ruleName})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[RESPONSE BLOCK] %s %s - Triggered rule: %s%s", ansiBrightRed, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logResponseRedact(method, reqURL, ruleName string) {
	ev := s.recordLogEvent(logEvent{Level: "response_redact", Method: method, URL: reqURL, Rule: ruleName})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[RESPONSE REDACT] %s %s - Triggered rule: %s%s", ansiCyan, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logDryRunBlock(method, reqURL, ruleName string) {
	ev := s.recordLogEvent(logEvent{Level: "dry_run_block", Method: method, URL: reqURL, Rule: ruleName})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[DRY-RUN BLOCK] %s %s - Would have triggered rule: %s%s", ansiGray, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logDryRunRedact(method, reqURL, ruleName string) {
	ev := s.recordLogEvent(logEvent{Level: "dry_run_redact", Method: method, URL: reqURL, Rule: ruleName})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[DRY-RUN REDACT] %s %s - Would have triggered rule: %s%s", ansiGray, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logResponseDryRunBlock(method, reqURL, ruleName string) {
	ev := s.recordLogEvent(logEvent{Level: "response_dry_run_block", Method: method, URL: reqURL, Rule: ruleName})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[RESPONSE DRY-RUN BLOCK] %s %s - Would have triggered rule: %s%s", ansiGray, method, reqURL, ruleName, ansiReset)
}

func (s *Server) logResponseDryRunRedact(method, reqURL, ruleName string) {
	ev := s.recordLogEvent(logEvent{Level: "response_dry_run_redact", Method: method, URL: reqURL, Rule: ruleName})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
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
// block, redact, rate_limited, token_rate_limited, unauthorized,
// ip_denied, budget_exceeded, failover, or dry-run event (dry_run_block,
// dry_run_redact, response_dry_run_block, response_dry_run_redact). Text
// alone is enough for a Slack incoming webhook (which reads exactly that
// field and ignores the rest); the remaining fields serve a generic JSON
// webhook consumer that wants the event structured instead of parsed
// back out of a sentence. Like every other log line in this package, it
// carries the rule name that matched, never the matched secret itself;
// Rule is empty for a rate_limited, token_rate_limited, unauthorized,
// ip_denied, budget_exceeded, or failover event, since none of those is
// attributable to any one rule.
// Cost and Budget are set only for budget_exceeded; FailedTarget and
// NextTarget only for failover; omitted (via omitempty) for every other
// event.
type webhookAlert struct {
	Text         string   `json:"text"`
	Event        string   `json:"event"`
	Method       string   `json:"method"`
	URL          string   `json:"url"`
	Rule         string   `json:"rule"`
	Time         string   `json:"time"`
	Cost         *float64 `json:"cost,omitempty"`
	Budget       *float64 `json:"budget,omitempty"`
	FailedTarget string   `json:"failed_target,omitempty"`
	NextTarget   string   `json:"next_target,omitempty"`

	// Client is set on a budget_exceeded event fired by a named proxy
	// key's own cost_budget, and always set on an anomaly_detected
	// event — see logEvent.Client.
	Client string `json:"client,omitempty"`

	// RemoteIP is only set on an ip_denied or country_denied event —
	// see logEvent.RemoteIP.
	RemoteIP string `json:"remote_ip,omitempty"`

	// Country is only set on a country_denied event — see
	// logEvent.Country.
	Country string `json:"country,omitempty"`

	// Rate and Baseline are only set on an anomaly_detected event —
	// see logEvent.Rate/logEvent.Baseline.
	Rate     int      `json:"rate,omitempty"`
	Baseline *float64 `json:"baseline,omitempty"`

	// Target is only set on a target_ejected or target_recovered event
	// — see logEvent.Target.
	Target string `json:"target,omitempty"`
}

// WebhookTarget is one resolved entry in Server.Webhooks: a destination
// URL plus an optional filter of the event names it should receive.
type WebhookTarget struct {
	URL *url.URL

	// Events, if non-empty, restricts this destination to only the
	// named event names (see webhookAlert.Event for the full set —
	// "block", "redact", "budget_exceeded", and so on). Empty/nil (the
	// zero value) matches every event, the same unfiltered behavior
	// Server.WebhookURL alone has always had.
	Events []string
}

// matches reports whether t should receive an event named event — every
// event, if Events is empty, otherwise only a named match.
func (t WebhookTarget) matches(event string) bool {
	if len(t.Events) == 0 {
		return true
	}
	for _, e := range t.Events {
		if e == event {
			return true
		}
	}
	return false
}

// deliverWebhookPayload marshals payload once and POSTs it to every
// configured destination that wants this event: Server.WebhookURL
// (unconditionally, if set — the original, still-unfiltered behavior)
// plus every Server.Webhooks entry whose own Events filter matches —
// shared by notifyWebhook, notifyBudgetWebhook, and notifyFailoverWebhook
// so the actual delivery mechanics (timeout, error logging, no retry)
// live in exactly one place. Each destination is POSTed to on its own
// goroutine, so a slow or unreachable endpoint never delays the
// client's actual request (already decided and logged by the time this
// runs) and never delays or blocks delivery to any other destination
// either. A delivery failure (or a non-2xx response) is logged as an
// internal error and otherwise ignored: there is no retry, and it never
// changes the outcome of the request that triggered it.
func (s *Server) deliverWebhookPayload(payload webhookAlert) {
	webhookURL := s.getWebhookURL()
	webhooks := s.getWebhooks()
	if webhookURL == nil && len(webhooks) == 0 {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		// payload is always this one fixed, plain shape, so this should
		// never actually happen — mirrors logEventJSON's own fallback.
		s.logError("aiproxy: webhook: failed to encode alert: %v", err)
		return
	}

	if webhookURL != nil {
		s.postWebhook("webhook_url", webhookURL, data)
	}
	for i, target := range webhooks {
		if target.matches(payload.Event) {
			s.postWebhook(fmt.Sprintf("webhooks[%d]", i), target.URL, data)
		}
	}
}

// postWebhook POSTs data to target on its own goroutine. A delivery
// error is logged with label identifying which configured destination
// failed (its position in Webhooks, or "webhook_url" for the top-level
// one) — deliberately never the URL itself, even in an error message:
// a webhook URL, a Slack incoming webhook especially, typically embeds
// a bearer credential directly in its path, so it gets the same
// treatment as every other secret aiproxy handles.
func (s *Server) postWebhook(label string, target *url.URL, data []byte) {
	go func() {
		resp, err := webhookClient.Post(target.String(), "application/json", bytes.NewReader(data))
		if err != nil {
			s.logError("aiproxy: webhook (%s): delivery failed: %v", label, err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			s.logError("aiproxy: webhook (%s): endpoint returned status %d", label, resp.StatusCode)
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
	case event == "token_rate_limited":
		text = fmt.Sprintf("[%s] %s %s - Token rate limit exceeded", strings.ToUpper(event), method, reqURL)
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

// notifyClientBudgetWebhook is notifyBudgetWebhook's per-client
// counterpart — see logClientBudgetExceeded for why this is a separate
// method rather than a branch inside the existing one.
func (s *Server) notifyClientBudgetWebhook(method, reqURL, client string, cost, budget float64) {
	text := fmt.Sprintf("[BUDGET_EXCEEDED] %s %s - client %s: estimated cost %.4f exceeds budget %.4f", method, reqURL, client, cost, budget)
	s.deliverWebhookPayload(webhookAlert{
		Text:   text,
		Event:  "budget_exceeded",
		Method: method,
		URL:    reqURL,
		Client: client,
		Time:   time.Now().UTC().Format(time.RFC3339),
		Cost:   &cost,
		Budget: &budget,
	})
}

// notifyAnomalyWebhook builds and delivers a webhookAlert for the
// anomaly_detected event — kept separate from notifyWebhook for the
// same reason as notifyBudgetWebhook: this event carries a client, a
// rate, and a baseline instead of a rule name.
func (s *Server) notifyAnomalyWebhook(client, method, reqURL string, currentCount int, baseline float64) {
	text := fmt.Sprintf("[ANOMALY_DETECTED] %s %s - client %s: %d requests this minute vs. baseline %.1f", method, reqURL, client, currentCount, baseline)
	s.deliverWebhookPayload(webhookAlert{
		Text:     text,
		Event:    "anomaly_detected",
		Method:   method,
		URL:      reqURL,
		Client:   client,
		Time:     time.Now().UTC().Format(time.RFC3339),
		Rate:     currentCount,
		Baseline: &baseline,
	})
}

// notifyFailoverWebhook builds and delivers a webhookAlert for the
// failover event — kept separate from notifyWebhook for the same reason
// as notifyBudgetWebhook: this event carries a failed/next target pair
// instead of a rule name.
func (s *Server) notifyFailoverWebhook(method, reqURL, failedTarget, nextTarget string) {
	text := fmt.Sprintf("[FAILOVER] %s %s - %s unreachable, trying %s", method, reqURL, failedTarget, nextTarget)
	s.deliverWebhookPayload(webhookAlert{
		Text:         text,
		Event:        "failover",
		Method:       method,
		URL:          reqURL,
		Time:         time.Now().UTC().Format(time.RFC3339),
		FailedTarget: failedTarget,
		NextTarget:   nextTarget,
	})
}

// notifyTargetEjectedWebhook builds and delivers a webhookAlert for the
// target_ejected event — no method/URL, same reasoning as
// logTargetEjected: the target itself is the whole story, independent
// of which client request happened to trigger the transition.
func (s *Server) notifyTargetEjectedWebhook(target string) {
	s.deliverWebhookPayload(webhookAlert{
		Text:   fmt.Sprintf("[TARGET EJECTED] %s temporarily deprioritized after repeated failures", target),
		Event:  "target_ejected",
		Time:   time.Now().UTC().Format(time.RFC3339),
		Target: target,
	})
}

// notifyTargetRecoveredWebhook builds and delivers a webhookAlert for
// the target_recovered event.
func (s *Server) notifyTargetRecoveredWebhook(target string) {
	s.deliverWebhookPayload(webhookAlert{
		Text:   fmt.Sprintf("[TARGET RECOVERED] %s", target),
		Event:  "target_recovered",
		Time:   time.Now().UTC().Format(time.RFC3339),
		Target: target,
	})
}

// notifyIPDeniedWebhook builds and delivers a webhookAlert for the
// ip_denied event — kept separate from notifyWebhook for the same
// reason as notifyBudgetWebhook/notifyFailoverWebhook: this event
// carries a remote IP instead of a rule name.
func (s *Server) notifyIPDeniedWebhook(remoteIP, method, reqURL string) {
	text := fmt.Sprintf("[IP_DENIED] %s %s - %s not in ip_allow_list, or in ip_deny_list", method, reqURL, remoteIP)
	s.deliverWebhookPayload(webhookAlert{
		Text:     text,
		Event:    "ip_denied",
		Method:   method,
		URL:      reqURL,
		Time:     time.Now().UTC().Format(time.RFC3339),
		RemoteIP: remoteIP,
	})
}

// notifyCountryDeniedWebhook builds and delivers a webhookAlert for the
// country_denied event — kept separate from notifyWebhook for the same
// reason as notifyIPDeniedWebhook: this event carries a remote IP (and
// its resolved country) instead of a rule name.
func (s *Server) notifyCountryDeniedWebhook(remoteIP, country, method, reqURL string) {
	label := country
	if label == "" {
		label = "unresolved"
	}
	text := fmt.Sprintf("[COUNTRY_DENIED] %s %s - %s (%s) not in country_allow_list, or in country_deny_list", method, reqURL, remoteIP, label)
	s.deliverWebhookPayload(webhookAlert{
		Text:     text,
		Event:    "country_denied",
		Method:   method,
		URL:      reqURL,
		Time:     time.Now().UTC().Format(time.RFC3339),
		RemoteIP: remoteIP,
		Country:  country,
	})
}

// logEventJSON marshals ev (stamping the current time) and logs it as a
// single line, for LogFormatJSON.
func (s *Server) logEventJSON(ev logEvent) {
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339)
	}
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

// appendToLogFile writes data plus a trailing newline to Server.LogFile,
// if configured, serialized against concurrent writers by logFileMu. A
// write failure is reported to the terminal only, via logf directly —
// never routed back through logError/recordLogEvent, which would
// recurse into this exact same failing write on every subsequent event.
//
// When AuditChain is set, data is first replaced with its chained
// envelope (see auditlog.Chain.Wrap) — inside the very same logFileMu
// critical section as the write, not before it, so the order lines are
// chained in always matches the order they land in the file. Doing
// that in two separate locked sections would let two goroutines chain
// in one order but write in another, corrupting the chain without any
// real tampering ever happening.
func (s *Server) appendToLogFile(data []byte) {
	f := s.getLogFile()
	if f == nil {
		return
	}

	s.logFileMu.Lock()
	if s.AuditChain != nil {
		wrapped, err := s.AuditChain.Wrap(data)
		if err != nil {
			s.logFileMu.Unlock()
			s.logf("aiproxy: audit_log: failed to chain entry, line dropped: %v", err)
			return
		}
		data = wrapped
	}
	line := append(append([]byte(nil), data...), '\n')
	_, err := f.Write(line)
	s.logFileMu.Unlock()
	if err != nil {
		s.logf("aiproxy: log_file: write failed: %v", err)
	}
}

// recordLogEvent stamps ev's Time if not already set and appends it to
// Server.LogFile as one JSON line (see appendToLogFile) — independent
// of LogFormat, so a durable on-disk record exists even when the
// terminal is showing colored text, not JSON. It returns the (now
// time-stamped) event so the caller can pass the exact same value on to
// logEventJSON for LogFormatJSON's own terminal output, keeping both
// records' timestamps identical instead of two independent, slightly
// different ones.
func (s *Server) recordLogEvent(ev logEvent) logEvent {
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if data, err := json.Marshal(ev); err == nil {
		s.appendToLogFile(data)
	}
	return ev
}

// logError logs an internal, non-request-scoped problem (e.g. a failed
// cache write) — as a JSON line under LogFormatJSON, so it never breaks
// the guarantee that every line in that mode is valid JSON, or as a
// plain line otherwise.
func (s *Server) logError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ev := s.recordLogEvent(logEvent{Level: "error", Message: msg})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
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
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	Redacted    int64 `json:"redacted"`
	RateLimited int64 `json:"rate_limited"`

	// TokenRateLimited counts requests rejected by the token-based
	// circuit breaker — see limiter.TokenLimiter. Distinct from
	// RateLimited, which is the plain request-count breaker.
	TokenRateLimited int64 `json:"token_rate_limited"`
	CacheHits        int64 `json:"cache_hits"`

	// StaleCacheHits mirrors stats.Snapshot.StaleCacheHits — see there.
	StaleCacheHits   int64 `json:"stale_cache_hits"`
	TotalTokens      int64 `json:"total_tokens"`
	ResponseBlocked  int64 `json:"response_blocked"`
	ResponseRedacted int64 `json:"response_redacted"`

	// Failover counts how many times this target's candidate list moved
	// on to the next URL because an earlier one was unreachable — always
	// 0 for a single-URL target. Broken down per target like Allowed,
	// unlike Unauthorized/the dry-run fields below.
	Failover int64 `json:"failover"`

	// Latency summarizes observed upstream response times — see
	// stats.LatencySnapshot. Broken down per target like Allowed, same
	// reasoning as Failover: a target's own latency profile is exactly
	// what a per-target breakdown exists to surface.
	Latency stats.LatencySnapshot `json:"latency"`

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

	// IPDenied is likewise only meaningful at the top level, and always
	// 0 inside per_target — an IP-denied request never gets far enough
	// to resolve a target either.
	IPDenied int64 `json:"ip_denied"`

	// CountryDenied is likewise only meaningful at the top level, and
	// always 0 inside per_target — same reasoning as IPDenied.
	CountryDenied int64 `json:"country_denied"`

	// AnomalyDetected is likewise only meaningful at the top level, and
	// always 0 inside per_target — broken down per client instead (see
	// PerClient), not per target.
	AnomalyDetected int64 `json:"anomaly_detected"`

	// TargetsEjected/TargetsRecovered are likewise only meaningful at
	// the top level, and always 0 inside per_target — see
	// stats.Snapshot.TargetsEjected/TargetsRecovered.
	TargetsEjected   int64 `json:"targets_ejected"`
	TargetsRecovered int64 `json:"targets_recovered"`

	EstimatedCost *float64                      `json:"estimated_cost,omitempty"`
	PerTarget     map[string]statsSnapshotJSON  `json:"per_target,omitempty"`
	PerRule       map[string]stats.RuleSnapshot `json:"per_rule,omitempty"`

	// PerClient breaks down by named proxy API key instead of target or
	// rule — see stats.ClientSnapshot. Only meaningful at the top level,
	// same reasoning as PerRule: which client is independent of which
	// target the request happened to route to, so toStatsSnapshotJSON
	// never sets it inside PerTarget.
	PerClient map[string]stats.ClientSnapshot `json:"per_client,omitempty"`

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
		TokenRateLimited:       snap.TokenRateLimited,
		CacheHits:              snap.CacheHits,
		StaleCacheHits:         snap.StaleCacheHits,
		TotalTokens:            snap.TotalTokens,
		ResponseBlocked:        snap.ResponseBlocked,
		ResponseRedacted:       snap.ResponseRedacted,
		DryRunBlocked:          snap.DryRunBlocked,
		DryRunRedacted:         snap.DryRunRedacted,
		ResponseDryRunBlocked:  snap.ResponseDryRunBlocked,
		ResponseDryRunRedacted: snap.ResponseDryRunRedacted,
		Unauthorized:           snap.Unauthorized,
		IPDenied:               snap.IPDenied,
		CountryDenied:          snap.CountryDenied,
		AnomalyDetected:        snap.AnomalyDetected,
		TargetsEjected:         snap.TargetsEjected,
		TargetsRecovered:       snap.TargetsRecovered,
		Failover:               snap.Failover,
		Latency:                snap.Latency,
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
	if len(snap.PerClient) > 0 {
		out.PerClient = snap.PerClient
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

// serveHealthz answers healthzPath with a minimal, always-healthy JSON
// body — see healthzPath's doc comment for why this is the one
// reserved path with no auth/IP gating and no dependency checks of its
// own. GET-only, same as every other reserved path.
func (s *Server) serveHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// serveStats answers statsPath with the current Stats snapshot as JSON,
// letting a long-running proxy be monitored without waiting for Ctrl+C.
// It never touches rules, the rate limiter, or the cache, and is never
// itself counted in Stats — it isn't a proxied request.
func (s *Server) serveStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", "")
		return
	}
	payload := withCostBudget(toStatsSnapshotJSON(s.Stats.Snapshot(), s.getCostPer1KTokens()), s.getCostBudget())
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logError("aiproxy: stats: failed to encode response: %v", err)
	}
}

// serveCacheClear answers cacheClearPath by deleting every entry from
// the response cache right now — see cache.Cache.Clear. Only POST is
// accepted, since this mutates state rather than reading it. A 404
// (not a 200 that quietly did nothing) is returned when caching isn't
// enabled at all: there's nothing to clear, and a caller expecting this
// to actually do something deserves to know it can't rather than
// silently succeeding. Like serveStats/serveMetrics, this never touches
// rules or the rate limiter and is never itself counted in Stats.
func (s *Server) serveCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", "")
		return
	}
	cch := s.getCache()
	if cch == nil {
		writeError(w, r, http.StatusNotFound, "cache_disabled", "cache is not enabled", "")
		return
	}
	if err := cch.Clear(); err != nil {
		s.logError("aiproxy: cache clear: %v", err)
		writeError(w, r, http.StatusInternalServerError, "cache_clear_failed", "failed to clear cache", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"cleared": true})
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
	{"aiproxy_requests_token_rate_limited_total", "Total number of requests rejected by the token-based rate limiter.", func(s stats.Snapshot) int64 { return s.TokenRateLimited }},
	{"aiproxy_cache_hits_total", "Total number of requests served from the local response cache.", func(s stats.Snapshot) int64 { return s.CacheHits }},
	{"aiproxy_stale_cache_hits_total", "Total number of cache hits served past their entry's own staleness warning threshold, relative to cache_ttl_seconds.", func(s stats.Snapshot) int64 { return s.StaleCacheHits }},
	{"aiproxy_tokens_used_total", "Total number of tokens reported in upstream response usage fields.", func(s stats.Snapshot) int64 { return s.TotalTokens }},
	{"aiproxy_responses_blocked_total", "Total number of upstream responses withheld from the client by a rule.", func(s stats.Snapshot) int64 { return s.ResponseBlocked }},
	{"aiproxy_responses_redacted_total", "Total number of upstream responses forwarded with a matched secret redacted.", func(s stats.Snapshot) int64 { return s.ResponseRedacted }},
	{"aiproxy_failover_total", "Total number of times this target's candidate list moved on to the next URL because an earlier one was unreachable.", func(s stats.Snapshot) int64 { return s.Failover }},
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

// promClientCounters mirrors promCounters for the per-client breakdown
// — which named proxy API key a request was authenticated with,
// independent of which target it happened to route to. A smaller set
// than promCounters, matching stats.ClientSnapshot's own smaller field
// set: no cache-hit/failover/latency/dry-run equivalent, since none of
// those are meaningfully attributable to a caller rather than a
// target/route.
var promClientCounters = []struct {
	name string
	help string
	get  func(stats.ClientSnapshot) int64
}{
	{"aiproxy_client_allowed_total", "Total number of requests allowed and forwarded, authenticated with this proxy API key.", func(c stats.ClientSnapshot) int64 { return c.Allowed }},
	{"aiproxy_client_blocked_total", "Total number of requests blocked by a rule, authenticated with this proxy API key.", func(c stats.ClientSnapshot) int64 { return c.Blocked }},
	{"aiproxy_client_redacted_total", "Total number of requests redacted, authenticated with this proxy API key.", func(c stats.ClientSnapshot) int64 { return c.Redacted }},
	{"aiproxy_client_rate_limited_total", "Total number of requests rejected by the rate limiter, authenticated with this proxy API key.", func(c stats.ClientSnapshot) int64 { return c.RateLimited }},
	{"aiproxy_client_token_rate_limited_total", "Total number of requests rejected by the token-based rate limiter, authenticated with this proxy API key.", func(c stats.ClientSnapshot) int64 { return c.TokenRateLimited }},
	{"aiproxy_client_anomaly_detected_total", "Total number of requests rejected for spiking past this client's own recent baseline request rate.", func(c stats.ClientSnapshot) int64 { return c.AnomalyDetected }},
	{"aiproxy_client_tokens_used_total", "Total number of tokens reported in upstream response usage fields, for requests authenticated with this proxy API key.", func(c stats.ClientSnapshot) int64 { return c.TotalTokens }},
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

	writeLatencyHistogram(w, snap.PerTarget, names)

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

	clientNames := make([]string, 0, len(snap.PerClient))
	for name := range snap.PerClient {
		clientNames = append(clientNames, name)
	}
	sort.Strings(clientNames)

	for _, c := range promClientCounters {
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
		for _, name := range clientNames {
			fmt.Fprintf(w, "%s{client=%q} %d\n", c.name, promLabelValue(name), c.get(snap.PerClient[name]))
		}
	}

	if costPer1KTokens > 0 && len(clientNames) > 0 {
		fmt.Fprintln(w, "# HELP aiproxy_client_estimated_cost Estimated cost of tokens used so far, for requests authenticated with this proxy API key.")
		fmt.Fprintln(w, "# TYPE aiproxy_client_estimated_cost counter")
		for _, name := range clientNames {
			c := snap.PerClient[name]
			fmt.Fprintf(w, "aiproxy_client_estimated_cost{client=%q} %g\n", promLabelValue(name), c.EstimatedCost(costPer1KTokens))
		}
	}

	// Unlabeled, same reasoning as promDryRunCounters: a rejected
	// request never gets far enough to resolve a target to label it
	// with.
	fmt.Fprintln(w, "# HELP aiproxy_unauthorized_total Total number of requests rejected for a missing or invalid Proxy-Authorization header.")
	fmt.Fprintln(w, "# TYPE aiproxy_unauthorized_total counter")
	fmt.Fprintf(w, "aiproxy_unauthorized_total %d\n", snap.Unauthorized)

	// Unlabeled, same reasoning as aiproxy_unauthorized_total: an
	// IP-denied request never gets far enough to resolve a target.
	fmt.Fprintln(w, "# HELP aiproxy_ip_denied_total Total number of requests rejected by the IP allow/deny list.")
	fmt.Fprintln(w, "# TYPE aiproxy_ip_denied_total counter")
	fmt.Fprintf(w, "aiproxy_ip_denied_total %d\n", snap.IPDenied)

	// Unlabeled, same reasoning as aiproxy_ip_denied_total: a
	// country-denied request never gets far enough to resolve a target.
	fmt.Fprintln(w, "# HELP aiproxy_country_denied_total Total number of requests rejected by the GeoIP country allow/deny list.")
	fmt.Fprintln(w, "# TYPE aiproxy_country_denied_total counter")
	fmt.Fprintf(w, "aiproxy_country_denied_total %d\n", snap.CountryDenied)

	// Unlabeled: broken down per client via aiproxy_client_anomaly_detected_total
	// above instead, not per target.
	fmt.Fprintln(w, "# HELP aiproxy_anomaly_detected_total Total number of requests rejected for spiking past their client's own recent baseline request rate.")
	fmt.Fprintln(w, "# TYPE aiproxy_anomaly_detected_total counter")
	fmt.Fprintf(w, "aiproxy_anomaly_detected_total %d\n", snap.AnomalyDetected)

	// Unlabeled: the transition is about one specific candidate URL, not
	// a route label, so there's no target dimension to break this down
	// by — see stats.Snapshot.TargetsEjected/TargetsRecovered.
	fmt.Fprintln(w, "# HELP aiproxy_targets_ejected_total Total number of times a candidate upstream URL crossed its consecutive-failure threshold and was temporarily deprioritized.")
	fmt.Fprintln(w, "# TYPE aiproxy_targets_ejected_total counter")
	fmt.Fprintf(w, "aiproxy_targets_ejected_total %d\n", snap.TargetsEjected)
	fmt.Fprintln(w, "# HELP aiproxy_targets_recovered_total Total number of times a previously-ejected candidate upstream URL succeeded again.")
	fmt.Fprintln(w, "# TYPE aiproxy_targets_recovered_total counter")
	fmt.Fprintf(w, "aiproxy_targets_recovered_total %d\n", snap.TargetsRecovered)

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

// writeLatencyHistogram emits one aiproxy_upstream_latency_seconds
// histogram series per target, labeled target="<name>", in the exact
// shape Prometheus's histogram_quantile() expects: cumulative _bucket
// lines per "le" bound (ascending, ending in "+Inf"), then _sum and
// _count — see stats.LatencySnapshot. names is the same sorted target
// list writePromMetrics already built, for a stable scrape-to-scrape
// order shared with every other series.
func writeLatencyHistogram(w io.Writer, perTarget map[string]stats.Snapshot, names []string) {
	fmt.Fprintln(w, "# HELP aiproxy_upstream_latency_seconds Observed latency of successful upstream responses, per target — use histogram_quantile() for percentiles.")
	fmt.Fprintln(w, "# TYPE aiproxy_upstream_latency_seconds histogram")
	for _, name := range names {
		label := promLabelValue(name)
		lat := perTarget[name].Latency
		for _, b := range lat.Buckets {
			fmt.Fprintf(w, "aiproxy_upstream_latency_seconds_bucket{target=%q,le=%q} %d\n", label, b.Le, b.Count)
		}
		fmt.Fprintf(w, "aiproxy_upstream_latency_seconds_sum{target=%q} %g\n", label, lat.SumSeconds)
		fmt.Fprintf(w, "aiproxy_upstream_latency_seconds_count{target=%q} %d\n", label, lat.Count)
	}
}

// serveMetrics answers metricsPath with the current Stats snapshot in
// Prometheus's text exposition format. Like serveStats, it never
// touches rules, the rate limiter, or the cache, and a scrape is never
// itself counted in Stats.
func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", "")
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
	if breakdown := snap.PerClientString(cost); breakdown != "" {
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
	// The JSON shape is computed and written to LogFile unconditionally
	// — a durable on-disk record should include the session's own final
	// summary regardless of what --log-format the terminal is showing.
	payload := withCostBudget(toStatsSnapshotJSON(s.Stats.Snapshot(), s.getCostPer1KTokens()), s.getCostBudget())
	data, err := json.Marshal(payload)
	if err != nil {
		s.logError("aiproxy: summary: failed to encode: %v", err)
		return
	}
	s.appendToLogFile(data)

	if s.LogFormat == LogFormatJSON {
		s.logf("%s", data)
		return
	}
	s.logf("%s", s.Summary())
}

// errorLogWriter adapts http.Server.ErrorLog's *log.Logger-based output
// into this package's own LogEvent-based event stream. Without this,
// Go's internal server errors — most commonly a TLS handshake failure,
// the ordinary result of a stray plain-HTTP health check or port scan
// hitting a TLS-enabled listener — would instead go straight to
// log.Default()'s own destination (the process's real stderr),
// bypassing LogFormat/LogFile entirely and, under LogFormatJSON,
// breaking the documented "every line in the stream is valid JSON"
// guarantee the very first time TLS is enabled and something other
// than a real client connects.
type errorLogWriter struct {
	server *Server
}

func (w errorLogWriter) Write(p []byte) (int, error) {
	w.server.LogEvent("server_error", strings.TrimSpace(string(p)))
	return len(p), nil
}

// ListenAndServe starts the proxy and blocks until ctx is cancelled or a
// fatal server error occurs. Serves plain HTTP unless both TLSCertFile
// and TLSKeyFile are set, in which case it terminates TLS itself via
// http.Server.ListenAndServeTLS instead. When AdminAddr is also set, a
// second http.Server is started for it, serving adminMux instead of s
// (see AdminAddr's doc comment) — under the same TLS configuration as
// the main listener, so a caller who wants the admin surface isolated
// on its own network boundary doesn't also have to manage a second
// certificate purely to keep both listeners on equal footing. A fatal
// error on either listener stops both; ctx cancellation shuts both down
// gracefully together.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.httpServer = &http.Server{
		Addr:     s.Addr,
		Handler:  s,
		ErrorLog: log.New(errorLogWriter{server: s}, "", 0),
	}

	errCh := make(chan error, 2)
	serve := func(srv *http.Server) {
		var err error
		if s.TLSCertFile != "" && s.TLSKeyFile != "" {
			err = srv.ListenAndServeTLS(s.TLSCertFile, s.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}
	go serve(s.httpServer)

	if s.AdminAddr != "" {
		s.adminHTTPServer = &http.Server{
			Addr:     s.AdminAddr,
			Handler:  adminMux{server: s},
			ErrorLog: log.New(errorLogWriter{server: s}, "", 0),
		}
		go serve(s.adminHTTPServer)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := s.httpServer.Shutdown(shutdownCtx)
		if s.adminHTTPServer != nil {
			if adminErr := s.adminHTTPServer.Shutdown(shutdownCtx); adminErr != nil && err == nil {
				err = adminErr
			}
		}
		s.logSummary()
		return err
	case err := <-errCh:
		return fmt.Errorf("proxy: %w", err)
	}
}
