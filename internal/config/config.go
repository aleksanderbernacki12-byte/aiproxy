// Package config reads aiproxy's on-disk JSON configuration. It only
// turns a config file into plain Go structs using the standard library's
// encoding/json — it knows nothing about regexes, rules, or the proxy,
// so it stays testable and reusable independently of how its data ends
// up being used.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// CustomRule is one user-defined rule as it appears in the config file,
// before its pattern has been compiled.
type CustomRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`

	// Action is "block" (the default when the field is absent) or
	// "redact": block rejects a matching request outright, redact masks
	// every occurrence of the matched pattern in the body and forwards
	// the request instead.
	Action string `json:"action,omitempty"`

	// DryRun, if true, makes this rule only report what it would have
	// done — via logs, the webhook, and stats — without actually
	// blocking or redacting anything; the request or response is
	// forwarded exactly as if the rule had never matched. False (the
	// default when the field is absent) means the rule is fully live.
	// Meant for trying a new rule out against real traffic before
	// trusting it to actually enforce anything.
	DryRun bool `json:"dry_run,omitempty"`

	// Targets, if non-empty, restricts this rule to only requests (and
	// their responses) routed to one of these targets — matching the
	// same label used in stats/logs/Prometheus: "default" for the
	// fallback --target, a configured targets[] entry's own Prefix, or
	// "model:<name>" for a configured model_routes[] entry. Empty (the
	// default when the field is absent) applies this rule to every
	// target, unchanged from before this field existed. Each entry must
	// name an actually-configured target/route; aiproxy validate and a
	// cold start both reject an unknown one, the same way an unknown
	// builtin_rule_actions key is rejected, rather than silently
	// compiling a rule that can never match.
	Targets []string `json:"targets,omitempty"`

	// Keys, if non-empty, restricts this rule to only requests (and
	// their responses) authenticated with one of these named proxy
	// keys — "default" for the anonymous top-level ProxyAPIKey, or a
	// ProxyAPIKeyEntry's own Name. Empty (the default when the field is
	// absent) applies this rule regardless of which key (or none at
	// all) made the request, unchanged from before this field existed.
	// When both Targets and Keys are set, a request must match both —
	// they narrow the same rule together, not independently. Each entry
	// must name an actually-configured key, same validation rigor as
	// Targets.
	Keys []string `json:"keys,omitempty"`
}

// PathRule is one path-prefix endpoint rule as it appears in the config
// file: block or explicitly allow every request under Prefix outright,
// independent of its content.
type PathRule struct {
	Name   string `json:"name"`
	Prefix string `json:"prefix"`

	// Action is "block" (reject every matching request before it's even
	// scanned) or "allow" (exempt every matching request from every
	// other rule — built-in, custom, body, and header — entirely; for a
	// known-safe endpoint, e.g. a health check, that would otherwise
	// risk a false positive). Unlike CustomRule.Action, there is no
	// default when the field is absent: block and allow are opposite
	// intents, so silently defaulting to either could surprise the user
	// in a way that matters.
	Action string `json:"action"`

	// DryRun, if true, makes a "block" rule only report what it would
	// have rejected — via logs, the webhook, and stats — instead of
	// actually rejecting it; the request is forwarded exactly as if the
	// rule had never matched. False (the default when the field is
	// absent) means the rule is fully live. Only meaningful combined
	// with "block": there is nothing to preview for "allow", which
	// never rejects anything to begin with, so combining the two is a
	// config error (see the CLI's path rule validation).
	DryRun bool `json:"dry_run,omitempty"`
}

// WebhookTarget is one additional webhook destination, alongside the
// top-level WebhookURL, as it appears in the config file.
type WebhookTarget struct {
	URL string `json:"url"`

	// Events, if non-empty, limits this destination to only the named
	// event types (e.g. ["budget_exceeded", "failover"]). Empty (the
	// default when the field is absent) means this destination receives
	// every event, same as WebhookURL's own unfiltered behavior. The
	// CLI's webhookEventNames has the full valid set.
	Events []string `json:"events,omitempty"`
}

// ProxyAPIKeyEntry is one additional named proxy key, alongside the
// top-level ProxyAPIKey, as it appears in the config file.
type ProxyAPIKeyEntry struct {
	// Name identifies this key in stats, logs, and webhook payloads —
	// never the key itself. Must be non-empty and unique among every
	// entry (and can't be "default", reserved for the anonymous
	// top-level ProxyAPIKey) — a collision would silently merge two
	// different callers' attributed numbers together.
	Name string `json:"name"`
	Key  string `json:"key"`

	// MaxRequestsPerMinute, if greater than zero, gives this key its own
	// dedicated rate limit — checked instead of whatever route or the
	// server-wide limiter would otherwise apply, since a caller's own
	// budget is authoritative regardless of which route they hit. Zero
	// (the default) means this key shares whatever route/global limiter
	// would otherwise apply, same as before this field existed.
	MaxRequestsPerMinute int `json:"max_requests_per_minute,omitempty"`

	// MaxTokensPerMinute, if greater than zero, gives this key its own
	// dedicated token-based rate limit — checked instead of whatever
	// route or the server-wide token breaker would otherwise apply, same
	// precedence MaxRequestsPerMinute already has. Zero (the default)
	// means this key shares whatever route/global token breaker would
	// otherwise apply.
	MaxTokensPerMinute int `json:"max_tokens_per_minute,omitempty"`

	// CostBudget, if greater than zero, is a threshold in the same
	// currency/rate as the top-level CostPer1KTokens — once this key's
	// own running cost (its own attributed TotalTokens priced at
	// CostPer1KTokens) reaches or passes it, aiproxy logs and
	// webhook-alerts a budget_exceeded event carrying this key's Name,
	// independent of the server-wide CostBudget (if any) and of every
	// other key's own budget — each fires once, on its own. Alert-only
	// by default, same as the top-level CostBudget — see
	// CostBudgetHardStop for actual enforcement. Only meaningful
	// alongside the top-level CostPer1KTokens: a budget with no rate to
	// price tokens at has nothing to compare against, so setting this
	// without CostPer1KTokens is a config error, same reasoning as the
	// top-level CostBudget. Zero (the default) means this key has no
	// budget of its own.
	CostBudget float64 `json:"cost_budget,omitempty"`

	// CostBudgetHardStop, if true, turns this key's own CostBudget from
	// a one-time alert into real enforcement: once its running cost has
	// reached or passed CostBudget, every subsequent request
	// authenticated with this key is rejected (402) instead of being
	// forwarded — independent of the server-wide CostBudgetHardStop (if
	// any) and of every other key's own, the same independence CostBudget
	// itself already has. A cache hit is never rejected — it costs
	// nothing additional regardless. Stays rejecting for the rest of the
	// process's life once tripped; there's no time window or reset, the
	// same "budgets never expire on their own" behavior CostBudget's own
	// one-shot alert already has. Only meaningful alongside CostBudget —
	// a hard stop with no budget to enforce is a config error, same
	// reasoning as CostBudget requiring CostPer1KTokens. false (the
	// default) keeps this key's own CostBudget alert-only, unchanged
	// from before this field existed.
	CostBudgetHardStop bool `json:"cost_budget_hard_stop,omitempty"`
}

// WeightedURL is one candidate in a Target's or ModelRoute's own
// WeightedURLs list — a single upstream URL plus its relative share of
// traffic. Weight must be positive; the actual probability of this
// candidate being chosen for any one request is Weight divided by the
// sum of every candidate's own Weight in the same list (weights don't
// need to add up to 100 or any particular total — only their relative
// proportions to each other matter).
type WeightedURL struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// Target is one path-prefix-to-upstream mapping for multi-target
// routing, as it appears in the config file, before URL/URLs has been
// parsed.
type Target struct {
	Prefix string `json:"prefix"`

	// URL is a single upstream — the original, still-supported shape.
	// Mutually exclusive with URLs: a target sets exactly one of the two.
	URL string `json:"url,omitempty"`

	// URLs, set instead of URL, gives this target an ordered list of
	// upstream candidates to fail over across: a request tries the first
	// URL, and only moves on to the next if that attempt never got a
	// response at all (a dial/TLS/timeout failure — the candidate was
	// unreachable). It never retries a different candidate just because
	// one returned an HTTP-level error response (a 5xx): by the time a
	// backend has responded at all, it may already have started acting
	// on the request, and blindly replaying that against a different
	// backend risks a duplicate side effect — a duplicate, possibly
	// billed, LLM call being the textbook case for this proxy. At least
	// one URL is required when this is set.
	URLs []string `json:"urls,omitempty"`

	// WeightedURLs, set instead of URL/URLs, gives this target a set of
	// candidates split by deliberate, configured proportion — a canary
	// rollout or an A/B comparison between two genuinely different
	// destinations (a new model, a different provider), unlike URLs'
	// own ordered failover list, which exists for candidates meant to
	// be interchangeable backups of the very same logical destination.
	// One candidate is chosen at random, in proportion to its own
	// Weight relative to the others, fresh for every request, so across
	// many requests the actual traffic split approximates the
	// configured weights. The chosen candidate still gets exactly the
	// same failover/target-ejection protection every other route
	// already has — if it happens to be unreachable, aiproxy still
	// tries the rest, in their declared order, rather than failing the
	// request outright, the same "never refuse a genuine attempt when
	// there's a healthier alternative" principle target_ejection_threshold
	// already established; a real outage on the smaller side of a split
	// can therefore temporarily skew the actual ratio toward the
	// healthier side, favoring uptime over strict adherence to the
	// configured proportion. At least two candidates are expected (a
	// single one makes the weight meaningless), though only one is
	// technically required, same as URLs.
	WeightedURLs []WeightedURL `json:"weighted_urls,omitempty"`

	// MaxRequestsPerMinute, if greater than zero, gives this target its
	// own dedicated rate limit instead of sharing the top-level
	// max_requests_per_minute limiter with every other target. Zero (the
	// default when the field is absent) means this target has no
	// override and simply shares the top-level limiter, same as before
	// per-target limits existed.
	MaxRequestsPerMinute int `json:"max_requests_per_minute,omitempty"`

	// MaxTokensPerMinute, if greater than zero, gives this target its own
	// dedicated token-based rate limit instead of sharing the top-level
	// max_tokens_per_minute breaker with every other target — same
	// meaning and same peek-before/record-after semantics as the
	// top-level MaxTokensPerMinute (see Config.MaxTokensPerMinute), just
	// scoped to this target's own traffic. Zero (the default) means this
	// target has no override and simply shares the top-level breaker,
	// same as MaxRequestsPerMinute.
	MaxTokensPerMinute int `json:"max_tokens_per_minute,omitempty"`

	// CostPer1KTokens, if greater than zero, prices this one target's
	// own tokens at its own rate instead of the top-level
	// Config.CostPer1KTokens — useful once traffic is actually routed
	// across providers with genuinely different pricing (OpenAI vs.
	// Anthropic vs. a self-hosted model, say), where a single global
	// rate would misprice every target that doesn't happen to match it.
	// A target CAN set this even when the top-level rate is zero/unset,
	// pricing only that target while leaving everything else unpriced.
	// Zero (the default when the field is absent) means this target has
	// no override and simply shares the top-level rate, same as before
	// per-target rates existed.
	CostPer1KTokens float64 `json:"cost_per_1k_tokens,omitempty"`

	// CacheEnabled, if set, overrides the top-level Config.CacheEnabled
	// for just this one target's own traffic: false opts this target
	// out of caching even while the top-level cache is on (a target
	// whose responses are highly volatile, or too sensitive to ever
	// persist to disk, alongside others that are safe to cache
	// normally); true is only meaningful — and requires — the top-level
	// cache already being on, since a per-target setting alone should
	// never be what silently stands up real on-disk cache
	// infrastructure. nil (the default when the field is absent) means
	// this target has no override and simply inherits the top-level
	// setting, same as before per-target overrides existed. A pointer,
	// not a plain bool, so "explicitly false" is distinguishable from
	// "not set at all."
	CacheEnabled *bool `json:"cache_enabled,omitempty"`

	// CacheTTLSeconds, if greater than zero, overrides the top-level
	// Config.CacheTTLSeconds for just this one target's own cache
	// entries — same meaning, just scoped to this target. Requires
	// caching to actually be active for this target (either the
	// top-level cache_enabled, or this same entry's own CacheEnabled
	// override). Zero (the default when the field is absent) means no
	// override; this target's entries expire on the top-level TTL
	// instead (or never, if that's unset too).
	CacheTTLSeconds int `json:"cache_ttl_seconds,omitempty"`

	// ShadowURL, if set, mirrors a copy of every request this target
	// forwards to a second, independent destination — after the exact
	// same rule processing (redaction included) the real request goes
	// through, so the shadow target can never receive anything the
	// real one wouldn't also see. Runs in the background: its response
	// (success or failure, whatever its status code) is discarded
	// entirely and never affects the client's own response in any
	// way — not its status code, not its latency, not whether it
	// succeeds at all. For canary-testing a new model/provider/version
	// against real production traffic with zero risk to what the
	// client actually receives. Independent of URL/URLs/WeightedURLs:
	// this target still resolves its own real candidate(s) completely
	// normally; the shadow is purely an extra, disposable copy sent
	// alongside, with no failover, retries, or target-ejection
	// tracking of its own. Must pass the same https validation as URL.
	// Empty (the default) means no shadowing at all for this target.
	ShadowURL string `json:"shadow_url,omitempty"`

	// ShadowSampleRate controls what fraction of this target's
	// forwarded requests actually get mirrored to ShadowURL — a value
	// in (0, 1]. Meaningless without ShadowURL, same reasoning as
	// CacheTTLSeconds without CacheEnabled. Zero/absent, when ShadowURL
	// IS set, defaults to 1.0 (mirror every forwarded request) —
	// configuring a shadow target at all is already a deliberate act,
	// so mirroring everything by default is the least surprising
	// starting point; lower it to reduce the shadow target's own
	// load/cost (and the real, possibly billed cost of a canary
	// upstream) once a full mirror isn't necessary.
	ShadowSampleRate float64 `json:"shadow_sample_rate,omitempty"`
}

// ModelRoute is one model-name-to-upstream mapping for content-based
// routing, as it appears in the config file, before URL/URLs has been
// parsed. Unlike Target, which routes by URL path prefix, a ModelRoute
// matches the "model" field inside the request body's own JSON — the
// way a single endpoint fronting several LLM providers (an
// OpenAI-compatible client pointed at one aiproxy URL, picking its
// model per request) can still be routed to the right upstream.
type ModelRoute struct {
	// Name identifies this route in stats, logs, and webhook payloads —
	// must be non-empty and unique among every entry.
	Name string `json:"name"`

	// Models is a non-empty list of glob patterns (path.Match syntax:
	// "*", "?", "[...]" — the same shape as a shell glob) matched
	// against the request body's top-level "model" field. Routes are
	// checked in the order they appear in the file; the first one with
	// any matching pattern wins, same "first match, in order" rule as
	// Targets' path prefixes.
	Models []string `json:"models"`

	// URL is a single upstream — same meaning as Target.URL. Mutually
	// exclusive with URLs: a route sets exactly one of the two.
	URL string `json:"url,omitempty"`

	// URLs, set instead of URL, gives this route an ordered failover
	// list — same meaning and same never-retry-on-5xx safety boundary
	// as Target.URLs.
	URLs []string `json:"urls,omitempty"`

	// WeightedURLs, set instead of URL/URLs, splits this route's own
	// traffic by deliberate, configured proportion — same meaning as
	// Target.WeightedURLs.
	WeightedURLs []WeightedURL `json:"weighted_urls,omitempty"`

	// MaxRequestsPerMinute, if greater than zero, gives this route its
	// own dedicated rate limit instead of sharing the top-level
	// max_requests_per_minute limiter with every other target — same
	// meaning as Target.MaxRequestsPerMinute.
	MaxRequestsPerMinute int `json:"max_requests_per_minute,omitempty"`

	// MaxTokensPerMinute, if greater than zero, gives this route its own
	// dedicated token-based rate limit instead of sharing the top-level
	// max_tokens_per_minute breaker with every other target — same
	// meaning as Target.MaxTokensPerMinute.
	MaxTokensPerMinute int `json:"max_tokens_per_minute,omitempty"`

	// CostPer1KTokens, if greater than zero, prices this route's own
	// tokens at its own rate instead of the top-level
	// Config.CostPer1KTokens — same meaning as Target.CostPer1KTokens,
	// keyed under the "model:<name>" label instead of a targets[]
	// prefix.
	CostPer1KTokens float64 `json:"cost_per_1k_tokens,omitempty"`

	// CacheEnabled/CacheTTLSeconds override the top-level cache settings
	// for just this route's own traffic — same meaning as
	// Target.CacheEnabled/Target.CacheTTLSeconds, keyed under the
	// "model:<name>" label instead of a targets[] prefix.
	CacheEnabled    *bool `json:"cache_enabled,omitempty"`
	CacheTTLSeconds int   `json:"cache_ttl_seconds,omitempty"`

	// ShadowURL/ShadowSampleRate mirror a copy of this route's own
	// forwarded requests to a second destination — same meaning as
	// Target.ShadowURL/Target.ShadowSampleRate, keyed under the
	// "model:<name>" label instead of a targets[] prefix.
	ShadowURL        string  `json:"shadow_url,omitempty"`
	ShadowSampleRate float64 `json:"shadow_sample_rate,omitempty"`
}

// Config is the top-level shape of aiproxy.json.
type Config struct {
	CustomRules []CustomRule `json:"custom_rules"`

	// MaxRequestsPerMinute caps how many requests the proxy's circuit
	// breaker allows per minute. Zero (the default when the field is
	// absent) means the rate limiter is disabled.
	MaxRequestsPerMinute int `json:"max_requests_per_minute"`

	// MaxTokensPerMinute, if greater than zero, caps how many upstream
	// response tokens the proxy allows to have been used within any
	// rolling minute before rejecting further requests with a 429 — a
	// second circuit breaker, orthogonal to MaxRequestsPerMinute's plain
	// request count, for traffic where a handful of huge completions can
	// matter more than how many calls were made. Unlike
	// MaxRequestsPerMinute, a request's own cost isn't known until its
	// response comes back, so this only ever rejects once the window is
	// already at or over budget from usage recorded so far — a single
	// very large request can still push the window over by more than
	// this many tokens before the next one is rejected. Zero (the
	// default when the field is absent) disables this breaker entirely.
	MaxTokensPerMinute int `json:"max_tokens_per_minute,omitempty"`

	// MaxRequestsPerMinutePerIP, if greater than zero, gives every
	// distinct caller IP its own dedicated request budget of this many
	// requests per rolling minute — independent of, and checked before,
	// proxy_api_key/proxy_api_keys identity, so a caller that never
	// presents a key (or one aiproxy doesn't even require) still can't
	// monopolize the proxy the way it could sharing one pool with every
	// other unidentified caller. A network-layer gate, checked alongside
	// ip_allow_list/ip_deny_list — see the iplimiter package. Zero (the
	// default when the field is absent) disables this entirely.
	MaxRequestsPerMinutePerIP int `json:"max_requests_per_minute_per_ip,omitempty"`

	// UpstreamResponseTimeoutSeconds, if greater than zero, caps how
	// long aiproxy waits for an upstream to begin responding (its
	// status line and headers) to a forwarded request before giving up
	// — protects against a hung or dead upstream connection that
	// accepted the request but never responds at all. It never affects
	// an upstream that starts responding promptly, no matter how long
	// the response body or stream itself then takes to finish — see
	// UpstreamTotalTimeoutSeconds for a cap on that. Zero (the default
	// when the field is absent) means no limit, Go's stdlib default
	// behavior — the same one aiproxy has always had.
	UpstreamResponseTimeoutSeconds int `json:"upstream_response_timeout_seconds,omitempty"`

	// UpstreamTotalTimeoutSeconds, if greater than zero, caps a
	// forwarded request's entire round trip — connecting, headers, and
	// reading the complete response or stream, across every failover
	// candidate tried for it — at this many seconds, aborting it if
	// it's still running past that point. Unlike
	// UpstreamResponseTimeoutSeconds, this can cut off a legitimately
	// long-running streaming completion that's actively sending data;
	// only set it when a hard ceiling on total request duration is
	// actually wanted, independent of whether the upstream is still
	// making progress. Zero (the default when the field is absent)
	// means no limit.
	UpstreamTotalTimeoutSeconds int `json:"upstream_total_timeout_seconds,omitempty"`

	// CORSAllowedOrigins, if non-empty, makes aiproxy answer CORS
	// preflight requests (an OPTIONS request carrying an
	// Access-Control-Request-Method header — the browser's own signal
	// that this OPTIONS exists purely to ask permission for a
	// cross-origin request, never reaching rules, rate limiting, auth,
	// or the upstream target) and add CORS response headers to every
	// response aiproxy produces, including a rejection (block,
	// rate-limited, ip_denied, ...) — so a browser-based client's own
	// error handling actually sees why a request failed instead of an
	// opaque CORS failure masking the real reason. "*" matches any
	// origin; anything else must be an exact "scheme://host[:port]"
	// origin (no path/query/fragment), checked against the request's
	// own Origin header — aiproxy always echoes back that specific
	// origin value in Access-Control-Allow-Origin, never the literal
	// "*", the one echo shape that's always spec-correct whether or not
	// CORSAllowCredentials is set (a literal "*" is forbidden alongside
	// credentials). Empty (the default when the field is absent)
	// disables CORS handling entirely — the exact behavior aiproxy had
	// before this feature existed.
	CORSAllowedOrigins []string `json:"cors_allowed_origins,omitempty"`

	// CORSAllowedMethods lists the HTTP methods a preflight response
	// advertises as allowed. Only meaningful alongside
	// CORSAllowedOrigins. Defaults to "GET, POST, PUT, PATCH, DELETE,
	// OPTIONS" when CORSAllowedOrigins is set but this is left
	// empty/absent — a reasonable default covering every method a
	// typical LLM API and aiproxy's own admin endpoints actually use.
	CORSAllowedMethods []string `json:"cors_allowed_methods,omitempty"`

	// CORSAllowedHeaders, if set, restricts which request headers a
	// preflight response advertises as allowed, instead of aiproxy's
	// own default of reflecting back whatever the browser's preflight
	// actually asked for (via Access-Control-Request-Headers) — the
	// same permissive-but-safe default most CORS middleware uses, since
	// CORS exists to protect a server from a malicious *page*, not the
	// other way around, and a hand-typed allowlist here risks silently
	// breaking Proxy-Authorization/Authorization/X-Api-Key the moment
	// one is left off. Only meaningful alongside CORSAllowedOrigins.
	CORSAllowedHeaders []string `json:"cors_allowed_headers,omitempty"`

	// CORSAllowCredentials, if true, adds
	// Access-Control-Allow-Credentials: true to every CORS-eligible
	// response. Only meaningful alongside CORSAllowedOrigins.
	CORSAllowCredentials bool `json:"cors_allow_credentials,omitempty"`

	// CORSMaxAgeSeconds, if greater than zero, is how long (via
	// Access-Control-Max-Age) a browser may cache a preflight response
	// before sending a new one for the same request shape. Zero/absent
	// (the default) omits the header, leaving the browser's own default
	// in effect. Only meaningful alongside CORSAllowedOrigins.
	CORSMaxAgeSeconds int `json:"cors_max_age_seconds,omitempty"`

	// TargetEjectionThreshold, if greater than zero, temporarily
	// deprioritizes a candidate upstream URL once it has failed this
	// many times in a row with a transport-level error (dial/TLS/timeout
	// — never an HTTP-level error response, the same "only a genuinely
	// unreachable candidate counts" rule failover itself already
	// applies) — see the breaker package. Deprioritized only ever means
	// a route with more than one candidate tries a healthier one first;
	// a single-target route (or a route whose every candidate is
	// currently deprioritized) always still makes a genuine attempt,
	// since there is nothing better to try instead. Requires
	// TargetEjectionCooldownSeconds to also be set. Zero (the default
	// when the field is absent) disables this entirely.
	TargetEjectionThreshold int `json:"target_ejection_threshold,omitempty"`

	// TargetEjectionCooldownSeconds is how long a candidate stays
	// deprioritized after crossing TargetEjectionThreshold, before being
	// preferred again. Only meaningful alongside
	// TargetEjectionThreshold: a cooldown for a breaker that never trips
	// has nothing to time, so setting this without
	// TargetEjectionThreshold is a config error, same reasoning as
	// AnomalyDryRun requiring AnomalyMultiplier.
	TargetEjectionCooldownSeconds int `json:"target_ejection_cooldown_seconds,omitempty"`

	// TargetHealthCheckIntervalSeconds, if greater than zero, makes
	// aiproxy proactively probe every currently configured candidate
	// upstream URL (--target plus every targets[]/model_routes[]
	// candidate, deduplicated) on this interval, in the background,
	// independent of real client traffic — so a dead target is
	// discovered and deprioritized before a real request has to fail
	// against it first, rather than only reactively after one does.
	// Feeds the exact same breaker.Registry TargetEjectionThreshold
	// already configures: a probe that fails is recorded exactly like a
	// real request's own transport-level failure, and a probe that
	// succeeds clears it exactly like a real request's own success —
	// one shared notion of "unhealthy," with no separate threshold,
	// cooldown, log line, or webhook event of its own. Requires
	// TargetEjectionThreshold/TargetEjectionCooldownSeconds to already
	// be set — there's no breaker for a health check to report into
	// otherwise. Zero (the default when the field is absent) disables
	// this entirely; aiproxy only ever finds out about a dead target
	// reactively, the exact behavior it always had before this feature
	// existed.
	TargetHealthCheckIntervalSeconds int `json:"target_health_check_interval_seconds,omitempty"`

	// TargetHealthCheckPath, if set, is the path probed on each
	// candidate instead of its own configured path — e.g. probing
	// "/health" on every candidate rather than each target's own base
	// URL. A probe counts as healthy the moment it receives ANY HTTP
	// response at all, regardless of status code — the same "only a
	// genuine transport-level failure counts" rule failover itself
	// already applies — since an arbitrary upstream LLM API has no
	// universal unauthenticated health-check convention, but completing
	// the HTTP exchange at all still proves the candidate is genuinely
	// reachable. Only meaningful alongside
	// TargetHealthCheckIntervalSeconds; empty (the default) probes each
	// candidate's own configured URL unchanged.
	TargetHealthCheckPath string `json:"target_health_check_path,omitempty"`

	// AnomalyMultiplier, if greater than zero, flags — and, unless
	// AnomalyDryRun is set, rejects with a 429 — a request from a
	// named proxy client (see ProxyAPIKeys) whose current minute's
	// request count has reached this many times its own established
	// recent baseline (an exponential moving average of its own past
	// per-minute counts — see the anomaly package). A complement to
	// MaxRequestsPerMinute's fixed cap: that only ever catches a
	// caller that's too fast in absolute terms, never one that's
	// merely far faster than it itself normally is — a caller well
	// under any configured fixed limit can still be a runaway agent
	// loop relative to its own quiet-normal traffic. Only meaningful
	// for an identified caller (ProxyAPIKey/ProxyAPIKeys configured);
	// a fully anonymous proxy has no notion of "one caller's own
	// baseline" to compare against, so this has no effect without one.
	// Zero (the default when the field is absent) disables this
	// breaker entirely.
	AnomalyMultiplier float64 `json:"anomaly_multiplier,omitempty"`

	// AnomalyDryRun, if true, makes AnomalyMultiplier only report what
	// it would have done — via logs, the webhook, and stats — without
	// actually rejecting anything, the same escape hatch CustomRule's
	// own DryRun gives a new content rule. Meant for tuning
	// AnomalyMultiplier against real traffic before trusting it to
	// actually enforce anything — a statistical threshold is
	// inherently more prone to a false positive than an exact secret
	// pattern match. False (the default) means the breaker is fully
	// live whenever AnomalyMultiplier is set. Meaningless (and
	// rejected by aiproxy validate) without AnomalyMultiplier also set.
	AnomalyDryRun bool `json:"anomaly_dry_run,omitempty"`

	// CacheEnabled turns on the proxy's local on-disk response cache.
	// False (the default when the field is absent) means the cache is
	// disabled.
	CacheEnabled bool `json:"cache_enabled"`

	// CacheTTLSeconds, if greater than zero, expires a cached response
	// this many seconds after it was written — a request whose matching
	// entry is older than this is treated as a cache miss and forwarded
	// upstream again, same as if nothing had ever been cached for it.
	// Zero (the default when the field is absent) means cached entries
	// never expire on their own, same behavior as before this field
	// existed. Only meaningful alongside CacheEnabled: a TTL for a cache
	// that's off has nothing to expire, so setting this without
	// CacheEnabled is a config error, same reasoning as CostBudget
	// requiring CostPer1KTokens.
	CacheTTLSeconds int `json:"cache_ttl_seconds,omitempty"`

	// CacheMaxSizeBytes, if greater than zero, caps the total on-disk
	// size of every cached entry combined — once writing a new entry
	// would push the total over this limit, the least-recently-used
	// entries (an in-memory index, evicted oldest-used-first, tracked
	// separately from CacheTTLSeconds' own write-time-based expiry) are
	// deleted until there's room again. A single entry larger than this
	// limit on its own is never deleted just for existing — there's
	// nothing meaningful to evict it in favor of. Zero (the default when
	// the field is absent) means the cache is never size-capped,
	// unbounded, same behavior as before this field existed. Only
	// meaningful alongside CacheEnabled, same reasoning as
	// CacheTTLSeconds.
	CacheMaxSizeBytes int64 `json:"cache_max_size_bytes,omitempty"`

	// CacheRequestCoalescing, if true, collapses concurrent requests
	// that would otherwise all be simultaneous cache misses for the
	// exact same content into one: the first one forwards normally,
	// and every other one that arrives before it finishes waits for its
	// response instead of independently forwarding an identical,
	// redundant duplicate to the same upstream target — a "thundering
	// herd" of otherwise-identical calls (many agents happening to ask
	// the same question at once, say) collapsed into one real upstream
	// call. Purely an optimization, invisible to the client: a
	// coalesced response looks exactly like an ordinary forwarded one,
	// with no marker header the way an idempotency replay has. Only
	// meaningful alongside CacheEnabled — the "content-derived cache
	// key" this collapses requests by is the same key the real response
	// cache itself already computes, so setting this without
	// CacheEnabled is a config error, same reasoning as
	// CacheTTLSeconds. false (the default) means concurrent identical
	// requests are all forwarded independently, unchanged from before
	// this field existed.
	CacheRequestCoalescing bool `json:"cache_request_coalescing,omitempty"`

	// SemanticCacheEnabled turns on an approximate second cache layer:
	// when the exact-match cache misses, aiproxy checks whether a
	// recent, sufficiently similar request (see SemanticCacheThreshold)
	// already produced a cached answer for this target, using only a
	// local text-similarity comparison — no external embeddings API, no
	// added latency or cost on a miss. Global only, no per-target
	// override, mirroring CacheRequestCoalescing rather than the older
	// per-target CacheEnabled/CacheTTLSeconds pattern. A hit here is
	// marked with an X-Semantic-Cache-Hit response header, unlike
	// CacheRequestCoalescing's deliberately invisible replay: unlike
	// coalescing, which serves the literal answer the client would have
	// gotten anyway, a semantic hit can serve the answer to a materially
	// different request, which the client should be able to detect. Only
	// meaningful alongside CacheEnabled, same reasoning as
	// CacheRequestCoalescing: there's no cache key for a semantic match
	// to point at otherwise. false (the default) means this second
	// lookup layer never runs at all, unchanged from before this field
	// existed.
	SemanticCacheEnabled bool `json:"semantic_cache_enabled,omitempty"`

	// SemanticCacheThreshold is the minimum Jaccard similarity (0
	// exclusive, 1 inclusive) two requests' extracted prompt text must
	// reach for the more recent one to be served the older one's cached
	// answer — see the semcache package. Required whenever
	// SemanticCacheEnabled is true: unlike CacheTTLSeconds' "zero means
	// never expire" default, there is no universally safe default
	// threshold (too low risks serving a mismatched answer, too high
	// makes the feature a no-op, and the right value is inherently
	// workload-specific), the same reasoning IdempotencyTTLSeconds
	// already requires an explicit value for — including that same
	// field's asymmetry: a threshold set without SemanticCacheEnabled is
	// not itself flagged as an error, only the reverse.
	SemanticCacheThreshold float64 `json:"semantic_cache_threshold,omitempty"`

	// IdempotencyEnabled turns on Idempotency-Key deduplication: a
	// client that sends the same Idempotency-Key header on a retried
	// request gets back the exact same response instead of triggering a
	// second (and possibly separately billed) upstream call — including
	// when the retry arrives while the first attempt is still in
	// flight, in which case it waits for that attempt to finish rather
	// than forwarding a duplicate. Deliberately independent of
	// CacheEnabled: a cache hit is about content ("has this exact body
	// been sent before, to anyone"), this is about intent ("is this the
	// same caller retrying the same logical operation"). Records live
	// only in memory and are lost on restart. false (the default) means
	// an Idempotency-Key header, if sent, is simply ignored — unchanged
	// from before this field existed.
	IdempotencyEnabled bool `json:"idempotency_enabled,omitempty"`

	// IdempotencyTTLSeconds is how long a completed record stays
	// replayable after it was produced, in seconds — required whenever
	// IdempotencyEnabled is true, unlike CacheTTLSeconds' own "zero
	// means never expire" default: idempotency records live in memory
	// with no separate size cap the way the on-disk cache has
	// (CacheMaxSizeBytes), so leaving them to accumulate forever isn't
	// a safe default here. Only meaningful alongside IdempotencyEnabled
	// — setting this without it is a config error, same reasoning as
	// CacheTTLSeconds requiring CacheEnabled.
	IdempotencyTTLSeconds int `json:"idempotency_ttl_seconds,omitempty"`

	// CostPer1KTokens prices the shutdown summary's total token count at
	// this rate per 1,000 tokens, in whatever currency and rate the user
	// knows applies to their own usage. Zero (the default when the field
	// is absent) disables cost estimation entirely — aiproxy has no
	// built-in, inevitably-stale pricing table to fall back on.
	CostPer1KTokens float64 `json:"cost_per_1k_tokens"`

	// Targets adds path-prefix-routed upstreams on top of the proxy's
	// default --target. A request whose path starts with a Target's
	// Prefix is forwarded to that Target's URL instead, with the matched
	// prefix stripped. An empty slice (the default when the field is
	// absent) means every request just goes to the default --target.
	Targets []Target `json:"targets"`

	// ModelRoutes routes by the request body's own "model" field instead
	// of by URL path prefix — see ModelRoute. Checked before Targets: if
	// a request's model matches an entry here, that route is used and
	// Targets' path-prefix matching is skipped entirely for that
	// request. An empty slice (the default when the field is absent)
	// means no request is ever routed this way, same as before this
	// field existed.
	ModelRoutes []ModelRoute `json:"model_routes,omitempty"`

	// BuiltinRuleActions overrides the action of one or more of aiproxy's
	// built-in secret-blocking rules, keyed by rule name (see the CLI's
	// builtinRules for the current list). Values are "block" (every
	// built-in rule's long-standing default, still applied to any
	// built-in rule not mentioned here), "redact" (same meaning as
	// CustomRule.Action), or "off" (skip the rule entirely — the one
	// value CustomRule.Action has no equivalent for, since leaving a
	// custom rule out of the list already does that). A key that isn't a
	// real built-in rule name, or a value that isn't one of those three,
	// is a config error.
	BuiltinRuleActions map[string]string `json:"builtin_rule_actions,omitempty"`

	// MaxBodyBytes caps how large a single request body aiproxy will
	// buffer in memory before rejecting it with a 413. Zero (the default
	// when the field is absent) does not mean "no limit" the way it does
	// for every other numeric field above — it means
	// proxy.DefaultMaxBodyBytes applies instead, since a reverse proxy
	// that buffers every request body fully in memory before it can be
	// inspected must never expose an actually-unbounded size by default.
	MaxBodyBytes int64 `json:"max_body_size_bytes,omitempty"`

	// WebhookURL, if set, is an http or https endpoint aiproxy POSTs a
	// JSON alert to every time a rule blocks or redacts a request, or the
	// rate limiter rejects one — a Slack incoming webhook URL, or any
	// other endpoint willing to receive one. Empty (the default when the
	// field is absent) disables alerting entirely; nothing is ever
	// POSTed.
	WebhookURL string `json:"webhook_url,omitempty"`

	// Webhooks lists additional webhook destinations beyond WebhookURL,
	// each optionally filtered to a subset of event types via its own
	// Events field. WebhookURL, if set, is still notified of every
	// event exactly as before this field existed; entries here are
	// additional, useful for routing a specific event (e.g.
	// budget_exceeded) to a different destination than the general
	// block/redact stream — a budget alert to one Slack channel,
	// block/redact to another. An empty slice (the default when the
	// field is absent) means WebhookURL, if set, is the only
	// destination, same as before this field existed.
	Webhooks []WebhookTarget `json:"webhooks,omitempty"`

	// PathRules blocks or allows whole endpoints by path prefix,
	// independent of their content — checked before any body/header
	// secret scanning, so an "allow" entry exempts everything under its
	// prefix from every built-in and custom rule. An empty slice (the
	// default when the field is absent) means no path is treated
	// specially.
	PathRules []PathRule `json:"path_rules,omitempty"`

	// CostBudget, if set, is a threshold in the same currency/rate as
	// CostPer1KTokens — once the running total cost (TotalTokens priced
	// at CostPer1KTokens) reaches or passes it, aiproxy logs a
	// budget_exceeded event, alerts WebhookURL if set, and reports it in
	// GET /_aiproxy/stats and the Prometheus endpoint. Alert-only by
	// default — see CostBudgetHardStop for actual enforcement. Fires
	// once per process lifetime, not on every request past the
	// threshold. Only meaningful alongside CostPer1KTokens: a budget
	// with no rate to price tokens at has nothing to compare against,
	// so setting this without CostPer1KTokens is a config error. Zero
	// (the default when the field is absent) disables the check
	// entirely.
	CostBudget float64 `json:"cost_budget,omitempty"`

	// CostBudgetHardStop, if true, turns CostBudget from a one-time
	// alert into real enforcement: once the running total cost has
	// reached or passed CostBudget, every subsequent request is
	// rejected (402 Payment Required) instead of being forwarded — not
	// just the one that happened to cross it, every one after, for the
	// rest of the process's life (there's no time window or reset). A
	// cache hit is never rejected — it costs nothing additional
	// regardless of the budget. Applies uniformly across every
	// target/route; a named proxy_api_key can additionally set its own
	// cost_budget_hard_stop (see ProxyAPIKeyEntry.CostBudgetHardStop),
	// checked independently. Only meaningful alongside CostBudget — a
	// hard stop with no budget to enforce is a config error, same
	// reasoning as CostBudget requiring CostPer1KTokens. false (the
	// default) keeps CostBudget alert-only, unchanged from before this
	// field existed.
	CostBudgetHardStop bool `json:"cost_budget_hard_stop,omitempty"`

	// ProxyAPIKey, if set, requires every request to the proxy — not
	// just the ones forwarded upstream, but GET /_aiproxy/stats and
	// /_aiproxy/metrics too — to present it as a
	// "Proxy-Authorization: Bearer <key>" header, matched with a
	// constant-time comparison; anything missing or wrong gets a 407
	// rather than ever reaching rules, the rate limiter, or an upstream
	// target. Proxy-Authorization is the standard HTTP header for
	// authenticating to a proxy itself (RFC 7235) — distinct from
	// Authorization/X-Api-Key, which carry the client's own credential
	// for the proxied upstream API and are never touched by this check.
	// Empty (the default when the field is absent) disables the check
	// entirely — anyone who can reach the proxy's listen address can use
	// it, same as before this field existed.
	ProxyAPIKey string `json:"proxy_api_key,omitempty"`

	// ProxyAPIKeys lists additional named proxy keys beyond ProxyAPIKey
	// — so several agents/teams can share one proxy while each getting
	// their own attributed stats and token/cost tracking (see
	// GET /_aiproxy/stats' per_client field) and, if given their own
	// max_requests_per_minute, their own dedicated rate limit that takes
	// precedence over whatever route or the server-wide limiter would
	// otherwise apply for that caller. Every request must present
	// ProxyAPIKey (if set) or one of these; ProxyAPIKey keeps working
	// completely unchanged (a single, anonymous key labeled "default" in
	// stats) and can be freely combined with ProxyAPIKeys, the same
	// relationship WebhookURL has to Webhooks. An empty slice (the
	// default when the field is absent) means ProxyAPIKey alone (or no
	// auth at all, if that's empty too) is unchanged from before this
	// field existed.
	ProxyAPIKeys []ProxyAPIKeyEntry `json:"proxy_api_keys,omitempty"`

	// IPAllowList, if non-empty, restricts which client IPs may reach
	// the proxy at all: a request whose remote IP doesn't match any
	// entry here is rejected with a 403, before proxy_api_key or
	// anything else downstream is even checked. Each entry is a CIDR
	// range ("10.0.0.0/8") or a single IP address ("192.168.1.5",
	// treated as that address's full-width /32 or /128). Checked after
	// IPDenyList — a deny match always wins, even for an IP that's also
	// allow-listed, useful for carving an exception out of a broader
	// allow range. Empty (the default) means every source IP is
	// allowed, unless IPDenyList itself denies it. Based on the actual
	// TCP peer address, never a client-supplied header like
	// X-Forwarded-For, which would let any caller simply claim a
	// trusted IP.
	IPAllowList []string `json:"ip_allow_list,omitempty"`

	// IPDenyList unconditionally rejects any request whose remote IP
	// matches an entry here, regardless of IPAllowList — see
	// IPAllowList's doc comment for the full precedence and matching
	// rules. Empty (the default) denies nothing.
	IPDenyList []string `json:"ip_deny_list,omitempty"`

	// GeoIPRangesFile is the path to a CSV file mapping IP ranges to
	// 2-letter country codes ("1.2.3.0/24,US" per line, "#" comments
	// and blank lines ignored) — see the geoip package. Required
	// whenever CountryAllowList or CountryDenyList is set; there's
	// nothing to resolve a request's country from otherwise.
	GeoIPRangesFile string `json:"geoip_ranges_file,omitempty"`

	// CountryAllowList/CountryDenyList restrict which client
	// countries may reach the proxy at all, resolved from
	// GeoIPRangesFile — checked independently of IPAllowList/
	// IPDenyList: a request must pass both checks, and an explicit IP
	// allow-list entry is never an exemption from a country-level
	// deny (or vice versa) — deliberately, to keep the two dimensions
	// simple to reason about rather than adding cross-list precedence
	// rules. Within this pair, CountryDenyList always wins, even over
	// a country also present in CountryAllowList, the same precedence
	// IPAllowList/IPDenyList already use. An IP whose country can't be
	// resolved at all (not covered by any GeoIPRangesFile range) is
	// denied whenever either list is non-empty — the same "can't
	// evaluate it, so deny" rule checkIPAccess already applies to an
	// unparseable remote IP. Each entry is a 2-letter ISO 3166-1
	// alpha-2 code, case-insensitive.
	CountryAllowList []string `json:"country_allow_list,omitempty"`
	CountryDenyList  []string `json:"country_deny_list,omitempty"`

	// LogFile, if set, is a path every log event — the same ones printed
	// to stdout/stderr, plus the shutdown summary — is also appended to,
	// always as one JSON object per line regardless of --log-format,
	// since a durable on-disk record is meant to be grepped/parsed
	// later, not read live in a terminal. The file is opened in append
	// mode and reopened on every SIGHUP reload, whether or not this path
	// actually changed — the same convention nginx and PostgreSQL use so
	// external log rotation (rename the file, then signal the process)
	// works without aiproxy needing any rotation logic of its own: a
	// tool like logrotate renames the current file out of the way and
	// sends SIGHUP, and the next reload's reopen creates a fresh file at
	// this same path. Empty (the default when the field is absent)
	// disables file logging entirely — the same behavior as before this
	// field existed.
	LogFile string `json:"log_file,omitempty"`
}

// Load reads and parses the config file at path. If the file does not
// exist, the returned error satisfies os.IsNotExist so callers can treat
// a missing config file as "nothing configured" rather than fatal.
//
// Before parsing, the raw file is passed through expandEnvVars, so any
// field — proxy_api_key and webhook_url are the obvious candidates, but
// nothing is special-cased — can reference an environment variable
// instead of embedding it in the file directly.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	expanded, err := expandEnvVars(data)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(expanded, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &cfg, nil
}

// envVarNamePattern is what expandEnvVars accepts between "${" and "}":
// the same identifier shape every shell accepts for a variable name.
var envVarNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// expandEnvVars replaces every "${NAME}" reference in raw with the
// current process's environment variable NAME, before the file is ever
// parsed as JSON — so substitution works uniformly across the whole
// file, not just in fields aiproxy specifically knows are secrets.
// "$$" escapes to a literal "$" without attempting substitution — the
// way to stop any field from being treated as a reference at all. A
// custom_rules pattern that wants to actually match a literal "${" in
// request bodies (detecting an env-var-style secret reference leaking
// through) doesn't need this escape: regex-escaping the dollar sign as
// "\$\{...\}" (required anyway, since bare "$" is a regex end-of-string
// anchor, not a literal character) already keeps the "$" from being
// immediately followed by "{" in the raw file, so expandEnvVars leaves
// it untouched on its own. A bare "$" not immediately followed by "{" or
// another "$" (an end-of-line regex anchor is by far the most common case) is
// left untouched.
//
// A referenced variable that isn't set is an error, same as malformed
// JSON: silently substituting an empty string could quietly disable
// proxy_api_key's entire auth check or break a webhook URL, and aiproxy
// would rather refuse to start than run with a config that silently
// isn't what was intended.
func expandEnvVars(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '$' {
			out.WriteByte(c)
			continue
		}
		if i+1 < len(raw) && raw[i+1] == '$' {
			out.WriteByte('$')
			i++
			continue
		}
		if i+1 >= len(raw) || raw[i+1] != '{' {
			out.WriteByte(c)
			continue
		}

		closeOffset := bytes.IndexByte(raw[i+2:], '}')
		if closeOffset == -1 {
			return nil, fmt.Errorf("malformed ${...} reference at byte %d: missing closing '}'", i)
		}
		name := string(raw[i+2 : i+2+closeOffset])
		if !envVarNamePattern.MatchString(name) {
			return nil, fmt.Errorf("malformed reference ${%s}: not a valid environment variable name", name)
		}
		value, ok := os.LookupEnv(name)
		if !ok {
			return nil, fmt.Errorf("environment variable %q is not set", name)
		}
		out.WriteString(value)
		i += 2 + closeOffset // advance to the closing '}'; the loop's i++ steps past it
	}
	return out.Bytes(), nil
}
