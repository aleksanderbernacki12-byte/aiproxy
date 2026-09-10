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

	// CostBudget, if greater than zero, is a threshold in the same
	// currency/rate as the top-level CostPer1KTokens — once this key's
	// own running cost (its own attributed TotalTokens priced at
	// CostPer1KTokens) reaches or passes it, aiproxy logs and
	// webhook-alerts a budget_exceeded event carrying this key's Name,
	// independent of the server-wide CostBudget (if any) and of every
	// other key's own budget — each fires once, on its own. Same
	// alert-only (never enforcement) semantics as the top-level
	// CostBudget: this never blocks or otherwise changes how a request
	// is handled. Only meaningful alongside the top-level
	// CostPer1KTokens: a budget with no rate to price tokens at has
	// nothing to compare against, so setting this without
	// CostPer1KTokens is a config error, same reasoning as the top-level
	// CostBudget. Zero (the default) means this key has no budget of
	// its own.
	CostBudget float64 `json:"cost_budget,omitempty"`
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

	// MaxRequestsPerMinute, if greater than zero, gives this target its
	// own dedicated rate limit instead of sharing the top-level
	// max_requests_per_minute limiter with every other target. Zero (the
	// default when the field is absent) means this target has no
	// override and simply shares the top-level limiter, same as before
	// per-target limits existed.
	MaxRequestsPerMinute int `json:"max_requests_per_minute,omitempty"`
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

	// MaxRequestsPerMinute, if greater than zero, gives this route its
	// own dedicated rate limit instead of sharing the top-level
	// max_requests_per_minute limiter with every other target — same
	// meaning as Target.MaxRequestsPerMinute.
	MaxRequestsPerMinute int `json:"max_requests_per_minute,omitempty"`
}

// Config is the top-level shape of aiproxy.json.
type Config struct {
	CustomRules []CustomRule `json:"custom_rules"`

	// MaxRequestsPerMinute caps how many requests the proxy's circuit
	// breaker allows per minute. Zero (the default when the field is
	// absent) means the rate limiter is disabled.
	MaxRequestsPerMinute int `json:"max_requests_per_minute"`

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
	// GET /_aiproxy/stats and the Prometheus endpoint. It never blocks or
	// otherwise affects traffic — this is visibility only, not
	// enforcement. Fires once per process lifetime, not on every request
	// past the threshold. Only meaningful alongside CostPer1KTokens: a
	// budget with no rate to price tokens at has nothing to compare
	// against, so setting this without CostPer1KTokens is a config error.
	// Zero (the default when the field is absent) disables the check
	// entirely.
	CostBudget float64 `json:"cost_budget,omitempty"`

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
