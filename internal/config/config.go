// Package config reads aiproxy's on-disk JSON configuration. It only
// turns a config file into plain Go structs using the standard library's
// encoding/json — it knows nothing about regexes, rules, or the proxy,
// so it stays testable and reusable independently of how its data ends
// up being used.
package config

import (
	"encoding/json"
	"fmt"
	"os"
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
}

// Target is one path-prefix-to-upstream mapping for multi-target
// routing, as it appears in the config file, before URL has been parsed.
type Target struct {
	Prefix string `json:"prefix"`
	URL    string `json:"url"`

	// MaxRequestsPerMinute, if greater than zero, gives this target its
	// own dedicated rate limit instead of sharing the top-level
	// max_requests_per_minute limiter with every other target. Zero (the
	// default when the field is absent) means this target has no
	// override and simply shares the top-level limiter, same as before
	// per-target limits existed.
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

	// WebhookURL, if set, is an HTTPS endpoint aiproxy POSTs a JSON alert
	// to every time a rule blocks or redacts a request — a Slack incoming
	// webhook URL, or any other endpoint willing to receive one. Empty
	// (the default when the field is absent) disables alerting entirely;
	// nothing is ever POSTed.
	WebhookURL string `json:"webhook_url,omitempty"`

	// PathRules blocks or allows whole endpoints by path prefix,
	// independent of their content — checked before any body/header
	// secret scanning, so an "allow" entry exempts everything under its
	// prefix from every built-in and custom rule. An empty slice (the
	// default when the field is absent) means no path is treated
	// specially.
	PathRules []PathRule `json:"path_rules,omitempty"`
}

// Load reads and parses the config file at path. If the file does not
// exist, the returned error satisfies os.IsNotExist so callers can treat
// a missing config file as "nothing configured" rather than fatal.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &cfg, nil
}
