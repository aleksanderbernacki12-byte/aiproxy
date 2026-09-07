// Package rules implements the security engine that decides whether a
// request should be allowed or blocked. It has no dependency on the
// proxy package or on net/http, so it can be unit tested completely
// isolated from the network stack.
package rules

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Action is the verdict produced by evaluating a request against the
// rule set.
type Action int

const (
	Allow Action = iota
	Block
	// Redact matches like Block, but instead of rejecting the request,
	// every occurrence of the matched pattern is replaced with a
	// placeholder and the request is forwarded — the leaked secret never
	// reaches the upstream, but the caller isn't broken by a 403 for
	// something that doesn't need to stop the whole request. Only
	// meaningful on a BodyRegexRule, which has a pattern to redact; on a
	// path Rule it behaves like Allow, since there is no matched text to
	// replace. The replacement happens in the body or in the one header
	// value that matched, whichever it was — see Evaluate.
	Redact
)

func (a Action) String() string {
	switch a {
	case Allow:
		return "allow"
	case Block:
		return "block"
	case Redact:
		return "redact"
	default:
		return "unknown"
	}
}

// Rule matches a request by path prefix and assigns an action when it
// matches.
type Rule struct {
	Name       string
	PathPrefix string // "" matches any path
	Action     Action
}

// BodyRegexRule matches a request by running a pre-compiled regular
// expression against its body and assigns an action when it matches.
// Pattern must be compiled once at startup (e.g. with regexp.MustCompile)
// and reused across requests; the engine never compiles it itself.
type BodyRegexRule struct {
	Name    string
	Pattern *regexp.Regexp
	Action  Action
}

// Request is the minimal information the engine needs to evaluate a
// request. It deliberately avoids any *http.Request dependency. Body
// carries the full, already-buffered request body in cleartext so rules
// can inspect it without touching the network stack. Headers is optional
// and carries whichever header values the caller considers worth
// scanning — the same body rule patterns are matched against each of
// them, so a leaked secret pasted into a header (rather than the body)
// is caught too. The caller decides which headers to include; a caller
// with nothing worth scanning can leave it nil. In particular, aiproxy's
// own proxy package deliberately omits the headers a client legitimately
// uses to authenticate to the proxied upstream itself (Authorization,
// Proxy-Authorization, X-Api-Key) — see filterHeadersForScanning there —
// since those are expected to contain exactly the kind of value these
// patterns are built to catch.
type Request struct {
	Method  string
	URL     string
	Body    []byte
	Headers map[string][]string
}

// Engine evaluates requests against ordered rule sets. Body regex rules
// are checked first — against the body, then, if nothing there matched,
// against every header value in Request.Headers — then path rules;
// within each set the first match wins. When nothing matches, the
// engine's Default action applies.
type Engine struct {
	Default Action

	rules     []Rule
	bodyRules []BodyRegexRule
}

// NewEngine creates an empty engine with the given default action.
func NewEngine(defaultAction Action) *Engine {
	return &Engine{Default: defaultAction}
}

// AddRule appends a path rule to the end of the evaluation order.
func (e *Engine) AddRule(r Rule) {
	e.rules = append(e.rules, r)
}

// AddBodyRegexRule appends a body regex rule to the end of the
// evaluation order.
func (e *Engine) AddBodyRegexRule(r BodyRegexRule) {
	e.bodyRules = append(e.bodyRules, r)
}

// Rules returns a copy of the current path rule set.
func (e *Engine) Rules() []Rule {
	return append([]Rule(nil), e.rules...)
}

// BodyRegexRules returns a copy of the current body regex rule set.
func (e *Engine) BodyRegexRules() []BodyRegexRule {
	return append([]BodyRegexRule(nil), e.bodyRules...)
}

// Evaluate returns the action for req, the name of the rule that
// produced it (empty when the default action applied), the body the
// caller should actually use going forward, and the headers it should
// actually use going forward. Both are req.Body/req.Headers unchanged,
// unless the matched rule's Action is Redact, in which case every
// occurrence of its pattern — in the body, or in the one header that
// matched, whichever it was — has been replaced with a
// "[REDACTED:<rule name>]" placeholder; the other of the two always
// comes back unchanged. Body rules are checked first (in registration
// order), then header values (by header name in sorted order, then in
// registration order within each header) — so a body match always wins
// over a header match when both are present. Headers is scanned in
// whatever form req.Headers was given; the caller decides which headers
// are worth scanning at all (see Request.Headers).
func (e *Engine) Evaluate(req Request) (Action, string, []byte, map[string][]string, error) {
	for _, r := range e.bodyRules {
		if r.Pattern.Match(req.Body) {
			if r.Action == Redact {
				placeholder := []byte("[REDACTED:" + r.Name + "]")
				return Redact, r.Name, r.Pattern.ReplaceAll(req.Body, placeholder), req.Headers, nil
			}
			return r.Action, r.Name, req.Body, req.Headers, nil
		}
	}

	if action, ruleName, headers, matched := e.evaluateHeaders(req.Headers); matched {
		return action, ruleName, req.Body, headers, nil
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return Block, "", req.Body, req.Headers, fmt.Errorf("rules: invalid url %q: %w", req.URL, err)
	}

	for _, r := range e.rules {
		if strings.HasPrefix(u.Path, r.PathPrefix) {
			return r.Action, r.Name, req.Body, req.Headers, nil
		}
	}
	return e.Default, "", req.Body, req.Headers, nil
}

// evaluateHeaders runs every body rule against each value of every
// header in headers, in sorted header-name order, and reports whether
// any of them matched. A Redact match returns a copy of headers with
// only that one header's values rewritten — every occurrence of the
// pattern replaced across all of that header's values, not just the one
// that matched — leaving every other header, including other values of
// the same name, untouched.
func (e *Engine) evaluateHeaders(headers map[string][]string) (action Action, ruleName string, result map[string][]string, matched bool) {
	if len(headers) == 0 {
		return Allow, "", headers, false
	}

	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		for _, r := range e.bodyRules {
			for _, v := range headers[name] {
				if !r.Pattern.MatchString(v) {
					continue
				}
				if r.Action != Redact {
					return r.Action, r.Name, headers, true
				}
				placeholder := "[REDACTED:" + r.Name + "]"
				redacted := make(map[string][]string, len(headers))
				for k, vv := range headers {
					redacted[k] = vv
				}
				newValues := make([]string, len(headers[name]))
				for i, hv := range headers[name] {
					newValues[i] = r.Pattern.ReplaceAllString(hv, placeholder)
				}
				redacted[name] = newValues
				return Redact, r.Name, redacted, true
			}
		}
	}
	return Allow, "", headers, false
}
