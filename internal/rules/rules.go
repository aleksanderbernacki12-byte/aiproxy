// Package rules implements the security engine that decides whether a
// request should be allowed or blocked. It has no dependency on the
// proxy package or on net/http, so it can be unit tested completely
// isolated from the network stack.
package rules

import (
	"fmt"
	"net/url"
	"regexp"
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
// matches, independent of the request's content — checked before any
// body or header secret scanning (see Engine). Block rejects every
// matching request outright, before it's even scanned; Allow exempts
// every matching request from every other rule, body and header
// scanning included — a deliberate, explicit opt-out for a known-safe
// endpoint (e.g. a health check) that would otherwise risk a false
// positive. Redact has no meaning here — there is no matched text to
// replace — and is treated exactly like Allow if set. DryRun, when
// true, reports what the rule would have done (see DryRunMatch)
// without actually enforcing it — the request is treated exactly as if
// the rule had not matched, and evaluation continues to any remaining
// rules. Only meaningful combined with Block; there is nothing to
// preview for Allow, which never rejects anything to begin with.
type Rule struct {
	Name       string
	PathPrefix string // "" matches any path
	Action     Action
	DryRun     bool
}

// BodyRegexRule matches a request by running a pre-compiled regular
// expression against its body and assigns an action when it matches.
// Pattern must be compiled once at startup (e.g. with regexp.MustCompile)
// and reused across requests; the engine never compiles it itself.
// DryRun, when true, reports what the rule would have done (see
// DryRunMatch) without actually blocking or redacting anything — the
// request or response is treated exactly as if the rule had not
// matched, and evaluation continues to any remaining rules. Meant for
// trying a new rule out against real traffic before trusting it to
// actually enforce anything.
type BodyRegexRule struct {
	Name    string
	Pattern *regexp.Regexp
	Action  Action
	DryRun  bool

	// Targets, if non-empty, restricts this rule to matching only a
	// request/response whose Request.Target (see Evaluate/EvaluateResponse)
	// is one of these values — a request routed anywhere else is treated
	// exactly as if this rule didn't exist, falling through to whatever
	// rule or Default would otherwise apply. Empty (nil, the default)
	// means this rule applies to every target, unchanged from before this
	// field existed.
	Targets []string

	// Keys, if non-empty, restricts this rule to matching only a
	// request/response whose Request.Key is one of these values — same
	// falls-through-as-if-absent behavior as Targets. Empty (nil, the
	// default) means this rule applies regardless of which key (or none)
	// made the request. When both Targets and Keys are set, both must
	// match — the two dimensions narrow the same rule together rather
	// than being alternatives.
	Keys []string
}

// inScope reports whether a BodyRegexRule scoped to targets/keys applies
// to a request resolved to reqTarget/reqKey: true whenever a given list
// is empty (no restriction on that dimension) or contains the request's
// value. Two empty lists therefore always return true, the same
// "applies everywhere" behavior every rule had before Targets/Keys
// existed.
func inScope(targets, keys []string, reqTarget, reqKey string) bool {
	if len(targets) > 0 && !containsString(targets, reqTarget) {
		return false
	}
	if len(keys) > 0 && !containsString(keys, reqKey) {
		return false
	}
	return true
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// DryRunMatch records one rule that matched during evaluation but was
// marked DryRun: Action is what it would have done (Block or Redact)
// had it not been in dry-run mode. Evaluate and EvaluateResponse each
// report every distinct rule name that matched
// this way, deduplicated — a rule that matched more than once (e.g. in
// both the body and a header) is reported only once.
type DryRunMatch struct {
	RuleName string
	Action   Action
}

// dedupeDryRunMatches removes any entry whose RuleName has already
// appeared earlier in hits, preserving order of first appearance. It
// reuses hits' own backing array, so the slice passed in must not be
// read again afterwards.
func dedupeDryRunMatches(hits []DryRunMatch) []DryRunMatch {
	if len(hits) < 2 {
		return hits
	}
	seen := make(map[string]bool, len(hits))
	out := hits[:0]
	for _, h := range hits {
		if seen[h.RuleName] {
			continue
		}
		seen[h.RuleName] = true
		out = append(out, h)
	}
	return out
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

	// Target and Key identify which resolved upstream target and which
	// authenticated proxy key (if any) this request belongs to, purely so
	// a BodyRegexRule's own Targets/Keys scoping (see BodyRegexRule) can
	// be checked against it — the engine assigns no other meaning to
	// either value and never inspects them itself beyond that comparison.
	// A caller with no such concept (or that never scopes any rule) can
	// leave both zero-valued: every rule with empty Targets/Keys still
	// matches unconditionally either way.
	Target string
	Key    string
}

// Engine evaluates requests against ordered rule sets. Path rules are
// checked first: a match returns immediately, without ever touching
// body or header content — Block rejects the whole endpoint outright,
// Allow exempts it from every other rule entirely (see Rule). If
// nothing there matches, every body regex rule is checked against the
// body and every header value in Request.Headers: any Block match wins,
// otherwise every matching Redact rule is applied. When nothing matches
// at all, the engine's Default action applies.
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

// MaskSecrets replaces every match of every body regex rule in s with
// "[REDACTED:<rule name>]", regardless of the rule's action, dry-run flag,
// or target/client scoping. It is for log output only and never affects
// policy decisions: a log line must not carry a secret just because the
// rule that recognizes it is scoped elsewhere or only in dry-run.
func (e *Engine) MaskSecrets(s string) string {
	if e == nil {
		return s
	}
	for _, rule := range e.bodyRules {
		if rule.Pattern == nil {
			continue
		}
		s = rule.Pattern.ReplaceAllLiteralString(s, "[REDACTED:"+rule.Name+"]")
	}
	return s
}

// Evaluate returns the action for req, the name of the rule that
// produced it (empty when the default action applied), the body the
// caller should actually use going forward, the headers it should
// actually use going forward, and every DryRun rule that matched along
// the way (nil if none). Path rules are checked first and, on a match,
// skip body/header scanning entirely (see Rule). Otherwise every body
// regex rule is checked against the original body and every header
// value (see evaluateContent): a single Block match anywhere blocks the
// request, named after the first matching Block rule in registration
// order; with no Block match, every matching Redact rule's pattern is
// replaced with "[REDACTED:<rule name>]" in the body and in every header
// value, and the result is named after the first matching Redact rule.
// Headers is scanned in whatever form req.Headers was
// given; the caller decides which headers are worth scanning at all
// (see Request.Headers). A rule marked DryRun never produces the
// returned action or modifies the body/headers when it matches —
// evaluation simply continues as if it hadn't, after recording it in
// the returned []DryRunMatch.
func (e *Engine) Evaluate(req Request) (Action, string, []byte, map[string][]string, []DryRunMatch, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return Block, "", req.Body, req.Headers, nil, fmt.Errorf("rules: invalid url %q: %w", req.URL, err)
	}

	var dryRunHits []DryRunMatch

	for _, r := range e.rules {
		if strings.HasPrefix(u.Path, r.PathPrefix) {
			action := r.Action
			if action == Redact {
				action = Allow
			}
			if r.DryRun {
				dryRunHits = append(dryRunHits, DryRunMatch{RuleName: r.Name, Action: action})
				continue
			}
			return action, r.Name, req.Body, req.Headers, dryRunHits, nil
		}
	}

	action, ruleName, body, headers, contentDryRunHits, matched := e.evaluateContent(req.Body, req.Headers, req.Target, req.Key)
	dryRunHits = dedupeDryRunMatches(append(dryRunHits, contentDryRunHits...))
	if matched {
		return action, ruleName, body, headers, dryRunHits, nil
	}
	return e.Default, "", req.Body, req.Headers, dryRunHits, nil
}

// EvaluateResponse checks body — an upstream response body, not a
// request — against the same body regex rules Evaluate uses, entirely
// ignoring header and path rules: a response has no request path, and
// its headers are provider metadata, not model-generated content.
// target and key are the same values the originating request's own
// Request.Target/Request.Key carried, so a rule scoped via
// BodyRegexRule.Targets/Keys applies identically to that request's
// response as it did to the request itself. It returns the action, the
// name of the rule that produced it (empty when nothing matched, which
// is always Allow here — there is no Default to fall back to the way
// Evaluate has for an unmatched request), the body to actually forward,
// and every DryRun rule that matched (nil if none). Block beats Redact
// and every matching Redact rule is applied, exactly as in Evaluate.
func (e *Engine) EvaluateResponse(body []byte, target, key string) (Action, string, []byte, []DryRunMatch) {
	action, ruleName, result, _, dryRunHits, matched := e.evaluateContent(body, nil, target, key)
	if !matched {
		return Allow, "", body, dryRunHits
	}
	return action, ruleName, result, dryRunHits
}

// evaluateContent checks every in-scope body regex rule against the
// original body and header values before deciding, so a Redact rule can
// never hide a later Block rule's match (review finding #4). matched is
// false when no enforced rule matched. Dry-run matches are collected
// once per rule and never affect the result. headers is never mutated;
// a redaction returns copies.
func (e *Engine) evaluateContent(body []byte, headers map[string][]string, target, key string) (action Action, ruleName string, resultBody []byte, resultHeaders map[string][]string, dryRunHits []DryRunMatch, matched bool) {
	resultBody, resultHeaders = body, headers
	var blockName, redactName string
	var redactRules []BodyRegexRule
	for _, r := range e.bodyRules {
		if !inScope(r.Targets, r.Keys, target, key) || !r.matchesContent(body, headers) {
			continue
		}
		if r.DryRun {
			dryRunHits = append(dryRunHits, DryRunMatch{RuleName: r.Name, Action: r.Action})
			continue
		}
		switch r.Action {
		case Block:
			if blockName == "" {
				blockName = r.Name
			}
		case Redact:
			if redactName == "" {
				redactName = r.Name
			}
			redactRules = append(redactRules, r)
		}
	}
	if blockName != "" {
		return Block, blockName, body, headers, dryRunHits, true
	}
	if redactName == "" {
		return Allow, "", body, headers, dryRunHits, false
	}
	for _, r := range redactRules {
		resultBody = r.Pattern.ReplaceAll(resultBody, []byte("[REDACTED:"+r.Name+"]"))
		resultHeaders = r.redactHeaders(resultHeaders)
	}
	return Redact, redactName, resultBody, resultHeaders, dryRunHits, true
}

func (r BodyRegexRule) matchesContent(body []byte, headers map[string][]string) bool {
	if r.Pattern.Match(body) {
		return true
	}
	for _, values := range headers {
		for _, value := range values {
			if r.Pattern.MatchString(value) {
				return true
			}
		}
	}
	return false
}

// redactHeaders returns headers with r's matches replaced, copying the map
// and any changed value slice so the caller's headers are never mutated.
func (r BodyRegexRule) redactHeaders(headers map[string][]string) map[string][]string {
	placeholder := "[REDACTED:" + r.Name + "]"
	var result map[string][]string
	for name, values := range headers {
		var redacted []string
		for index, value := range values {
			if !r.Pattern.MatchString(value) {
				continue
			}
			if redacted == nil {
				redacted = append([]string(nil), values...)
			}
			redacted[index] = r.Pattern.ReplaceAllString(value, placeholder)
		}
		if redacted == nil {
			continue
		}
		if result == nil {
			result = make(map[string][]string, len(headers))
			for k, v := range headers {
				result[k] = v
			}
		}
		result[name] = redacted
	}
	if result == nil {
		return headers
	}
	return result
}
