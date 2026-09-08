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
}

// DryRunMatch records one rule that matched during evaluation but was
// marked DryRun: Action is what it would have done (Block or Redact)
// had it not been in dry-run mode. Evaluate, EvaluateResponse, and
// evaluateHeaders each report every distinct rule name that matched
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
}

// Engine evaluates requests against ordered rule sets. Path rules are
// checked first: a match returns immediately, without ever touching
// body or header content — Block rejects the whole endpoint outright,
// Allow exempts it from every other rule entirely (see Rule). If
// nothing there matches, body regex rules are checked next — against
// the body, then, if nothing there matched, against every header value
// in Request.Headers. Within each set the first match wins. When
// nothing matches at all, the engine's Default action applies.
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
// caller should actually use going forward, the headers it should
// actually use going forward, and every DryRun rule that matched along
// the way (nil if none). Body/headers are req.Body/req.Headers
// unchanged, unless the matched rule's Action is Redact, in which case
// every occurrence of its pattern — in the body, or in the one header
// that matched, whichever it was — has been replaced with a
// "[REDACTED:<rule name>]" placeholder; the other of the two always
// comes back unchanged. Path rules are checked first and, on a match,
// skip body/header scanning entirely (see Rule); otherwise body rules
// are checked next (in registration order), then header values (by
// header name in sorted order, then in registration order within each
// header) — so a body match always wins over a header match when both
// are present. Headers is scanned in whatever form req.Headers was
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

	for _, r := range e.bodyRules {
		if r.Pattern.Match(req.Body) {
			if r.DryRun {
				dryRunHits = append(dryRunHits, DryRunMatch{RuleName: r.Name, Action: r.Action})
				continue
			}
			if r.Action == Redact {
				placeholder := []byte("[REDACTED:" + r.Name + "]")
				return Redact, r.Name, r.Pattern.ReplaceAll(req.Body, placeholder), req.Headers, dryRunHits, nil
			}
			return r.Action, r.Name, req.Body, req.Headers, dryRunHits, nil
		}
	}

	action, ruleName, headers, matched, headerDryRunHits := e.evaluateHeaders(req.Headers)
	dryRunHits = dedupeDryRunMatches(append(dryRunHits, headerDryRunHits...))
	if matched {
		return action, ruleName, req.Body, headers, dryRunHits, nil
	}

	return e.Default, "", req.Body, req.Headers, dryRunHits, nil
}

// EvaluateResponse checks body — an upstream response body, not a
// request — against the same body regex rules Evaluate uses, entirely
// ignoring header and path rules: a response has no request path, and
// its headers are provider metadata, not model-generated content. It
// returns the action, the name of the rule that produced it (empty when
// nothing matched, which is always Allow here — there is no Default to
// fall back to the way Evaluate has for an unmatched request), the body
// to actually forward (body unchanged, unless the matched rule's Action
// is Redact, in which case every occurrence of its pattern has been
// replaced with a "[REDACTED:<rule name>]" placeholder, same convention
// as Evaluate), and every DryRun rule that matched (nil if none) — see
// Evaluate for what DryRun means.
func (e *Engine) EvaluateResponse(body []byte) (Action, string, []byte, []DryRunMatch) {
	var dryRunHits []DryRunMatch
	for _, r := range e.bodyRules {
		if r.Pattern.Match(body) {
			if r.DryRun {
				dryRunHits = append(dryRunHits, DryRunMatch{RuleName: r.Name, Action: r.Action})
				continue
			}
			if r.Action == Redact {
				placeholder := []byte("[REDACTED:" + r.Name + "]")
				return Redact, r.Name, r.Pattern.ReplaceAll(body, placeholder), dryRunHits
			}
			return r.Action, r.Name, body, dryRunHits
		}
	}
	return Allow, "", body, dryRunHits
}

// evaluateHeaders runs every body rule against each value of every
// header in headers, in sorted header-name order, and reports whether
// any of them matched, along with every DryRun rule matched along the
// way (nil if none, not deduplicated — the caller merges and dedupes
// against its own accumulated hits). A Redact match returns a copy of
// headers with only that one header's values rewritten — every
// occurrence of the pattern replaced across all of that header's
// values, not just the one that matched — leaving every other header,
// including other values of the same name, untouched. A DryRun rule
// that matches a header value is recorded but never returned as the
// actual action — scanning continues to the next rule/value exactly as
// if it hadn't matched.
func (e *Engine) evaluateHeaders(headers map[string][]string) (action Action, ruleName string, result map[string][]string, matched bool, dryRunHits []DryRunMatch) {
	if len(headers) == 0 {
		return Allow, "", headers, false, nil
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
				if r.DryRun {
					dryRunHits = append(dryRunHits, DryRunMatch{RuleName: r.Name, Action: r.Action})
					continue
				}
				if r.Action != Redact {
					return r.Action, r.Name, headers, true, dryRunHits
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
				return Redact, r.Name, redacted, true, dryRunHits
			}
		}
	}
	return Allow, "", headers, false, dryRunHits
}
