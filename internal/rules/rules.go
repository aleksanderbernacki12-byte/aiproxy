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
	// every occurrence of the matched pattern in the body is replaced
	// with a placeholder and the request is forwarded — the leaked
	// secret never reaches the upstream, but the caller isn't broken by
	// a 403 for something that doesn't need to stop the whole request.
	// Only meaningful on a BodyRegexRule, which has a pattern to redact;
	// on a path Rule it behaves like Allow, since there is no matched
	// text to replace.
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
// can inspect it without touching the network stack.
type Request struct {
	Method string
	URL    string
	Body   []byte
}

// Engine evaluates requests against ordered rule sets. Body regex rules
// are checked first, then path rules; within each set the first match
// wins. When nothing matches, the engine's Default action applies.
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
// produced it (empty when the default action applied), and the body the
// caller should actually use going forward: req.Body unchanged, unless
// the matched rule's Action is Redact, in which case every occurrence of
// its pattern has been replaced with a "[REDACTED:<rule name>]"
// placeholder.
func (e *Engine) Evaluate(req Request) (Action, string, []byte, error) {
	for _, r := range e.bodyRules {
		if r.Pattern.Match(req.Body) {
			if r.Action == Redact {
				placeholder := []byte("[REDACTED:" + r.Name + "]")
				return Redact, r.Name, r.Pattern.ReplaceAll(req.Body, placeholder), nil
			}
			return r.Action, r.Name, req.Body, nil
		}
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return Block, "", req.Body, fmt.Errorf("rules: invalid url %q: %w", req.URL, err)
	}

	for _, r := range e.rules {
		if strings.HasPrefix(u.Path, r.PathPrefix) {
			return r.Action, r.Name, req.Body, nil
		}
	}
	return e.Default, "", req.Body, nil
}
