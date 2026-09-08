// Package stats tracks aggregate counters for a running proxy: how many
// requests were allowed, blocked, rate-limited, or served from cache,
// and how many tokens were used in total — both overall and broken down
// per target, for a multi-target setup. It knows nothing about HTTP,
// rules, or the proxy — just counting.
package stats

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// counters is one set of atomic counters, safe for concurrent use
// without a mutex. Stats keeps one for the overall total and one per
// target.
type counters struct {
	allowed          atomic.Int64
	blocked          atomic.Int64
	redacted         atomic.Int64
	rateLimited      atomic.Int64
	cacheHits        atomic.Int64
	totalTokens      atomic.Int64
	responseBlocked  atomic.Int64
	responseRedacted atomic.Int64
}

func (c *counters) snapshot() Snapshot {
	return Snapshot{
		Allowed:          c.allowed.Load(),
		Blocked:          c.blocked.Load(),
		Redacted:         c.redacted.Load(),
		RateLimited:      c.rateLimited.Load(),
		CacheHits:        c.cacheHits.Load(),
		TotalTokens:      c.totalTokens.Load(),
		ResponseBlocked:  c.responseBlocked.Load(),
		ResponseRedacted: c.responseRedacted.Load(),
	}
}

// ruleCounters tracks the block/redact outcomes attributable to one
// named rule (built-in, custom, or path), for both requests and
// responses. Unlike counters, it is never nested per target: which rule
// matched is independent of which target the request happened to route
// to, so there is exactly one set of these per rule name, globally.
type ruleCounters struct {
	blocked          atomic.Int64
	redacted         atomic.Int64
	responseBlocked  atomic.Int64
	responseRedacted atomic.Int64
}

func (c *ruleCounters) snapshot() RuleSnapshot {
	return RuleSnapshot{
		Blocked:          c.blocked.Load(),
		Redacted:         c.redacted.Load(),
		ResponseBlocked:  c.responseBlocked.Load(),
		ResponseRedacted: c.responseRedacted.Load(),
	}
}

// Stats holds a running proxy's counters. The zero value is not usable;
// construct one with New.
type Stats struct {
	overall counters

	mu        sync.Mutex
	perTarget map[string]*counters
	perRule   map[string]*ruleCounters
}

// New creates a Stats with every counter at zero.
func New() *Stats {
	return &Stats{
		perTarget: make(map[string]*counters),
		perRule:   make(map[string]*ruleCounters),
	}
}

// counterFor returns the counters for target, creating them on first use.
func (s *Stats) counterFor(target string) *counters {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.perTarget[target]
	if !ok {
		c = &counters{}
		s.perTarget[target] = c
	}
	return c
}

// ruleCounterFor returns the ruleCounters for ruleName, creating them on
// first use.
func (s *Stats) ruleCounterFor(ruleName string) *ruleCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.perRule[ruleName]
	if !ok {
		c = &ruleCounters{}
		s.perRule[ruleName] = c
	}
	return c
}

// RecordAllow records one request that passed rules and the rate
// limiter and was forwarded upstream, attributing it to target (the
// matched multi-target routing prefix, or "default" for the fallback
// --target).
func (s *Stats) RecordAllow(target string) {
	s.overall.allowed.Add(1)
	s.counterFor(target).allowed.Add(1)
}

// RecordBlock records one request the rule engine blocked, attributing
// it to both target and the name of the rule that matched.
func (s *Stats) RecordBlock(target, ruleName string) {
	s.overall.blocked.Add(1)
	s.counterFor(target).blocked.Add(1)
	s.ruleCounterFor(ruleName).blocked.Add(1)
}

// RecordRedact records one request the rule engine forwarded with a
// matched secret masked out of its body, rather than blocking outright.
func (s *Stats) RecordRedact(target, ruleName string) {
	s.overall.redacted.Add(1)
	s.counterFor(target).redacted.Add(1)
	s.ruleCounterFor(ruleName).redacted.Add(1)
}

// RecordRateLimited records one request the circuit breaker rejected.
func (s *Stats) RecordRateLimited(target string) {
	s.overall.rateLimited.Add(1)
	s.counterFor(target).rateLimited.Add(1)
}

// RecordCacheHit records one request served from the on-disk cache
// instead of reaching the upstream target.
func (s *Stats) RecordCacheHit(target string) {
	s.overall.cacheHits.Add(1)
	s.counterFor(target).cacheHits.Add(1)
}

// RecordTokensUsed adds n to the running total of tokens used for
// target, as reported by upstream responses.
func (s *Stats) RecordTokensUsed(target string, n int) {
	if n > 0 {
		s.overall.totalTokens.Add(int64(n))
		s.counterFor(target).totalTokens.Add(int64(n))
	}
}

// RecordResponseBlock records one upstream response the rule engine
// withheld from the client because a rule matched something in it —
// distinct from RecordBlock, which is a request never sent upstream at
// all; this is a leak caught coming back instead of going out.
func (s *Stats) RecordResponseBlock(target, ruleName string) {
	s.overall.responseBlocked.Add(1)
	s.counterFor(target).responseBlocked.Add(1)
	s.ruleCounterFor(ruleName).responseBlocked.Add(1)
}

// RecordResponseRedact records one upstream response the rule engine
// forwarded with a matched secret masked out of it, rather than
// withholding it outright.
func (s *Stats) RecordResponseRedact(target, ruleName string) {
	s.overall.responseRedacted.Add(1)
	s.counterFor(target).responseRedacted.Add(1)
	s.ruleCounterFor(ruleName).responseRedacted.Add(1)
}

// RuleSnapshot is a point-in-time copy of one named rule's block/redact
// counters, for both requests and responses.
type RuleSnapshot struct {
	Blocked          int64 `json:"blocked"`
	Redacted         int64 `json:"redacted"`
	ResponseBlocked  int64 `json:"response_blocked"`
	ResponseRedacted int64 `json:"response_redacted"`
}

// Snapshot is a point-in-time copy of the counters, safe to read and
// print without further synchronization. PerTarget holds the same
// breakdown keyed by target name; a Snapshot inside PerTarget never has
// its own nested PerTarget or PerRule. PerRule holds a breakdown keyed
// by rule name instead of target — which built-in, custom, or path rule
// is actually firing, and how often, independent of which target the
// matching request happened to route to.
type Snapshot struct {
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	Redacted    int64 `json:"redacted"`
	RateLimited int64 `json:"rate_limited"`
	CacheHits   int64 `json:"cache_hits"`
	TotalTokens int64 `json:"total_tokens"`

	// ResponseBlocked and ResponseRedacted count the same two outcomes
	// as Blocked and Redacted, but for a rule matching the upstream's
	// response instead of the client's request — a leak caught coming
	// back rather than going out.
	ResponseBlocked  int64 `json:"response_blocked"`
	ResponseRedacted int64 `json:"response_redacted"`

	PerTarget map[string]Snapshot     `json:"per_target,omitempty"`
	PerRule   map[string]RuleSnapshot `json:"per_rule,omitempty"`
}

// Snapshot returns the current value of every counter, overall, per
// target, and per rule.
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	perTarget := make(map[string]Snapshot, len(s.perTarget))
	for name, c := range s.perTarget {
		perTarget[name] = c.snapshot()
	}
	perRule := make(map[string]RuleSnapshot, len(s.perRule))
	for name, c := range s.perRule {
		perRule[name] = c.snapshot()
	}
	s.mu.Unlock()

	snap := s.overall.snapshot()
	snap.PerTarget = perTarget
	snap.PerRule = perRule
	return snap
}

// EstimatedCost prices TotalTokens at costPer1KTokens per 1,000 tokens.
// This is a plain unit conversion — aiproxy has no opinion on currency,
// on what the rate actually covers (e.g. a blended input/output rate vs.
// separate ones), or on whether it is still accurate; the caller
// supplies the rate and is responsible for what it means.
func (s Snapshot) EstimatedCost(costPer1KTokens float64) float64 {
	return float64(s.TotalTokens) / 1000 * costPer1KTokens
}

// String renders the snapshot as a short, aligned, human-readable block.
func (s Snapshot) String() string {
	return fmt.Sprintf(
		"=== aiproxy session summary ===\n"+
			"Requests allowed:    %d\n"+
			"Requests blocked:    %d\n"+
			"Requests redacted:   %d\n"+
			"Rate-limited (429):  %d\n"+
			"Cache hits:          %d\n"+
			"Total tokens used:   %d\n"+
			"Responses blocked:   %d\n"+
			"Responses redacted:  %d",
		s.Allowed, s.Blocked, s.Redacted, s.RateLimited, s.CacheHits, s.TotalTokens,
		s.ResponseBlocked, s.ResponseRedacted,
	)
}

// PerTargetString renders a per-target breakdown, sorted by target name,
// pricing each target's tokens at costPer1KTokens (omitted when zero).
// It returns "" when fewer than two targets were ever recorded — a
// single-target run's breakdown would just repeat the block above, so
// there is nothing worth adding.
func (s Snapshot) PerTargetString(costPer1KTokens float64) string {
	if len(s.PerTarget) < 2 {
		return ""
	}

	names := make([]string, 0, len(s.PerTarget))
	for name := range s.PerTarget {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("=== per-target breakdown ===")
	for _, name := range names {
		t := s.PerTarget[name]
		fmt.Fprintf(&b, "\n[%s] allowed=%d blocked=%d redacted=%d rate-limited=%d cache-hits=%d tokens=%d response-blocked=%d response-redacted=%d",
			name, t.Allowed, t.Blocked, t.Redacted, t.RateLimited, t.CacheHits, t.TotalTokens, t.ResponseBlocked, t.ResponseRedacted)
		if costPer1KTokens > 0 {
			fmt.Fprintf(&b, " cost=%.4f", t.EstimatedCost(costPer1KTokens))
		}
	}
	return b.String()
}

// PerRuleString renders a per-rule breakdown, sorted by rule name. It
// returns "" once no rule has ever matched — unlike PerTargetString,
// this shows even a single entry: the overall totals already conflate
// every rule together, so one rule's own numbers are never redundant
// with them the way a single target's are with the totals above.
func (s Snapshot) PerRuleString() string {
	if len(s.PerRule) == 0 {
		return ""
	}

	names := make([]string, 0, len(s.PerRule))
	for name := range s.PerRule {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("=== per-rule breakdown ===")
	for _, name := range names {
		r := s.PerRule[name]
		fmt.Fprintf(&b, "\n[%s] blocked=%d redacted=%d response-blocked=%d response-redacted=%d",
			name, r.Blocked, r.Redacted, r.ResponseBlocked, r.ResponseRedacted)
	}
	return b.String()
}
