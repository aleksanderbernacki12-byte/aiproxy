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
	allowed     atomic.Int64
	blocked     atomic.Int64
	rateLimited atomic.Int64
	cacheHits   atomic.Int64
	totalTokens atomic.Int64
}

func (c *counters) snapshot() Snapshot {
	return Snapshot{
		Allowed:     c.allowed.Load(),
		Blocked:     c.blocked.Load(),
		RateLimited: c.rateLimited.Load(),
		CacheHits:   c.cacheHits.Load(),
		TotalTokens: c.totalTokens.Load(),
	}
}

// Stats holds a running proxy's counters. The zero value is not usable;
// construct one with New.
type Stats struct {
	overall counters

	mu        sync.Mutex
	perTarget map[string]*counters
}

// New creates a Stats with every counter at zero.
func New() *Stats {
	return &Stats{perTarget: make(map[string]*counters)}
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

// RecordAllow records one request that passed rules and the rate
// limiter and was forwarded upstream, attributing it to target (the
// matched multi-target routing prefix, or "default" for the fallback
// --target).
func (s *Stats) RecordAllow(target string) {
	s.overall.allowed.Add(1)
	s.counterFor(target).allowed.Add(1)
}

// RecordBlock records one request the rule engine blocked.
func (s *Stats) RecordBlock(target string) {
	s.overall.blocked.Add(1)
	s.counterFor(target).blocked.Add(1)
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

// Snapshot is a point-in-time copy of the counters, safe to read and
// print without further synchronization. PerTarget holds the same
// breakdown keyed by target name; a Snapshot inside PerTarget never has
// its own nested PerTarget.
type Snapshot struct {
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	RateLimited int64 `json:"rate_limited"`
	CacheHits   int64 `json:"cache_hits"`
	TotalTokens int64 `json:"total_tokens"`

	PerTarget map[string]Snapshot `json:"per_target,omitempty"`
}

// Snapshot returns the current value of every counter, overall and per
// target.
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	perTarget := make(map[string]Snapshot, len(s.perTarget))
	for name, c := range s.perTarget {
		perTarget[name] = c.snapshot()
	}
	s.mu.Unlock()

	snap := s.overall.snapshot()
	snap.PerTarget = perTarget
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
			"Rate-limited (429):  %d\n"+
			"Cache hits:          %d\n"+
			"Total tokens used:   %d",
		s.Allowed, s.Blocked, s.RateLimited, s.CacheHits, s.TotalTokens,
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
		fmt.Fprintf(&b, "\n[%s] allowed=%d blocked=%d rate-limited=%d cache-hits=%d tokens=%d",
			name, t.Allowed, t.Blocked, t.RateLimited, t.CacheHits, t.TotalTokens)
		if costPer1KTokens > 0 {
			fmt.Fprintf(&b, " cost=%.4f", t.EstimatedCost(costPer1KTokens))
		}
	}
	return b.String()
}
