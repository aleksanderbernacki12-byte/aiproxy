// Package stats tracks aggregate counters for a running proxy: how many
// requests were allowed, blocked, rate-limited, or served from cache,
// and how many tokens were used in total. It knows nothing about HTTP,
// rules, or the proxy — just counting — and uses only the standard
// library (sync/atomic), so it is safe for concurrent use without a
// mutex.
package stats

import (
	"fmt"
	"sync/atomic"
)

// Stats holds a running proxy's counters. The zero value is not usable;
// construct one with New.
type Stats struct {
	allowed     atomic.Int64
	blocked     atomic.Int64
	rateLimited atomic.Int64
	cacheHits   atomic.Int64
	totalTokens atomic.Int64
}

// New creates a Stats with every counter at zero.
func New() *Stats {
	return &Stats{}
}

// RecordAllow records one request that passed rules and the rate
// limiter and was forwarded upstream.
func (s *Stats) RecordAllow() { s.allowed.Add(1) }

// RecordBlock records one request the rule engine blocked.
func (s *Stats) RecordBlock() { s.blocked.Add(1) }

// RecordRateLimited records one request the circuit breaker rejected.
func (s *Stats) RecordRateLimited() { s.rateLimited.Add(1) }

// RecordCacheHit records one request served from the on-disk cache
// instead of reaching the upstream target.
func (s *Stats) RecordCacheHit() { s.cacheHits.Add(1) }

// RecordTokensUsed adds n to the running total of tokens used, as
// reported by upstream responses.
func (s *Stats) RecordTokensUsed(n int) {
	if n > 0 {
		s.totalTokens.Add(int64(n))
	}
}

// Snapshot is a point-in-time copy of the counters, safe to read and
// print without further synchronization.
type Snapshot struct {
	Allowed     int64
	Blocked     int64
	RateLimited int64
	CacheHits   int64
	TotalTokens int64
}

// Snapshot returns the current value of every counter.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		Allowed:     s.allowed.Load(),
		Blocked:     s.blocked.Load(),
		RateLimited: s.rateLimited.Load(),
		CacheHits:   s.cacheHits.Load(),
		TotalTokens: s.totalTokens.Load(),
	}
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
