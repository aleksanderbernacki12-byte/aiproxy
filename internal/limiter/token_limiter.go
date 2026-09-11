package limiter

import (
	"sync"
	"time"
)

// TokenLimiter throttles by a rolling count of tokens actually used
// within a window, rather than by request count (see Limiter). Unlike
// Limiter, checking and recording are two separate steps: a request's
// token cost isn't known until its response has come back, so Allow only
// peeks at whether the window is already at or over budget from usage
// recorded so far — it never records anything itself — and Add records
// the actual usage once it's known. This means a single very large
// request can push the window over budget by more than maxTokens before
// the next Allow call starts rejecting — the same tradeoff commercial
// LLM APIs' own per-minute token limits make, since there is no way to
// reserve tokens for a cost nobody knows yet. Safe for concurrent use.
type TokenLimiter struct {
	maxTokens int
	window    time.Duration

	mu      sync.Mutex
	entries []tokenEntry
}

// tokenEntry is one Add call's contribution to the rolling window.
type tokenEntry struct {
	at     time.Time
	tokens int
}

// NewTokenLimiter creates a TokenLimiter that treats the rolling sum of
// tokens Add has recorded within any window-long interval as at budget
// once it reaches maxTokens.
func NewTokenLimiter(maxTokens int, window time.Duration) *TokenLimiter {
	return &TokenLimiter{maxTokens: maxTokens, window: window}
}

// Allow reports whether the current window's recorded token usage is
// still under the configured budget. It never records anything itself —
// call Add once a request's actual token usage is known. Allow is safe
// for concurrent use.
func (l *TokenLimiter) Allow() bool {
	return l.allow(time.Now())
}

// allow is the deterministic core of Allow, taking the current instant
// as a parameter so it can be exercised precisely (and without sleeping)
// by tests in this package.
func (l *TokenLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evict(now)
	return l.sum() < l.maxTokens
}

// Add records n tokens as used right now, counting toward whatever
// window a future Allow call checks against. n <= 0 is a no-op — there
// is nothing meaningful to record for a response that reported no
// usage. Add is safe for concurrent use.
func (l *TokenLimiter) Add(n int) {
	if n <= 0 {
		return
	}
	l.add(n, time.Now())
}

// add is the deterministic core of Add — see allow.
func (l *TokenLimiter) add(n int, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evict(now)
	l.entries = append(l.entries, tokenEntry{at: now, tokens: n})
}

// Info reports the configured maximum, how many tokens remain
// available in the current rolling window, and how long until the
// oldest recorded usage ages out of it — the values behind the
// RateLimit-* response headers. Safe for concurrent use.
func (l *TokenLimiter) Info() (max, remaining int, resetIn time.Duration) {
	return l.info(time.Now())
}

// info is the deterministic core of Info — see allow.
func (l *TokenLimiter) info(now time.Time) (max, remaining int, resetIn time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evict(now)

	remaining = l.maxTokens - l.sum()
	if remaining < 0 {
		remaining = 0
	}
	if len(l.entries) == 0 {
		return l.maxTokens, remaining, 0
	}
	resetIn = l.window - now.Sub(l.entries[0].at)
	if resetIn < 0 {
		resetIn = 0
	}
	return l.maxTokens, remaining, resetIn
}

// evict drops every entry older than window, relative to now. Callers
// must hold mu.
func (l *TokenLimiter) evict(now time.Time) {
	cutoff := now.Add(-l.window)
	live := l.entries[:0]
	for _, e := range l.entries {
		if e.at.After(cutoff) {
			live = append(live, e)
		}
	}
	l.entries = live
}

// sum totals every currently-live entry's tokens. Callers must hold mu.
func (l *TokenLimiter) sum() int {
	total := 0
	for _, e := range l.entries {
		total += e.tokens
	}
	return total
}
