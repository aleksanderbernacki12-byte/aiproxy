// Package limiter implements a local circuit breaker for the proxy: a
// simple, thread-safe rate limiter that trips once a caller exceeds a
// configured number of requests within a rolling time window. It uses a
// sliding window log and only the standard library (sync, time) — no
// external dependencies.
package limiter

import (
	"sync"
	"time"
)

// Limiter allows at most maxRequests calls to Allow within any rolling
// window-long interval. It is safe for concurrent use.
type Limiter struct {
	maxRequests int
	window      time.Duration

	mu         sync.Mutex
	timestamps []time.Time
}

// New creates a Limiter that permits at most maxRequests calls to Allow
// within any rolling period of length window.
func New(maxRequests int, window time.Duration) *Limiter {
	return &Limiter{
		maxRequests: maxRequests,
		window:      window,
	}
}

// Allow reports whether a request arriving right now may proceed, and
// records it if so. Allow is safe for concurrent use.
func (l *Limiter) Allow() bool {
	return l.allow(time.Now())
}

// allow is the deterministic core of Allow, taking the current instant as
// a parameter so it can be exercised precisely (and without sleeping) by
// tests in this package.
func (l *Limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	live := l.timestamps[:0]
	for _, ts := range l.timestamps {
		if ts.After(cutoff) {
			live = append(live, ts)
		}
	}
	l.timestamps = live

	if len(l.timestamps) >= l.maxRequests {
		return false
	}
	l.timestamps = append(l.timestamps, now)
	return true
}

// Info reports the configured maximum, how many calls remain available
// in the current rolling window, and how long until the oldest
// currently-counted call ages out of it (freeing capacity) — the
// values behind the RateLimit-* response headers. Safe for concurrent
// use, and safe to call independently of Allow, though the proxy
// package always calls it immediately after Allow to report the exact
// state that call's decision just produced.
func (l *Limiter) Info() (max, remaining int, resetIn time.Duration) {
	return l.info(time.Now())
}

// info is the deterministic core of Info — see allow.
func (l *Limiter) info(now time.Time) (max, remaining int, resetIn time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	live := l.timestamps[:0]
	for _, ts := range l.timestamps {
		if ts.After(cutoff) {
			live = append(live, ts)
		}
	}
	l.timestamps = live

	remaining = l.maxRequests - len(l.timestamps)
	if remaining < 0 {
		remaining = 0
	}
	if len(l.timestamps) == 0 {
		return l.maxRequests, remaining, 0
	}
	resetIn = l.window - now.Sub(l.timestamps[0])
	if resetIn < 0 {
		resetIn = 0
	}
	return l.maxRequests, remaining, resetIn
}
