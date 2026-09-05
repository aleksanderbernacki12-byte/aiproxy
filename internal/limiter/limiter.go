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
