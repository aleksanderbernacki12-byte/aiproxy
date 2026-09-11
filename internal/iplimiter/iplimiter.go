// Package iplimiter rate-limits by caller IP address, independent of
// any proxy_api_key identity — a caller that never presents a key (or
// one aiproxy doesn't even require) still gets its own dedicated
// request budget instead of sharing one pool with every other
// unidentified caller. It wraps many limiter.Limiter instances, one
// per IP, created lazily the first time that IP is seen.
//
// Unlike a per-target or per-key limiter — both bounded by how many
// targets/keys are actually configured — the set of IPs a real
// internet-facing proxy sees is unbounded and entirely influenced by
// whoever is calling it, so Registry also evicts an IP's state once
// it's gone quiet for a while (see Sweep) rather than remembering
// every IP it has ever seen for the life of the process.
package iplimiter

import (
	"sync"
	"time"

	"aiproxy/internal/limiter"
)

// staleAfterFactor is how many multiples of window an IP's limiter may
// sit idle before Sweep removes it — long enough that a genuinely
// still-active caller's own state is never evicted out from under it
// (its own next request would refresh lastSeen well before this
// elapses), short enough that a one-off or long-gone caller's state
// doesn't linger indefinitely. A fixed multiple, not a separate config
// field — one reasonable default, not a new knob every deployment
// needs, the same reasoning behind the cache package's own
// staleThresholdRatio.
const staleAfterFactor = 2

// entry is one IP's own limiter plus when it was last actually used —
// the latter purely for Sweep's eviction decision, never consulted by
// Allow/Info themselves.
type entry struct {
	limiter  *limiter.Limiter
	lastSeen time.Time
}

// Registry tracks a Limiter per distinct IP under one lock. The zero
// value is not usable; construct one with NewRegistry.
type Registry struct {
	maxRequests int
	window      time.Duration

	mu      sync.Mutex
	entries map[string]*entry
}

// NewRegistry creates a Registry giving each distinct IP its own
// budget of maxRequests calls to Allow within any rolling window-long
// interval — the exact same semantics as limiter.New, just one
// independent instance per IP instead of one shared instance for
// everyone.
func NewRegistry(maxRequests int, window time.Duration) *Registry {
	return &Registry{
		maxRequests: maxRequests,
		window:      window,
		entries:     make(map[string]*entry),
	}
}

// entryLocked returns ip's own entry, creating it on first use and
// always refreshing lastSeen — every caller of this (Allow and Info
// alike) represents genuine current activity from ip. Caller must hold
// r.mu.
func (r *Registry) entryLocked(ip string) *entry {
	e, ok := r.entries[ip]
	if !ok {
		e = &entry{limiter: limiter.New(r.maxRequests, r.window)}
		r.entries[ip] = e
	}
	e.lastSeen = time.Now()
	return e
}

// Allow reports whether a request from ip arriving right now may
// proceed, and records it if so — see limiter.Limiter.Allow. Safe for
// concurrent use.
func (r *Registry) Allow(ip string) bool {
	r.mu.Lock()
	l := r.entryLocked(ip).limiter
	r.mu.Unlock()
	return l.Allow()
}

// Info reports ip's own configured maximum, remaining budget, and time
// until reset — see limiter.Limiter.Info. Safe for concurrent use, and
// safe to call independently of Allow, though the proxy package always
// calls it immediately after Allow to report the state that call's
// decision just produced.
func (r *Registry) Info(ip string) (max, remaining int, resetIn time.Duration) {
	r.mu.Lock()
	l := r.entryLocked(ip).limiter
	r.mu.Unlock()
	return l.Info()
}

// Sweep removes every IP whose entry has sat idle for at least
// staleAfterFactor*window — see Registry's own doc comment for why
// this exists at all. Safe to call concurrently with Allow/Info (and
// with itself, though only ever one caller — the proxy package's own
// background sweep goroutine — actually does).
func (r *Registry) Sweep() {
	r.sweep(time.Now())
}

// sweep is the deterministic core of Sweep, taking the current instant
// as a parameter so it can be exercised precisely (and without
// sleeping) by tests.
func (r *Registry) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-staleAfterFactor * r.window)
	for ip, e := range r.entries {
		if e.lastSeen.Before(cutoff) {
			delete(r.entries, ip)
		}
	}
}

// Len reports how many distinct IPs currently have live state — for
// tests and diagnostics, never consulted by Allow/Info/Sweep
// themselves.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
