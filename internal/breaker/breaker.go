// Package breaker tracks per-target consecutive transport-level failure
// counts and, once a target crosses a configured threshold, marks it
// "ejected" for a cooldown period — so a caller trying several
// candidate upstreams in order (see the proxy package's
// failoverTransport) can prefer a healthy one over a known-bad one
// still in cooldown, without ever refusing to genuinely attempt a
// target when there's no better candidate to try instead. It has no
// dependency on the proxy package or on net/http, so it stays testable
// completely isolated from the network stack, mirroring the anomaly
// package's own isolation.
package breaker

import (
	"sync"
	"time"
)

// targetState is one target's own failure/ejection bookkeeping.
type targetState struct {
	consecutiveFailures int
	ejectedUntil        time.Time
}

// Registry tracks every target's state under one lock — cheap enough
// per request given how rarely a real transport failure happens
// relative to successful requests. The zero value is not usable;
// construct one with NewRegistry.
type Registry struct {
	threshold int
	cooldown  time.Duration

	mu      sync.Mutex
	targets map[string]*targetState
}

// NewRegistry creates a Registry that ejects a target once it has
// failed threshold times in a row, for cooldown once ejected. threshold
// must be positive for ejection to ever actually trigger; a Registry is
// otherwise harmless to keep around unused (RecordFailure simply never
// reaches threshold and IsEjected never returns true).
func NewRegistry(threshold int, cooldown time.Duration) *Registry {
	return &Registry{
		threshold: threshold,
		cooldown:  cooldown,
		targets:   make(map[string]*targetState),
	}
}

// stateLocked returns target's state, creating it on first use. Caller
// must hold r.mu.
func (r *Registry) stateLocked(target string) *targetState {
	st, ok := r.targets[target]
	if !ok {
		st = &targetState{}
		r.targets[target] = st
	}
	return st
}

// isEjectedLocked reports whether st is currently within its ejected
// cooldown window. Caller must hold r.mu.
func isEjectedLocked(st *targetState) bool {
	return !st.ejectedUntil.IsZero() && time.Now().Before(st.ejectedUntil)
}

// RecordFailure records one more consecutive transport-level failure
// for target, returning true exactly once — the moment this failure
// crosses threshold and target transitions from healthy to ejected —
// so the caller can log/alert on that transition without repeating it
// on every subsequent failure while still in cooldown.
//
// If target's previous cooldown has already elapsed, its failure count
// is reset before counting this one: without this, a target that never
// actually recovers (kept being genuinely retried — see IsEjected's doc
// comment on why that happens for a single-candidate target) would
// have a consecutive-failure count permanently stuck above threshold
// after its first cooldown expires, and RecordFailure's "crossed
// threshold" transition would then never fire again for it — silently
// leaving it un-reflagged as ejected even though it's still down.
func (r *Registry) RecordFailure(target string) (justEjected bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stateLocked(target)
	if !st.ejectedUntil.IsZero() && !isEjectedLocked(st) {
		st.consecutiveFailures = 0
		st.ejectedUntil = time.Time{}
	}
	st.consecutiveFailures++
	if r.threshold > 0 && st.consecutiveFailures == r.threshold {
		st.ejectedUntil = time.Now().Add(r.cooldown)
		return true
	}
	return false
}

// RecordSuccess resets target's consecutive-failure count and clears
// any active ejection, returning true exactly once — when a success
// arrives for a target that was actually ejected at the time — so the
// caller can log/alert on recovery without noise for a target that was
// never ejected to begin with.
func (r *Registry) RecordSuccess(target string) (recovered bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stateLocked(target)
	recovered = isEjectedLocked(st)
	st.consecutiveFailures = 0
	st.ejectedUntil = time.Time{}
	return recovered
}

// IsEjected reports whether target is currently within its ejected
// cooldown window. A target with no recorded state at all (never
// failed) is never ejected.
//
// Ejection only ever helps a caller with more than one candidate skip
// ahead to a healthier one first — it is never, on its own, a reason to
// refuse a genuine attempt: a caller with no other candidate to try
// should still call through to the real upstream every time, ejected or
// not, which is exactly why a target that's actually still down keeps
// generating fresh RecordFailure calls throughout (and past) its own
// cooldown rather than going quiet the moment it's first ejected.
func (r *Registry) IsEjected(target string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.targets[target]
	if !ok {
		return false
	}
	return isEjectedLocked(st)
}
