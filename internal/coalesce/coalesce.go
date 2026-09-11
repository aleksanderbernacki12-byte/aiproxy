// Package coalesce deduplicates concurrent requests that would
// otherwise all be simultaneous cache misses for the exact same
// content: the first one to arrive is forwarded normally, and every
// other one that arrives before it finishes waits for its response
// instead of independently forwarding an identical, redundant
// duplicate to the same upstream target — a "thundering herd" of
// otherwise-identical calls (many agents happening to ask the same
// question at once, say) collapsed into one.
//
// Deliberately much shorter-lived than the proxy package's own
// idempotency package: a coalesced record only ever needs to exist for
// the few moments a request is actually in flight — once it completes,
// the real on-disk response cache (see the cache package) takes over
// serving that exact content to every future request, so there is
// nothing left for this package to remember afterward, and no sweep or
// TTL of its own. No conflict detection either, unlike idempotency: a
// coalescing key is the same content-derived cache key the real cache
// itself already computes, so two genuinely different request bodies
// always produce two different keys on their own — there is no
// client-chosen value that could ever collide across two unrelated
// requests the way an Idempotency-Key could.
package coalesce

import (
	"net/http"
	"sync"
	"time"
)

// DefaultWaitTimeout is how long Claim blocks waiting for the current
// owner of a key before giving up — see Claim's own doc comment for why
// giving up here means falling back to an ordinary forward (Bypass)
// rather than an error the way idempotency.Registry.Claim's own
// Timeout does: coalescing is a purely internal, transparent
// optimization the caller never opted into, so the safe, unsurprising
// fallback on any doubt is to behave exactly as if it had never been
// attempted. Not configurable, the same "an internal safety valve, not
// a value worth tuning per deployment" reasoning as
// idempotency.DefaultWaitTimeout.
const DefaultWaitTimeout = 60 * time.Second

// Response is a complete, replayable HTTP response captured for one
// coalescing key.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Outcome is what a caller of Claim must do next.
type Outcome int

const (
	// Own means no other request is currently coalescing on this key:
	// the caller must forward the request itself, then call either
	// Store (once a real response is known) or Release (if the request
	// never reaches one — blocked, rate-limited, or otherwise rejected
	// before forwarding).
	Own Outcome = iota

	// Replay means another request already completed for this exact
	// key while the caller was waiting: the caller should serve the
	// returned Response verbatim and forward nothing.
	Replay

	// Bypass means the caller waited for the current owner but gave up
	// after DefaultWaitTimeout: it should forward the request itself,
	// exactly as if coalescing had never been attempted — and, unlike
	// Own, must NOT call Store or Release afterward, since it was never
	// granted ownership of the key in the first place.
	Bypass
)

type entry struct {
	done     chan struct{}
	response *Response
}

// Group coalesces concurrent claims for the same key. The zero value is
// not usable; construct one with NewGroup.
type Group struct {
	waitTimeout time.Duration

	mu      sync.Mutex
	entries map[string]*entry
}

// NewGroup creates a Group whose Claim gives up waiting on a still-in-flight
// key after waitTimeout.
func NewGroup(waitTimeout time.Duration) *Group {
	return &Group{waitTimeout: waitTimeout, entries: make(map[string]*entry)}
}

// Claim resolves what the caller should do for one request identified
// by key (the same content-derived cache key the real response cache
// itself uses).
//
// If no other request is currently coalescing on key, this atomically
// registers one and returns (nil, Own) — the caller now owns it. If
// another request already owns key and is still in flight, this blocks
// until it calls Store or Release; if it Stores a Response, this
// returns it (Replay); if it instead Releases (abandons) the key, this
// retries from scratch — trying to become the new owner itself — rather
// than leaving the caller stuck behind a permanently abandoned attempt.
// If nobody completes the key within DefaultWaitTimeout, this gives up
// and returns (nil, Bypass) instead of waiting indefinitely.
func (g *Group) Claim(key string) (*Response, Outcome) {
	for {
		g.mu.Lock()
		e, ok := g.entries[key]
		if !ok {
			g.entries[key] = &entry{done: make(chan struct{})}
			g.mu.Unlock()
			return nil, Own
		}
		g.mu.Unlock()

		select {
		case <-e.done:
			if e.response == nil {
				// Abandoned by its owner (Release, not Store) — loop
				// back and try to claim it ourselves, from scratch.
				continue
			}
			return e.response, Replay
		case <-time.After(g.waitTimeout):
			return nil, Bypass
		}
	}
}

// Store completes an owned claim for key with resp, waking every
// request already blocked waiting on it in Claim so they replay it,
// then forgets the key entirely — once the real response cache has
// this content (see the cache package), there is nothing left for this
// package to replay it from itself. A no-op if no such in-flight entry
// exists — already Released, already Stored, or claimed by a request
// that gave up waiting (Bypass) — so it's always safe to call
// unconditionally from a response-handling path that doesn't itself
// track whether the claim is still live.
//
// Because the key is forgotten immediately, a brand new Claim call for
// the same key that arrives after Store has already returned gets Own,
// not Replay — deliberately: the intended caller always checks the
// real response cache first (a write there happens right alongside
// this Store call), so that new claim is expected to find a genuine
// cache hit before it would ever reach this package at all. The
// microseconds-wide window between the two writes, where a genuinely
// unlucky concurrent arrival could still slip through as an extra,
// redundant forward, is an accepted tradeoff — a rare missed
// optimization, never a correctness problem, in exchange for this
// package needing no sweep or TTL of its own the way a longer-lived
// registry (see the idempotency package) does.
func (g *Group) Store(key string, resp *Response) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[key]
	if !ok || e.response != nil {
		return
	}
	e.response = resp
	close(e.done)
	delete(g.entries, key)
}

// Release abandons an owned claim for key without storing a response —
// used when the owning request never reached a real upstream answer
// (blocked, rate-limited, cost-budget-rejected, or otherwise rejected
// before forwarding). Every request blocked waiting on it in Claim
// wakes and retries its own claim from scratch, rather than staying
// stuck behind a permanently abandoned attempt. A no-op if no such
// in-flight entry exists — safe to call unconditionally, e.g. from a
// single deferred call registered right after a successful Own.
func (g *Group) Release(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[key]
	if !ok || e.response != nil {
		return
	}
	delete(g.entries, key)
	close(e.done)
}

// Len reports how many keys currently have a request in flight for
// them — for tests and diagnostics, never consulted by Claim/Store/
// Release themselves. Always 0 between requests: Store/Release both
// remove their own entry as soon as the claim completes, so this is
// never a source of unbounded memory growth the way a longer-lived
// registry (see the idempotency package) needs its own sweep to avoid.
func (g *Group) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.entries)
}
