// Package idempotency deduplicates retried requests that carry the same
// client-supplied Idempotency-Key: the first request with a given key
// is forwarded normally, and every retry that arrives with the same key
// — whether the first has already finished or is still in flight — gets
// back the exact same response instead of triggering a second (and
// possibly separately billed) upstream call.
//
// This is deliberately independent of the proxy package's own on-disk
// response cache: a cache hit is about *content* ("has this exact body
// been sent before, to anyone"), while an idempotency replay is about
// *intent* ("is this the same caller retrying the same logical
// operation") — a client-chosen key precedes and is independent of the
// body it happens to be attached to. Records live only in memory and
// are lost on restart, which is the right tradeoff for a mechanism
// whose whole point is protecting a narrow, recent retry window, not
// long-term persistence.
package idempotency

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Response is a complete, replayable HTTP response captured for one
// idempotency key — the exact status code, headers, and body a first
// request produced, served verbatim to every retry that arrives with
// the same key before it expires.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Outcome is what a caller of Claim must do next.
type Outcome int

const (
	// Own means no matching record exists yet: the caller must forward
	// the request itself, then call either Store (once a real response
	// is known) or Release (if the request never reaches one — blocked,
	// rate-limited, or otherwise rejected before forwarding).
	Own Outcome = iota

	// Replay means a completed record already exists for this exact
	// (client, key, body): the caller should serve the returned
	// Response verbatim and forward nothing.
	Replay

	// Conflict means a record exists for this (client, key) but its
	// operation hash differs from this request's own — the same idempotency
	// key was reused for a genuinely different request. The caller
	// should reject the request rather than either replaying the wrong
	// response or silently forwarding a second, different one.
	Conflict

	// Timeout means a matching in-flight record exists but its owner
	// never completed (Store or Release) within the configured wait
	// timeout. The caller should reject the request with a clear
	// "still in progress" signal rather than risk a duplicate forward.
	Timeout
	// Canceled means the caller's context ended while waiting on an
	// in-flight owner: the client is gone, so the caller writes nothing.
	Canceled
	// Full means the registry is at MaxEntries and every entry is still
	// in flight, so nothing can be evicted to make room. The caller
	// should reject the request rather than forward it untracked.
	Full
)

// DefaultMaxEntries and DefaultMaxBytes bound memory within one TTL.
const (
	DefaultMaxEntries = 10_000
	DefaultMaxBytes   = 64 << 20
)

// DefaultWaitTimeout is how long Claim blocks waiting for an in-flight
// record's owner before giving up and returning Timeout — long enough
// for any real upstream LLM call to plausibly finish, short enough that
// a genuinely stuck owner (a bug, a panic that somehow skipped its own
// Release) doesn't leave a concurrent retry hanging indefinitely. Not
// configurable: this bounds an internal safety valve, not a value an
// operator has a real reason to tune per deployment.
const DefaultWaitTimeout = 60 * time.Second

type recordKey struct {
	client string
	key    string
}

// entry is one idempotency key's own state: either owned by a request
// still in flight (response nil, done open) or completed (response set,
// done closed) — or, briefly, abandoned (done closed, response nil,
// about to be removed) when its owner calls Release instead of Store.
type entry struct {
	operationHash [32]byte
	done          chan struct{}
	response      *Response
	storedAt      time.Time
}

// Registry coordinates idempotency-key deduplication across concurrent
// requests, one entry per (client, key) pair. The zero value is not
// usable; construct one with NewRegistry.
type Registry struct {
	ttl         time.Duration
	waitTimeout time.Duration

	// MaxEntries and MaxBytes cap the records kept within the TTL; when
	// full, the oldest completed records are evicted first. In-flight
	// records are never evicted.
	MaxEntries  int
	MaxBytes    int64
	storedBytes int64

	mu      sync.Mutex
	entries map[recordKey]*entry
}

// NewRegistry creates a Registry whose completed records are forgotten
// ttl after they were stored (see Sweep), and whose Claim gives up
// waiting on a still-in-flight record after waitTimeout.
func NewRegistry(ttl, waitTimeout time.Duration) *Registry {
	return &Registry{
		ttl:         ttl,
		waitTimeout: waitTimeout,
		MaxEntries:  DefaultMaxEntries,
		MaxBytes:    DefaultMaxBytes,
		entries:     make(map[recordKey]*entry),
	}
}

// Claim resolves what the caller should do for one request identified
// by client (empty string is a valid, single shared namespace when no
// proxy_api_key/proxy_api_keys is configured at all — the same
// collapsing-to-one-identity behavior every other per-client feature in
// this codebase already has) and its own Idempotency-Key header value,
// whose whole operation (see the caller) hashes to operationHash. If ctx ends
// while waiting on an in-flight owner, it returns (nil, Canceled).
//
// If no record exists yet, this atomically creates one and returns
// (nil, Own) — the caller now owns it. If a record exists with a
// matching operationHash and is already complete, it returns the stored
// Response immediately. If a record exists with a matching operationHash but
// is still in flight, this blocks (up to waitTimeout) until its owner
// calls Store or Release; if the owner Releases (abandons) it, this
// retries from scratch — trying to become the new owner itself — rather
// than leaving the caller stuck behind a permanently failed attempt. If
// a record exists with a *different* operationHash, it returns (nil,
// Conflict) without ever blocking.
func (r *Registry) Claim(ctx context.Context, client, key string, operationHash [32]byte) (*Response, Outcome) {
	rk := recordKey{client: client, key: key}
	for {
		r.mu.Lock()
		e, ok := r.entries[rk]
		if !ok {
			if !r.makeRoomLocked(1, 0) {
				r.mu.Unlock()
				return nil, Full
			}
			r.entries[rk] = &entry{operationHash: operationHash, done: make(chan struct{})}
			r.mu.Unlock()
			return nil, Own
		}
		if e.operationHash != operationHash {
			r.mu.Unlock()
			return nil, Conflict
		}
		r.mu.Unlock()

		select {
		case <-e.done:
			if e.response == nil {
				// Abandoned by its owner (Release, not Store) — the
				// entry is already gone (see Release); loop back and
				// try to claim it ourselves, from scratch.
				continue
			}
			return e.response, Replay
		case <-time.After(r.waitTimeout):
			return nil, Timeout
		case <-ctx.Done():
			return nil, Canceled
		}
	}
}

// Store completes an owned claim for (client, key) with resp, waking
// every request blocked waiting on it in Claim so they replay it. A
// no-op if no such in-flight entry exists — already Released, already
// Stored, or swept — so it's always safe to call unconditionally from a
// response-handling path that doesn't itself track whether the claim is
// still live.
func (r *Registry) Store(client, key string, resp *Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rk := recordKey{client: client, key: key}
	e, ok := r.entries[rk]
	if !ok || e.response != nil {
		return
	}
	// Room is made while e is still in flight, so it can never be picked
	// as the oldest completed entry and evict itself (storedAt ties are
	// common on coarse clocks).
	size := int64(len(resp.Body))
	keep := size <= r.MaxBytes && r.makeRoomLocked(0, size)
	e.response = resp
	e.storedAt = time.Now()
	close(e.done)
	if !keep {
		// Too large to keep: requests already waiting still get this
		// response (done is closed), but the record is dropped, so a
		// later retry is processed fresh instead of holding the memory.
		delete(r.entries, rk)
		return
	}
	r.storedBytes += size
}

// makeRoomLocked evicts the oldest completed records until one more
// record (newEntries) and bytes more stored bytes fit. It reports false
// when only in-flight records remain and there is still no room.
func (r *Registry) makeRoomLocked(newEntries int, bytes int64) bool {
	for len(r.entries)+newEntries > r.MaxEntries || r.storedBytes+bytes > r.MaxBytes {
		var oldestKey recordKey
		var oldest *entry
		for k, e := range r.entries {
			if e.response != nil && (oldest == nil || e.storedAt.Before(oldest.storedAt)) {
				oldestKey, oldest = k, e
			}
		}
		if oldest == nil {
			return false
		}
		r.deleteCompletedLocked(oldestKey, oldest)
	}
	return true
}

func (r *Registry) deleteCompletedLocked(k recordKey, e *entry) {
	delete(r.entries, k)
	r.storedBytes -= int64(len(e.response.Body))
}

// Release abandons an owned claim for (client, key) without storing a
// response — used when the owning request never reached a real
// upstream answer (blocked, rate-limited, cost-budget-rejected, or
// otherwise rejected before forwarding). Every request blocked waiting
// on it in Claim wakes and retries its own claim from scratch, rather
// than staying stuck behind a permanently abandoned attempt. A no-op if
// no such in-flight entry exists (already Stored, already Released, or
// never claimed at all) — safe to call unconditionally, e.g. from a
// single deferred call registered right after a successful Own.
func (r *Registry) Release(client, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rk := recordKey{client: client, key: key}
	e, ok := r.entries[rk]
	if !ok || e.response != nil {
		return
	}
	delete(r.entries, rk)
	close(e.done)
}

// Sweep removes every completed record older than ttl — see Registry's
// own doc comment for why records aren't kept indefinitely. An in-flight
// record (no response stored yet) is never removed regardless of age,
// however long its owner's request legitimately takes.
func (r *Registry) Sweep() {
	r.sweep(time.Now())
}

// sweep is the deterministic core of Sweep, taking the current instant
// as a parameter so it can be exercised precisely (and without
// sleeping) by tests.
func (r *Registry) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-r.ttl)
	for k, e := range r.entries {
		if e.response == nil {
			continue // still in flight; never swept regardless of age
		}
		if e.storedAt.Before(cutoff) {
			r.deleteCompletedLocked(k, e)
		}
	}
}

// Len reports how many records (in flight or completed) currently
// exist — for tests and diagnostics, never consulted by Claim/Store/
// Release/Sweep themselves.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
