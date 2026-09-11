package idempotency

import (
	"crypto/sha256"
	"net/http"
	"sync"
	"testing"
	"time"
)

func hashOf(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

func TestRegistry_FirstClaimReturnsOwn(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	resp, outcome := r.Claim("client", "key1", hashOf("body"))
	if outcome != Own {
		t.Fatalf("outcome = %v, want Own", outcome)
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil", resp)
	}
}

func TestRegistry_ReplayAfterStore(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	bodyHash := hashOf("body")
	if _, outcome := r.Claim("client", "key1", bodyHash); outcome != Own {
		t.Fatalf("first claim outcome = %v, want Own", outcome)
	}

	want := &Response{StatusCode: 200, Header: http.Header{"X-Test": {"1"}}, Body: []byte("hello")}
	r.Store("client", "key1", want)

	got, outcome := r.Claim("client", "key1", bodyHash)
	if outcome != Replay {
		t.Fatalf("second claim outcome = %v, want Replay", outcome)
	}
	if got != want {
		t.Fatalf("replayed response = %+v, want the exact stored pointer %+v", got, want)
	}
}

func TestRegistry_ConflictOnDifferentBodyHash(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	if _, outcome := r.Claim("client", "key1", hashOf("body-a")); outcome != Own {
		t.Fatalf("first claim outcome = %v, want Own", outcome)
	}

	// Still in flight (never Stored/Released) — a conflicting body hash
	// must be detected immediately, without blocking at all.
	start := time.Now()
	_, outcome := r.Claim("client", "key1", hashOf("body-b"))
	elapsed := time.Since(start)
	if outcome != Conflict {
		t.Fatalf("outcome = %v, want Conflict", outcome)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("conflict detection took %s, want near-instant (must never block)", elapsed)
	}
}

func TestRegistry_ConflictDetectedEvenAfterCompletion(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	bodyHash := hashOf("body-a")
	r.Claim("client", "key1", bodyHash)
	r.Store("client", "key1", &Response{StatusCode: 200})

	if _, outcome := r.Claim("client", "key1", hashOf("body-b")); outcome != Conflict {
		t.Fatalf("outcome = %v, want Conflict", outcome)
	}
}

func TestRegistry_DifferentClientsAreIndependent(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	bodyHash := hashOf("body")

	if _, outcome := r.Claim("client-a", "shared-key", bodyHash); outcome != Own {
		t.Fatalf("client-a claim outcome = %v, want Own", outcome)
	}
	// The exact same key value, but a different client — must be its
	// own, independent Own, never a Conflict or a Replay of client-a's
	// unrelated record.
	if _, outcome := r.Claim("client-b", "shared-key", bodyHash); outcome != Own {
		t.Fatalf("client-b claim outcome = %v, want Own (independent of client-a's own record)", outcome)
	}
}

func TestRegistry_ConcurrentWaiterBlocksThenReplays(t *testing.T) {
	r := NewRegistry(time.Minute, 2*time.Second)
	bodyHash := hashOf("body")
	if _, outcome := r.Claim("client", "key1", bodyHash); outcome != Own {
		t.Fatalf("first claim outcome = %v, want Own", outcome)
	}

	waiterStarted := make(chan struct{})
	waiterDone := make(chan struct {
		resp    *Response
		outcome Outcome
	}, 1)
	go func() {
		close(waiterStarted)
		resp, outcome := r.Claim("client", "key1", bodyHash)
		waiterDone <- struct {
			resp    *Response
			outcome Outcome
		}{resp, outcome}
	}()
	<-waiterStarted
	time.Sleep(50 * time.Millisecond) // give the waiter a real chance to actually block

	select {
	case got := <-waiterDone:
		t.Fatalf("waiter returned early (outcome=%v) before the owner ever Stored", got.outcome)
	default:
	}

	want := &Response{StatusCode: 201, Body: []byte("owner's response")}
	r.Store("client", "key1", want)

	select {
	case got := <-waiterDone:
		if got.outcome != Replay {
			t.Fatalf("waiter outcome = %v, want Replay", got.outcome)
		}
		if got.resp != want {
			t.Fatalf("waiter got %+v, want the exact stored pointer %+v", got.resp, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never woke up after Store")
	}
}

func TestRegistry_ReleaseLetsWaiterReclaim(t *testing.T) {
	r := NewRegistry(time.Minute, 2*time.Second)
	bodyHash := hashOf("body")
	r.Claim("client", "key1", bodyHash) // original owner

	waiterDone := make(chan Outcome, 1)
	go func() {
		_, outcome := r.Claim("client", "key1", bodyHash)
		waiterDone <- outcome
	}()
	time.Sleep(50 * time.Millisecond) // let the waiter actually start blocking

	r.Release("client", "key1") // original owner abandons — e.g. rate-limited

	select {
	case outcome := <-waiterDone:
		if outcome != Own {
			t.Fatalf("waiter outcome after Release = %v, want Own (must get a fair shot at its own attempt)", outcome)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never woke up after Release")
	}
}

func TestRegistry_ReleaseAfterStoreIsANoOp(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	bodyHash := hashOf("body")
	r.Claim("client", "key1", bodyHash)
	r.Store("client", "key1", &Response{StatusCode: 200})

	// Must never panic (double-close) and must never disturb the
	// already-stored record.
	r.Release("client", "key1")

	resp, outcome := r.Claim("client", "key1", bodyHash)
	if outcome != Replay {
		t.Fatalf("outcome after a no-op Release = %v, want Replay (the stored record must survive)", outcome)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("resp.StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestRegistry_ReleaseOnUnknownKeyIsANoOp(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	r.Release("client", "never-claimed") // must not panic
	if got := r.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
}

func TestRegistry_StoreOnUnknownKeyIsANoOp(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	r.Store("client", "never-claimed", &Response{StatusCode: 200}) // must not panic
	if got := r.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0 (a Store with no matching claim must not fabricate one)", got)
	}
}

func TestRegistry_WaitTimesOutIfOwnerNeverCompletes(t *testing.T) {
	r := NewRegistry(time.Minute, 100*time.Millisecond)
	bodyHash := hashOf("body")
	r.Claim("client", "key1", bodyHash) // owner never Stores or Releases

	start := time.Now()
	_, outcome := r.Claim("client", "key1", bodyHash)
	elapsed := time.Since(start)
	if outcome != Timeout {
		t.Fatalf("outcome = %v, want Timeout", outcome)
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("returned after only %s, want at least the 100ms wait timeout", elapsed)
	}
}

func TestRegistry_SweepExpiresOnlyCompletedEntriesPastTTL(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	r.Claim("client", "key1", hashOf("body"))
	r.Store("client", "key1", &Response{StatusCode: 200})

	now := time.Now()
	r.sweep(now.Add(30 * time.Second)) // well within the 1-minute TTL
	if got := r.Len(); got != 1 {
		t.Fatalf("Len() after an early sweep = %d, want 1 (not yet expired)", got)
	}

	r.sweep(now.Add(90 * time.Second)) // past the 1-minute TTL
	if got := r.Len(); got != 0 {
		t.Fatalf("Len() after a late sweep = %d, want 0 (expired)", got)
	}
}

func TestRegistry_SweepNeverRemovesInFlightEntry(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	r.Claim("client", "key1", hashOf("body")) // never Stored — still "in flight"

	r.sweep(time.Now().Add(24 * time.Hour)) // arbitrarily far in the future
	if got := r.Len(); got != 1 {
		t.Fatalf("Len() after sweeping an in-flight entry = %d, want 1 (must never be swept while in flight, regardless of age)", got)
	}
}

func TestRegistry_Len(t *testing.T) {
	r := NewRegistry(time.Minute, time.Second)
	if got := r.Len(); got != 0 {
		t.Fatalf("Len() on a fresh Registry = %d, want 0", got)
	}
	r.Claim("client-a", "key1", hashOf("body"))
	r.Claim("client-b", "key1", hashOf("body"))
	if got := r.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
}

// TestRegistry_ConcurrentClaimsForTheSameKeyOnlyOneWinsOwn is a
// race-detector-friendly stress test: many goroutines racing to Claim
// the exact same (client, key, bodyHash) simultaneously must produce
// exactly one Own and the rest either Replay (once the owner Stores) or
// still legitimately Own if they observe an abandoned/expired state —
// but never more than one genuine, simultaneous Own for the same live
// record.
func TestRegistry_ConcurrentClaimsForTheSameKeyOnlyOneWinsOwn(t *testing.T) {
	r := NewRegistry(time.Minute, 2*time.Second)
	bodyHash := hashOf("body")

	const n = 20
	var wg sync.WaitGroup
	outcomes := make([]Outcome, n)
	ready := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			_, outcome := r.Claim("client", "key1", bodyHash)
			outcomes[i] = outcome
		}(i)
	}
	close(ready)
	time.Sleep(20 * time.Millisecond) // let every goroutine actually reach Claim and start waiting
	r.Store("client", "key1", &Response{StatusCode: 200})
	wg.Wait()

	ownCount := 0
	for _, o := range outcomes {
		if o == Own {
			ownCount++
		} else if o != Replay {
			t.Errorf("unexpected outcome %v (want exactly one Own, the rest Replay)", o)
		}
	}
	if ownCount != 1 {
		t.Fatalf("Own count = %d, want exactly 1", ownCount)
	}
}
