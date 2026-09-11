package coalesce

import (
	"sync"
	"testing"
	"time"
)

func TestGroup_FirstClaimReturnsOwn(t *testing.T) {
	g := NewGroup(time.Second)
	resp, outcome := g.Claim("key1")
	if outcome != Own {
		t.Fatalf("outcome = %v, want Own", outcome)
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil", resp)
	}
}

// TestGroup_StoreForgetsTheKeyImmediately proves a completed claim is
// removed right away — nothing lingers for a later, unrelated request
// with the same key to (incorrectly) replay once the real cache is
// what should be serving that content going forward.
func TestGroup_StoreForgetsTheKeyImmediately(t *testing.T) {
	g := NewGroup(time.Second)
	g.Claim("key1")
	g.Store("key1", &Response{StatusCode: 200})

	if got := g.Len(); got != 0 {
		t.Fatalf("Len() right after Store = %d, want 0", got)
	}

	// A later claim for the same key is a brand new Own, not a Replay
	// of the long-gone record.
	if _, outcome := g.Claim("key1"); outcome != Own {
		t.Fatalf("claim after Store completed and was forgotten = %v, want Own", outcome)
	}
}

func TestGroup_DifferentKeysAreIndependent(t *testing.T) {
	g := NewGroup(time.Second)
	if _, outcome := g.Claim("key1"); outcome != Own {
		t.Fatalf("key1 claim outcome = %v, want Own", outcome)
	}
	if _, outcome := g.Claim("key2"); outcome != Own {
		t.Fatalf("key2 claim outcome = %v, want Own (independent of key1's own in-flight claim)", outcome)
	}
}

func TestGroup_ConcurrentWaiterBlocksThenReplays(t *testing.T) {
	g := NewGroup(2 * time.Second)
	if _, outcome := g.Claim("key1"); outcome != Own {
		t.Fatalf("first claim outcome = %v, want Own", outcome)
	}

	waiterStarted := make(chan struct{})
	waiterDone := make(chan struct {
		resp    *Response
		outcome Outcome
	}, 1)
	go func() {
		close(waiterStarted)
		resp, outcome := g.Claim("key1")
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
	g.Store("key1", want)

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

func TestGroup_ReleaseLetsWaiterReclaim(t *testing.T) {
	g := NewGroup(2 * time.Second)
	g.Claim("key1") // original owner

	waiterDone := make(chan Outcome, 1)
	go func() {
		_, outcome := g.Claim("key1")
		waiterDone <- outcome
	}()
	time.Sleep(50 * time.Millisecond) // let the waiter actually start blocking

	g.Release("key1") // original owner abandons — e.g. blocked by a rule

	select {
	case outcome := <-waiterDone:
		if outcome != Own {
			t.Fatalf("waiter outcome after Release = %v, want Own (must get a fair shot at its own attempt)", outcome)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never woke up after Release")
	}
}

func TestGroup_ReleaseAfterStoreIsANoOp(t *testing.T) {
	g := NewGroup(time.Second)
	g.Claim("key1")
	g.Store("key1", &Response{StatusCode: 200})

	// Must never panic (double-close); the key is already gone anyway.
	g.Release("key1")

	if got := g.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
}

func TestGroup_ReleaseOnUnknownKeyIsANoOp(t *testing.T) {
	g := NewGroup(time.Second)
	g.Release("never-claimed") // must not panic
	if got := g.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
}

func TestGroup_StoreOnUnknownKeyIsANoOp(t *testing.T) {
	g := NewGroup(time.Second)
	g.Store("never-claimed", &Response{StatusCode: 200}) // must not panic
	if got := g.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0 (a Store with no matching claim must not fabricate one)", got)
	}
}

func TestGroup_ClaimGivesUpAndReturnsBypassAfterWaitTimeout(t *testing.T) {
	g := NewGroup(100 * time.Millisecond)
	g.Claim("key1") // owner never Stores or Releases

	start := time.Now()
	resp, outcome := g.Claim("key1")
	elapsed := time.Since(start)
	if outcome != Bypass {
		t.Fatalf("outcome = %v, want Bypass", outcome)
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil", resp)
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("returned after only %s, want at least the 100ms wait timeout", elapsed)
	}
}

func TestGroup_Len(t *testing.T) {
	g := NewGroup(time.Second)
	if got := g.Len(); got != 0 {
		t.Fatalf("Len() on a fresh Group = %d, want 0", got)
	}
	g.Claim("key1")
	g.Claim("key2")
	if got := g.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
}

// TestGroup_ConcurrentClaimsForTheSameKeyOnlyOneWinsOwn is a
// race-detector-friendly stress test: many goroutines racing to Claim
// the exact same key simultaneously must produce exactly one Own —
// never more than one genuine, simultaneous owner for the same live
// record.
func TestGroup_ConcurrentClaimsForTheSameKeyOnlyOneWinsOwn(t *testing.T) {
	g := NewGroup(2 * time.Second)

	const n = 20
	var wg sync.WaitGroup
	outcomes := make([]Outcome, n)
	ready := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			_, outcome := g.Claim("key1")
			outcomes[i] = outcome
		}(i)
	}
	close(ready)
	time.Sleep(20 * time.Millisecond) // let every goroutine actually reach Claim and start waiting
	g.Store("key1", &Response{StatusCode: 200})
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
