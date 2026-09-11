package iplimiter

import (
	"sync"
	"testing"
	"time"

	"aiproxy/internal/limiter"
)

func TestRegistry_EachIPGetsItsOwnIndependentBudget(t *testing.T) {
	r := NewRegistry(2, time.Minute)

	if !r.Allow("1.1.1.1") || !r.Allow("1.1.1.1") {
		t.Fatal("first two requests from 1.1.1.1: want both allowed")
	}
	if r.Allow("1.1.1.1") {
		t.Fatal("3rd request from 1.1.1.1: want denied (budget exhausted)")
	}

	// A different IP must have its own, completely independent budget —
	// not share the exhausted one above.
	if !r.Allow("2.2.2.2") || !r.Allow("2.2.2.2") {
		t.Fatal("first two requests from 2.2.2.2: want both allowed, independent of 1.1.1.1's own exhausted budget")
	}
	if r.Allow("2.2.2.2") {
		t.Fatal("3rd request from 2.2.2.2: want denied (its own budget exhausted)")
	}
}

func TestRegistry_Info_ReflectsThePerIPBudget(t *testing.T) {
	r := NewRegistry(5, time.Minute)
	r.Allow("1.1.1.1")
	r.Allow("1.1.1.1")

	max, remaining, resetIn := r.Info("1.1.1.1")
	if max != 5 {
		t.Errorf("max = %d, want 5", max)
	}
	if remaining != 3 {
		t.Errorf("remaining = %d, want 3 (5 - 2 used)", remaining)
	}
	if resetIn <= 0 || resetIn > time.Minute {
		t.Errorf("resetIn = %s, want a positive value up to the full window", resetIn)
	}

	// A never-seen IP reads as a fresh, full budget.
	max2, remaining2, _ := r.Info("9.9.9.9")
	if max2 != 5 || remaining2 != 5 {
		t.Errorf("info for a never-seen IP = (%d, %d), want (5, 5)", max2, remaining2)
	}
}

func TestRegistry_Sweep_RemovesOnlyIdleEntries(t *testing.T) {
	r := NewRegistry(5, time.Minute)
	base := time.Now()

	r.mu.Lock()
	r.entries["idle.ip"] = &entry{limiter: limiter.New(5, time.Minute), lastSeen: base.Add(-3 * time.Minute)}
	r.entries["active.ip"] = &entry{limiter: limiter.New(5, time.Minute), lastSeen: base}
	r.mu.Unlock()

	r.sweep(base)

	if r.Len() != 1 {
		t.Fatalf("Len() after sweep = %d, want 1", r.Len())
	}
	r.mu.Lock()
	_, activeStillThere := r.entries["active.ip"]
	_, idleStillThere := r.entries["idle.ip"]
	r.mu.Unlock()
	if !activeStillThere {
		t.Error("active.ip was swept away, want it kept (recently active)")
	}
	if idleStillThere {
		t.Error("idle.ip survived the sweep, want it removed (idle past staleAfterFactor*window)")
	}
}

func TestRegistry_Sweep_NeverRemovesAStillWithinWindowEntry(t *testing.T) {
	r := NewRegistry(5, time.Minute)
	base := time.Now()
	r.Allow("1.1.1.1") // lastSeen = base (approximately now)

	// Just under staleAfterFactor*window (2 minutes) of idleness: must
	// survive.
	r.sweep(base.Add(119 * time.Second))
	if r.Len() != 1 {
		t.Fatalf("Len() after a near-but-not-quite-stale sweep = %d, want 1 (not yet idle long enough)", r.Len())
	}

	r.sweep(base.Add(121 * time.Second))
	if r.Len() != 0 {
		t.Fatalf("Len() after a genuinely stale sweep = %d, want 0", r.Len())
	}
}

func TestRegistry_ConcurrentAccessNeverRaces(t *testing.T) {
	r := NewRegistry(1000, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			r.Allow("1.1.1.1")
		}()
		go func() {
			defer wg.Done()
			r.Info("1.1.1.1")
		}()
		go func() {
			defer wg.Done()
			r.Sweep()
		}()
	}
	wg.Wait()
}

func TestRegistry_Len_TracksDistinctIPsSeen(t *testing.T) {
	r := NewRegistry(5, time.Minute)
	if r.Len() != 0 {
		t.Fatalf("Len() on a fresh Registry = %d, want 0", r.Len())
	}
	r.Allow("1.1.1.1")
	r.Allow("2.2.2.2")
	r.Allow("1.1.1.1") // same IP again: must not grow Len further
	if r.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", r.Len())
	}
}
