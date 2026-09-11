package breaker_test

import (
	"sync"
	"testing"
	"time"

	"aiproxy/internal/breaker"
)

func TestRegistry_NeverEjectsBelowThreshold(t *testing.T) {
	r := breaker.NewRegistry(3, time.Minute)
	for i := 0; i < 2; i++ {
		if justEjected := r.RecordFailure("target-a"); justEjected {
			t.Fatalf("failure %d: justEjected = true, want false (below threshold)", i+1)
		}
	}
	if r.IsEjected("target-a") {
		t.Fatal("IsEjected = true, want false (below threshold)")
	}
}

func TestRegistry_EjectsExactlyAtThreshold(t *testing.T) {
	r := breaker.NewRegistry(3, time.Minute)
	r.RecordFailure("target-a")
	r.RecordFailure("target-a")
	if justEjected := r.RecordFailure("target-a"); !justEjected {
		t.Fatal("3rd failure: justEjected = false, want true (crossed threshold)")
	}
	if !r.IsEjected("target-a") {
		t.Fatal("IsEjected = false, want true (just ejected)")
	}
}

func TestRegistry_DoesNotReEjectWhileAlreadyEjected(t *testing.T) {
	r := breaker.NewRegistry(2, time.Minute)
	r.RecordFailure("target-a")
	if justEjected := r.RecordFailure("target-a"); !justEjected {
		t.Fatal("2nd failure: justEjected = false, want true")
	}
	for i := 0; i < 5; i++ {
		if justEjected := r.RecordFailure("target-a"); justEjected {
			t.Fatalf("failure %d while already ejected: justEjected = true, want false (no repeat transition)", i+3)
		}
	}
	if !r.IsEjected("target-a") {
		t.Fatal("IsEjected = false, want true (still within cooldown)")
	}
}

func TestRegistry_IsEjected_TrueDuringCooldownFalseAfter(t *testing.T) {
	r := breaker.NewRegistry(1, 50*time.Millisecond)
	r.RecordFailure("target-a")
	if !r.IsEjected("target-a") {
		t.Fatal("IsEjected = false immediately after ejection, want true")
	}
	time.Sleep(100 * time.Millisecond)
	if r.IsEjected("target-a") {
		t.Fatal("IsEjected = true after cooldown elapsed, want false")
	}
}

func TestRegistry_RecordSuccess_ResetsCounterAndClearsEjection(t *testing.T) {
	r := breaker.NewRegistry(3, time.Minute)
	r.RecordFailure("target-a")
	r.RecordFailure("target-a")
	r.RecordSuccess("target-a")

	// The failure count must have reset to zero — two more failures
	// (which would have crossed threshold=3 without the reset) must not
	// eject on their own.
	r.RecordFailure("target-a")
	if justEjected := r.RecordFailure("target-a"); justEjected {
		t.Fatal("justEjected = true after only 2 failures post-reset, want false")
	}
	if r.IsEjected("target-a") {
		t.Fatal("IsEjected = true, want false")
	}
}

func TestRegistry_RecordSuccess_ReturnsTrueOnlyWhenActuallyEjected(t *testing.T) {
	r := breaker.NewRegistry(2, time.Minute)

	if recovered := r.RecordSuccess("never-failed"); recovered {
		t.Fatal("RecordSuccess on a target that never failed: recovered = true, want false")
	}

	r.RecordFailure("target-a")
	if recovered := r.RecordSuccess("target-a"); recovered {
		t.Fatal("RecordSuccess below threshold (never ejected): recovered = true, want false")
	}

	r.RecordFailure("target-b")
	r.RecordFailure("target-b")
	if !r.IsEjected("target-b") {
		t.Fatal("target-b should be ejected before the recovery check")
	}
	if recovered := r.RecordSuccess("target-b"); !recovered {
		t.Fatal("RecordSuccess on an actually-ejected target: recovered = false, want true")
	}
	if r.IsEjected("target-b") {
		t.Fatal("IsEjected = true after RecordSuccess, want false")
	}
}

// TestRegistry_ReEjectsAfterCooldownIfStillFailing proves a target
// that's still genuinely down keeps getting correctly re-flagged after
// each cooldown expires, rather than silently going quiet forever after
// its first ejection — see RecordFailure's doc comment on why a stale,
// permanently-above-threshold counter would otherwise prevent this.
func TestRegistry_ReEjectsAfterCooldownIfStillFailing(t *testing.T) {
	r := breaker.NewRegistry(2, 30*time.Millisecond)
	r.RecordFailure("target-a")
	if justEjected := r.RecordFailure("target-a"); !justEjected {
		t.Fatal("first ejection: justEjected = false, want true")
	}

	time.Sleep(60 * time.Millisecond) // let the cooldown naturally elapse
	if r.IsEjected("target-a") {
		t.Fatal("IsEjected = true after cooldown elapsed, want false")
	}

	// Still down: two more consecutive failures should re-eject exactly
	// as if this were the first time, not silently fail to re-trigger.
	r.RecordFailure("target-a")
	if justEjected := r.RecordFailure("target-a"); !justEjected {
		t.Fatal("re-ejection after cooldown: justEjected = false, want true")
	}
	if !r.IsEjected("target-a") {
		t.Fatal("IsEjected = false immediately after re-ejection, want true")
	}
}

func TestRegistry_TargetsAreIndependent(t *testing.T) {
	r := breaker.NewRegistry(1, time.Minute)
	r.RecordFailure("target-a")
	if r.IsEjected("target-b") {
		t.Fatal("target-b ejected by target-a's own failure, want independent state")
	}
	if !r.IsEjected("target-a") {
		t.Fatal("target-a should be ejected")
	}
}

func TestRegistry_ZeroThreshold_NeverEjects(t *testing.T) {
	r := breaker.NewRegistry(0, time.Minute)
	for i := 0; i < 50; i++ {
		if justEjected := r.RecordFailure("target-a"); justEjected {
			t.Fatalf("failure %d: justEjected = true with threshold=0, want always false (feature disabled)", i+1)
		}
	}
	if r.IsEjected("target-a") {
		t.Fatal("IsEjected = true with threshold=0, want false")
	}
}

// TestRegistry_ConcurrentAccess proves Registry is safe for concurrent
// use from many goroutines at once — real concurrent request handling
// is exactly how failoverTransport calls it in the proxy package.
func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := breaker.NewRegistry(5, 10*time.Millisecond)
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			target := "target-a"
			if g%2 == 0 {
				target = "target-b"
			}
			for i := 0; i < 100; i++ {
				r.RecordFailure(target)
				r.RecordSuccess(target)
				r.IsEjected(target)
			}
		}(g)
	}
	wg.Wait()
}
