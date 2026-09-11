package limiter

import (
	"sync"
	"testing"
	"time"
)

// TestLimiter_SixthRequestExceedsLimit proves, without any real sleeping,
// that a limiter configured for 5 requests per minute allows exactly the
// first 5 calls within the window and denies the 6th.
func TestLimiter_SixthRequestExceedsLimit(t *testing.T) {
	base := time.Now()
	l := New(5, time.Minute)

	for i := 1; i <= 5; i++ {
		if !l.allow(base) {
			t.Fatalf("request %d: want allowed, got denied", i)
		}
	}

	if l.allow(base) {
		t.Fatal("request 6 (same window): want denied, got allowed")
	}
	// A few more, still inside the window, must stay denied too.
	if l.allow(base.Add(time.Second)) {
		t.Fatal("request 7 (still same window): want denied, got allowed")
	}
}

// TestLimiter_ReleasesAfterWindowResets proves that once the 1-minute
// window has fully elapsed, the breaker releases and requests are allowed
// again.
func TestLimiter_ReleasesAfterWindowResets(t *testing.T) {
	base := time.Now()
	l := New(5, time.Minute)

	for i := 1; i <= 5; i++ {
		if !l.allow(base) {
			t.Fatalf("request %d: want allowed, got denied", i)
		}
	}
	if l.allow(base) {
		t.Fatal("request 6 (same window): want denied, got allowed")
	}

	// Just before the window elapses, still denied.
	almostReset := base.Add(time.Minute - time.Millisecond)
	if l.allow(almostReset) {
		t.Fatal("request just before window reset: want denied, got allowed")
	}

	// Once the window has fully elapsed, the oldest timestamps age out and
	// capacity frees up again.
	afterReset := base.Add(time.Minute + time.Millisecond)
	if !l.allow(afterReset) {
		t.Fatal("request after window reset: want allowed, got denied")
	}
}

// TestLimiter_ConcurrentAccessNeverExceedsMax exercises Allow (the public,
// mutex-guarded entry point) from many goroutines at once and proves that
// the count of allowed requests never exceeds the configured maximum,
// regardless of concurrent access. Run with -race to also prove there is
// no data race on the shared timestamp slice.
func TestLimiter_ConcurrentAccessNeverExceedsMax(t *testing.T) {
	const max = 50
	const attempts = 500

	l := New(max, time.Minute)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowedCount := 0

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow() {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowedCount != max {
		t.Fatalf("allowedCount = %d, want exactly %d", allowedCount, max)
	}
}

// TestLimiter_Info_ReflectsRemainingAndResetAcrossAWindow proves Info
// reports the configured maximum, decreasing remaining capacity, and a
// resetIn that shrinks toward zero as the window's oldest entry ages —
// the values behind the RateLimit-* response headers.
func TestLimiter_Info_ReflectsRemainingAndResetAcrossAWindow(t *testing.T) {
	base := time.Now()
	l := New(5, time.Minute)

	if max, remaining, resetIn := l.info(base); max != 5 || remaining != 5 || resetIn != 0 {
		t.Fatalf("info on a fresh window = (%d, %d, %s), want (5, 5, 0)", max, remaining, resetIn)
	}

	for i := 1; i <= 3; i++ {
		if !l.allow(base) {
			t.Fatalf("request %d: want allowed", i)
		}
	}
	max, remaining, resetIn := l.info(base)
	if max != 5 || remaining != 2 {
		t.Fatalf("info after 3 allowed = (%d, %d), want (5, 2)", max, remaining)
	}
	if resetIn <= 0 || resetIn > time.Minute {
		t.Fatalf("resetIn = %s, want a positive value up to the full window", resetIn)
	}

	// A moment later, resetIn (time until the oldest of those 3 entries
	// ages out) must have shrunk correspondingly.
	later := base.Add(10 * time.Second)
	_, _, resetInLater := l.info(later)
	if resetInLater >= resetIn {
		t.Fatalf("resetIn at t+10s = %s, want strictly less than at t+0s (%s)", resetInLater, resetIn)
	}
}

// TestLimiter_Info_RemainingIsZeroOnceExhausted proves remaining never
// goes negative once every slot in the window is used, and that Info
// still reports a positive resetIn (there's still an oldest entry to
// age out) even though the limiter itself is currently denying.
func TestLimiter_Info_RemainingIsZeroOnceExhausted(t *testing.T) {
	base := time.Now()
	l := New(2, time.Minute)

	l.allow(base)
	l.allow(base)
	if l.allow(base) {
		t.Fatal("3rd request: want denied")
	}

	max, remaining, resetIn := l.info(base)
	if max != 2 {
		t.Fatalf("max = %d, want 2", max)
	}
	if remaining != 0 {
		t.Fatalf("remaining = %d, want 0 once exhausted, never negative", remaining)
	}
	if resetIn <= 0 {
		t.Fatal("resetIn = 0, want positive — the two live entries haven't aged out yet")
	}
}

// TestLimiter_Info_ResetInZeroOnceWindowFullyElapsed proves resetIn
// returns to 0 once every entry has aged out, exactly like a fresh,
// never-used limiter.
func TestLimiter_Info_ResetInZeroOnceWindowFullyElapsed(t *testing.T) {
	base := time.Now()
	l := New(2, time.Minute)
	l.allow(base)

	afterReset := base.Add(time.Minute + time.Millisecond)
	max, remaining, resetIn := l.info(afterReset)
	if max != 2 || remaining != 2 {
		t.Fatalf("info once fully elapsed = (%d, %d), want (2, 2)", max, remaining)
	}
	if resetIn != 0 {
		t.Fatalf("resetIn = %s, want 0 once every entry has aged out", resetIn)
	}
}
