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
