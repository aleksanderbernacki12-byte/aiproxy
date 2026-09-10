package limiter

import (
	"sync"
	"testing"
	"time"
)

// TestTokenLimiter_AllowNeverRecordsByItself proves Allow is a pure peek:
// calling it many times, with no Add in between, never moves the window
// closer to budget — unlike Limiter.Allow, which records every call that
// passes.
func TestTokenLimiter_AllowNeverRecordsByItself(t *testing.T) {
	base := time.Now()
	l := NewTokenLimiter(10, time.Minute)

	for i := 1; i <= 100; i++ {
		if !l.allow(base) {
			t.Fatalf("call %d: want allowed (nothing ever recorded), got denied", i)
		}
	}
}

// TestTokenLimiter_DeniesOnceRecordedUsageReachesBudget proves Allow
// switches from true to false once Add has recorded at least maxTokens
// within the window, and stays false for further Adds.
func TestTokenLimiter_DeniesOnceRecordedUsageReachesBudget(t *testing.T) {
	base := time.Now()
	l := NewTokenLimiter(100, time.Minute)

	l.add(40, base)
	if !l.allow(base) {
		t.Fatal("after 40/100 tokens: want allowed, got denied")
	}

	l.add(59, base)
	if !l.allow(base) {
		t.Fatal("after 99/100 tokens: want allowed, got denied")
	}

	l.add(1, base)
	if l.allow(base) {
		t.Fatal("after 100/100 tokens: want denied, got allowed")
	}

	l.add(1, base)
	if l.allow(base) {
		t.Fatal("after 101/100 tokens: want denied, got allowed")
	}
}

// TestTokenLimiter_SingleLargeAddCanExceedBudget documents the
// intentional overshoot tradeoff described in TokenLimiter's doc
// comment: a single Add larger than the whole budget is still recorded
// in full, since by the time it's known the request has already
// happened — there is nothing left to reject.
func TestTokenLimiter_SingleLargeAddCanExceedBudget(t *testing.T) {
	base := time.Now()
	l := NewTokenLimiter(100, time.Minute)

	if !l.allow(base) {
		t.Fatal("before any usage: want allowed, got denied")
	}
	l.add(10000, base)
	if l.allow(base) {
		t.Fatal("after a single 10000-token response against a 100-token budget: want denied, got allowed")
	}
}

// TestTokenLimiter_ReleasesAfterWindowResets proves that once the
// window has fully elapsed, the oldest recorded usage ages out and
// capacity frees up again — the same behavior Limiter's own sliding
// window provides for request counts.
func TestTokenLimiter_ReleasesAfterWindowResets(t *testing.T) {
	base := time.Now()
	l := NewTokenLimiter(100, time.Minute)

	l.add(100, base)
	if l.allow(base) {
		t.Fatal("immediately after reaching budget: want denied, got allowed")
	}

	almostReset := base.Add(time.Minute - time.Millisecond)
	if l.allow(almostReset) {
		t.Fatal("just before window reset: want denied, got allowed")
	}

	afterReset := base.Add(time.Minute + time.Millisecond)
	if !l.allow(afterReset) {
		t.Fatal("after window reset: want allowed, got denied")
	}
}

// TestTokenLimiter_AddOfZeroOrNegativeIsNoOp proves Add(n) for n <= 0
// never affects the window — a response that reported no usable usage
// figure must never count as if it had used zero-cost tokens that could
// still, incorrectly, occupy a slot.
func TestTokenLimiter_AddOfZeroOrNegativeIsNoOp(t *testing.T) {
	base := time.Now()
	l := NewTokenLimiter(1, time.Minute)

	l.add(0, base)
	l.add(-5, base)
	if !l.allow(base) {
		t.Fatal("after Add(0) and Add(-5): want still allowed, got denied")
	}
}

// TestTokenLimiter_ConcurrentAccessNeverRaces exercises Allow and Add
// (the public, mutex-guarded entry points) from many goroutines at once.
// Run with -race to prove there is no data race on the shared entries
// slice; unlike Limiter's equivalent test, there is no single "allowed
// count" invariant to assert here, since Allow and Add are independent
// operations.
func TestTokenLimiter_ConcurrentAccessNeverRaces(t *testing.T) {
	const attempts = 500

	l := NewTokenLimiter(1000, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.Allow()
		}()
		go func() {
			defer wg.Done()
			l.Add(1)
		}()
	}
	wg.Wait()
}
