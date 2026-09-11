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

// TestTokenLimiter_Info_ReflectsRemainingAndResetAsUsageAccrues proves
// Info reports the configured maximum, decreasing remaining budget as
// Add records usage, and a resetIn that shrinks as the oldest recorded
// entry ages — the values behind the RateLimit-* response headers.
func TestTokenLimiter_Info_ReflectsRemainingAndResetAsUsageAccrues(t *testing.T) {
	base := time.Now()
	l := NewTokenLimiter(100, time.Minute)

	if max, remaining, resetIn := l.info(base); max != 100 || remaining != 100 || resetIn != 0 {
		t.Fatalf("info on a fresh window = (%d, %d, %s), want (100, 100, 0)", max, remaining, resetIn)
	}

	l.add(40, base)
	max, remaining, resetIn := l.info(base)
	if max != 100 || remaining != 60 {
		t.Fatalf("info after 40/100 used = (%d, %d), want (100, 60)", max, remaining)
	}
	if resetIn <= 0 || resetIn > time.Minute {
		t.Fatalf("resetIn = %s, want a positive value up to the full window", resetIn)
	}

	later := base.Add(10 * time.Second)
	_, _, resetInLater := l.info(later)
	if resetInLater >= resetIn {
		t.Fatalf("resetIn at t+10s = %s, want strictly less than at t+0s (%s)", resetInLater, resetIn)
	}
}

// TestTokenLimiter_Info_RemainingNeverNegativeOnceOverBudget proves a
// single large Add that overshoots the budget (see
// TestTokenLimiter_SingleLargeAddCanExceedBudget) still reports
// remaining as 0, never a negative number.
func TestTokenLimiter_Info_RemainingNeverNegativeOnceOverBudget(t *testing.T) {
	base := time.Now()
	l := NewTokenLimiter(100, time.Minute)

	l.add(10000, base)
	max, remaining, resetIn := l.info(base)
	if max != 100 {
		t.Fatalf("max = %d, want 100", max)
	}
	if remaining != 0 {
		t.Fatalf("remaining = %d, want 0, never negative", remaining)
	}
	if resetIn <= 0 {
		t.Fatal("resetIn = 0, want positive — the overshooting entry hasn't aged out yet")
	}
}

// TestTokenLimiter_Info_ResetInZeroOnceWindowFullyElapsed proves resetIn
// returns to 0 once every recorded entry has aged out.
func TestTokenLimiter_Info_ResetInZeroOnceWindowFullyElapsed(t *testing.T) {
	base := time.Now()
	l := NewTokenLimiter(100, time.Minute)
	l.add(50, base)

	afterReset := base.Add(time.Minute + time.Millisecond)
	max, remaining, resetIn := l.info(afterReset)
	if max != 100 || remaining != 100 {
		t.Fatalf("info once fully elapsed = (%d, %d), want (100, 100)", max, remaining)
	}
	if resetIn != 0 {
		t.Fatalf("resetIn = %s, want 0 once every entry has aged out", resetIn)
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
