package limiter

import (
	"sync"
	"testing"
	"time"
)

func TestLimiter_RollingWindowExpiresOnlyOldestAtExactBoundary(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	l := New(2, time.Minute)
	if !l.allow(base) || !l.allow(base.Add(30*time.Second)) {
		t.Fatal("initial requests must fit the window")
	}
	if l.allow(base.Add(time.Minute - time.Nanosecond)) {
		t.Fatal("oldest request must still count just before its expiry")
	}
	if !l.allow(base.Add(time.Minute)) {
		t.Fatal("oldest request must expire exactly at the window boundary")
	}
	if l.allow(base.Add(time.Minute)) {
		t.Fatal("expiring the oldest request must not reset the newer request")
	}
	max, remaining, reset := l.info(base.Add(time.Minute))
	if max != 2 || remaining != 0 || reset != 30*time.Second {
		t.Fatalf("info = (%d, %d, %s), want (2, 0, 30s)", max, remaining, reset)
	}
	if !l.allow(base.Add(90 * time.Second)) {
		t.Fatal("rejected attempts must not postpone the next slot's expiry")
	}
}

func TestTokenLimiter_RollingWindowExpiresOnlyOldestUsageAtExactBoundary(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	l := NewTokenLimiter(100, time.Minute)
	l.add(40, base)
	l.add(60, base.Add(30*time.Second))
	if l.allow(base.Add(time.Minute - time.Nanosecond)) {
		t.Fatal("all 100 tokens must still count just before expiry")
	}
	if !l.allow(base.Add(time.Minute)) {
		t.Fatal("the oldest 40 tokens must expire at the boundary")
	}
	max, remaining, reset := l.info(base.Add(time.Minute))
	if max != 100 || remaining != 40 || reset != 30*time.Second {
		t.Fatalf("info = (%d, %d, %s), want (100, 40, 30s)", max, remaining, reset)
	}
	l.add(40, base.Add(time.Minute))
	if l.allow(base.Add(time.Minute)) {
		t.Fatal("new usage must combine with the 60 tokens still in the window")
	}
	_, remaining, reset = l.info(base.Add(90 * time.Second))
	if remaining != 60 || reset != 30*time.Second {
		t.Fatalf("remaining/reset = (%d, %s), want (60, 30s)", remaining, reset)
	}
}

func TestTokenLimiter_ConcurrentAccountingDoesNotLoseUsage(t *testing.T) {
	const workers, tokensPerWorker, budget = 128, 3, 1000
	l := NewTokenLimiter(budget, time.Hour)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			l.Add(tokensPerWorker)
			l.Allow()
			l.Info()
		}()
	}
	close(start)
	wg.Wait()
	max, remaining, _ := l.Info()
	if max != budget || remaining != budget-workers*tokensPerWorker {
		t.Fatalf("concurrent accounting = (%d, %d), want (%d, %d)", max, remaining, budget, budget-workers*tokensPerWorker)
	}
	l.Add(remaining)
	if l.Allow() {
		t.Fatal("filling the remaining budget must reject the next request")
	}
}
