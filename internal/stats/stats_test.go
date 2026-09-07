package stats_test

import (
	"strings"
	"sync"
	"testing"

	"aiproxy/internal/stats"
)

func TestStats_RecordsAndSnapshotsCorrectly(t *testing.T) {
	s := stats.New()
	s.RecordAllow("default")
	s.RecordAllow("default")
	s.RecordBlock("default")
	s.RecordRedact("default")
	s.RecordRateLimited("default")
	s.RecordCacheHit("default")
	s.RecordCacheHit("default")
	s.RecordCacheHit("default")
	s.RecordTokensUsed("default", 100)
	s.RecordTokensUsed("default", 50)
	s.RecordResponseBlock("default")
	s.RecordResponseRedact("default")
	s.RecordResponseRedact("default")

	snap := s.Snapshot()
	if snap.Allowed != 2 {
		t.Errorf("Allowed = %d, want 2", snap.Allowed)
	}
	if snap.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", snap.Blocked)
	}
	if snap.Redacted != 1 {
		t.Errorf("Redacted = %d, want 1", snap.Redacted)
	}
	if snap.RateLimited != 1 {
		t.Errorf("RateLimited = %d, want 1", snap.RateLimited)
	}
	if snap.CacheHits != 3 {
		t.Errorf("CacheHits = %d, want 3", snap.CacheHits)
	}
	if snap.TotalTokens != 150 {
		t.Errorf("TotalTokens = %d, want 150", snap.TotalTokens)
	}
	if snap.ResponseBlocked != 1 {
		t.Errorf("ResponseBlocked = %d, want 1", snap.ResponseBlocked)
	}
	if snap.ResponseRedacted != 2 {
		t.Errorf("ResponseRedacted = %d, want 2", snap.ResponseRedacted)
	}
}

func TestStats_RecordTokensUsedIgnoresZeroAndNegative(t *testing.T) {
	s := stats.New()
	s.RecordTokensUsed("default", 0)
	s.RecordTokensUsed("default", -5)
	s.RecordTokensUsed("default", 10)

	if got := s.Snapshot().TotalTokens; got != 10 {
		t.Fatalf("TotalTokens = %d, want 10 (zero/negative values must be ignored)", got)
	}
}

// TestStats_ConcurrentRecordingIsAccurate hammers every counter from many
// goroutines at once and proves the final totals are exact, under -race,
// which is the whole point of using atomics instead of a plain int.
func TestStats_ConcurrentRecordingIsAccurate(t *testing.T) {
	const n = 500
	s := stats.New()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.RecordAllow("default")
			s.RecordBlock("default")
			s.RecordRedact("default")
			s.RecordRateLimited("default")
			s.RecordCacheHit("default")
			s.RecordTokensUsed("default", 1)
		}()
	}
	wg.Wait()

	snap := s.Snapshot()
	if snap.Allowed != n {
		t.Errorf("Allowed = %d, want %d", snap.Allowed, n)
	}
	if snap.Blocked != n {
		t.Errorf("Blocked = %d, want %d", snap.Blocked, n)
	}
	if snap.Redacted != n {
		t.Errorf("Redacted = %d, want %d", snap.Redacted, n)
	}
	if snap.RateLimited != n {
		t.Errorf("RateLimited = %d, want %d", snap.RateLimited, n)
	}
	if snap.CacheHits != n {
		t.Errorf("CacheHits = %d, want %d", snap.CacheHits, n)
	}
	if snap.TotalTokens != n {
		t.Errorf("TotalTokens = %d, want %d", snap.TotalTokens, n)
	}
}

// TestStats_ConcurrentRecordingAcrossTargetsIsAccurate hammers several
// distinct targets concurrently and proves both the overall totals and
// every individual target's totals come out exact — the per-target map
// lookup takes a mutex only to find/create the counters, so this is what
// actually proves that path is race-free and doesn't drop updates.
func TestStats_ConcurrentRecordingAcrossTargetsIsAccurate(t *testing.T) {
	const perTarget = 200
	targets := []string{"/openai", "/anthropic", "default"}
	s := stats.New()

	var wg sync.WaitGroup
	for _, target := range targets {
		for i := 0; i < perTarget; i++ {
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
				s.RecordAllow(target)
				s.RecordTokensUsed(target, 1)
			}(target)
		}
	}
	wg.Wait()

	snap := s.Snapshot()
	wantOverall := int64(perTarget * len(targets))
	if snap.Allowed != wantOverall {
		t.Errorf("overall Allowed = %d, want %d", snap.Allowed, wantOverall)
	}
	if snap.TotalTokens != wantOverall {
		t.Errorf("overall TotalTokens = %d, want %d", snap.TotalTokens, wantOverall)
	}
	for _, target := range targets {
		got, ok := snap.PerTarget[target]
		if !ok {
			t.Fatalf("PerTarget missing %q: %+v", target, snap.PerTarget)
		}
		if got.Allowed != perTarget {
			t.Errorf("PerTarget[%q].Allowed = %d, want %d", target, got.Allowed, perTarget)
		}
		if got.TotalTokens != perTarget {
			t.Errorf("PerTarget[%q].TotalTokens = %d, want %d", target, got.TotalTokens, perTarget)
		}
	}
}

func TestStats_PerTargetTracksSeparatelyFromOverall(t *testing.T) {
	s := stats.New()
	s.RecordAllow("/openai")
	s.RecordAllow("/openai")
	s.RecordAllow("/anthropic")
	s.RecordBlock("/openai")
	s.RecordTokensUsed("/openai", 10)
	s.RecordTokensUsed("/anthropic", 30)

	snap := s.Snapshot()
	if snap.Allowed != 3 {
		t.Fatalf("overall Allowed = %d, want 3", snap.Allowed)
	}
	if snap.TotalTokens != 40 {
		t.Fatalf("overall TotalTokens = %d, want 40", snap.TotalTokens)
	}

	openai, ok := snap.PerTarget["/openai"]
	if !ok {
		t.Fatalf("PerTarget missing /openai: %+v", snap.PerTarget)
	}
	if openai.Allowed != 2 || openai.Blocked != 1 || openai.TotalTokens != 10 {
		t.Fatalf("PerTarget[/openai] = %+v, want allowed=2 blocked=1 tokens=10", openai)
	}

	anthropic, ok := snap.PerTarget["/anthropic"]
	if !ok {
		t.Fatalf("PerTarget missing /anthropic: %+v", snap.PerTarget)
	}
	if anthropic.Allowed != 1 || anthropic.Blocked != 0 || anthropic.TotalTokens != 30 {
		t.Fatalf("PerTarget[/anthropic] = %+v, want allowed=1 blocked=0 tokens=30", anthropic)
	}
}

func TestSnapshot_StringContainsAllCounts(t *testing.T) {
	snap := stats.Snapshot{Allowed: 1, Blocked: 2, Redacted: 6, RateLimited: 3, CacheHits: 4, TotalTokens: 12345}
	rendered := snap.String()
	for _, want := range []string{"1", "2", "3", "4", "6", "12345"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("String() = %q, missing %q", rendered, want)
		}
	}
}

func TestSnapshot_EstimatedCost(t *testing.T) {
	cases := []struct {
		name        string
		totalTokens int64
		rate        float64
		want        float64
	}{
		{"1000 tokens at 0.03/1K", 1000, 0.03, 0.03},
		{"2500 tokens at 0.02/1K", 2500, 0.02, 0.05},
		{"zero tokens", 0, 0.03, 0},
		{"zero rate", 1000, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := stats.Snapshot{TotalTokens: tc.totalTokens}
			got := snap.EstimatedCost(tc.rate)
			if got != tc.want {
				t.Errorf("EstimatedCost(%v) = %v, want %v", tc.rate, got, tc.want)
			}
		})
	}
}

func TestSnapshot_PerTargetString_EmptyWithFewerThanTwoTargets(t *testing.T) {
	empty := stats.Snapshot{}
	if got := empty.PerTargetString(0); got != "" {
		t.Errorf("PerTargetString() with no targets = %q, want \"\"", got)
	}

	oneTarget := stats.Snapshot{PerTarget: map[string]stats.Snapshot{
		"default": {Allowed: 5},
	}}
	if got := oneTarget.PerTargetString(0); got != "" {
		t.Errorf("PerTargetString() with one target = %q, want \"\" (nothing new to say)", got)
	}
}

func TestSnapshot_PerTargetString_RendersSortedBreakdownWithCost(t *testing.T) {
	snap := stats.Snapshot{PerTarget: map[string]stats.Snapshot{
		"/anthropic": {Allowed: 1, TotalTokens: 30},
		"/openai":    {Allowed: 2, Blocked: 1, TotalTokens: 10},
	}}

	rendered := snap.PerTargetString(0.02)

	if !strings.HasPrefix(rendered, "=== per-target breakdown ===") {
		t.Fatalf("PerTargetString() = %q, want it to start with the breakdown header", rendered)
	}
	openaiIdx := strings.Index(rendered, "[/openai]")
	anthropicIdx := strings.Index(rendered, "[/anthropic]")
	if openaiIdx == -1 || anthropicIdx == -1 {
		t.Fatalf("PerTargetString() = %q, missing one of the target lines", rendered)
	}
	if openaiIdx < anthropicIdx {
		t.Errorf("PerTargetString() = %q, want /anthropic before /openai (sorted)", rendered)
	}
	if !strings.Contains(rendered, "[/openai] allowed=2 blocked=1 redacted=0 rate-limited=0 cache-hits=0 tokens=10 response-blocked=0 response-redacted=0 cost=0.0002") {
		t.Errorf("PerTargetString() missing correct /openai line: %q", rendered)
	}
	if !strings.Contains(rendered, "[/anthropic] allowed=1 blocked=0 redacted=0 rate-limited=0 cache-hits=0 tokens=30 response-blocked=0 response-redacted=0 cost=0.0006") {
		t.Errorf("PerTargetString() missing correct /anthropic line: %q", rendered)
	}
}

func TestSnapshot_PerTargetString_OmitsCostWhenRateIsZero(t *testing.T) {
	snap := stats.Snapshot{PerTarget: map[string]stats.Snapshot{
		"/openai":    {Allowed: 1, TotalTokens: 10},
		"/anthropic": {Allowed: 1, TotalTokens: 30},
	}}

	rendered := snap.PerTargetString(0)
	if strings.Contains(rendered, "cost=") {
		t.Errorf("PerTargetString(0) = %q, want no cost field when the rate is zero", rendered)
	}
}
