package stats_test

import (
	"strings"
	"sync"
	"testing"

	"aiproxy/internal/stats"
)

func TestStats_RecordsAndSnapshotsCorrectly(t *testing.T) {
	s := stats.New()
	s.RecordAllow()
	s.RecordAllow()
	s.RecordBlock()
	s.RecordRateLimited()
	s.RecordCacheHit()
	s.RecordCacheHit()
	s.RecordCacheHit()
	s.RecordTokensUsed(100)
	s.RecordTokensUsed(50)

	snap := s.Snapshot()
	if snap.Allowed != 2 {
		t.Errorf("Allowed = %d, want 2", snap.Allowed)
	}
	if snap.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", snap.Blocked)
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
}

func TestStats_RecordTokensUsedIgnoresZeroAndNegative(t *testing.T) {
	s := stats.New()
	s.RecordTokensUsed(0)
	s.RecordTokensUsed(-5)
	s.RecordTokensUsed(10)

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
			s.RecordAllow()
			s.RecordBlock()
			s.RecordRateLimited()
			s.RecordCacheHit()
			s.RecordTokensUsed(1)
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

func TestSnapshot_StringContainsAllCounts(t *testing.T) {
	snap := stats.Snapshot{Allowed: 1, Blocked: 2, RateLimited: 3, CacheHits: 4, TotalTokens: 12345}
	rendered := snap.String()
	for _, want := range []string{"1", "2", "3", "4", "12345"} {
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
