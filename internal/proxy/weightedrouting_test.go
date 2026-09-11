package proxy

import (
	"net/url"
	"testing"

	"aiproxy/internal/rules"
)

func TestPickWeightedIndexFrom_BoundariesRespectEachWeightsOwnShare(t *testing.T) {
	weights := []int{30, 70} // index 0 owns [0,30), index 1 owns [30,100)
	cases := []struct {
		r    int
		want int
	}{
		{0, 0},
		{29, 0},
		{30, 1},
		{99, 1},
	}
	for _, c := range cases {
		got := pickWeightedIndexFrom(weights, func(int) int { return c.r })
		if got != c.want {
			t.Errorf("pickWeightedIndexFrom(%v, r=%d) = %d, want %d", weights, c.r, got, c.want)
		}
	}
}

func TestPickWeightedIndexFrom_ThreeWayBoundaries(t *testing.T) {
	weights := []int{1, 1, 1} // each owns exactly one of [0,1) [1,2) [2,3)
	cases := []struct {
		r    int
		want int
	}{
		{0, 0},
		{1, 1},
		{2, 2},
	}
	for _, c := range cases {
		got := pickWeightedIndexFrom(weights, func(int) int { return c.r })
		if got != c.want {
			t.Errorf("pickWeightedIndexFrom(%v, r=%d) = %d, want %d", weights, c.r, got, c.want)
		}
	}
}

func TestPickWeightedIndexFrom_CallsRandIntNWithTheWeightSum(t *testing.T) {
	weights := []int{5, 10, 15}
	var gotTotal int
	pickWeightedIndexFrom(weights, func(total int) int {
		gotTotal = total
		return 0
	})
	if gotTotal != 30 {
		t.Errorf("randIntN was called with %d, want the sum of weights (30)", gotTotal)
	}
}

func TestWeightedOrdered_NilWeightsReturnsCandidatesUnchanged(t *testing.T) {
	a := mustParseURL(t, "https://a.example.com")
	b := mustParseURL(t, "https://b.example.com")
	candidates := []*url.URL{a, b}

	got := weightedOrdered(candidates, nil)
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("weightedOrdered with nil weights = %v, want candidates returned unchanged", got)
	}
}

func TestWeightedOrdered_SingleCandidateReturnedUnchanged(t *testing.T) {
	a := mustParseURL(t, "https://a.example.com")
	candidates := []*url.URL{a}

	got := weightedOrdered(candidates, []int{100})
	if len(got) != 1 || got[0] != a {
		t.Fatalf("weightedOrdered with one candidate = %v, want unchanged", got)
	}
}

// TestWeightedOrdered_HeavilyWeightedCandidateDominatesRealSelection
// proves weightedOrdered's real (non-deterministic) behavior actually
// splits traffic in proportion to the configured weights — using a
// deliberately lopsided ratio (1 : 999) so the outcome is
// statistically certain without needing to inject a fake random
// source into weightedOrdered itself.
func TestWeightedOrdered_HeavilyWeightedCandidateDominatesRealSelection(t *testing.T) {
	light := mustParseURL(t, "https://light.example.com")
	heavy := mustParseURL(t, "https://heavy.example.com")
	candidates := []*url.URL{light, heavy}
	weights := []int{1, 999}

	heavyFirstCount := 0
	const trials = 200
	for i := 0; i < trials; i++ {
		got := weightedOrdered(candidates, weights)
		if len(got) != 2 {
			t.Fatalf("weightedOrdered returned %d candidates, want 2", len(got))
		}
		if got[0] == heavy {
			heavyFirstCount++
			if got[1] != light {
				t.Fatalf("when heavy is picked first, light must be the only remaining candidate, got %v", got[1])
			}
		} else if got[0] != light {
			t.Fatalf("weightedOrdered()[0] = %v, want either light or heavy", got[0])
		}
	}
	// With a 999:1 ratio, "heavy" should win essentially every trial;
	// allow a wide margin purely to avoid any realistic flake.
	if heavyFirstCount < trials-5 {
		t.Fatalf("heavy candidate was picked first %d/%d times, want it to dominate given its 999:1 weight", heavyFirstCount, trials)
	}
}

// TestResolveRoute_WeightedRouteVariesTargetsAcrossCalls proves
// resolveRoute performs a genuinely fresh weighted pick on every call
// for a weighted route — not once at AddRoute time — which is exactly
// what makes the cache key (computed from targets[0] right after
// resolveRoute returns, in ServeHTTP) correctly vary per request
// instead of always identifying the same candidate the way a plain
// (unweighted) multi-candidate route's cache key always does.
func TestResolveRoute_WeightedRouteVariesTargetsAcrossCalls(t *testing.T) {
	a := mustParseURL(t, "https://a.example.com")
	b := mustParseURL(t, "https://b.example.com")
	s := New("unused", a, rules.NewEngine(rules.Allow))
	s.AddRoute("/split", []*url.URL{a, b}, []int{1, 1}, nil, nil)

	seenA, seenB := false, false
	for i := 0; i < 200 && !(seenA && seenB); i++ {
		targets, _, _, _, _ := s.resolveRoute("/split/v1")
		if len(targets) != 2 {
			t.Fatalf("resolveRoute returned %d targets, want 2", len(targets))
		}
		switch targets[0] {
		case a:
			seenA = true
		case b:
			seenB = true
		default:
			t.Fatalf("targets[0] = %v, want a or b", targets[0])
		}
	}
	if !seenA || !seenB {
		t.Fatalf("across 200 calls to a 50/50 weighted route, both candidates should have appeared as targets[0] at least once (seenA=%v, seenB=%v)", seenA, seenB)
	}
}

// mustParseURL is a small test helper for weighted-routing tests that
// only need a *url.URL identity, not a real listening server.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}
