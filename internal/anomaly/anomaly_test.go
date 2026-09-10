package anomaly

import (
	"sync"
	"testing"
	"time"
)

func TestDetector_ColdStartNeverFlagsAnomalous(t *testing.T) {
	d := NewDetector(2, DefaultWindow)
	now := time.Now()
	// A burst of requests in the very first window must never be
	// flagged: there's no established baseline yet to compare against
	// (baseline's zero value would otherwise make literally anything
	// look like an infinite-x spike).
	for i := 0; i < 100; i++ {
		anomalous, _, _ := d.check(now)
		if anomalous {
			t.Fatalf("request %d: flagged anomalous during the very first (cold) window", i)
		}
	}
}

func TestDetector_FlagsASpikeAgainstAnEstablishedBaseline(t *testing.T) {
	d := NewDetector(10, DefaultWindow) // 10x baseline triggers
	now := time.Now()

	// Establish a baseline of 10 requests/minute over a few windows.
	for w := 0; w < 5; w++ {
		windowStart := now.Add(time.Duration(w) * DefaultWindow)
		for i := 0; i < 10; i++ {
			d.check(windowStart)
		}
	}

	// Now a sudden spike: 100 requests in one window is 10x the
	// established baseline of 10 — should trip right at the 10x mark.
	// Immediately follows the setup loop's last window (w=4) with no
	// gap, so no empty window decays the baseline in between.
	spikeStart := now.Add(5 * DefaultWindow)
	var lastAnomalous bool
	var lastCount int
	var lastBaseline float64
	for i := 0; i < 100; i++ {
		lastAnomalous, lastCount, lastBaseline = d.check(spikeStart)
	}
	if !lastAnomalous {
		t.Fatalf("100 requests against a baseline of 10 (10x multiplier) was not flagged anomalous")
	}
	if lastCount != 100 {
		t.Errorf("currentCount = %d, want 100", lastCount)
	}
	if lastBaseline != 10 {
		t.Errorf("baseline = %g, want 10", lastBaseline)
	}
}

func TestDetector_NeverFlagsBelowMinRequestsFloor(t *testing.T) {
	d := NewDetector(1, DefaultWindow) // even 1x would trigger, if not for the floor
	now := time.Now()

	// Establish a near-zero baseline (1 request in the first window).
	d.check(now)

	// A second window with just a couple of requests: technically
	// several times the baseline, but still under minRequestsFloor.
	spikeStart := now.Add(DefaultWindow)
	for i := 0; i < minRequestsFloor-1; i++ {
		anomalous, count, _ := d.check(spikeStart)
		if anomalous {
			t.Fatalf("request %d (count=%d): flagged anomalous below minRequestsFloor (%d)", i, count, minRequestsFloor)
		}
	}
}

func TestDetector_NormalTrafficNeverFlagged(t *testing.T) {
	d := NewDetector(5, DefaultWindow)
	now := time.Now()

	// Steady traffic at roughly the same rate, window after window —
	// never a spike, never flagged, regardless of how many windows
	// pass.
	for w := 0; w < 20; w++ {
		windowStart := now.Add(time.Duration(w) * DefaultWindow)
		for i := 0; i < 20; i++ {
			anomalous, _, _ := d.check(windowStart)
			if anomalous {
				t.Fatalf("window %d, request %d: flagged anomalous under steady, unchanging traffic", w, i)
			}
		}
	}
}

func TestDetector_BaselineAdaptsToASustainedShiftOverTime(t *testing.T) {
	d := NewDetector(3, DefaultWindow)
	now := time.Now()

	// Baseline of 10/minute for a while.
	for w := 0; w < 5; w++ {
		windowStart := now.Add(time.Duration(w) * DefaultWindow)
		for i := 0; i < 10; i++ {
			d.check(windowStart)
		}
	}

	// Traffic genuinely, permanently shifts to 25/minute (2.5x the old
	// baseline — under this detector's 3x threshold, so the very first
	// elevated window should NOT be flagged)...
	var anomalousDuringShift bool
	for w := 5; w < 5+15; w++ {
		windowStart := now.Add(time.Duration(w) * DefaultWindow)
		for i := 0; i < 25; i++ {
			anomalous, _, _ := d.check(windowStart)
			if anomalous {
				anomalousDuringShift = true
			}
		}
	}
	if anomalousDuringShift {
		t.Fatal("a sustained shift to 2.5x the old baseline (under the 3x threshold) was flagged anomalous")
	}

	// ...and after many windows at the new steady rate, the baseline
	// should have adapted close to 25, not stayed pinned near 10.
	// Immediately follows the shift loop's last window (w=19) with no
	// gap, so no empty window decays the baseline in between.
	_, _, baseline := d.check(now.Add(20 * DefaultWindow))
	if baseline < 20 {
		t.Errorf("baseline = %g after 15 windows at the new steady rate, want it to have adapted well above the old 10 baseline", baseline)
	}
}

func TestDetector_LongIdleGapDecaysBaselineInsteadOfStayingStale(t *testing.T) {
	d := NewDetector(5, DefaultWindow)
	now := time.Now()

	// Establish a high baseline.
	for w := 0; w < 5; w++ {
		windowStart := now.Add(time.Duration(w) * DefaultWindow)
		for i := 0; i < 1000; i++ {
			d.check(windowStart)
		}
	}
	_, _, highBaseline := d.check(now.Add(5 * DefaultWindow))
	if highBaseline < 500 {
		t.Fatalf("setup: baseline = %g, want it well-established near 1000", highBaseline)
	}

	// A very long gap in traffic (well past maxCatchUpWindows) before
	// the client is seen again.
	longGapLater := now.Add(time.Duration(maxCatchUpWindows+10) * DefaultWindow)
	anomalous, count, baseline := d.check(longGapLater)
	if anomalous {
		t.Error("first request after a long idle gap was flagged anomalous against a now-meaningless stale baseline")
	}
	if count != 1 {
		t.Errorf("currentCount = %d, want 1 (a fresh window after the gap)", count)
	}
	if baseline != 0 {
		t.Errorf("baseline = %g, want 0 (reset cold after a gap past maxCatchUpWindows)", baseline)
	}
}

func TestDetector_ModerateGapDecaysBaselineThroughEmptyWindows(t *testing.T) {
	d := NewDetector(2, DefaultWindow)
	now := time.Now()

	for w := 0; w < 5; w++ {
		windowStart := now.Add(time.Duration(w) * DefaultWindow)
		for i := 0; i < 100; i++ {
			d.check(windowStart)
		}
	}

	// A moderate gap: several empty windows, but not enough to trigger
	// the cold-reset path.
	afterGap := now.Add(10 * DefaultWindow)
	_, _, baseline := d.check(afterGap)
	if baseline <= 0 || baseline >= 100 {
		t.Errorf("baseline = %g after several empty windows, want it decayed below 100 but still above 0", baseline)
	}
}

func TestRegistry_EmptyClientNeverFlaggedAndAllocatesNothing(t *testing.T) {
	r := NewRegistry(1, DefaultWindow)
	for i := 0; i < 1000; i++ {
		anomalous, count, baseline := r.Check("")
		if anomalous || count != 0 || baseline != 0 {
			t.Fatalf("Check(\"\") = (%v, %d, %g), want (false, 0, 0)", anomalous, count, baseline)
		}
	}
	if len(r.detectors) != 0 {
		t.Errorf("detectors map has %d entries, want 0 for an empty client label", len(r.detectors))
	}
}

func TestRegistry_TracksDistinctClientsIndependently(t *testing.T) {
	r := NewRegistry(10, DefaultWindow)

	// Establish very different baselines for two distinct clients.
	for i := 0; i < 5; i++ {
		r.Check("quiet-client")
	}
	for i := 0; i < 500; i++ {
		r.Check("busy-client")
	}

	if len(r.detectors) != 2 {
		t.Fatalf("detectors map has %d entries, want 2", len(r.detectors))
	}
	if r.detectors["quiet-client"] == r.detectors["busy-client"] {
		t.Fatal("distinct client labels share the same Detector")
	}
}

// TestRegistry_PropagatesWindowToLazilyCreatedDetectors proves a
// Registry's own window (not just its multiplier) reaches every
// Detector it creates on demand — the same short-window trick proxy
// package integration tests rely on to avoid real 60-second sleeps
// only works if the window actually threads all the way through.
func TestRegistry_PropagatesWindowToLazilyCreatedDetectors(t *testing.T) {
	const shortWindow = 10 * time.Millisecond
	r := NewRegistry(2, shortWindow)

	// Establish a baseline of 5/window.
	for w := 0; w < 5; w++ {
		time.Sleep(shortWindow)
		for i := 0; i < 5; i++ {
			r.Check("client")
		}
	}

	// A spike should trip almost immediately if the short window is
	// really in effect — no need for a real 60-second wait.
	time.Sleep(shortWindow)
	var anomalous bool
	for i := 0; i < 20 && !anomalous; i++ {
		anomalous, _, _ = r.Check("client")
	}
	if !anomalous {
		t.Fatal("spike never flagged — Registry's window doesn't appear to have reached its Detector")
	}
}

func TestRegistry_ConcurrentAccessNeverRaces(t *testing.T) {
	r := NewRegistry(5, DefaultWindow)
	var wg sync.WaitGroup
	clients := []string{"a", "b", "c", "d"}
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Check(clients[i%len(clients)])
		}(i)
	}
	wg.Wait()

	if len(r.detectors) != len(clients) {
		t.Errorf("detectors map has %d entries, want %d", len(r.detectors), len(clients))
	}
}
