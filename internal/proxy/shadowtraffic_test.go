package proxy

import (
	"net/url"
	"testing"
)

func TestShouldMirror_RateOneAlwaysMirrorsWithoutTouchingTheRNG(t *testing.T) {
	called := false
	got := shouldMirror(1.0, func() float64 {
		called = true
		return 0.999999
	})
	if !got {
		t.Fatalf("shouldMirror(1.0, ...) = false, want true")
	}
	if called {
		t.Fatalf("shouldMirror(1.0, ...) called randFloat64, want it skipped entirely")
	}
}

func TestShouldMirror_RateAboveOneAlsoAlwaysMirrors(t *testing.T) {
	// Defensive: getShadowTarget never produces a rate above 1.0 in
	// practice (compileShadowTarget rejects it), but shouldMirror
	// itself should still treat >=1 as "always" rather than relying on
	// randFloat64() < rate happening to hold.
	if !shouldMirror(1.5, func() float64 { return 0.999999 }) {
		t.Fatalf("shouldMirror(1.5, ...) = false, want true")
	}
}

func TestShouldMirror_RespectsTheBoundaryAgainstRandFloat64(t *testing.T) {
	cases := []struct {
		rate float64
		r    float64
		want bool
	}{
		{0.5, 0.49, true},
		{0.5, 0.5, false},
		{0.5, 0.99, false},
		{0.1, 0.09, true},
		{0.1, 0.1, false},
	}
	for _, c := range cases {
		got := shouldMirror(c.rate, func() float64 { return c.r })
		if got != c.want {
			t.Errorf("shouldMirror(%v, r=%v) = %v, want %v", c.rate, c.r, got, c.want)
		}
	}
}

func TestServer_GetShadowTarget_NoEntryMeansNotConfigured(t *testing.T) {
	s := newDrainTestServer(t)
	if _, _, ok := s.getShadowTarget("default"); ok {
		t.Fatalf("getShadowTarget on a Server with no TargetShadowURL at all = ok, want not ok")
	}
}

func TestServer_GetShadowTarget_DefaultsSampleRateToOne(t *testing.T) {
	s := newDrainTestServer(t)
	shadow, err := url.Parse("https://shadow.invalid")
	if err != nil {
		t.Fatalf("parse shadow url: %v", err)
	}
	s.TargetShadowURL = map[string]*url.URL{"default": shadow}

	gotURL, gotRate, ok := s.getShadowTarget("default")
	if !ok {
		t.Fatalf("getShadowTarget = not ok, want ok")
	}
	if gotURL != shadow {
		t.Fatalf("getShadowTarget url = %v, want %v", gotURL, shadow)
	}
	if gotRate != 1.0 {
		t.Fatalf("getShadowTarget rate = %v, want 1.0 (the default when TargetShadowSampleRate has no matching entry)", gotRate)
	}
}

func TestServer_GetShadowTarget_UsesTheConfiguredSampleRateWhenPresent(t *testing.T) {
	s := newDrainTestServer(t)
	shadow, err := url.Parse("https://shadow.invalid")
	if err != nil {
		t.Fatalf("parse shadow url: %v", err)
	}
	s.TargetShadowURL = map[string]*url.URL{"default": shadow}
	s.TargetShadowSampleRate = map[string]float64{"default": 0.25}

	_, gotRate, ok := s.getShadowTarget("default")
	if !ok {
		t.Fatalf("getShadowTarget = not ok, want ok")
	}
	if gotRate != 0.25 {
		t.Fatalf("getShadowTarget rate = %v, want 0.25", gotRate)
	}
}
