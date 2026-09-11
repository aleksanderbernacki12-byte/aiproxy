package proxy

import (
	"net/url"
	"testing"

	"aiproxy/internal/rules"
)

func newDrainTestServer(t *testing.T) *Server {
	t.Helper()
	target, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return New("unused", target, rules.NewEngine(rules.Allow))
}

func TestServer_DrainStatus_InitiallyNotDraining(t *testing.T) {
	s := newDrainTestServer(t)
	draining, since := s.drainStatus()
	if draining {
		t.Fatalf("draining = true, want false for a freshly constructed Server")
	}
	if !since.IsZero() {
		t.Fatalf("since = %v, want zero time", since)
	}
}

func TestServer_StartDraining_ReportsTransitionOnce(t *testing.T) {
	s := newDrainTestServer(t)
	alreadyDraining, since := s.startDraining()
	if alreadyDraining {
		t.Fatalf("startDraining: alreadyDraining = true on the first call, want false")
	}
	if since.IsZero() {
		t.Fatalf("startDraining: since is zero, want a real timestamp")
	}

	draining, gotSince := s.drainStatus()
	if !draining {
		t.Fatalf("drainStatus: draining = false after startDraining, want true")
	}
	if !gotSince.Equal(since) {
		t.Fatalf("drainStatus: since = %v, want %v", gotSince, since)
	}
}

// TestServer_StartDraining_SecondCallIsIdempotent proves a second
// startDraining while already draining reports alreadyDraining=true and
// returns the ORIGINAL start time, not a reset one — POSTing drainPath
// twice must never push the clock back on an in-progress drain.
func TestServer_StartDraining_SecondCallIsIdempotent(t *testing.T) {
	s := newDrainTestServer(t)
	_, firstSince := s.startDraining()
	alreadyDraining, secondSince := s.startDraining()
	if !alreadyDraining {
		t.Fatalf("startDraining: alreadyDraining = false on the second call, want true")
	}
	if !secondSince.Equal(firstSince) {
		t.Fatalf("startDraining: second call's since = %v, want the original %v unchanged", secondSince, firstSince)
	}
}

func TestServer_StopDraining_RevertsState(t *testing.T) {
	s := newDrainTestServer(t)
	s.startDraining()

	wasDraining := s.stopDraining()
	if !wasDraining {
		t.Fatalf("stopDraining: wasDraining = false, want true")
	}

	draining, since := s.drainStatus()
	if draining {
		t.Fatalf("drainStatus: draining = true after stopDraining, want false")
	}
	if !since.IsZero() {
		t.Fatalf("drainStatus: since = %v after stopDraining, want zero time", since)
	}
}

// TestServer_StopDraining_WhenNotDrainingReportsNoTransition proves
// DELETE drainPath while not draining is a harmless no-op the caller
// (serveDrain) can distinguish from a real transition, so it never logs
// or notifies a webhook for a drain that never existed.
func TestServer_StopDraining_WhenNotDrainingReportsNoTransition(t *testing.T) {
	s := newDrainTestServer(t)
	if wasDraining := s.stopDraining(); wasDraining {
		t.Fatalf("stopDraining: wasDraining = true on a Server that was never draining, want false")
	}
}
