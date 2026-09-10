// Package anomaly flags a sudden spike in one client's own request
// rate relative to its own recent baseline — a complement to
// internal/limiter's fixed max_requests_per_minute cap, which only
// ever catches a caller that's too fast in absolute terms, never one
// that's merely far faster than it itself normally is. Stdlib-only, no
// dependency on the proxy package.
package anomaly

import (
	"sync"
	"time"
)

// DefaultWindow is the bucket size the cli package constructs every
// production Registry with — one minute, the same granularity every
// other per-minute breaker in this project (max_requests_per_minute,
// max_tokens_per_minute) already uses. NewDetector/NewRegistry take an
// explicit window instead of hardcoding this, the same shape
// limiter.New/limiter.NewTokenLimiter already use, so tests (in this
// package and in the proxy package's own integration tests) can use a
// short window instead of waiting on real wall-clock minutes.
const DefaultWindow = time.Minute

// emaAlpha weights how much a single just-completed window moves the
// baseline: high enough that a genuine, sustained shift in traffic is
// reflected within a handful of windows, low enough that one window's
// own spike doesn't itself immediately distort the baseline it's
// being measured against.
const emaAlpha = 0.3

// minRequestsFloor is the smallest current-window count Check will
// ever flag as anomalous, regardless of the ratio to baseline — avoids
// flagging a client whose baseline is naturally near zero (a caller
// averaging 0.2 requests/minute would otherwise see its second-ever
// request in a window read as a "10x spike").
const minRequestsFloor = 5

// maxCatchUpWindows bounds how many empty windows Check will walk
// through one at a time to decay a stale baseline after a long gap in
// traffic — beyond this, the existing baseline is no longer meaningful
// anyway, so Check resets cold in one step instead of iterating
// potentially hundreds of thousands of empty windows for a client
// that simply hasn't been seen in a long time.
const maxCatchUpWindows = 1000

// Detector tracks one identity's own recent request-rate baseline — an
// exponential moving average of completed windows' request counts —
// and reports whether a just-recorded request pushes the current,
// still-open window to multiplier times that baseline or more. Safe
// for concurrent use.
type Detector struct {
	multiplier float64
	window     time.Duration

	mu          sync.Mutex
	windowStart time.Time
	windowCount int
	baseline    float64
	warm        bool // true once at least one full window has completed, so baseline is a real measurement, not its zero value
}

// NewDetector creates a Detector that flags a window whose count
// reaches multiplier times the established baseline, measured in
// buckets of the given window duration (DefaultWindow in production).
func NewDetector(multiplier float64, window time.Duration) *Detector {
	return &Detector{multiplier: multiplier, window: window}
}

// Check records one request against d's current window and reports
// whether it should be treated as anomalous, along with the current
// window's count (including this request) and the baseline it was
// compared against — both meaningful even when anomalous is false, so
// a caller always has real numbers to log or alert with.
func (d *Detector) Check() (anomalous bool, currentCount int, baseline float64) {
	return d.check(time.Now())
}

// check is the deterministic core of Check, taking the current instant
// as a parameter so it can be exercised precisely (and without
// sleeping) by tests in this package.
func (d *Detector) check(now time.Time) (anomalous bool, currentCount int, baseline float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.windowStart.IsZero() {
		d.windowStart = now
	}

	if elapsed := now.Sub(d.windowStart); elapsed >= time.Duration(maxCatchUpWindows)*d.window {
		d.baseline = 0
		d.warm = false
		d.windowStart = now
		d.windowCount = 0
	} else {
		for now.Sub(d.windowStart) >= d.window {
			d.rollWindowLocked()
		}
	}
	d.windowCount++

	anomalous = d.warm && d.windowCount >= minRequestsFloor && float64(d.windowCount) >= d.baseline*d.multiplier
	return anomalous, d.windowCount, d.baseline
}

func (d *Detector) rollWindowLocked() {
	if d.warm {
		d.baseline = emaAlpha*float64(d.windowCount) + (1-emaAlpha)*d.baseline
	} else {
		d.baseline = float64(d.windowCount)
		d.warm = true
	}
	d.windowCount = 0
	d.windowStart = d.windowStart.Add(d.window)
}

// Registry holds one Detector per client label, created lazily on
// first use — the set of labels is bounded by whichever names
// checkProxyAuth ever resolves (the anonymous "default" key and any
// configured proxy_api_keys[] entries), so there's nothing to
// preconfigure ahead of time. Safe for concurrent use.
type Registry struct {
	multiplier float64
	window     time.Duration

	mu        sync.Mutex
	detectors map[string]*Detector
}

// NewRegistry creates a Registry whose Detectors all flag a window
// whose count reaches multiplier times its own established baseline,
// measured in buckets of the given window duration (DefaultWindow in
// production).
func NewRegistry(multiplier float64, window time.Duration) *Registry {
	return &Registry{multiplier: multiplier, window: window, detectors: make(map[string]*Detector)}
}

// Check records one request for client and reports whether it's
// anomalous (see Detector.Check). client == "" always reports
// (false, 0, 0) without allocating a Detector — there's no notion of
// "this caller's own baseline" without an identified caller, the same
// convention proxy.Server's own per-client Stats methods already use
// for an empty client label.
func (r *Registry) Check(client string) (anomalous bool, currentCount int, baseline float64) {
	if client == "" {
		return false, 0, 0
	}
	return r.detectorFor(client).Check()
}

func (r *Registry) detectorFor(client string) *Detector {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.detectors[client]
	if !ok {
		d = NewDetector(r.multiplier, r.window)
		r.detectors[client] = d
	}
	return d
}
