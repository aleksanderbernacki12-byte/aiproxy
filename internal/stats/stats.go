// Package stats tracks aggregate counters for a running proxy: how many
// requests were allowed, blocked, rate-limited, or served from cache,
// and how many tokens were used in total — both overall and broken down
// per target, for a multi-target setup. It knows nothing about HTTP,
// rules, or the proxy — just counting.
package stats

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// latencyBucketsSeconds are the upper bounds of the histogram buckets
// RecordLatency sorts an observation into — Prometheus's own default
// client-library buckets, a reasonable spread from sub-10ms up to 10s
// for typical HTTP latencies. An observation past the last bound is
// still counted (in Count/SumSeconds and the final "+Inf" bucket) but
// not in any finite one. Declared as a fixed-size array, not a slice,
// so len() is a compile-time constant usable to size counters.latencyBuckets.
var latencyBucketsSeconds = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// counters is one set of atomic counters, safe for concurrent use
// without a mutex. Stats keeps one for the overall total and one per
// target.
type counters struct {
	allowed          atomic.Int64
	blocked          atomic.Int64
	redacted         atomic.Int64
	rateLimited      atomic.Int64
	cacheHits        atomic.Int64
	totalTokens      atomic.Int64
	responseBlocked  atomic.Int64
	responseRedacted atomic.Int64
	failover         atomic.Int64

	latencyBuckets  [len(latencyBucketsSeconds)]atomic.Int64
	latencyCount    atomic.Int64
	latencySumNanos atomic.Int64
}

func (c *counters) snapshot() Snapshot {
	return Snapshot{
		Allowed:          c.allowed.Load(),
		Blocked:          c.blocked.Load(),
		Redacted:         c.redacted.Load(),
		RateLimited:      c.rateLimited.Load(),
		CacheHits:        c.cacheHits.Load(),
		TotalTokens:      c.totalTokens.Load(),
		ResponseBlocked:  c.responseBlocked.Load(),
		ResponseRedacted: c.responseRedacted.Load(),
		Failover:         c.failover.Load(),
		Latency:          c.latencySnapshot(),
	}
}

// recordLatency sorts one observed duration into the histogram: the
// first bucket whose bound is >= the observation (non-cumulative at
// this point — latencySnapshot cumulates on read), plus the running
// count/sum every observation contributes to regardless of which
// bucket it landed in.
func (c *counters) recordLatency(d time.Duration) {
	c.latencyCount.Add(1)
	c.latencySumNanos.Add(int64(d))
	seconds := d.Seconds()
	for i, bound := range latencyBucketsSeconds {
		if seconds <= bound {
			c.latencyBuckets[i].Add(1)
			break
		}
	}
}

// latencySnapshot renders the histogram as cumulative "le" buckets, the
// shape Prometheus's histogram_quantile() expects: each bucket's count
// includes every observation at or below its bound, and the final
// "+Inf" bucket always equals Count.
func (c *counters) latencySnapshot() LatencySnapshot {
	buckets := make([]LatencyBucket, len(latencyBucketsSeconds)+1)
	var cumulative int64
	for i, bound := range latencyBucketsSeconds {
		cumulative += c.latencyBuckets[i].Load()
		buckets[i] = LatencyBucket{Le: strconv.FormatFloat(bound, 'g', -1, 64), Count: cumulative}
	}
	count := c.latencyCount.Load()
	buckets[len(latencyBucketsSeconds)] = LatencyBucket{Le: "+Inf", Count: count}
	return LatencySnapshot{
		Count:      count,
		SumSeconds: float64(c.latencySumNanos.Load()) / 1e9,
		Buckets:    buckets,
	}
}

// ruleCounters tracks the block/redact outcomes attributable to one
// named rule (built-in, custom, or path), for both requests and
// responses, live or dry-run. Unlike counters, it is never nested per
// target: which rule matched is independent of which target the
// request happened to route to, so there is exactly one set of these
// per rule name, globally.
type ruleCounters struct {
	blocked                atomic.Int64
	redacted               atomic.Int64
	responseBlocked        atomic.Int64
	responseRedacted       atomic.Int64
	dryRunBlocked          atomic.Int64
	dryRunRedacted         atomic.Int64
	responseDryRunBlocked  atomic.Int64
	responseDryRunRedacted atomic.Int64
}

func (c *ruleCounters) snapshot() RuleSnapshot {
	return RuleSnapshot{
		Blocked:                c.blocked.Load(),
		Redacted:               c.redacted.Load(),
		ResponseBlocked:        c.responseBlocked.Load(),
		ResponseRedacted:       c.responseRedacted.Load(),
		DryRunBlocked:          c.dryRunBlocked.Load(),
		DryRunRedacted:         c.dryRunRedacted.Load(),
		ResponseDryRunBlocked:  c.responseDryRunBlocked.Load(),
		ResponseDryRunRedacted: c.responseDryRunRedacted.Load(),
	}
}

// clientCounters tracks the handful of outcomes attributable to one
// named proxy API key — see Stats.RecordClientAllow and its siblings.
// Deliberately a smaller set of fields than the per-target counters:
// cache hits, failover, latency, and dry-run activity are inherently
// about the target/route a request happened to go through, not about
// who called it, so there's nothing meaningful to attribute there per
// client.
type clientCounters struct {
	allowed     atomic.Int64
	blocked     atomic.Int64
	redacted    atomic.Int64
	rateLimited atomic.Int64
	totalTokens atomic.Int64

	// budgetAlerted is this client's own one-shot latch for
	// CrossedClientBudget — separate from Stats.budgetAlerted (the
	// global one), so a named key's own cost_budget and the
	// server-wide cost_budget each fire independently, exactly once.
	budgetAlerted atomic.Bool
}

func (c *clientCounters) snapshot() ClientSnapshot {
	return ClientSnapshot{
		Allowed:     c.allowed.Load(),
		Blocked:     c.blocked.Load(),
		Redacted:    c.redacted.Load(),
		RateLimited: c.rateLimited.Load(),
		TotalTokens: c.totalTokens.Load(),
	}
}

// dryRunCounters tracks how often a dry-run rule matched, overall —
// never per target, for the same reason as ruleCounters: a dry-run
// rule's whole point is testing that one rule, not measuring which
// target its traffic happened to go to.
type dryRunCounters struct {
	blocked          atomic.Int64
	redacted         atomic.Int64
	responseBlocked  atomic.Int64
	responseRedacted atomic.Int64
}

// Stats holds a running proxy's counters. The zero value is not usable;
// construct one with New.
type Stats struct {
	overall       counters
	dryRun        dryRunCounters
	unauthorized  atomic.Int64
	ipDenied      atomic.Int64
	budgetAlerted atomic.Bool

	mu        sync.Mutex
	perTarget map[string]*counters
	perRule   map[string]*ruleCounters
	perClient map[string]*clientCounters
}

// New creates a Stats with every counter at zero.
func New() *Stats {
	return &Stats{
		perTarget: make(map[string]*counters),
		perRule:   make(map[string]*ruleCounters),
		perClient: make(map[string]*clientCounters),
	}
}

// counterFor returns the counters for target, creating them on first use.
func (s *Stats) counterFor(target string) *counters {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.perTarget[target]
	if !ok {
		c = &counters{}
		s.perTarget[target] = c
	}
	return c
}

// ruleCounterFor returns the ruleCounters for ruleName, creating them on
// first use.
func (s *Stats) ruleCounterFor(ruleName string) *ruleCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.perRule[ruleName]
	if !ok {
		c = &ruleCounters{}
		s.perRule[ruleName] = c
	}
	return c
}

// clientCounterFor returns the clientCounters for client, creating them
// on first use.
func (s *Stats) clientCounterFor(client string) *clientCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.perClient[client]
	if !ok {
		c = &clientCounters{}
		s.perClient[client] = c
	}
	return c
}

// RecordClientAllow, RecordClientBlock, RecordClientRedact,
// RecordClientRateLimited, and RecordClientTokensUsed are RecordAllow/
// RecordBlock/RecordRedact/RecordRateLimited/RecordTokensUsed's
// counterparts attributing the same outcome to a named proxy API key
// instead of a target — see clientCounters. client is "" whenever no
// proxy_api_key/proxy_api_keys is configured at all (nothing to
// attribute to), in which case these are all deliberate no-ops rather
// than accumulating a meaningless "" bucket.
func (s *Stats) RecordClientAllow(client string) {
	if client == "" {
		return
	}
	s.clientCounterFor(client).allowed.Add(1)
}

func (s *Stats) RecordClientBlock(client string) {
	if client == "" {
		return
	}
	s.clientCounterFor(client).blocked.Add(1)
}

func (s *Stats) RecordClientRedact(client string) {
	if client == "" {
		return
	}
	s.clientCounterFor(client).redacted.Add(1)
}

func (s *Stats) RecordClientRateLimited(client string) {
	if client == "" {
		return
	}
	s.clientCounterFor(client).rateLimited.Add(1)
}

func (s *Stats) RecordClientTokensUsed(client string, n int) {
	if client == "" || n <= 0 {
		return
	}
	s.clientCounterFor(client).totalTokens.Add(int64(n))
}

// RecordAllow records one request that passed rules and the rate
// limiter and was forwarded upstream, attributing it to target (the
// matched multi-target routing prefix, or "default" for the fallback
// --target).
func (s *Stats) RecordAllow(target string) {
	s.overall.allowed.Add(1)
	s.counterFor(target).allowed.Add(1)
}

// RecordBlock records one request the rule engine blocked, attributing
// it to both target and the name of the rule that matched.
func (s *Stats) RecordBlock(target, ruleName string) {
	s.overall.blocked.Add(1)
	s.counterFor(target).blocked.Add(1)
	s.ruleCounterFor(ruleName).blocked.Add(1)
}

// RecordRedact records one request the rule engine forwarded with a
// matched secret masked out of its body, rather than blocking outright.
func (s *Stats) RecordRedact(target, ruleName string) {
	s.overall.redacted.Add(1)
	s.counterFor(target).redacted.Add(1)
	s.ruleCounterFor(ruleName).redacted.Add(1)
}

// RecordRateLimited records one request the circuit breaker rejected.
func (s *Stats) RecordRateLimited(target string) {
	s.overall.rateLimited.Add(1)
	s.counterFor(target).rateLimited.Add(1)
}

// RecordUnauthorized records one request rejected for a missing or
// invalid Proxy-Authorization header, before any target was even
// resolved — so, unlike every other counter, this has no target
// parameter at all: there is nothing to attribute it to yet.
func (s *Stats) RecordUnauthorized() {
	s.unauthorized.Add(1)
}

// RecordIPDenied records one request rejected by the IP allow/deny
// list, before any target was even resolved — same reasoning as
// RecordUnauthorized: no target parameter, since there's nothing to
// attribute it to yet, and this check runs even before proxy
// authentication.
func (s *Stats) RecordIPDenied() {
	s.ipDenied.Add(1)
}

// RecordCacheHit records one request served from the on-disk cache
// instead of reaching the upstream target.
func (s *Stats) RecordCacheHit(target string) {
	s.overall.cacheHits.Add(1)
	s.counterFor(target).cacheHits.Add(1)
}

// RecordTokensUsed adds n to the running total of tokens used for
// target, as reported by upstream responses.
func (s *Stats) RecordTokensUsed(target string, n int) {
	if n > 0 {
		s.overall.totalTokens.Add(int64(n))
		s.counterFor(target).totalTokens.Add(int64(n))
	}
}

// RecordFailover records one candidate URL within target's failover
// list turning out to be unreachable, causing the request to move on to
// the next candidate. Attributed to target (the matched route, or
// "default") like most other counters — unlike RecordUnauthorized/the
// dry-run counters, a failover is always about one specific route's own
// candidate list, so there's no reason to keep it target-agnostic.
func (s *Stats) RecordFailover(target string) {
	s.overall.failover.Add(1)
	s.counterFor(target).failover.Add(1)
}

// RecordLatency records how long one successful upstream RoundTrip took
// for target — see failoverTransport in the proxy package, the only
// caller. When a request failed over across candidates before finally
// succeeding, d includes the time spent on the earlier, unreachable
// attempts too: that retry time is real added latency the client
// actually experienced for this request, not something to hide from
// the histogram.
func (s *Stats) RecordLatency(target string, d time.Duration) {
	s.overall.recordLatency(d)
	s.counterFor(target).recordLatency(d)
}

// RecordResponseBlock records one upstream response the rule engine
// withheld from the client because a rule matched something in it —
// distinct from RecordBlock, which is a request never sent upstream at
// all; this is a leak caught coming back instead of going out.
func (s *Stats) RecordResponseBlock(target, ruleName string) {
	s.overall.responseBlocked.Add(1)
	s.counterFor(target).responseBlocked.Add(1)
	s.ruleCounterFor(ruleName).responseBlocked.Add(1)
}

// RecordResponseRedact records one upstream response the rule engine
// forwarded with a matched secret masked out of it, rather than
// withholding it outright.
func (s *Stats) RecordResponseRedact(target, ruleName string) {
	s.overall.responseRedacted.Add(1)
	s.counterFor(target).responseRedacted.Add(1)
	s.ruleCounterFor(ruleName).responseRedacted.Add(1)
}

// RecordDryRunBlock records one request a dry_run rule would have
// blocked, had it not been in dry-run mode — the request was actually
// forwarded, unmodified. Unlike RecordBlock, this has no target
// parameter: a dry-run rule's whole point is testing that one rule, not
// measuring which target its traffic happened to go to.
func (s *Stats) RecordDryRunBlock(ruleName string) {
	s.dryRun.blocked.Add(1)
	s.ruleCounterFor(ruleName).dryRunBlocked.Add(1)
}

// RecordDryRunRedact records one request a dry_run rule would have
// redacted, had it not been in dry-run mode — the request was actually
// forwarded with nothing masked out.
func (s *Stats) RecordDryRunRedact(ruleName string) {
	s.dryRun.redacted.Add(1)
	s.ruleCounterFor(ruleName).dryRunRedacted.Add(1)
}

// RecordResponseDryRunBlock is RecordDryRunBlock's counterpart for a
// dry_run rule matching an upstream response instead of the client's
// request.
func (s *Stats) RecordResponseDryRunBlock(ruleName string) {
	s.dryRun.responseBlocked.Add(1)
	s.ruleCounterFor(ruleName).responseDryRunBlocked.Add(1)
}

// RecordResponseDryRunRedact is RecordDryRunRedact's counterpart for a
// dry_run rule matching an upstream response instead of the client's
// request.
func (s *Stats) RecordResponseDryRunRedact(ruleName string) {
	s.dryRun.responseRedacted.Add(1)
	s.ruleCounterFor(ruleName).responseDryRunRedacted.Add(1)
}

// CrossedBudget reports whether the running total cost — TotalTokens
// priced at costPer1KTokens — has just reached or passed budget for the
// first time since this Stats was created, via a one-shot CAS on
// budgetAlerted so a long-running proxy alerts exactly once rather than
// on every request past the threshold. budget <= 0 (unset) never
// crosses. cost is always returned (even when not crossed, or when
// budget is unset) so a caller with its own reason to log the current
// cost doesn't need a second call. Once fired, stays fired for the life
// of the process: a budget alert is meant to be a single "you've gone
// over" notice, not a recurring one, even if budget is later raised via
// a config reload.
func (s *Stats) CrossedBudget(costPer1KTokens, budget float64) (cost float64, crossed bool) {
	cost = float64(s.overall.totalTokens.Load()) / 1000 * costPer1KTokens
	if budget <= 0 || cost < budget {
		return cost, false
	}
	return cost, s.budgetAlerted.CompareAndSwap(false, true)
}

// CrossedClientBudget is CrossedBudget's per-client counterpart: it
// reports whether one specific client's own running cost — that
// client's TotalTokens priced at costPer1KTokens, not the whole
// proxy's — has just reached or passed its own budget for the first
// time, via the same one-shot CAS latch pattern, scoped to that
// client's own clientCounters instead of the shared overall one, so a
// named key's own budget and the server-wide budget (or another key's
// own budget) each fire independently. client == "" (no proxy key
// configured at all — nothing to attribute a budget to, and nothing to
// look up) never crosses and never creates a clientCounters entry,
// same no-op-on-empty-label discipline as every RecordClient* method;
// budget <= 0 (this client has no budget of its own) never crosses
// either, but cost is still computed and returned either way, same as
// CrossedBudget.
func (s *Stats) CrossedClientBudget(client string, costPer1KTokens, budget float64) (cost float64, crossed bool) {
	if client == "" {
		return 0, false
	}
	c := s.clientCounterFor(client)
	cost = float64(c.totalTokens.Load()) / 1000 * costPer1KTokens
	if budget <= 0 || cost < budget {
		return cost, false
	}
	return cost, c.budgetAlerted.CompareAndSwap(false, true)
}

// LatencyBucket is one cumulative "le" (less-than-or-equal) point of a
// LatencySnapshot's histogram, rendered the way Prometheus's text
// exposition format expects a bucket's bound: a decimal string for a
// finite bound, or "+Inf" for the last one.
type LatencyBucket struct {
	Le    string `json:"le"`
	Count int64  `json:"count"`
}

// LatencySnapshot is a point-in-time copy of one histogram of observed
// upstream latencies — see Stats.RecordLatency. Buckets is always the
// full, ordered set of latencyBucketsSeconds plus a final "+Inf" entry,
// even when Count is 0, for a structurally predictable shape scrape to
// scrape.
type LatencySnapshot struct {
	Count      int64           `json:"count"`
	SumSeconds float64         `json:"sum_seconds"`
	Buckets    []LatencyBucket `json:"buckets,omitempty"`
}

// AvgLatencyMillis returns the mean observed latency in milliseconds,
// or 0 before any observation has been recorded — a simple derived
// convenience for display, alongside the full histogram, the same role
// Snapshot.EstimatedCost plays for TotalTokens.
func (l LatencySnapshot) AvgLatencyMillis() float64 {
	if l.Count == 0 {
		return 0
	}
	return l.SumSeconds / float64(l.Count) * 1000
}

// RuleSnapshot is a point-in-time copy of one named rule's block/redact
// counters, for both requests and responses, live and dry-run.
type RuleSnapshot struct {
	Blocked          int64 `json:"blocked"`
	Redacted         int64 `json:"redacted"`
	ResponseBlocked  int64 `json:"response_blocked"`
	ResponseRedacted int64 `json:"response_redacted"`

	// DryRunBlocked, DryRunRedacted, ResponseDryRunBlocked, and
	// ResponseDryRunRedacted count what this rule would have done had
	// it not been marked dry_run — see Stats.RecordDryRunBlock.
	DryRunBlocked          int64 `json:"dry_run_blocked"`
	DryRunRedacted         int64 `json:"dry_run_redacted"`
	ResponseDryRunBlocked  int64 `json:"response_dry_run_blocked"`
	ResponseDryRunRedacted int64 `json:"response_dry_run_redacted"`
}

// ClientSnapshot is a point-in-time copy of one named proxy API key's
// attributed activity — see Stats.RecordClientAllow. A smaller set of
// fields than Snapshot: cache hits, failover, latency, and dry-run
// activity are inherently about the target/route a request happened to
// go through, not who called it, so there's nothing to attribute there
// per client.
type ClientSnapshot struct {
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	Redacted    int64 `json:"redacted"`
	RateLimited int64 `json:"rate_limited"`
	TotalTokens int64 `json:"total_tokens"`
}

// EstimatedCost prices TotalTokens at costPer1KTokens, the same unit
// conversion as Snapshot.EstimatedCost.
func (c ClientSnapshot) EstimatedCost(costPer1KTokens float64) float64 {
	return float64(c.TotalTokens) / 1000 * costPer1KTokens
}

// Snapshot is a point-in-time copy of the counters, safe to read and
// print without further synchronization. PerTarget holds the same
// breakdown keyed by target name; a Snapshot inside PerTarget never has
// its own nested PerTarget or PerRule. PerRule holds a breakdown keyed
// by rule name instead of target — which built-in, custom, or path rule
// is actually firing, and how often, independent of which target the
// matching request happened to route to.
type Snapshot struct {
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	Redacted    int64 `json:"redacted"`
	RateLimited int64 `json:"rate_limited"`
	CacheHits   int64 `json:"cache_hits"`
	TotalTokens int64 `json:"total_tokens"`

	// ResponseBlocked and ResponseRedacted count the same two outcomes
	// as Blocked and Redacted, but for a rule matching the upstream's
	// response instead of the client's request — a leak caught coming
	// back rather than going out.
	ResponseBlocked  int64 `json:"response_blocked"`
	ResponseRedacted int64 `json:"response_redacted"`

	// DryRunBlocked, DryRunRedacted, ResponseDryRunBlocked, and
	// ResponseDryRunRedacted count what a dry_run rule would have done
	// had it not been in dry-run mode — never broken down per target,
	// same reasoning as PerRule; see Stats.RecordDryRunBlock.
	DryRunBlocked          int64 `json:"dry_run_blocked"`
	DryRunRedacted         int64 `json:"dry_run_redacted"`
	ResponseDryRunBlocked  int64 `json:"response_dry_run_blocked"`
	ResponseDryRunRedacted int64 `json:"response_dry_run_redacted"`

	// Unauthorized counts requests rejected for a missing or invalid
	// Proxy-Authorization header, when Server.ProxyAPIKey is set. Never
	// broken down per target — see Stats.RecordUnauthorized.
	Unauthorized int64 `json:"unauthorized"`

	// IPDenied counts requests rejected by the IP allow/deny list,
	// before proxy authentication or anything else even runs. Never
	// broken down per target — see Stats.RecordIPDenied.
	IPDenied int64 `json:"ip_denied"`

	// Failover counts how many times a request moved on to the next
	// candidate URL in a target's failover list because an earlier one
	// was unreachable — see Stats.RecordFailover. Unlike Unauthorized
	// and the dry-run counters, this is broken down per target: a
	// failover is always about one specific route's own candidate list.
	Failover int64 `json:"failover"`

	// Latency summarizes observed upstream response times as a
	// Prometheus-style histogram — see Stats.RecordLatency. Present at
	// every level (top-level, and inside each PerTarget entry) same as
	// TotalTokens: a target's own latency profile is exactly the kind of
	// thing a per-target breakdown exists to surface.
	Latency LatencySnapshot `json:"latency"`

	PerTarget map[string]Snapshot     `json:"per_target,omitempty"`
	PerRule   map[string]RuleSnapshot `json:"per_rule,omitempty"`

	// PerClient holds a breakdown keyed by named proxy API key instead of
	// target or rule — see ClientSnapshot. Empty whenever no
	// proxy_api_key/proxy_api_keys is configured at all.
	PerClient map[string]ClientSnapshot `json:"per_client,omitempty"`
}

// Snapshot returns the current value of every counter, overall, per
// target, per rule, and per client.
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	perTarget := make(map[string]Snapshot, len(s.perTarget))
	for name, c := range s.perTarget {
		perTarget[name] = c.snapshot()
	}
	perRule := make(map[string]RuleSnapshot, len(s.perRule))
	for name, c := range s.perRule {
		perRule[name] = c.snapshot()
	}
	perClient := make(map[string]ClientSnapshot, len(s.perClient))
	for name, c := range s.perClient {
		perClient[name] = c.snapshot()
	}
	s.mu.Unlock()

	snap := s.overall.snapshot()
	snap.DryRunBlocked = s.dryRun.blocked.Load()
	snap.DryRunRedacted = s.dryRun.redacted.Load()
	snap.ResponseDryRunBlocked = s.dryRun.responseBlocked.Load()
	snap.ResponseDryRunRedacted = s.dryRun.responseRedacted.Load()
	snap.Unauthorized = s.unauthorized.Load()
	snap.IPDenied = s.ipDenied.Load()
	snap.PerTarget = perTarget
	snap.PerRule = perRule
	snap.PerClient = perClient
	return snap
}

// EstimatedCost prices TotalTokens at costPer1KTokens per 1,000 tokens.
// This is a plain unit conversion — aiproxy has no opinion on currency,
// on what the rate actually covers (e.g. a blended input/output rate vs.
// separate ones), or on whether it is still accurate; the caller
// supplies the rate and is responsible for what it means.
func (s Snapshot) EstimatedCost(costPer1KTokens float64) float64 {
	return float64(s.TotalTokens) / 1000 * costPer1KTokens
}

// String renders the snapshot as a short, aligned, human-readable block.
// The two dry-run lines are omitted entirely when no dry_run rule has
// ever matched — most runs have none configured, and four zeroes would
// just be noise.
func (s Snapshot) String() string {
	out := fmt.Sprintf(
		"=== aiproxy session summary ===\n"+
			"Requests allowed:    %d\n"+
			"Requests blocked:    %d\n"+
			"Requests redacted:   %d\n"+
			"Rate-limited (429):  %d\n"+
			"Cache hits:          %d\n"+
			"Total tokens used:   %d\n"+
			"Responses blocked:   %d\n"+
			"Responses redacted:  %d",
		s.Allowed, s.Blocked, s.Redacted, s.RateLimited, s.CacheHits, s.TotalTokens,
		s.ResponseBlocked, s.ResponseRedacted,
	)
	if s.DryRunBlocked > 0 || s.DryRunRedacted > 0 || s.ResponseDryRunBlocked > 0 || s.ResponseDryRunRedacted > 0 {
		out += fmt.Sprintf(
			"\nDry-run would-block:  %d\n"+
				"Dry-run would-redact: %d",
			s.DryRunBlocked+s.ResponseDryRunBlocked, s.DryRunRedacted+s.ResponseDryRunRedacted,
		)
	}
	// Only shown when nonzero, same reasoning as the dry-run lines: this
	// is always 0 for the vast majority of runs that never set
	// proxy_api_key, so printing it unconditionally would just be noise.
	if s.Unauthorized > 0 {
		out += fmt.Sprintf("\nUnauthorized (407):   %d", s.Unauthorized)
	}
	// Same reasoning again: 0 for every run that never configured
	// ip_allow_list/ip_deny_list, or that did but never actually denied
	// anything.
	if s.IPDenied > 0 {
		out += fmt.Sprintf("\nIP denied (403):      %d", s.IPDenied)
	}
	// Same reasoning again: 0 for every run that never configured a
	// multi-URL target, or that did but never needed to actually use it.
	if s.Failover > 0 {
		out += fmt.Sprintf("\nFailovers:            %d", s.Failover)
	}
	if s.Latency.Count > 0 {
		out += fmt.Sprintf("\nAvg upstream latency: %.1fms (n=%d)", s.Latency.AvgLatencyMillis(), s.Latency.Count)
	}
	return out
}

// PerTargetString renders a per-target breakdown, sorted by target name,
// pricing each target's tokens at costPer1KTokens (omitted when zero).
// It returns "" when fewer than two targets were ever recorded — a
// single-target run's breakdown would just repeat the block above, so
// there is nothing worth adding.
func (s Snapshot) PerTargetString(costPer1KTokens float64) string {
	if len(s.PerTarget) < 2 {
		return ""
	}

	names := make([]string, 0, len(s.PerTarget))
	for name := range s.PerTarget {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("=== per-target breakdown ===")
	for _, name := range names {
		t := s.PerTarget[name]
		fmt.Fprintf(&b, "\n[%s] allowed=%d blocked=%d redacted=%d rate-limited=%d cache-hits=%d tokens=%d response-blocked=%d response-redacted=%d",
			name, t.Allowed, t.Blocked, t.Redacted, t.RateLimited, t.CacheHits, t.TotalTokens, t.ResponseBlocked, t.ResponseRedacted)
		if costPer1KTokens > 0 {
			fmt.Fprintf(&b, " cost=%.4f", t.EstimatedCost(costPer1KTokens))
		}
		if t.Failover > 0 {
			fmt.Fprintf(&b, " failover=%d", t.Failover)
		}
		if t.Latency.Count > 0 {
			fmt.Fprintf(&b, " avg-latency=%.1fms", t.Latency.AvgLatencyMillis())
		}
	}
	return b.String()
}

// PerRuleString renders a per-rule breakdown, sorted by rule name. It
// returns "" once no rule has ever matched — unlike PerTargetString,
// this shows even a single entry: the overall totals already conflate
// every rule together, so one rule's own numbers are never redundant
// with them the way a single target's are with the totals above.
func (s Snapshot) PerRuleString() string {
	if len(s.PerRule) == 0 {
		return ""
	}

	names := make([]string, 0, len(s.PerRule))
	for name := range s.PerRule {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("=== per-rule breakdown ===")
	for _, name := range names {
		r := s.PerRule[name]
		fmt.Fprintf(&b, "\n[%s] blocked=%d redacted=%d response-blocked=%d response-redacted=%d",
			name, r.Blocked, r.Redacted, r.ResponseBlocked, r.ResponseRedacted)
		if r.DryRunBlocked > 0 || r.DryRunRedacted > 0 || r.ResponseDryRunBlocked > 0 || r.ResponseDryRunRedacted > 0 {
			fmt.Fprintf(&b, " dry-run-blocked=%d dry-run-redacted=%d dry-run-response-blocked=%d dry-run-response-redacted=%d",
				r.DryRunBlocked, r.DryRunRedacted, r.ResponseDryRunBlocked, r.ResponseDryRunRedacted)
		}
	}
	return b.String()
}

// PerClientString renders a per-client breakdown, sorted by client
// name, pricing each client's tokens at costPer1KTokens (omitted when
// zero) — same shape and reasoning as PerRuleString: shown even for a
// single client, since the overall totals already conflate every caller
// together. Returns "" when no proxy_api_key/proxy_api_keys traffic has
// ever been recorded.
func (s Snapshot) PerClientString(costPer1KTokens float64) string {
	if len(s.PerClient) == 0 {
		return ""
	}

	names := make([]string, 0, len(s.PerClient))
	for name := range s.PerClient {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("=== per-client breakdown ===")
	for _, name := range names {
		c := s.PerClient[name]
		fmt.Fprintf(&b, "\n[%s] allowed=%d blocked=%d redacted=%d rate-limited=%d tokens=%d",
			name, c.Allowed, c.Blocked, c.Redacted, c.RateLimited, c.TotalTokens)
		if costPer1KTokens > 0 {
			fmt.Fprintf(&b, " cost=%.4f", c.EstimatedCost(costPer1KTokens))
		}
	}
	return b.String()
}
