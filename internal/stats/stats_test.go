package stats_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"aiproxy/internal/stats"
)

func TestStats_RecordsAndSnapshotsCorrectly(t *testing.T) {
	s := stats.New()
	s.RecordAllow("default")
	s.RecordAllow("default")
	s.RecordBlock("default", "aws-access-key")
	s.RecordRedact("default", "openai-api-key")
	s.RecordRateLimited("default")
	s.RecordCacheHit("default")
	s.RecordCacheHit("default")
	s.RecordCacheHit("default")
	s.RecordTokensUsed("default", 100)
	s.RecordTokensUsed("default", 50)
	s.RecordResponseBlock("default", "aws-access-key")
	s.RecordResponseRedact("default", "openai-api-key")
	s.RecordResponseRedact("default", "openai-api-key")

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

	awsKey, ok := snap.PerRule["aws-access-key"]
	if !ok {
		t.Fatalf("PerRule missing aws-access-key: %+v", snap.PerRule)
	}
	if awsKey.Blocked != 1 || awsKey.ResponseBlocked != 1 || awsKey.Redacted != 0 || awsKey.ResponseRedacted != 0 {
		t.Fatalf("PerRule[aws-access-key] = %+v, want blocked=1 response-blocked=1", awsKey)
	}
	openaiKey, ok := snap.PerRule["openai-api-key"]
	if !ok {
		t.Fatalf("PerRule missing openai-api-key: %+v", snap.PerRule)
	}
	if openaiKey.Redacted != 1 || openaiKey.ResponseRedacted != 2 || openaiKey.Blocked != 0 || openaiKey.ResponseBlocked != 0 {
		t.Fatalf("PerRule[openai-api-key] = %+v, want redacted=1 response-redacted=2", openaiKey)
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
			s.RecordBlock("default", "test-rule")
			s.RecordRedact("default", "test-rule")
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
	testRule, ok := snap.PerRule["test-rule"]
	if !ok {
		t.Fatalf("PerRule missing test-rule: %+v", snap.PerRule)
	}
	if testRule.Blocked != n || testRule.Redacted != n {
		t.Errorf("PerRule[test-rule] = %+v, want blocked=%d redacted=%d", testRule, n, n)
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

// TestStats_ConcurrentRecordingAcrossRulesIsAccurate is
// TestStats_ConcurrentRecordingAcrossTargetsIsAccurate's counterpart for
// the per-rule map: several distinct rule names are hammered
// concurrently, proving the map lookup that creates a rule's counters
// on first use is race-free and never drops an update.
func TestStats_ConcurrentRecordingAcrossRulesIsAccurate(t *testing.T) {
	const perRule = 200
	ruleNames := []string{"aws-access-key", "openai-api-key", "custom-rule"}
	s := stats.New()

	var wg sync.WaitGroup
	for _, ruleName := range ruleNames {
		for i := 0; i < perRule; i++ {
			wg.Add(1)
			go func(ruleName string) {
				defer wg.Done()
				s.RecordBlock("default", ruleName)
				s.RecordResponseRedact("default", ruleName)
			}(ruleName)
		}
	}
	wg.Wait()

	snap := s.Snapshot()
	wantOverall := int64(perRule * len(ruleNames))
	if snap.Blocked != wantOverall {
		t.Errorf("overall Blocked = %d, want %d", snap.Blocked, wantOverall)
	}
	if snap.ResponseRedacted != wantOverall {
		t.Errorf("overall ResponseRedacted = %d, want %d", snap.ResponseRedacted, wantOverall)
	}
	for _, ruleName := range ruleNames {
		got, ok := snap.PerRule[ruleName]
		if !ok {
			t.Fatalf("PerRule missing %q: %+v", ruleName, snap.PerRule)
		}
		if got.Blocked != perRule {
			t.Errorf("PerRule[%q].Blocked = %d, want %d", ruleName, got.Blocked, perRule)
		}
		if got.ResponseRedacted != perRule {
			t.Errorf("PerRule[%q].ResponseRedacted = %d, want %d", ruleName, got.ResponseRedacted, perRule)
		}
	}
}

func TestStats_PerTargetTracksSeparatelyFromOverall(t *testing.T) {
	s := stats.New()
	s.RecordAllow("/openai")
	s.RecordAllow("/openai")
	s.RecordAllow("/anthropic")
	s.RecordBlock("/openai", "test-rule")
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

func TestSnapshot_PerRuleString_EmptyWithNoRules(t *testing.T) {
	empty := stats.Snapshot{}
	if got := empty.PerRuleString(); got != "" {
		t.Errorf("PerRuleString() with no rules = %q, want \"\"", got)
	}
}

// TestSnapshot_PerRuleString_RendersSingleRule proves PerRuleString
// shows a breakdown even for exactly one rule — unlike PerTargetString,
// which suppresses a single target as redundant with the totals above,
// a single rule's own numbers are never redundant: the overall totals
// still conflate whatever other rules exist.
func TestSnapshot_PerRuleString_RendersSingleRule(t *testing.T) {
	snap := stats.Snapshot{PerRule: map[string]stats.RuleSnapshot{
		"aws-access-key": {Blocked: 3},
	}}

	rendered := snap.PerRuleString()
	if !strings.HasPrefix(rendered, "=== per-rule breakdown ===") {
		t.Fatalf("PerRuleString() = %q, want it to start with the breakdown header", rendered)
	}
	if !strings.Contains(rendered, "[aws-access-key] blocked=3 redacted=0 response-blocked=0 response-redacted=0") {
		t.Errorf("PerRuleString() missing correct aws-access-key line: %q", rendered)
	}
}

func TestSnapshot_PerRuleString_RendersSortedBreakdown(t *testing.T) {
	snap := stats.Snapshot{PerRule: map[string]stats.RuleSnapshot{
		"openai-api-key": {Redacted: 2, ResponseRedacted: 1},
		"aws-access-key": {Blocked: 5, ResponseBlocked: 2},
	}}

	rendered := snap.PerRuleString()

	awsIdx := strings.Index(rendered, "[aws-access-key]")
	openaiIdx := strings.Index(rendered, "[openai-api-key]")
	if awsIdx == -1 || openaiIdx == -1 {
		t.Fatalf("PerRuleString() = %q, missing one of the rule lines", rendered)
	}
	if openaiIdx < awsIdx {
		t.Errorf("PerRuleString() = %q, want aws-access-key before openai-api-key (sorted)", rendered)
	}
	if !strings.Contains(rendered, "[aws-access-key] blocked=5 redacted=0 response-blocked=2 response-redacted=0") {
		t.Errorf("PerRuleString() missing correct aws-access-key line: %q", rendered)
	}
	if !strings.Contains(rendered, "[openai-api-key] blocked=0 redacted=2 response-blocked=0 response-redacted=1") {
		t.Errorf("PerRuleString() missing correct openai-api-key line: %q", rendered)
	}
}

// TestStats_RecordDryRunBlockAndRedact_TracksOverallAndPerRuleOnly
// proves the dry-run counters land in the overall snapshot and the
// per-rule breakdown, but — unlike every live counter — are never
// broken down per target: a dry-run rule's whole point is testing that
// one rule, not measuring which target its traffic went to.
func TestStats_RecordDryRunBlockAndRedact_TracksOverallAndPerRuleOnly(t *testing.T) {
	s := stats.New()
	s.RecordDryRunBlock("aws-access-key")
	s.RecordDryRunBlock("aws-access-key")
	s.RecordDryRunRedact("openai-api-key")
	s.RecordResponseDryRunBlock("aws-access-key")
	s.RecordResponseDryRunRedact("openai-api-key")
	s.RecordResponseDryRunRedact("openai-api-key")

	snap := s.Snapshot()
	if snap.DryRunBlocked != 2 {
		t.Errorf("DryRunBlocked = %d, want 2", snap.DryRunBlocked)
	}
	if snap.DryRunRedacted != 1 {
		t.Errorf("DryRunRedacted = %d, want 1", snap.DryRunRedacted)
	}
	if snap.ResponseDryRunBlocked != 1 {
		t.Errorf("ResponseDryRunBlocked = %d, want 1", snap.ResponseDryRunBlocked)
	}
	if snap.ResponseDryRunRedacted != 2 {
		t.Errorf("ResponseDryRunRedacted = %d, want 2", snap.ResponseDryRunRedacted)
	}

	awsKey, ok := snap.PerRule["aws-access-key"]
	if !ok {
		t.Fatalf("PerRule missing aws-access-key: %+v", snap.PerRule)
	}
	if awsKey.DryRunBlocked != 2 || awsKey.ResponseDryRunBlocked != 1 {
		t.Errorf("PerRule[aws-access-key] = %+v, want dry-run-blocked=2 response-dry-run-blocked=1", awsKey)
	}
	openaiKey, ok := snap.PerRule["openai-api-key"]
	if !ok {
		t.Fatalf("PerRule missing openai-api-key: %+v", snap.PerRule)
	}
	if openaiKey.DryRunRedacted != 1 || openaiKey.ResponseDryRunRedacted != 2 {
		t.Errorf("PerRule[openai-api-key] = %+v, want dry-run-redacted=1 response-dry-run-redacted=2", openaiKey)
	}

	for target, snapshot := range snap.PerTarget {
		if snapshot.DryRunBlocked != 0 || snapshot.DryRunRedacted != 0 {
			t.Errorf("PerTarget[%q] = %+v, want dry-run counters to stay 0 (dry-run is never broken down per target)", target, snapshot)
		}
	}
}

// TestSnapshot_String_OmitsDryRunLinesWhenNoDryRunActivity proves the
// shutdown summary stays exactly as before when no dry_run rule has
// ever matched — most runs have none configured, so the lines would
// just be noise.
func TestSnapshot_String_OmitsDryRunLinesWhenNoDryRunActivity(t *testing.T) {
	snap := stats.Snapshot{Allowed: 5}
	if rendered := snap.String(); strings.Contains(rendered, "Dry-run") {
		t.Errorf("String() = %q, want no dry-run lines when nothing matched", rendered)
	}
}

// TestSnapshot_String_IncludesDryRunLinesWhenNonZero proves the
// shutdown summary surfaces dry-run activity, combining the request and
// response counters into the same would-block/would-redact totals.
func TestSnapshot_String_IncludesDryRunLinesWhenNonZero(t *testing.T) {
	snap := stats.Snapshot{DryRunBlocked: 2, ResponseDryRunBlocked: 1, DryRunRedacted: 3, ResponseDryRunRedacted: 0}
	rendered := snap.String()
	if !strings.Contains(rendered, "Dry-run would-block:  3") {
		t.Errorf("String() = %q, want would-block total of 3 (2 request + 1 response)", rendered)
	}
	if !strings.Contains(rendered, "Dry-run would-redact: 3") {
		t.Errorf("String() = %q, want would-redact total of 3 (3 request + 0 response)", rendered)
	}
}

// TestSnapshot_PerRuleString_IncludesDryRunSuffixWhenNonZero proves a
// rule with dry-run activity gets the extra dry-run fields appended to
// its line, while a rule with none stays at the plain live-only line.
func TestSnapshot_PerRuleString_IncludesDryRunSuffixWhenNonZero(t *testing.T) {
	snap := stats.Snapshot{PerRule: map[string]stats.RuleSnapshot{
		"aws-access-key": {Blocked: 1},
		"candidate-rule": {DryRunBlocked: 4, ResponseDryRunRedacted: 2},
	}}

	rendered := snap.PerRuleString()
	if !strings.Contains(rendered, "[aws-access-key] blocked=1 redacted=0 response-blocked=0 response-redacted=0\n") {
		t.Errorf("PerRuleString() missing plain aws-access-key line (no dry-run suffix expected): %q", rendered)
	}
	if !strings.Contains(rendered, "[candidate-rule] blocked=0 redacted=0 response-blocked=0 response-redacted=0 dry-run-blocked=4 dry-run-redacted=0 dry-run-response-blocked=0 dry-run-response-redacted=2") {
		t.Errorf("PerRuleString() missing candidate-rule line with dry-run suffix: %q", rendered)
	}
}

func TestStats_RecordUnauthorized_TracksOverallOnly(t *testing.T) {
	s := stats.New()
	s.RecordUnauthorized()
	s.RecordUnauthorized()
	s.RecordAllow("default")

	snap := s.Snapshot()
	if snap.Unauthorized != 2 {
		t.Errorf("Unauthorized = %d, want 2", snap.Unauthorized)
	}
	for target, t2 := range snap.PerTarget {
		if t2.Unauthorized != 0 {
			t.Errorf("PerTarget[%q].Unauthorized = %d, want 0 (never broken down per target)", target, t2.Unauthorized)
		}
	}
}

func TestSnapshot_String_OmitsUnauthorizedLineWhenZero(t *testing.T) {
	snap := stats.Snapshot{Allowed: 5}
	if rendered := snap.String(); strings.Contains(rendered, "Unauthorized") {
		t.Errorf("String() = %q, want no Unauthorized line when nothing was rejected", rendered)
	}
}

func TestSnapshot_String_IncludesUnauthorizedLineWhenNonZero(t *testing.T) {
	snap := stats.Snapshot{Unauthorized: 3}
	rendered := snap.String()
	if !strings.Contains(rendered, "Unauthorized (407):   3") {
		t.Errorf("String() = %q, want the unauthorized count", rendered)
	}
}

func TestStats_CrossedBudget_UnsetBudgetNeverCrosses(t *testing.T) {
	s := stats.New()
	s.RecordTokensUsed("default", 1_000_000)

	if _, crossed := s.CrossedBudget(1.0, 0); crossed {
		t.Error("CrossedBudget with budget=0 (unset) reported crossed, want never")
	}
}

func TestStats_CrossedBudget_BelowBudgetNeverCrosses(t *testing.T) {
	s := stats.New()
	s.RecordTokensUsed("default", 1000) // cost = 1000/1000*0.01 = 0.01

	cost, crossed := s.CrossedBudget(0.01, 10.0)
	if crossed {
		t.Error("CrossedBudget reported crossed while cost is well under budget")
	}
	if cost != 0.01 {
		t.Errorf("cost = %g, want 0.01", cost)
	}
}

func TestStats_CrossedBudget_FiresExactlyOnce(t *testing.T) {
	s := stats.New()
	s.RecordTokensUsed("default", 10_000) // cost = 10_000/1000*1.0 = 10.0

	cost, crossed := s.CrossedBudget(1.0, 5.0)
	if !crossed {
		t.Fatal("first CrossedBudget call over budget reported crossed=false, want true")
	}
	if cost != 10.0 {
		t.Errorf("cost = %g, want 10.0", cost)
	}

	// Further requests keep pushing the cost up, but the alert must not
	// fire again — it's a one-time notice, not a recurring one.
	s.RecordTokensUsed("default", 10_000)
	if _, crossed := s.CrossedBudget(1.0, 5.0); crossed {
		t.Error("second CrossedBudget call reported crossed=true, want the one-shot latch to suppress it")
	}
}

func TestStats_CrossedBudget_ExactlyAtBudgetCounts(t *testing.T) {
	s := stats.New()
	s.RecordTokensUsed("default", 5_000) // cost = 5.0, exactly at budget

	if _, crossed := s.CrossedBudget(1.0, 5.0); !crossed {
		t.Error("CrossedBudget at exactly the threshold reported crossed=false, want true (>=, not >)")
	}
}

func TestStats_RecordLatency_TracksOverallAndPerTarget(t *testing.T) {
	s := stats.New()
	s.RecordLatency("default", 20*time.Millisecond)
	s.RecordLatency("default", 60*time.Millisecond)
	s.RecordLatency("other", 4*time.Second)

	snap := s.Snapshot()
	if snap.Latency.Count != 3 {
		t.Errorf("overall Latency.Count = %d, want 3", snap.Latency.Count)
	}
	wantSum := 0.020 + 0.060 + 4.0
	if diff := snap.Latency.SumSeconds - wantSum; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("overall Latency.SumSeconds = %g, want %g", snap.Latency.SumSeconds, wantSum)
	}

	def := snap.PerTarget["default"]
	if def.Latency.Count != 2 {
		t.Errorf("PerTarget[default].Latency.Count = %d, want 2", def.Latency.Count)
	}
	other := snap.PerTarget["other"]
	if other.Latency.Count != 1 {
		t.Errorf("PerTarget[other].Latency.Count = %d, want 1", other.Latency.Count)
	}
}

func TestStats_RecordLatency_BucketsAreCumulative(t *testing.T) {
	s := stats.New()
	s.RecordLatency("default", 3*time.Millisecond)  // falls in the 0.005 bucket
	s.RecordLatency("default", 20*time.Millisecond) // falls in the 0.025 bucket
	s.RecordLatency("default", 20*time.Second)      // past every finite bound

	snap := s.Snapshot()
	buckets := snap.PerTarget["default"].Latency.Buckets
	if len(buckets) == 0 {
		t.Fatal("Buckets is empty, want the full fixed set")
	}

	byLe := make(map[string]int64, len(buckets))
	for _, b := range buckets {
		byLe[b.Le] = b.Count
	}

	if byLe["0.005"] != 1 {
		t.Errorf(`bucket le="0.005" = %d, want 1 (cumulative: just the 3ms observation)`, byLe["0.005"])
	}
	if byLe["0.01"] != 1 {
		t.Errorf(`bucket le="0.01" = %d, want 1 (cumulative, still just the 3ms observation)`, byLe["0.01"])
	}
	if byLe["0.025"] != 2 {
		t.Errorf(`bucket le="0.025" = %d, want 2 (cumulative: 3ms and 20ms both included)`, byLe["0.025"])
	}
	if byLe["10"] != 2 {
		t.Errorf(`bucket le="10" = %d, want 2 (the 20s observation is past every finite bound)`, byLe["10"])
	}
	if byLe["+Inf"] != 3 {
		t.Errorf(`bucket le="+Inf" = %d, want 3 (must always equal Count)`, byLe["+Inf"])
	}
}

func TestSnapshot_AvgLatencyMillis(t *testing.T) {
	l := stats.LatencySnapshot{Count: 0}
	if got := l.AvgLatencyMillis(); got != 0 {
		t.Errorf("AvgLatencyMillis with Count=0 = %g, want 0", got)
	}

	l = stats.LatencySnapshot{Count: 2, SumSeconds: 0.300}
	if got := l.AvgLatencyMillis(); got != 150 {
		t.Errorf("AvgLatencyMillis = %g, want 150", got)
	}
}

func TestSnapshot_String_OmitsLatencyLineWhenZero(t *testing.T) {
	snap := stats.Snapshot{Allowed: 5}
	if rendered := snap.String(); strings.Contains(rendered, "latency") {
		t.Errorf("String() = %q, want no latency line when nothing was recorded", rendered)
	}
}

func TestSnapshot_String_IncludesLatencyLineWhenNonZero(t *testing.T) {
	snap := stats.Snapshot{Latency: stats.LatencySnapshot{Count: 4, SumSeconds: 0.4}}
	rendered := snap.String()
	if !strings.Contains(rendered, "Avg upstream latency: 100.0ms (n=4)") {
		t.Errorf("String() = %q, want the avg latency line", rendered)
	}
}

func TestSnapshot_PerTargetString_IncludesAvgLatency(t *testing.T) {
	snap := stats.Snapshot{PerTarget: map[string]stats.Snapshot{
		"a": {Allowed: 1, Latency: stats.LatencySnapshot{Count: 2, SumSeconds: 0.2}},
		"b": {Allowed: 1},
	}}
	rendered := snap.PerTargetString(0)
	if !strings.Contains(rendered, "[a]") || !strings.Contains(rendered, "avg-latency=100.0ms") {
		t.Errorf("PerTargetString() = %q, want target a's avg-latency", rendered)
	}
	if strings.Contains(rendered, "[b] ") && strings.Contains(rendered[strings.Index(rendered, "[b]"):], "avg-latency") {
		t.Errorf("PerTargetString() = %q, want target b (no observations) to omit avg-latency", rendered)
	}
}
