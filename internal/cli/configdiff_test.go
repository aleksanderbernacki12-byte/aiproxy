package cli

import (
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aiproxy/internal/config"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestDiffConfig_NoChanges_ReturnsEmpty(t *testing.T) {
	cfg := &config.Config{MaxRequestsPerMinute: 60, CacheEnabled: true}
	if got := diffConfig(cfg, cfg); len(got) != 0 {
		t.Fatalf("diffConfig(cfg, cfg) = %+v, want empty", got)
	}
}

func TestDiffConfig_DetectsScalarFieldChange(t *testing.T) {
	old := &config.Config{MaxRequestsPerMinute: 60}
	newCfg := &config.Config{MaxRequestsPerMinute: 100}

	changes := diffConfig(old, newCfg)
	if len(changes) != 1 {
		t.Fatalf("len(changes) = %d, want 1: %+v", len(changes), changes)
	}
	want := configFieldChange{JSONName: "max_requests_per_minute", Old: "60", New: "100"}
	if changes[0] != want {
		t.Fatalf("changes[0] = %+v, want %+v", changes[0], want)
	}
}

func TestDiffConfig_NilOldTreatedAsZeroValue(t *testing.T) {
	newCfg := &config.Config{MaxRequestsPerMinute: 100, CacheEnabled: true}
	changes := diffConfig(nil, newCfg)

	byName := make(map[string]configFieldChange, len(changes))
	for _, c := range changes {
		byName[c.JSONName] = c
	}
	if c, ok := byName["max_requests_per_minute"]; !ok || c.Old != "0" || c.New != "100" {
		t.Errorf("max_requests_per_minute change = %+v, want Old=0 New=100", c)
	}
	if c, ok := byName["cache_enabled"]; !ok || c.Old != "false" || c.New != "true" {
		t.Errorf("cache_enabled change = %+v, want Old=false New=true", c)
	}
}

func TestDiffConfig_NilNewTreatedAsZeroValue(t *testing.T) {
	old := &config.Config{MaxRequestsPerMinute: 100}
	changes := diffConfig(old, nil)

	if len(changes) != 1 || changes[0].JSONName != "max_requests_per_minute" || changes[0].Old != "100" || changes[0].New != "0" {
		t.Fatalf("changes = %+v, want a single max_requests_per_minute 100 -> 0", changes)
	}
}

// TestDiffConfig_RedactsProxyAPIKey proves an actual secret value never
// appears in a diff — the whole point of sensitiveConfigFields — even
// though the field genuinely changed and would otherwise be reported
// just like any other string field.
func TestDiffConfig_RedactsProxyAPIKey(t *testing.T) {
	old := &config.Config{ProxyAPIKey: "old-secret-value"}
	newCfg := &config.Config{ProxyAPIKey: "new-secret-value"}

	changes := diffConfig(old, newCfg)
	if len(changes) != 1 {
		t.Fatalf("len(changes) = %d, want 1: %+v", len(changes), changes)
	}
	c := changes[0]
	if c.JSONName != "proxy_api_key" {
		t.Fatalf("JSONName = %q, want proxy_api_key", c.JSONName)
	}
	if c.Old != "(hidden)" || c.New != "(hidden)" {
		t.Fatalf("Old/New = %q/%q, want both (hidden) — a secret must never appear in a diff", c.Old, c.New)
	}
	if strings.Contains(c.Old, "secret") || strings.Contains(c.New, "secret") {
		t.Fatalf("diff leaked the actual secret value: %+v", c)
	}
}

func TestDiffConfig_RedactsWebhookURL(t *testing.T) {
	old := &config.Config{WebhookURL: "https://hooks.slack.com/services/OLD/TOKEN"}
	newCfg := &config.Config{WebhookURL: "https://hooks.slack.com/services/NEW/TOKEN"}

	changes := diffConfig(old, newCfg)
	if len(changes) != 1 || changes[0].Old != "(hidden)" || changes[0].New != "(hidden)" {
		t.Fatalf("changes = %+v, want a single webhook_url change redacted to (hidden)", changes)
	}
}

// TestDiffConfig_SliceFieldsShowEntryCountOnly proves a slice field's
// diff never dumps its actual contents (which, for something like
// proxy_api_keys, would otherwise leak every named key's own secret
// value) — only how many entries it has, on each side.
func TestDiffConfig_SliceFieldsShowEntryCountOnly(t *testing.T) {
	old := &config.Config{ProxyAPIKeys: []config.ProxyAPIKeyEntry{{Name: "team-a", Key: "secret-a"}}}
	newCfg := &config.Config{ProxyAPIKeys: []config.ProxyAPIKeyEntry{
		{Name: "team-a", Key: "secret-a"},
		{Name: "team-b", Key: "secret-b"},
	}}

	changes := diffConfig(old, newCfg)
	if len(changes) != 1 {
		t.Fatalf("len(changes) = %d, want 1: %+v", len(changes), changes)
	}
	c := changes[0]
	if c.JSONName != "proxy_api_keys" {
		t.Fatalf("JSONName = %q, want proxy_api_keys", c.JSONName)
	}
	if c.Old != "1 entries" || c.New != "2 entries" {
		t.Fatalf("Old/New = %q/%q, want \"1 entries\"/\"2 entries\"", c.Old, c.New)
	}
	if strings.Contains(c.New, "secret") {
		t.Fatalf("diff leaked a proxy key's own secret value: %+v", c)
	}
}

func TestDiffConfig_EmptyStringRendersAsEmptyMarker(t *testing.T) {
	old := &config.Config{GeoIPRangesFile: ""}
	newCfg := &config.Config{GeoIPRangesFile: "ranges.csv"}

	changes := diffConfig(old, newCfg)
	if len(changes) != 1 || changes[0].Old != "(empty)" || changes[0].New != "ranges.csv" {
		t.Fatalf("changes = %+v, want Old=(empty) New=ranges.csv", changes)
	}
}

func TestSummarizeConfigDiff_JoinsWithArrow(t *testing.T) {
	changes := []configFieldChange{
		{JSONName: "max_requests_per_minute", Old: "60", New: "100"},
		{JSONName: "cache_enabled", Old: "false", New: "true"},
	}
	want := "max_requests_per_minute: 60 -> 100; cache_enabled: false -> true"
	if got := summarizeConfigDiff(changes); got != want {
		t.Fatalf("summarizeConfigDiff = %q, want %q", got, want)
	}
}

func TestSummarizeConfigDiff_EmptyForNoChanges(t *testing.T) {
	if got := summarizeConfigDiff(nil); got != "" {
		t.Fatalf("summarizeConfigDiff(nil) = %q, want empty", got)
	}
}

// newTestServerForReload builds a minimal, real *proxy.Server plus a
// log buffer — everything reloadConfig needs to actually run, so these
// tests exercise the real function, not a mock of it.
func newTestServerForReload(t *testing.T) (*proxy.Server, *strings.Builder) {
	t.Helper()
	targetURL, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	var logBuf strings.Builder
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(&logBuf, "", 0)
	return srv, &logBuf
}

// TestReloadConfig_LogsDiffOnChange proves the real, full reload
// pipeline — parse, validate, apply, diff, log — reports exactly what
// changed between two genuinely different config files on disk, not
// just that "a reload happened."
func TestReloadConfig_LogsDiffOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{"max_requests_per_minute": 60}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	srv, logBuf := newTestServerForReload(t)
	cfg1, _, err := resolveConfig(path)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"max_requests_per_minute": 100}`), 0o644); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	reloadConfig(srv, path, cfg1)

	if !strings.Contains(logBuf.String(), "max_requests_per_minute: 60 -> 100") {
		t.Fatalf("log missing the expected diff line: %q", logBuf.String())
	}
}

// TestReloadConfig_NoChanges_LogsNoChangesMessage proves a reload
// triggered against an unchanged file reports that plainly, rather than
// an empty or misleading diff summary.
func TestReloadConfig_NoChanges_LogsNoChangesMessage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{"max_requests_per_minute": 60}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	srv, logBuf := newTestServerForReload(t)
	cfg1, _, err := resolveConfig(path)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}

	reloadConfig(srv, path, cfg1)

	if !strings.Contains(logBuf.String(), "(no changes)") {
		t.Fatalf("log missing the (no changes) marker: %q", logBuf.String())
	}
	if strings.Contains(logBuf.String(), "->") {
		t.Fatalf("log unexpectedly contains a diff arrow for an unchanged reload: %q", logBuf.String())
	}
}

// TestReloadConfig_InvalidConfig_ReturnsUnchangedPrevCfg proves a
// rejected reload doesn't corrupt the diff baseline for whatever the
// *next* successful reload eventually compares against — the returned
// config must still be exactly prevCfg, the one actually still running.
func TestReloadConfig_InvalidConfig_ReturnsUnchangedPrevCfg(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{"max_requests_per_minute": 60}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	srv, logBuf := newTestServerForReload(t)
	cfg1, _, err := resolveConfig(path)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"anomaly_dry_run": true}`), 0o644); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	got := reloadConfig(srv, path, cfg1)

	if got != cfg1 {
		t.Fatalf("reloadConfig returned %+v, want the unchanged prevCfg %+v after a rejected reload", got, cfg1)
	}
	if !strings.Contains(logBuf.String(), "reload failed") {
		t.Fatalf("log missing the expected failure message: %q", logBuf.String())
	}
}
