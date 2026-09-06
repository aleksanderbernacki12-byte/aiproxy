package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"aiproxy/internal/config"
	"aiproxy/internal/rules"
)

func TestLoad_ParsesCustomRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": [{"name": "mitt-foretag-hemlighet", "pattern": "SECRET_[0-9]+"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.CustomRules) != 1 {
		t.Fatalf("len(CustomRules) = %d, want 1", len(cfg.CustomRules))
	}
	got := cfg.CustomRules[0]
	if got.Name != "mitt-foretag-hemlighet" || got.Pattern != "SECRET_[0-9]+" {
		t.Fatalf("CustomRules[0] = %+v, want name=mitt-foretag-hemlighet pattern=SECRET_[0-9]+", got)
	}
}

func TestLoad_ParsesMaxRequestsPerMinute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"max_requests_per_minute": 5}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.MaxRequestsPerMinute != 5 {
		t.Fatalf("MaxRequestsPerMinute = %d, want 5", cfg.MaxRequestsPerMinute)
	}
}

func TestLoad_ParsesCostPer1KTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cost_per_1k_tokens": 0.03}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CostPer1KTokens != 0.03 {
		t.Fatalf("CostPer1KTokens = %v, want 0.03", cfg.CostPer1KTokens)
	}
}

func TestLoad_CostPer1KTokensDefaultsToZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": []}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CostPer1KTokens != 0 {
		t.Fatalf("CostPer1KTokens = %v, want 0 (disabled) when absent", cfg.CostPer1KTokens)
	}
}

func TestLoad_ParsesCacheEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !cfg.CacheEnabled {
		t.Fatal("CacheEnabled = false, want true")
	}
}

func TestLoad_CacheEnabledDefaultsToFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": []}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CacheEnabled {
		t.Fatal("CacheEnabled = true, want false (disabled) when absent")
	}
}

func TestLoad_MaxRequestsPerMinuteDefaultsToZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": []}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.MaxRequestsPerMinute != 0 {
		t.Fatalf("MaxRequestsPerMinute = %d, want 0 (disabled) when absent", cfg.MaxRequestsPerMinute)
	}
}

func TestLoad_ParsesTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "url": "https://api.openai.com"},
		{"prefix": "/anthropic", "url": "https://api.anthropic.com"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("len(Targets) = %d, want 2", len(cfg.Targets))
	}
	if cfg.Targets[0] != (config.Target{Prefix: "/openai", URL: "https://api.openai.com"}) {
		t.Errorf("Targets[0] = %+v, want prefix=/openai url=https://api.openai.com", cfg.Targets[0])
	}
	if cfg.Targets[1] != (config.Target{Prefix: "/anthropic", URL: "https://api.anthropic.com"}) {
		t.Errorf("Targets[1] = %+v, want prefix=/anthropic url=https://api.anthropic.com", cfg.Targets[1])
	}
}

func TestLoad_ParsesTargetMaxRequestsPerMinute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "url": "https://api.openai.com", "max_requests_per_minute": 30},
		{"prefix": "/anthropic", "url": "https://api.anthropic.com"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Targets[0].MaxRequestsPerMinute != 30 {
		t.Fatalf("Targets[0].MaxRequestsPerMinute = %d, want 30", cfg.Targets[0].MaxRequestsPerMinute)
	}
	if cfg.Targets[1].MaxRequestsPerMinute != 0 {
		t.Fatalf("Targets[1].MaxRequestsPerMinute = %d, want 0 (absent means no override)", cfg.Targets[1].MaxRequestsPerMinute)
	}
}

func TestLoad_TargetsDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": []}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Targets) != 0 {
		t.Fatalf("len(Targets) = %d, want 0 when absent", len(cfg.Targets))
	}
}

func TestLoad_MissingFileReportsNotExist(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("err = %v, want an os.IsNotExist error", err)
	}
}

// TestLoad_CustomRuleBecomesActiveInEngine proves the full pipeline the
// cli package wires together at startup: a custom_rules entry loaded
// from aiproxy.json, once compiled with regexp.Compile and added to
// a rules.Engine, actually blocks a request whose body matches it — and
// leaves non-matching requests untouched.
func TestLoad_CustomRuleBecomesActiveInEngine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": [{"name": "mitt-foretag-hemlighet", "pattern": "SECRET_[0-9]+"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	for _, cr := range cfg.CustomRules {
		// Mirrors cli.loadCustomRules: custom patterns are compiled with
		// regexp.Compile (not MustCompile), since they come from a file a
		// user can mistype.
		pattern, err := regexp.Compile(cr.Pattern)
		if err != nil {
			t.Fatalf("regexp.Compile(%q) failed: %v", cr.Pattern, err)
		}
		engine.AddBodyRegexRule(rules.BodyRegexRule{
			Name:    cr.Name,
			Pattern: pattern,
			Action:  rules.Block,
		})
	}

	action, ruleName, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/upload",
		Body:   []byte(`payload=SECRET_98765`),
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Block {
		t.Fatalf("action = %v, want %v", action, rules.Block)
	}
	if ruleName != "mitt-foretag-hemlighet" {
		t.Fatalf("rule = %q, want %q", ruleName, "mitt-foretag-hemlighet")
	}

	action2, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/upload",
		Body:   []byte(`payload=not-a-secret`),
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action2 != rules.Allow {
		t.Fatalf("action = %v, want %v", action2, rules.Allow)
	}
}
