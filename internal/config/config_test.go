package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	if got.Action != "" {
		t.Fatalf("CustomRules[0].Action = %q, want empty when absent", got.Action)
	}
}

func TestLoad_ParsesCustomRuleAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": [{"name": "openai-like-key", "pattern": "sk-[A-Za-z0-9]+", "action": "redact"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CustomRules[0].Action != "redact" {
		t.Fatalf("CustomRules[0].Action = %q, want redact", cfg.CustomRules[0].Action)
	}
}

func TestLoad_ParsesCustomRuleDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": [
		{"name": "candidate-rule", "pattern": "CANDIDATE-[0-9]+", "dry_run": true},
		{"name": "live-rule", "pattern": "LIVE-[0-9]+"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !cfg.CustomRules[0].DryRun {
		t.Fatalf("CustomRules[0].DryRun = %v, want true", cfg.CustomRules[0].DryRun)
	}
	if cfg.CustomRules[1].DryRun {
		t.Fatalf("CustomRules[1].DryRun = %v, want false when absent", cfg.CustomRules[1].DryRun)
	}
}

func TestLoad_ParsesCustomRuleTargetsAndKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": [
		{"name": "scoped-rule", "pattern": "SECRET_[0-9]+", "targets": ["/openai", "model:fast"], "keys": ["mobile-app"]},
		{"name": "unscoped-rule", "pattern": "OTHER_[0-9]+"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.CustomRules[0].Targets) != 2 || cfg.CustomRules[0].Targets[0] != "/openai" || cfg.CustomRules[0].Targets[1] != "model:fast" {
		t.Fatalf("CustomRules[0].Targets = %v, want [/openai model:fast]", cfg.CustomRules[0].Targets)
	}
	if len(cfg.CustomRules[0].Keys) != 1 || cfg.CustomRules[0].Keys[0] != "mobile-app" {
		t.Fatalf("CustomRules[0].Keys = %v, want [mobile-app]", cfg.CustomRules[0].Keys)
	}
	if cfg.CustomRules[1].Targets != nil {
		t.Fatalf("CustomRules[1].Targets = %v, want nil when absent", cfg.CustomRules[1].Targets)
	}
	if cfg.CustomRules[1].Keys != nil {
		t.Fatalf("CustomRules[1].Keys = %v, want nil when absent", cfg.CustomRules[1].Keys)
	}
}

func TestLoad_ParsesBuiltinRuleActions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"builtin_rule_actions": {"aws-access-key": "redact"}}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got := cfg.BuiltinRuleActions["aws-access-key"]; got != "redact" {
		t.Fatalf(`BuiltinRuleActions["aws-access-key"] = %q, want "redact"`, got)
	}
	if len(cfg.BuiltinRuleActions) != 1 {
		t.Fatalf("len(BuiltinRuleActions) = %d, want 1", len(cfg.BuiltinRuleActions))
	}
}

func TestLoad_BuiltinRuleActionsDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.BuiltinRuleActions) != 0 {
		t.Fatalf("len(BuiltinRuleActions) = %d, want 0 when absent", len(cfg.BuiltinRuleActions))
	}
}

func TestLoad_ParsesMaxBodySizeBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"max_body_size_bytes": 5242880}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.MaxBodyBytes != 5242880 {
		t.Fatalf("MaxBodyBytes = %d, want 5242880", cfg.MaxBodyBytes)
	}
}

func TestLoad_MaxBodySizeBytesDefaultsToZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.MaxBodyBytes != 0 {
		t.Fatalf("MaxBodyBytes = %d, want 0 when absent", cfg.MaxBodyBytes)
	}
}

func TestLoad_ParsesUpstreamTimeouts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"upstream_response_timeout_seconds": 5, "upstream_total_timeout_seconds": 30}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.UpstreamResponseTimeoutSeconds != 5 {
		t.Fatalf("UpstreamResponseTimeoutSeconds = %d, want 5", cfg.UpstreamResponseTimeoutSeconds)
	}
	if cfg.UpstreamTotalTimeoutSeconds != 30 {
		t.Fatalf("UpstreamTotalTimeoutSeconds = %d, want 30", cfg.UpstreamTotalTimeoutSeconds)
	}
}

func TestLoad_UpstreamTimeoutsDefaultToZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.UpstreamResponseTimeoutSeconds != 0 {
		t.Fatalf("UpstreamResponseTimeoutSeconds = %d, want 0 when absent", cfg.UpstreamResponseTimeoutSeconds)
	}
	if cfg.UpstreamTotalTimeoutSeconds != 0 {
		t.Fatalf("UpstreamTotalTimeoutSeconds = %d, want 0 when absent", cfg.UpstreamTotalTimeoutSeconds)
	}
}

func TestLoad_ParsesTargetEjectionSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"target_ejection_threshold": 5, "target_ejection_cooldown_seconds": 30}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.TargetEjectionThreshold != 5 {
		t.Fatalf("TargetEjectionThreshold = %d, want 5", cfg.TargetEjectionThreshold)
	}
	if cfg.TargetEjectionCooldownSeconds != 30 {
		t.Fatalf("TargetEjectionCooldownSeconds = %d, want 30", cfg.TargetEjectionCooldownSeconds)
	}
}

func TestLoad_TargetEjectionSettingsDefaultToZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.TargetEjectionThreshold != 0 {
		t.Fatalf("TargetEjectionThreshold = %d, want 0 when absent", cfg.TargetEjectionThreshold)
	}
	if cfg.TargetEjectionCooldownSeconds != 0 {
		t.Fatalf("TargetEjectionCooldownSeconds = %d, want 0 when absent", cfg.TargetEjectionCooldownSeconds)
	}
}

func TestLoad_ParsesCORSSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"cors_allowed_origins": ["https://app.example.com", "https://other.example.com"],
		"cors_allowed_methods": ["GET", "POST"],
		"cors_allowed_headers": ["Content-Type", "X-Api-Key"],
		"cors_allow_credentials": true,
		"cors_max_age_seconds": 600
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.CORSAllowedOrigins) != 2 || cfg.CORSAllowedOrigins[0] != "https://app.example.com" {
		t.Fatalf("CORSAllowedOrigins = %v, want the two configured origins", cfg.CORSAllowedOrigins)
	}
	if len(cfg.CORSAllowedMethods) != 2 {
		t.Fatalf("CORSAllowedMethods = %v, want 2 entries", cfg.CORSAllowedMethods)
	}
	if len(cfg.CORSAllowedHeaders) != 2 {
		t.Fatalf("CORSAllowedHeaders = %v, want 2 entries", cfg.CORSAllowedHeaders)
	}
	if !cfg.CORSAllowCredentials {
		t.Fatal("CORSAllowCredentials = false, want true")
	}
	if cfg.CORSMaxAgeSeconds != 600 {
		t.Fatalf("CORSMaxAgeSeconds = %d, want 600", cfg.CORSMaxAgeSeconds)
	}
}

func TestLoad_CORSSettingsDefaultToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.CORSAllowedOrigins) != 0 {
		t.Fatalf("CORSAllowedOrigins = %v, want empty when absent", cfg.CORSAllowedOrigins)
	}
	if cfg.CORSAllowCredentials {
		t.Fatal("CORSAllowCredentials = true, want false when absent")
	}
	if cfg.CORSMaxAgeSeconds != 0 {
		t.Fatalf("CORSMaxAgeSeconds = %d, want 0 when absent", cfg.CORSMaxAgeSeconds)
	}
}

func TestLoad_ParsesWebhookURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"webhook_url": "https://hooks.example.com/alert"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.WebhookURL != "https://hooks.example.com/alert" {
		t.Fatalf("WebhookURL = %q, want %q", cfg.WebhookURL, "https://hooks.example.com/alert")
	}
}

func TestLoad_WebhookURLDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.WebhookURL != "" {
		t.Fatalf("WebhookURL = %q, want empty when absent", cfg.WebhookURL)
	}
}

func TestLoad_ParsesWebhooks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"webhooks": [
		{"url": "https://hooks.example.com/budget", "events": ["budget_exceeded"]},
		{"url": "https://hooks.example.com/everything"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Webhooks) != 2 {
		t.Fatalf("len(Webhooks) = %d, want 2", len(cfg.Webhooks))
	}
	if cfg.Webhooks[0].URL != "https://hooks.example.com/budget" {
		t.Errorf("Webhooks[0].URL = %q, want the budget endpoint", cfg.Webhooks[0].URL)
	}
	if len(cfg.Webhooks[0].Events) != 1 || cfg.Webhooks[0].Events[0] != "budget_exceeded" {
		t.Errorf("Webhooks[0].Events = %v, want [budget_exceeded]", cfg.Webhooks[0].Events)
	}
	if cfg.Webhooks[1].URL != "https://hooks.example.com/everything" {
		t.Errorf("Webhooks[1].URL = %q, want the catch-all endpoint", cfg.Webhooks[1].URL)
	}
	if len(cfg.Webhooks[1].Events) != 0 {
		t.Errorf("Webhooks[1].Events = %v, want empty (no filter given)", cfg.Webhooks[1].Events)
	}
}

func TestLoad_WebhooksDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Webhooks) != 0 {
		t.Fatalf("Webhooks = %v, want empty when absent", cfg.Webhooks)
	}
}

func TestLoad_ParsesProxyAPIKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "s3cr3t-shared-key"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ProxyAPIKey != "s3cr3t-shared-key" {
		t.Fatalf("ProxyAPIKey = %q, want %q", cfg.ProxyAPIKey, "s3cr3t-shared-key")
	}
}

func TestLoad_ProxyAPIKeyDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ProxyAPIKey != "" {
		t.Fatalf("ProxyAPIKey = %q, want empty when absent", cfg.ProxyAPIKey)
	}
}

func TestLoad_ParsesProxyAPIKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [
		{"name": "team-a", "key": "key-1"},
		{"name": "team-b", "key": "key-2", "max_requests_per_minute": 60}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.ProxyAPIKeys) != 2 {
		t.Fatalf("len(ProxyAPIKeys) = %d, want 2", len(cfg.ProxyAPIKeys))
	}
	if cfg.ProxyAPIKeys[0].Name != "team-a" || cfg.ProxyAPIKeys[0].Key != "key-1" {
		t.Errorf("ProxyAPIKeys[0] = %+v, want name=team-a key=key-1", cfg.ProxyAPIKeys[0])
	}
	if cfg.ProxyAPIKeys[1].MaxRequestsPerMinute != 60 {
		t.Errorf("ProxyAPIKeys[1].MaxRequestsPerMinute = %d, want 60", cfg.ProxyAPIKeys[1].MaxRequestsPerMinute)
	}
}

func TestLoad_ParsesProxyAPIKeyCostBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [
		{"name": "team-a", "key": "key-1", "cost_budget": 10.5}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.ProxyAPIKeys) != 1 {
		t.Fatalf("len(ProxyAPIKeys) = %d, want 1", len(cfg.ProxyAPIKeys))
	}
	if cfg.ProxyAPIKeys[0].CostBudget != 10.5 {
		t.Errorf("ProxyAPIKeys[0].CostBudget = %g, want 10.5", cfg.ProxyAPIKeys[0].CostBudget)
	}
}

func TestLoad_ParsesProxyAPIKeyMaxTokensPerMinute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [
		{"name": "team-a", "key": "key-1", "max_tokens_per_minute": 5000}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ProxyAPIKeys[0].MaxTokensPerMinute != 5000 {
		t.Errorf("ProxyAPIKeys[0].MaxTokensPerMinute = %d, want 5000", cfg.ProxyAPIKeys[0].MaxTokensPerMinute)
	}
}

func TestLoad_ProxyAPIKeysDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.ProxyAPIKeys) != 0 {
		t.Fatalf("ProxyAPIKeys = %v, want empty when absent", cfg.ProxyAPIKeys)
	}
}

func TestLoad_ParsesModelRoutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [
		{"name": "anthropic", "models": ["claude-*"], "url": "https://api.anthropic.com"},
		{"name": "openai", "models": ["gpt-*", "o1*"], "urls": ["https://api.openai.com", "https://backup.openai.com"], "max_requests_per_minute": 60}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.ModelRoutes) != 2 {
		t.Fatalf("len(ModelRoutes) = %d, want 2", len(cfg.ModelRoutes))
	}
	if cfg.ModelRoutes[0].Name != "anthropic" || len(cfg.ModelRoutes[0].Models) != 1 || cfg.ModelRoutes[0].Models[0] != "claude-*" {
		t.Errorf("ModelRoutes[0] = %+v, want name=anthropic models=[claude-*]", cfg.ModelRoutes[0])
	}
	if cfg.ModelRoutes[0].URL != "https://api.anthropic.com" {
		t.Errorf("ModelRoutes[0].URL = %q, want https://api.anthropic.com", cfg.ModelRoutes[0].URL)
	}
	if len(cfg.ModelRoutes[1].URLs) != 2 {
		t.Errorf("len(ModelRoutes[1].URLs) = %d, want 2", len(cfg.ModelRoutes[1].URLs))
	}
	if cfg.ModelRoutes[1].MaxRequestsPerMinute != 60 {
		t.Errorf("ModelRoutes[1].MaxRequestsPerMinute = %d, want 60", cfg.ModelRoutes[1].MaxRequestsPerMinute)
	}
}

func TestLoad_ParsesModelRouteMaxTokensPerMinute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [
		{"name": "anthropic", "models": ["claude-*"], "url": "https://api.anthropic.com", "max_tokens_per_minute": 20000}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ModelRoutes[0].MaxTokensPerMinute != 20000 {
		t.Fatalf("ModelRoutes[0].MaxTokensPerMinute = %d, want 20000", cfg.ModelRoutes[0].MaxTokensPerMinute)
	}
}

func TestLoad_ModelRoutesDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.ModelRoutes) != 0 {
		t.Fatalf("ModelRoutes = %v, want empty when absent", cfg.ModelRoutes)
	}
}

func TestLoad_ParsesIPAllowAndDenyLists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"ip_allow_list": ["10.0.0.0/8", "192.168.1.5"],
		"ip_deny_list": ["10.0.5.0/24"]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.IPAllowList) != 2 || cfg.IPAllowList[0] != "10.0.0.0/8" || cfg.IPAllowList[1] != "192.168.1.5" {
		t.Errorf("IPAllowList = %v, want [10.0.0.0/8 192.168.1.5]", cfg.IPAllowList)
	}
	if len(cfg.IPDenyList) != 1 || cfg.IPDenyList[0] != "10.0.5.0/24" {
		t.Errorf("IPDenyList = %v, want [10.0.5.0/24]", cfg.IPDenyList)
	}
}

func TestLoad_IPListsDefaultToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.IPAllowList) != 0 || len(cfg.IPDenyList) != 0 {
		t.Fatalf("IPAllowList=%v IPDenyList=%v, want both empty when absent", cfg.IPAllowList, cfg.IPDenyList)
	}
}

func TestLoad_ParsesGeoIPFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"geoip_ranges_file": "/etc/aiproxy/geoip.csv",
		"country_allow_list": ["SE", "NO"],
		"country_deny_list": ["KP"]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.GeoIPRangesFile != "/etc/aiproxy/geoip.csv" {
		t.Errorf("GeoIPRangesFile = %q, want /etc/aiproxy/geoip.csv", cfg.GeoIPRangesFile)
	}
	if len(cfg.CountryAllowList) != 2 || cfg.CountryAllowList[0] != "SE" || cfg.CountryAllowList[1] != "NO" {
		t.Errorf("CountryAllowList = %v, want [SE NO]", cfg.CountryAllowList)
	}
	if len(cfg.CountryDenyList) != 1 || cfg.CountryDenyList[0] != "KP" {
		t.Errorf("CountryDenyList = %v, want [KP]", cfg.CountryDenyList)
	}
}

func TestLoad_GeoIPFieldsDefaultToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.GeoIPRangesFile != "" || len(cfg.CountryAllowList) != 0 || len(cfg.CountryDenyList) != 0 {
		t.Fatalf("GeoIPRangesFile=%q CountryAllowList=%v CountryDenyList=%v, want all empty when absent", cfg.GeoIPRangesFile, cfg.CountryAllowList, cfg.CountryDenyList)
	}
}

func TestLoad_ParsesCostBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cost_per_1k_tokens": 0.03, "cost_budget": 10.5}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CostBudget != 10.5 {
		t.Fatalf("CostBudget = %g, want 10.5", cfg.CostBudget)
	}
}

func TestLoad_CostBudgetDefaultsToZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CostBudget != 0 {
		t.Fatalf("CostBudget = %g, want 0 when absent", cfg.CostBudget)
	}
}

func TestLoad_ParsesPathRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"path_rules": [
		{"name": "block-admin", "prefix": "/admin", "action": "block"},
		{"name": "health-check", "prefix": "/health", "action": "allow"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.PathRules) != 2 {
		t.Fatalf("len(PathRules) = %d, want 2: %+v", len(cfg.PathRules), cfg.PathRules)
	}
	if cfg.PathRules[0] != (config.PathRule{Name: "block-admin", Prefix: "/admin", Action: "block"}) {
		t.Fatalf("PathRules[0] = %+v, want block-admin", cfg.PathRules[0])
	}
	if cfg.PathRules[1] != (config.PathRule{Name: "health-check", Prefix: "/health", Action: "allow"}) {
		t.Fatalf("PathRules[1] = %+v, want health-check", cfg.PathRules[1])
	}
}

func TestLoad_ParsesPathRuleDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"path_rules": [{"name": "candidate-block", "prefix": "/new", "action": "block", "dry_run": true}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PathRules[0] != (config.PathRule{Name: "candidate-block", Prefix: "/new", Action: "block", DryRun: true}) {
		t.Fatalf("PathRules[0] = %+v, want DryRun true", cfg.PathRules[0])
	}
}

func TestLoad_PathRulesDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.PathRules) != 0 {
		t.Fatalf("PathRules = %+v, want empty when absent", cfg.PathRules)
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

func TestLoad_ParsesCacheTTLSeconds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "cache_ttl_seconds": 300}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CacheTTLSeconds != 300 {
		t.Fatalf("CacheTTLSeconds = %d, want 300", cfg.CacheTTLSeconds)
	}
}

func TestLoad_CacheTTLSecondsDefaultsToZero(t *testing.T) {
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
	if cfg.CacheTTLSeconds != 0 {
		t.Fatalf("CacheTTLSeconds = %d, want 0 (no expiry) when absent", cfg.CacheTTLSeconds)
	}
}

func TestLoad_ParsesCacheMaxSizeBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "cache_max_size_bytes": 104857600}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CacheMaxSizeBytes != 104857600 {
		t.Fatalf("CacheMaxSizeBytes = %d, want 104857600", cfg.CacheMaxSizeBytes)
	}
}

func TestLoad_CacheMaxSizeBytesDefaultsToZero(t *testing.T) {
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
	if cfg.CacheMaxSizeBytes != 0 {
		t.Fatalf("CacheMaxSizeBytes = %d, want 0 (unbounded) when absent", cfg.CacheMaxSizeBytes)
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

func TestLoad_ParsesMaxTokensPerMinute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"max_tokens_per_minute": 10000}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.MaxTokensPerMinute != 10000 {
		t.Fatalf("MaxTokensPerMinute = %d, want 10000", cfg.MaxTokensPerMinute)
	}
}

func TestLoad_MaxTokensPerMinuteDefaultsToZero(t *testing.T) {
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
	if cfg.MaxTokensPerMinute != 0 {
		t.Fatalf("MaxTokensPerMinute = %d, want 0 (disabled) when absent", cfg.MaxTokensPerMinute)
	}
}

func TestLoad_ParsesAnomalyFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"anomaly_multiplier": 50, "anomaly_dry_run": true}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AnomalyMultiplier != 50 {
		t.Errorf("AnomalyMultiplier = %g, want 50", cfg.AnomalyMultiplier)
	}
	if !cfg.AnomalyDryRun {
		t.Error("AnomalyDryRun = false, want true")
	}
}

func TestLoad_AnomalyFieldsDefaultToZeroAndFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AnomalyMultiplier != 0 {
		t.Fatalf("AnomalyMultiplier = %g, want 0 (disabled) when absent", cfg.AnomalyMultiplier)
	}
	if cfg.AnomalyDryRun {
		t.Fatal("AnomalyDryRun = true, want false when absent")
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
	if cfg.Targets[0].Prefix != "/openai" || cfg.Targets[0].URL != "https://api.openai.com" || len(cfg.Targets[0].URLs) != 0 {
		t.Errorf("Targets[0] = %+v, want prefix=/openai url=https://api.openai.com", cfg.Targets[0])
	}
	if cfg.Targets[1].Prefix != "/anthropic" || cfg.Targets[1].URL != "https://api.anthropic.com" || len(cfg.Targets[1].URLs) != 0 {
		t.Errorf("Targets[1] = %+v, want prefix=/anthropic url=https://api.anthropic.com", cfg.Targets[1])
	}
}

func TestLoad_ParsesTargetURLsFailoverList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "urls": ["https://api.openai.com", "https://backup.example.com"]}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("len(Targets) = %d, want 1", len(cfg.Targets))
	}
	got := cfg.Targets[0]
	if got.URL != "" {
		t.Errorf("URL = %q, want empty when urls is set", got.URL)
	}
	want := []string{"https://api.openai.com", "https://backup.example.com"}
	if len(got.URLs) != len(want) || got.URLs[0] != want[0] || got.URLs[1] != want[1] {
		t.Errorf("URLs = %v, want %v", got.URLs, want)
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

func TestLoad_ParsesTargetMaxTokensPerMinute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "url": "https://api.openai.com", "max_tokens_per_minute": 50000},
		{"prefix": "/anthropic", "url": "https://api.anthropic.com"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Targets[0].MaxTokensPerMinute != 50000 {
		t.Fatalf("Targets[0].MaxTokensPerMinute = %d, want 50000", cfg.Targets[0].MaxTokensPerMinute)
	}
	if cfg.Targets[1].MaxTokensPerMinute != 0 {
		t.Fatalf("Targets[1].MaxTokensPerMinute = %d, want 0 (absent means no override)", cfg.Targets[1].MaxTokensPerMinute)
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

	action, ruleName, _, _, _, err := engine.Evaluate(rules.Request{
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

	action2, _, _, _, _, err := engine.Evaluate(rules.Request{
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

func TestLoad_ExpandsEnvVarReferences(t *testing.T) {
	t.Setenv("AIPROXY_TEST_KEY", "s3cr3t-from-env")
	t.Setenv("AIPROXY_TEST_WEBHOOK", "https://hooks.example.com/incoming/abc123")

	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "${AIPROXY_TEST_KEY}", "webhook_url": "${AIPROXY_TEST_WEBHOOK}"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ProxyAPIKey != "s3cr3t-from-env" {
		t.Fatalf("ProxyAPIKey = %q, want %q", cfg.ProxyAPIKey, "s3cr3t-from-env")
	}
	if cfg.WebhookURL != "https://hooks.example.com/incoming/abc123" {
		t.Fatalf("WebhookURL = %q, want %q", cfg.WebhookURL, "https://hooks.example.com/incoming/abc123")
	}
}

func TestLoad_UnsetEnvVarReference_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "${AIPROXY_TEST_DEFINITELY_NOT_SET}"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("Load returned no error for a reference to an unset environment variable, want an error")
	}
	if !strings.Contains(err.Error(), "AIPROXY_TEST_DEFINITELY_NOT_SET") {
		t.Fatalf("error = %q, want it to name the missing variable", err.Error())
	}
}

func TestLoad_MalformedEnvVarReference_MissingClosingBrace_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "${UNCLOSED"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("Load returned no error for an unclosed ${ reference, want an error")
	}
}

func TestLoad_MalformedEnvVarReference_InvalidName_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "${1NOT-VALID}"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("Load returned no error for an invalid variable name, want an error")
	}
}

func TestLoad_EscapedDollarSign_ProducesLiteralBraceWithNoSubstitution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	// $$ escapes to a literal $, so this must load successfully and keep
	// the literal text even though AIPROXY_TEST_ESCAPED is never set —
	// proving no substitution was attempted.
	raw := `{"custom_rules": [{"name": "env-leak", "pattern": "$${AIPROXY_TEST_ESCAPED}"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.CustomRules) != 1 || cfg.CustomRules[0].Pattern != "${AIPROXY_TEST_ESCAPED}" {
		t.Fatalf("CustomRules = %+v, want pattern literal \"${AIPROXY_TEST_ESCAPED}\"", cfg.CustomRules)
	}
}

func TestLoad_BareDollarSign_PassesThroughUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	// A regex end-of-line anchor ($) not followed by "{" or another "$"
	// must never be treated as the start of a variable reference.
	raw := `{"custom_rules": [{"name": "ends-with-secret", "pattern": "SECRET$"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.CustomRules) != 1 || cfg.CustomRules[0].Pattern != "SECRET$" {
		t.Fatalf("CustomRules = %+v, want pattern unchanged \"SECRET$\"", cfg.CustomRules)
	}
}

func TestLoad_NoEnvVarReferences_BehavesExactlyAsBefore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "plain-key-no-substitution"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ProxyAPIKey != "plain-key-no-substitution" {
		t.Fatalf("ProxyAPIKey = %q, want %q", cfg.ProxyAPIKey, "plain-key-no-substitution")
	}
}

func TestLoad_ParsesLogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"log_file": "/var/log/aiproxy.jsonl"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.LogFile != "/var/log/aiproxy.jsonl" {
		t.Fatalf("LogFile = %q, want %q", cfg.LogFile, "/var/log/aiproxy.jsonl")
	}
}

func TestLoad_LogFileDefaultsToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.LogFile != "" {
		t.Fatalf("LogFile = %q, want empty when absent", cfg.LogFile)
	}
}
