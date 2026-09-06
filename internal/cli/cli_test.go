package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aiproxy/internal/cache"
	"aiproxy/internal/cli"
)

// TestRunStart_InvalidCustomRulePattern_FatalsWithClearMessage proves that
// a malformed regex in a custom rule now exits gracefully via log.Fatalf
// with a readable message, instead of panicking with a stack trace. Since
// log.Fatalf terminates the process, this re-execs the test binary as a
// subprocess and inspects its exit status and stderr — the standard Go
// pattern for testing code paths that call os.Exit.
func TestRunStart_InvalidCustomRulePattern_FatalsWithClearMessage(t *testing.T) {
	if os.Getenv("AIPROXY_TEST_CRASHER") == "1" {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "aiproxy.json")
		invalidConfig := `{"custom_rules": [{"name": "broken-rule", "pattern": "SECRET_[0-9+"}]}`
		if err := os.WriteFile(configPath, []byte(invalidConfig), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cli.Execute([]string{"start", "-target", "https://example.com", "-config", configPath}, os.Stdout, os.Stderr)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunStart_InvalidCustomRulePattern_FatalsWithClearMessage")
	cmd.Env = append(os.Environ(), "AIPROXY_TEST_CRASHER=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected the subprocess to exit with an error, got %v (stderr: %s)", err, stderr.String())
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1 (log.Fatalf's os.Exit(1))", exitErr.ExitCode())
	}

	output := stderr.String()
	if strings.Contains(output, "panic:") {
		t.Fatalf("stderr still contains a panic stack trace, want a clean log.Fatalf message: %q", output)
	}
	if !strings.Contains(output, "Fatal error: Invalid regex pattern in custom rule broken-rule") {
		t.Fatalf("stderr missing expected fatal message: %q", output)
	}
}

// TestRunStart_InvalidBuiltinRuleAction_FatalsWithClearMessage proves an
// unrecognized builtin_rule_actions value is treated exactly like a bad
// custom rule action or a bad regex: a clean log.Fatal before anything
// starts serving.
func TestRunStart_InvalidBuiltinRuleAction_FatalsWithClearMessage(t *testing.T) {
	if os.Getenv("AIPROXY_TEST_CRASHER") == "1" {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "aiproxy.json")
		invalidConfig := `{"builtin_rule_actions": {"aws-access-key": "delete"}}`
		if err := os.WriteFile(configPath, []byte(invalidConfig), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cli.Execute([]string{"start", "-target", "https://example.com", "-config", configPath}, os.Stdout, os.Stderr)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunStart_InvalidBuiltinRuleAction_FatalsWithClearMessage")
	cmd.Env = append(os.Environ(), "AIPROXY_TEST_CRASHER=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected the subprocess to exit with an error, got %v (stderr: %s)", err, stderr.String())
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1 (log.Fatalf's os.Exit(1))", exitErr.ExitCode())
	}

	output := stderr.String()
	if !strings.Contains(output, "Fatal error: Invalid action for built-in rule aws-access-key") {
		t.Fatalf("stderr missing expected fatal message: %q", output)
	}
}

// TestRunStart_UnknownBuiltinRuleName_FatalsWithClearMessage proves a
// builtin_rule_actions key that doesn't match any real built-in rule
// (almost always a typo) fails the same clean way, rather than silently
// being ignored.
func TestRunStart_UnknownBuiltinRuleName_FatalsWithClearMessage(t *testing.T) {
	if os.Getenv("AIPROXY_TEST_CRASHER") == "1" {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "aiproxy.json")
		invalidConfig := `{"builtin_rule_actions": {"aws-acess-key": "redact"}}`
		if err := os.WriteFile(configPath, []byte(invalidConfig), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cli.Execute([]string{"start", "-target", "https://example.com", "-config", configPath}, os.Stdout, os.Stderr)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunStart_UnknownBuiltinRuleName_FatalsWithClearMessage")
	cmd.Env = append(os.Environ(), "AIPROXY_TEST_CRASHER=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected the subprocess to exit with an error, got %v (stderr: %s)", err, stderr.String())
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1 (log.Fatalf's os.Exit(1))", exitErr.ExitCode())
	}

	output := stderr.String()
	if !strings.Contains(output, `"aws-acess-key" is not a built-in rule`) {
		t.Fatalf("stderr missing expected fatal message: %q", output)
	}
}

// TestRunStart_CacheDirectoryCannotBeCreated_FatalsWithClearMessage
// proves a cache directory that can't be created (here: something else
// already occupies that path) is treated the same way as a bad regex or
// bad target — a clean log.Fatal before anything starts serving, not a
// half-started proxy or a crash. Runs as a subprocess for the same
// reason as the test above: log.Fatal calls os.Exit.
func TestRunStart_CacheDirectoryCannotBeCreated_FatalsWithClearMessage(t *testing.T) {
	if os.Getenv("AIPROXY_TEST_CRASHER") == "1" {
		cli.Execute([]string{"start", "-target", "https://example.com"}, os.Stdout, os.Stderr)
		return
	}

	dir := t.TempDir()
	// A regular file where the cache expects to create a directory
	// forces cache.New's os.MkdirAll to fail.
	if err := os.WriteFile(filepath.Join(dir, cache.DirName), []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aiproxy.json"), []byte(`{"cache_enabled": true}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunStart_CacheDirectoryCannotBeCreated_FatalsWithClearMessage")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "AIPROXY_TEST_CRASHER=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected the subprocess to exit with an error, got %v (stderr: %s)", err, stderr.String())
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1 (log.Fatal's os.Exit(1))", exitErr.ExitCode())
	}

	output := stderr.String()
	if strings.Contains(output, "panic:") {
		t.Fatalf("stderr still contains a panic stack trace, want a clean log.Fatal message: %q", output)
	}
	if !strings.Contains(output, "cache:") {
		t.Fatalf("stderr missing the cache failure message: %q", output)
	}
}

// TestRunStart_InvalidLogFormat_ReturnsErrorExitCode proves -log-format
// is validated up front, before -target or any config loading — an
// invalid value should be rejected immediately with a clear message and
// exit code 2, the same as any other bad flag, never silently falling
// back to text or json.
func TestRunStart_InvalidLogFormat_ReturnsErrorExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"start", "-log-format", "yaml"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-log-format") {
		t.Fatalf("stderr missing a clear -log-format error: %q", stderr.String())
	}
}

// runValidate never calls log.Fatal/os.Exit — reporting problems via a
// normal return code is the whole point — so unlike the start tests
// above, these run directly in-process with no subprocess needed.

func TestExecute_Validate_ValidConfig_ReturnsZeroAndSummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"custom_rules": [{"name": "internal-secret", "pattern": "SECRET_[0-9]+"}],
		"targets": [{"prefix": "/openai", "url": "https://api.openai.com"}],
		"max_requests_per_minute": 60,
		"cache_enabled": true,
		"cost_per_1k_tokens": 0.03
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "is valid") {
		t.Fatalf("stdout missing valid confirmation: %q", out)
	}
	if !strings.Contains(out, "custom rules:            1") {
		t.Fatalf("stdout missing custom rule count: %q", out)
	}
	if !strings.Contains(out, "target routes:           1") {
		t.Fatalf("stdout missing target route count: %q", out)
	}
}

func TestExecute_Validate_InvalidRegexAndBadTargetURL_ReportsBothProblems(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"custom_rules": [{"name": "broken-rule", "pattern": "SECRET_[0-9+"}],
		"targets": [{"prefix": "/openai", "url": "http://api.openai.com"}]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout: %s)", code, stdout.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "broken-rule") {
		t.Errorf("stderr missing the bad regex problem: %q", errOut)
	}
	if !strings.Contains(errOut, "/openai") || !strings.Contains(errOut, "https") {
		t.Errorf("stderr missing the bad target URL problem (http instead of https): %q", errOut)
	}
	if !strings.Contains(errOut, "2 problem(s)") {
		t.Errorf("stderr should report both problems found, not stop at the first: %q", errOut)
	}
}

func TestExecute_Validate_InvalidCustomRuleAction_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": [{"name": "bad-action-rule", "pattern": "SECRET_[0-9]+", "action": "delete"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout: %s)", code, stdout.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "bad-action-rule") || !strings.Contains(errOut, `"delete"`) {
		t.Errorf("stderr missing the invalid action problem: %q", errOut)
	}
}

func TestExecute_Validate_ValidConfig_WithRedactAction_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": [{"name": "openai-like-key", "pattern": "sk-[A-Za-z0-9]+", "action": "redact"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
}

func TestExecute_Validate_InvalidBuiltinRuleAction_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"builtin_rule_actions": {"github-token": "delete"}}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout: %s)", code, stdout.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "github-token") || !strings.Contains(errOut, `"delete"`) {
		t.Errorf("stderr missing the invalid action problem: %q", errOut)
	}
}

func TestExecute_Validate_UnknownBuiltinRuleName_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"builtin_rule_actions": {"aws-acess-key": "redact"}}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout: %s)", code, stdout.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, `"aws-acess-key" is not a built-in rule`) {
		t.Errorf("stderr missing the unknown rule name problem: %q", errOut)
	}
}

func TestExecute_Validate_ValidConfig_WithBuiltinRuleRedactAction_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"builtin_rule_actions": {"aws-access-key": "redact"}}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "built-in rule overrides: 1") {
		t.Fatalf("stdout missing built-in rule override count: %q", stdout.String())
	}
}

// TestExecute_Validate_ValidConfig_WithEveryBuiltinRuleOverride_ReturnsZero
// proves every entry in the expanded built-in secret catalog (private
// keys, Slack/Stripe/Google/npm tokens, on top of the original
// AWS/OpenAI/GitHub/Anthropic four) is actually wired into the same
// builtin_rule_actions validation path, not just added to builtinRules
// without being reachable through config.
func TestExecute_Validate_ValidConfig_WithEveryBuiltinRuleOverride_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"builtin_rule_actions": {
		"private-key": "redact",
		"slack-token": "redact",
		"stripe-api-key": "redact",
		"google-api-key": "redact",
		"npm-access-token": "redact"
	}}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "built-in rule overrides: 5") {
		t.Fatalf("stdout missing built-in rule override count: %q", stdout.String())
	}
}

func TestExecute_Validate_DuplicateTargetPrefix_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "url": "https://api.openai.com"},
		{"prefix": "/openai", "url": "https://api.openai.com/v2"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "duplicate prefix") {
		t.Fatalf("stderr missing duplicate prefix problem: %q", stderr.String())
	}
}

func TestExecute_Validate_NegativeTargetMaxRequestsPerMinute_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "url": "https://api.openai.com", "max_requests_per_minute": -10}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "/openai") || !strings.Contains(errOut, "max_requests_per_minute") {
		t.Fatalf("stderr missing the negative per-target rate limit problem: %q", errOut)
	}
}

func TestExecute_Validate_ValidConfig_WithPerTargetRateLimit_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "url": "https://api.openai.com", "max_requests_per_minute": 30}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
}

func TestExecute_Validate_NegativeNumericFields_ReportsProblems(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"max_requests_per_minute": -5, "cost_per_1k_tokens": -0.1}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "max_requests_per_minute") {
		t.Errorf("stderr missing negative rate limit problem: %q", errOut)
	}
	if !strings.Contains(errOut, "cost_per_1k_tokens") {
		t.Errorf("stderr missing negative cost problem: %q", errOut)
	}
}

func TestExecute_Validate_NoConfigFile_ReportsNothingToValidate(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Nothing to validate") {
		t.Fatalf("stdout missing nothing-to-validate message: %q", stdout.String())
	}
}

func TestExecute_Validate_ExplicitMissingConfigFile_IsHardError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", "/does/not/exist/aiproxy.json"}, &stdout, &stderr)

	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for an explicitly-requested missing config file")
	}
	if stderr.String() == "" {
		t.Fatal("stderr should explain why validation failed")
	}
}
