package cli_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aiproxy/internal/auditlog"
	"aiproxy/internal/cache"
	"aiproxy/internal/cli"
	"aiproxy/internal/proxy"
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

// TestRunStart_InvalidWebhookURL_FatalsWithClearMessage proves a
// webhook_url that fails https validation is treated the same way as a
// bad --target or a bad targets[].url: a clean log.Fatal before
// anything starts serving, rather than only failing much later when the
// first block/redact event tries to deliver it.
func TestRunStart_InvalidWebhookURL_FatalsWithClearMessage(t *testing.T) {
	if os.Getenv("AIPROXY_TEST_CRASHER") == "1" {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "aiproxy.json")
		invalidConfig := `{"webhook_url": "not a url"}`
		if err := os.WriteFile(configPath, []byte(invalidConfig), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cli.Execute([]string{"start", "-target", "https://example.com", "-config", configPath}, os.Stdout, os.Stderr)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunStart_InvalidWebhookURL_FatalsWithClearMessage")
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
	if !strings.Contains(output, "webhook_url") {
		t.Fatalf("stderr missing expected fatal message: %q", output)
	}
}

// TestRunStart_InvalidPathRuleAction_FatalsWithClearMessage proves a
// path_rules entry with a bad action is treated the same way as a bad
// custom rule action or a bad regex: a clean log.Fatal before anything
// starts serving.
func TestRunStart_InvalidPathRuleAction_FatalsWithClearMessage(t *testing.T) {
	if os.Getenv("AIPROXY_TEST_CRASHER") == "1" {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "aiproxy.json")
		invalidConfig := `{"path_rules": [{"name": "bad-action", "prefix": "/admin", "action": "delete"}]}`
		if err := os.WriteFile(configPath, []byte(invalidConfig), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cli.Execute([]string{"start", "-target", "https://example.com", "-config", configPath}, os.Stdout, os.Stderr)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunStart_InvalidPathRuleAction_FatalsWithClearMessage")
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
	if !strings.Contains(output, "bad-action") {
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

// TestRunStart_TLSCertWithoutKey_ReturnsErrorExitCode and
// TestRunStart_TLSKeyWithoutCert_ReturnsErrorExitCode prove -tls-cert
// and -tls-key are validated up front, before -target or any config
// loading, same as -log-format: setting exactly one without the other
// is rejected immediately with a clear message and exit code 2, never
// silently falling back to plain HTTP.
func TestRunStart_TLSCertWithoutKey_ReturnsErrorExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"start", "-tls-cert", "cert.pem"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-tls-cert and -tls-key must be set together") {
		t.Fatalf("stderr missing a clear -tls-cert/-tls-key error: %q", stderr.String())
	}
}

func TestRunStart_TLSKeyWithoutCert_ReturnsErrorExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"start", "-tls-key", "key.pem"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-tls-cert and -tls-key must be set together") {
		t.Fatalf("stderr missing a clear -tls-cert/-tls-key error: %q", stderr.String())
	}
}

// TestRunStart_AuditLogKeyFileWithoutLogFile_ReturnsErrorExitCode proves
// -audit-log-key-file is rejected up front when log_file isn't
// configured — there'd be nothing to chain — before any config loading
// that could hit log.Fatal, so this runs directly in-process.
func TestRunStart_AuditLogKeyFileWithoutLogFile_ReturnsErrorExitCode(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyPath, []byte("test-key"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"start", "-target", "https://example.com", "-audit-log-key-file", keyPath}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-audit-log-key-file requires log_file") {
		t.Fatalf("stderr missing a clear -audit-log-key-file/log_file error: %q", stderr.String())
	}
}

// TestRunStart_AuditLogKeyFileMissing_ReturnsErrorExitCode proves a
// nonexistent key file path is reported clearly rather than crashing.
func TestRunStart_AuditLogKeyFileMissing_ReturnsErrorExitCode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "aiproxy.json")
	logPath := filepath.Join(dir, "aiproxy.log")
	raw := fmt.Sprintf(`{"log_file": %q}`, logPath)
	if err := os.WriteFile(configPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{
		"start", "-target", "https://example.com",
		"-config", configPath,
		"-audit-log-key-file", filepath.Join(dir, "does-not-exist.key"),
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "audit log key file") {
		t.Fatalf("stderr missing a clear audit log key file error: %q", stderr.String())
	}
}

// TestExecute_VerifyLog_IntactChain_ReturnsZeroAndOK and its siblings
// exercise `aiproxy verify-log` directly: it never blocks or calls
// log.Fatal, so every case runs in-process.
func TestExecute_VerifyLog_IntactChain_ReturnsZeroAndOK(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyPath, []byte("test-key"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")

	chain := auditlog.NewChain([]byte("test-key"), "")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	for _, ev := range []string{`{"level":"allow"}`, `{"level":"block","rule":"x"}`} {
		wrapped, err := chain.Wrap([]byte(ev))
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if _, err := f.Write(append(wrapped, '\n')); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	f.Close()

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"verify-log", "-audit-log-key-file", keyPath, logPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OK") || !strings.Contains(stdout.String(), "2 chained line") {
		t.Fatalf("stdout = %q, want an OK message mentioning 2 chained lines", stdout.String())
	}
}

func TestExecute_VerifyLog_TamperedChain_ReturnsOneAndReportsBrokenLine(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyPath, []byte("test-key"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")

	chain := auditlog.NewChain([]byte("test-key"), "")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	for _, ev := range []string{`{"level":"allow"}`, `{"level":"block"}`} {
		wrapped, err := chain.Wrap([]byte(ev))
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if _, err := f.Write(append(wrapped, '\n')); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	f.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	tampered := bytes.Replace(data, []byte(`"level":"block"`), []byte(`"level":"allow"`), 1)
	if err := os.WriteFile(logPath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered log file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"verify-log", "-audit-log-key-file", keyPath, logPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "chain broken at line 2") {
		t.Fatalf("stderr = %q, want a message about the chain breaking at line 2", stderr.String())
	}
}

func TestExecute_VerifyLog_WrongKey_ReturnsOneAndReportsBrokenLine(t *testing.T) {
	dir := t.TempDir()
	rightKeyPath := filepath.Join(dir, "right.key")
	wrongKeyPath := filepath.Join(dir, "wrong.key")
	if err := os.WriteFile(rightKeyPath, []byte("right-key"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	if err := os.WriteFile(wrongKeyPath, []byte("wrong-key"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")

	chain := auditlog.NewChain([]byte("right-key"), "")
	wrapped, err := chain.Wrap([]byte(`{"level":"allow"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if err := os.WriteFile(logPath, append(wrapped, '\n'), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"verify-log", "-audit-log-key-file", wrongKeyPath, logPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "chain broken at line 1") {
		t.Fatalf("stderr = %q, want a message about the chain breaking at line 1", stderr.String())
	}
}

func TestExecute_VerifyLog_MissingKeyFlag_ReturnsUsageErrorExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"verify-log", "somefile.jsonl"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-audit-log-key-file is required") {
		t.Fatalf("stderr missing a clear required-flag error: %q", stderr.String())
	}
}

func TestExecute_VerifyLog_MissingLogFileArg_ReturnsUsageErrorExitCode(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyPath, []byte("test-key"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"verify-log", "-audit-log-key-file", keyPath}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr: %s)", code, stderr.String())
	}
}

func TestExecute_VerifyLog_NonexistentLogFile_ReturnsErrorExitCode(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyPath, []byte("test-key"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"verify-log", "-audit-log-key-file", keyPath, filepath.Join(dir, "does-not-exist.jsonl")}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr: %s)", code, stderr.String())
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
// keys, Slack/Stripe/Google/npm tokens, and a generic JWT, on top of
// the original AWS/OpenAI/GitHub/Anthropic four) is actually wired into
// the same builtin_rule_actions validation path, not just added to
// builtinRules without being reachable through config.
func TestExecute_Validate_ValidConfig_WithEveryBuiltinRuleOverride_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"builtin_rule_actions": {
		"private-key": "redact",
		"slack-token": "redact",
		"stripe-api-key": "redact",
		"google-api-key": "redact",
		"npm-access-token": "redact",
		"jwt": "redact"
	}}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "built-in rule overrides: 6") {
		t.Fatalf("stdout missing built-in rule override count: %q", stdout.String())
	}
}

// TestExecute_Validate_ValidConfig_WithBuiltinRuleOff_ReturnsZero proves
// "off" is accepted for builtin_rule_actions — the only way to fully
// disable a built-in rule, unlike "block"/"redact" which both keep it
// active. Actual request-handling behavior (that an "off" rule's
// pattern really is skipped, while every other built-in rule keeps
// firing) is verified by hand against the compiled binary, the same way
// as every other built-in pattern's detection — this test covers the
// config-to-validation wiring only.
func TestExecute_Validate_ValidConfig_WithBuiltinRuleOff_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"builtin_rule_actions": {"jwt": "off"}}`
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

func TestExecute_Validate_TargetURLAndURLsBothSet_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "url": "https://api.openai.com", "urls": ["https://backup.example.com"]}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("stderr missing mutually-exclusive problem: %q", stderr.String())
	}
}

func TestExecute_Validate_TargetNeitherURLNorURLsSet_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [{"prefix": "/openai"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "must set one of url or urls") {
		t.Fatalf("stderr missing missing-url problem: %q", stderr.String())
	}
}

func TestExecute_Validate_TargetURLsInvalidEntry_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "urls": ["https://api.openai.com", "not a url"]}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "urls[1]") {
		t.Fatalf("stderr missing urls[1] problem: %q", stderr.String())
	}
}

func TestExecute_Validate_ValidConfig_WithFailoverTarget_ReturnsZeroAndReportsCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "urls": ["https://api.openai.com", "https://backup.example.com"]},
		{"prefix": "/anthropic", "url": "https://api.anthropic.com"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "target routes:           2") {
		t.Fatalf("stdout missing target routes count: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "routes with failover:    1") {
		t.Fatalf("stdout missing routes-with-failover count: %q", stdout.String())
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

func TestExecute_Validate_NegativeTargetMaxTokensPerMinute_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"targets": [
		{"prefix": "/openai", "url": "https://api.openai.com", "max_tokens_per_minute": -10}
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
	if !strings.Contains(errOut, "/openai") || !strings.Contains(errOut, "max_tokens_per_minute") {
		t.Fatalf("stderr missing the negative per-target token rate limit problem: %q", errOut)
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

func TestExecute_Validate_PathRuleBadPrefix_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"path_rules": [{"name": "bad", "prefix": "admin", "action": "block"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "path_rules") {
		t.Fatalf("stderr missing path_rules problem: %q", stderr.String())
	}
}

func TestExecute_Validate_DuplicatePathRulePrefix_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"path_rules": [
		{"name": "a", "prefix": "/admin", "action": "block"},
		{"name": "b", "prefix": "/admin", "action": "allow"}
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

// TestExecute_Validate_PathRuleInvalidAction_ReportsProblem proves an
// action other than exactly "block" or "allow" is rejected — including
// "redact" and "off", which are valid elsewhere (custom_rules,
// builtin_rule_actions) but have no equivalent meaning for a path rule.
func TestExecute_Validate_PathRuleInvalidAction_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"path_rules": [{"name": "bad-action", "prefix": "/admin", "action": "redact"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "bad-action") || !strings.Contains(stderr.String(), `"block" or "allow"`) {
		t.Fatalf("stderr missing the invalid path rule action problem: %q", stderr.String())
	}
}

// TestExecute_Validate_PathRuleMissingAction_ReportsProblem proves an
// absent action is a config error rather than silently defaulting —
// unlike custom_rules[].action, block and allow are opposite intents,
// so there is no safe default to fall back to.
func TestExecute_Validate_PathRuleMissingAction_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"path_rules": [{"name": "no-action", "prefix": "/admin"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "no-action") {
		t.Fatalf("stderr missing the missing-action problem: %q", stderr.String())
	}
}

func TestExecute_Validate_ValidConfig_WithPathRules_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"path_rules": [
		{"name": "block-admin", "prefix": "/admin", "action": "block"},
		{"name": "health-check", "prefix": "/health", "action": "allow"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "path rules:              2") {
		t.Fatalf("stdout missing path rules summary line: %q", stdout.String())
	}
}

// TestExecute_Validate_PathRuleDryRunWithAllowAction_ReportsProblem
// proves dry_run combined with action "allow" is rejected: "allow"
// never rejects anything to begin with, so there is nothing for
// dry_run to preview.
func TestExecute_Validate_PathRuleDryRunWithAllowAction_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"path_rules": [{"name": "health-check", "prefix": "/health", "action": "allow", "dry_run": true}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "health-check") || !strings.Contains(stderr.String(), "dry_run") {
		t.Fatalf("stderr missing the dry_run+allow problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ReportsDryRunRuleCount proves the summary counts
// dry_run entries across both custom_rules and path_rules together.
func TestExecute_Validate_ReportsDryRunRuleCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"custom_rules": [{"name": "candidate", "pattern": "CANDIDATE-[0-9]+", "dry_run": true}],
		"path_rules": [
			{"name": "block-admin", "prefix": "/admin", "action": "block", "dry_run": true},
			{"name": "block-legacy", "prefix": "/legacy", "action": "block"}
		]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "rules in dry-run:        2") {
		t.Fatalf("stdout missing dry-run rule count line: %q", stdout.String())
	}
}

// TestExecute_Validate_ReportsProxyAuthenticationStatus proves the
// summary reports whether proxy_api_key is set, without ever echoing
// the key's actual value back — same discipline as webhook_url.
func TestExecute_Validate_ReportsProxyAuthenticationStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "s3cr3t-shared-key"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "proxy authentication:    true") {
		t.Fatalf("stdout missing proxy authentication summary line: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "s3cr3t-shared-key") {
		t.Fatalf("stdout leaked the proxy API key: %q", stdout.String())
	}
}

func TestExecute_Validate_NegativeNumericFields_ReportsProblems(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"max_requests_per_minute": -5, "cost_per_1k_tokens": -0.1, "max_body_size_bytes": -1}`
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
	if !strings.Contains(errOut, "max_body_size_bytes") {
		t.Errorf("stderr missing negative max body size problem: %q", errOut)
	}
}

func TestExecute_Validate_NegativeMaxTokensPerMinute_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"max_tokens_per_minute": -5}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "max_tokens_per_minute") {
		t.Errorf("stderr missing negative token rate limit problem: %q", stderr.String())
	}
}

func TestExecute_Validate_ValidConfig_WithMaxTokensPerMinute_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"max_tokens_per_minute": 10000}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
}

func TestExecute_Validate_NegativeAnomalyMultiplier_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"anomaly_multiplier": -5}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "anomaly_multiplier") {
		t.Errorf("stderr missing negative anomaly_multiplier problem: %q", stderr.String())
	}
}

func TestExecute_Validate_AnomalyDryRunWithoutMultiplier_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"anomaly_dry_run": true}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "anomaly_dry_run requires anomaly_multiplier") {
		t.Errorf("stderr missing anomaly_dry_run-requires-anomaly_multiplier problem: %q", stderr.String())
	}
}

func TestExecute_Validate_ValidConfig_WithAnomalyDetection_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"anomaly_multiplier": 50, "anomaly_dry_run": true}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "anomaly detection:       50x baseline (dry-run)") {
		t.Fatalf("stdout missing anomaly detection summary: %q", stdout.String())
	}
}

func TestExecute_Validate_NegativeCostBudget_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cost_per_1k_tokens": 0.03, "cost_budget": -1}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cost_budget") {
		t.Errorf("stderr missing negative cost_budget problem: %q", stderr.String())
	}
}

func TestExecute_Validate_CostBudgetWithoutCostRate_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cost_budget": 10}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (cost_budget with no cost_per_1k_tokens set)", code)
	}
	if !strings.Contains(stderr.String(), "cost_budget requires cost_per_1k_tokens") {
		t.Errorf("stderr missing cost_budget-requires-rate problem: %q", stderr.String())
	}
}

func TestExecute_Validate_ValidConfig_WithCostBudget_ReportsSummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cost_per_1k_tokens": 0.03, "cost_budget": 10.5}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cost budget:             10.5") {
		t.Fatalf("stdout missing cost budget summary line: %q", stdout.String())
	}
}

func TestExecute_Validate_ValidConfig_WithLogFile_ReportsPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	logPath := filepath.Join(dir, "aiproxy.log")
	raw := fmt.Sprintf(`{"log_file": %q}`, logPath)
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "log file:                "+logPath) {
		t.Fatalf("stdout missing log file summary line: %q", stdout.String())
	}
}

func TestExecute_Validate_NoLogFile_ReportsDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "log file:                disabled") {
		t.Fatalf("stdout missing disabled log file summary line: %q", stdout.String())
	}
}

func TestExecute_Validate_LogFileUnwritablePath_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	// A path under a directory that doesn't exist can never be opened.
	badLogPath := filepath.Join(dir, "no-such-directory", "aiproxy.log")
	raw := fmt.Sprintf(`{"log_file": %q}`, badLogPath)
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "log_file") {
		t.Fatalf("stderr missing log_file problem: %q", stderr.String())
	}
}

// TestExecute_Validate_InvalidWebhookURL_ReportsProblem proves a
// webhook_url with an unsupported scheme is reported as a config
// problem, not silently ignored or only discovered once a block/redact
// event tries and fails to deliver it.
func TestExecute_Validate_InvalidWebhookURL_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"webhook_url": "ftp://hooks.example.com/alert"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "webhook_url") {
		t.Errorf("stderr missing webhook_url problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ValidConfig_WithWebhookURL_ReturnsZero proves a
// well-formed https webhook_url passes validation and is reflected in
// the summary, without ever printing the URL itself (it can carry a
// bearer credential in its path, e.g. a Slack incoming webhook).
func TestExecute_Validate_ValidConfig_WithWebhookURL_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"webhook_url": "https://hooks.example.com/services/T0/B0/XXXXXXXX"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "webhook alerts:          true") {
		t.Fatalf("stdout missing webhook alerts summary line: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "XXXXXXXX") {
		t.Fatalf("stdout leaked the webhook URL itself: %q", stdout.String())
	}
}

// TestExecute_Validate_ValidConfig_WithPlainHTTPWebhookURL_ReturnsZero
// proves webhook_url deliberately accepts plain http, unlike --target
// and targets[].url: a webhook alert only ever carries a method/url/rule
// name, never a secret, and a common real receiver is a local or
// internal-network endpoint with no TLS in front of it at all.
func TestExecute_Validate_ValidConfig_WithPlainHTTPWebhookURL_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"webhook_url": "http://127.0.0.1:9000/hook"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "webhook alerts:          true") {
		t.Fatalf("stdout missing webhook alerts summary line: %q", stdout.String())
	}
}

// TestExecute_Validate_Webhooks_InvalidURLReportsProblem proves a bad
// webhooks[].url is caught, the same as a bad top-level webhook_url.
func TestExecute_Validate_Webhooks_InvalidURLReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"webhooks": [{"url": "ftp://hooks.example.com/alert"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "webhooks[0].url") {
		t.Errorf("stderr missing webhooks[0].url problem: %q", stderr.String())
	}
}

// TestExecute_Validate_Webhooks_UnrecognizedEventNameReportsProblem
// proves a typo'd event name in webhooks[].events fails validation
// instead of silently never matching anything — same discipline as
// builtin_rule_actions rejecting an unrecognized rule name.
func TestExecute_Validate_Webhooks_UnrecognizedEventNameReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"webhooks": [{"url": "https://hooks.example.com/alert", "events": ["blocK"]}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "webhooks[0].events") || !strings.Contains(stderr.String(), "blocK") {
		t.Errorf("stderr missing the unrecognized event name problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ValidConfig_WithWebhooks_ReturnsZero proves a
// well-formed webhooks list passes validation and is reflected in the
// summary by count only, never leaking a destination URL.
func TestExecute_Validate_ValidConfig_WithWebhooks_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"webhooks": [
		{"url": "https://hooks.example.com/budget", "events": ["budget_exceeded"]},
		{"url": "https://hooks.example.com/everything"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "additional webhooks:     2") {
		t.Fatalf("stdout missing additional webhooks count: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "hooks.example.com") {
		t.Fatalf("stdout leaked a webhook destination URL: %q", stdout.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_EmptyNameReportsProblem proves an
// entry with no name is rejected — it's the stats/log attribution
// label, so it can't be blank.
func TestExecute_Validate_ProxyAPIKeys_EmptyNameReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [{"name": "", "key": "some-key"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "name must not be empty") {
		t.Errorf("stderr missing the empty-name problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_ReservedDefaultNameReportsProblem
// proves "default" (reserved for the anonymous top-level
// proxy_api_key) can't be reused as a named key's name.
func TestExecute_Validate_ProxyAPIKeys_ReservedDefaultNameReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [{"name": "default", "key": "some-key"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "reserved") {
		t.Errorf("stderr missing the reserved-name problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_DuplicateNameReportsProblem proves
// two entries can't share a name — it would silently merge two
// different callers' attributed stats together.
func TestExecute_Validate_ProxyAPIKeys_DuplicateNameReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [
		{"name": "team-a", "key": "key-1"},
		{"name": "team-a", "key": "key-2"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "duplicate name") {
		t.Errorf("stderr missing the duplicate-name problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_DuplicateKeyReportsProblem proves
// two entries can't share the same key value — ambiguous which name
// a request authenticated with it would be attributed to.
func TestExecute_Validate_ProxyAPIKeys_DuplicateKeyReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [
		{"name": "team-a", "key": "shared-key"},
		{"name": "team-b", "key": "shared-key"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "team-b") || !strings.Contains(stderr.String(), "duplicates") {
		t.Errorf("stderr missing the duplicate-key problem: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "shared-key") {
		t.Errorf("stderr leaked the key value itself: %q", stderr.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_EmptyKeyReportsProblem proves an
// entry with a name but no key is rejected.
func TestExecute_Validate_ProxyAPIKeys_EmptyKeyReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [{"name": "team-a", "key": ""}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "team-a") || !strings.Contains(stderr.String(), "key must not be empty") {
		t.Errorf("stderr missing the empty-key problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_NegativeMaxRequestsPerMinuteReportsProblem
// proves the per-key rate limit override can't be negative.
func TestExecute_Validate_ProxyAPIKeys_NegativeMaxRequestsPerMinuteReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [{"name": "team-a", "key": "some-key", "max_requests_per_minute": -5}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "max_requests_per_minute") {
		t.Errorf("stderr missing the negative-rate-limit problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_NegativeMaxTokensPerMinuteReportsProblem
// proves the per-key token rate limit override can't be negative, same
// rule as max_requests_per_minute.
func TestExecute_Validate_ProxyAPIKeys_NegativeMaxTokensPerMinuteReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [{"name": "team-a", "key": "some-key", "max_tokens_per_minute": -5}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "max_tokens_per_minute") {
		t.Errorf("stderr missing the negative-token-rate-limit problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_NegativeCostBudgetReportsProblem
// proves a named key's own cost_budget can't be negative, same rule as
// the top-level cost_budget.
func TestExecute_Validate_ProxyAPIKeys_NegativeCostBudgetReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cost_per_1k_tokens": 0.03, "proxy_api_keys": [{"name": "team-a", "key": "some-key", "cost_budget": -5}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cost_budget") || !strings.Contains(stderr.String(), "must not be negative") {
		t.Errorf("stderr missing the negative-cost_budget problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ProxyAPIKeys_CostBudgetWithoutCostPer1KTokensReportsProblem
// proves a named key's own cost_budget requires the top-level
// cost_per_1k_tokens to be set — same reasoning as the top-level
// cost_budget requiring it: a budget with no rate to price tokens at
// has nothing to compare against.
func TestExecute_Validate_ProxyAPIKeys_CostBudgetWithoutCostPer1KTokensReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [{"name": "team-a", "key": "some-key", "cost_budget": 5}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "team-a") || !strings.Contains(stderr.String(), "cost_budget requires the top-level cost_per_1k_tokens") {
		t.Errorf("stderr missing the cost_per_1k_tokens requirement problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ValidConfig_WithProxyAPIKeyCostBudget_ReturnsZero
// proves a well-formed per-key cost_budget (alongside the required
// top-level cost_per_1k_tokens) passes validation.
func TestExecute_Validate_ValidConfig_WithProxyAPIKeyCostBudget_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cost_per_1k_tokens": 0.03, "proxy_api_keys": [{"name": "team-a", "key": "key-1", "cost_budget": 10}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "additional proxy keys:   1") {
		t.Fatalf("stdout missing additional proxy keys count: %q", stdout.String())
	}
}

// TestExecute_Validate_ValidConfig_WithProxyAPIKeys_ReturnsZero proves a
// well-formed proxy_api_keys list passes validation, is reflected in
// the summary by count only, and never leaks a key value or the names
// (names aren't secret, but this asserts the count line specifically).
func TestExecute_Validate_ValidConfig_WithProxyAPIKeys_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_keys": [
		{"name": "team-a", "key": "key-1"},
		{"name": "team-b", "key": "key-2", "max_requests_per_minute": 60}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "additional proxy keys:   2") {
		t.Fatalf("stdout missing additional proxy keys count: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "key-1") || strings.Contains(stdout.String(), "key-2") {
		t.Fatalf("stdout leaked a proxy key value: %q", stdout.String())
	}
}

// TestExecute_Validate_CacheTTLSeconds_NegativeReportsProblem proves a
// negative cache_ttl_seconds is rejected, same as every other numeric
// field in the config.
func TestExecute_Validate_CacheTTLSeconds_NegativeReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "cache_ttl_seconds": -5}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cache_ttl_seconds") {
		t.Errorf("stderr missing cache_ttl_seconds problem: %q", stderr.String())
	}
}

// TestExecute_Validate_CacheTTLSeconds_WithoutCacheEnabledReportsProblem
// proves setting a TTL for a cache that's off is caught, same reasoning
// as cost_budget requiring cost_per_1k_tokens.
func TestExecute_Validate_CacheTTLSeconds_WithoutCacheEnabledReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_ttl_seconds": 30}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cache_ttl_seconds requires cache_enabled") {
		t.Errorf("stderr missing the cache_enabled requirement problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ValidConfig_WithCacheTTL_ReturnsZero proves a
// well-formed cache_ttl_seconds passes validation and shows up in the
// summary.
func TestExecute_Validate_ValidConfig_WithCacheTTL_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "cache_ttl_seconds": 30}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cache ttl:               30s") {
		t.Fatalf("stdout missing cache ttl summary line: %q", stdout.String())
	}
}

// TestExecute_Validate_ValidConfig_CacheEnabledNoTTL_ReturnsZero proves
// cache_enabled alone (no TTL, the pre-existing behavior) still passes
// validation and reports "no expiry" in the summary.
func TestExecute_Validate_ValidConfig_CacheEnabledNoTTL_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cache ttl:               none") {
		t.Fatalf("stdout missing the no-expiry cache ttl summary line: %q", stdout.String())
	}
}

// TestExecute_Validate_CacheMaxSizeBytes_NegativeReportsProblem proves a
// negative cache_max_size_bytes is rejected, same as every other
// numeric field in the config.
func TestExecute_Validate_CacheMaxSizeBytes_NegativeReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "cache_max_size_bytes": -5}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cache_max_size_bytes") {
		t.Errorf("stderr missing cache_max_size_bytes problem: %q", stderr.String())
	}
}

// TestExecute_Validate_CacheMaxSizeBytes_WithoutCacheEnabledReportsProblem
// proves setting a size cap for a cache that's off is caught, same
// reasoning as cache_ttl_seconds requiring cache_enabled.
func TestExecute_Validate_CacheMaxSizeBytes_WithoutCacheEnabledReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_max_size_bytes": 1000}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cache_max_size_bytes requires cache_enabled") {
		t.Errorf("stderr missing the cache_enabled requirement problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ValidConfig_WithCacheMaxSize_ReturnsZero proves a
// well-formed cache_max_size_bytes passes validation and shows up in
// the summary.
func TestExecute_Validate_ValidConfig_WithCacheMaxSize_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "cache_max_size_bytes": 1000}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cache max size:          1000 bytes") {
		t.Fatalf("stdout missing cache max size summary line: %q", stdout.String())
	}
}

// TestExecute_Validate_ValidConfig_CacheEnabledNoMaxSize_ReturnsZero
// proves cache_enabled alone (no size cap, the pre-existing behavior)
// still passes validation and reports "unbounded" in the summary.
func TestExecute_Validate_ValidConfig_CacheEnabledNoMaxSize_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cache max size:          unbounded") {
		t.Fatalf("stdout missing the unbounded cache max size summary line: %q", stdout.String())
	}
}

// TestExecute_Validate_IPAllowList_InvalidEntryReportsProblem proves a
// malformed ip_allow_list entry (neither a valid IP nor a valid CIDR
// range) is rejected.
func TestExecute_Validate_IPAllowList_InvalidEntryReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"ip_allow_list": ["not-an-ip"]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "ip_allow_list") || !strings.Contains(stderr.String(), "not a valid IP address or CIDR range") {
		t.Errorf("stderr missing the invalid-entry problem: %q", stderr.String())
	}
}

// TestExecute_Validate_IPDenyList_InvalidCIDRReportsProblem proves a
// malformed ip_deny_list CIDR (bad prefix length) is rejected.
func TestExecute_Validate_IPDenyList_InvalidCIDRReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"ip_deny_list": ["10.0.0.0/99"]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "ip_deny_list") || !strings.Contains(stderr.String(), "not a valid IP address or CIDR range") {
		t.Errorf("stderr missing the invalid-CIDR problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ValidConfig_WithIPLists_ReturnsZero proves a
// well-formed ip_allow_list/ip_deny_list — mixing CIDR ranges and bare
// IP addresses — passes validation and is reflected in the summary.
func TestExecute_Validate_ValidConfig_WithIPLists_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"ip_allow_list": ["10.0.0.0/8", "192.168.1.5"],
		"ip_deny_list": ["10.0.5.0/24"]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "IP allow list entries:   2") {
		t.Fatalf("stdout missing IP allow list entry count: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "IP deny list entries:    1") {
		t.Fatalf("stdout missing IP deny list entry count: %q", stdout.String())
	}
}

// TestExecute_Validate_CountryListWithoutGeoIPRangesFile_ReportsProblem
// proves country_allow_list/country_deny_list is rejected when
// geoip_ranges_file isn't set — there's nothing to resolve a request's
// country from otherwise.
func TestExecute_Validate_CountryListWithoutGeoIPRangesFile_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"country_deny_list": ["KP"]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "requires geoip_ranges_file") {
		t.Errorf("stderr missing the requires-geoip_ranges_file problem: %q", stderr.String())
	}
}

// TestExecute_Validate_GeoIPRangesFile_MissingFileReportsProblem proves
// a geoip_ranges_file pointing at a nonexistent path is rejected
// clearly rather than deferred to a runtime failure.
func TestExecute_Validate_GeoIPRangesFile_MissingFileReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := fmt.Sprintf(`{"geoip_ranges_file": %q}`, filepath.Join(dir, "does-not-exist.csv"))
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "geoip_ranges_file") {
		t.Errorf("stderr missing the geoip_ranges_file problem: %q", stderr.String())
	}
}

// TestExecute_Validate_CountryList_InvalidCodeReportsProblem proves a
// malformed country code (not 2 letters) is rejected.
func TestExecute_Validate_CountryList_InvalidCodeReportsProblem(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "geoip.csv")
	if err := os.WriteFile(csvPath, []byte("1.2.3.0/24,US\n"), 0o644); err != nil {
		t.Fatalf("write geoip csv: %v", err)
	}
	path := filepath.Join(dir, "aiproxy.json")
	raw := fmt.Sprintf(`{"geoip_ranges_file": %q, "country_allow_list": ["USA"]}`, csvPath)
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "country_allow_list") || !strings.Contains(stderr.String(), "not a 2-letter country code") {
		t.Errorf("stderr missing the invalid-country-code problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ValidConfig_WithGeoIP_ReturnsZero proves a
// well-formed geoip_ranges_file + country lists passes validation and
// is reflected in the summary.
func TestExecute_Validate_ValidConfig_WithGeoIP_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "geoip.csv")
	if err := os.WriteFile(csvPath, []byte("1.2.3.0/24,US\n5.6.7.0/24,SE\n"), 0o644); err != nil {
		t.Fatalf("write geoip csv: %v", err)
	}
	path := filepath.Join(dir, "aiproxy.json")
	raw := fmt.Sprintf(`{
		"geoip_ranges_file": %q,
		"country_allow_list": ["se", "no"],
		"country_deny_list": ["kp"]
	}`, csvPath)
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "GeoIP ranges file:       "+csvPath) {
		t.Fatalf("stdout missing GeoIP ranges file path: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "country allow list:      2") {
		t.Fatalf("stdout missing country allow list entry count: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "country deny list:       1") {
		t.Fatalf("stdout missing country deny list entry count: %q", stdout.String())
	}
}

// TestExecute_Validate_ModelRoutes_EmptyNameReportsProblem proves an
// entry with no name is rejected — it's the stats/log attribution
// label, so it can't be blank.
func TestExecute_Validate_ModelRoutes_EmptyNameReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [{"name": "", "models": ["claude-*"], "url": "https://api.anthropic.com"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "name must not be empty") {
		t.Errorf("stderr missing the empty-name problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ModelRoutes_DuplicateNameReportsProblem proves
// two entries can't share a name — it would silently merge two
// different upstreams' attributed stats together.
func TestExecute_Validate_ModelRoutes_DuplicateNameReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [
		{"name": "anthropic", "models": ["claude-*"], "url": "https://api.anthropic.com"},
		{"name": "anthropic", "models": ["claude-3-*"], "url": "https://backup.anthropic.com"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "duplicate name") {
		t.Errorf("stderr missing the duplicate-name problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ModelRoutes_EmptyModelsReportsProblem proves an
// entry with no models list is rejected — nothing for it to ever match.
func TestExecute_Validate_ModelRoutes_EmptyModelsReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [{"name": "anthropic", "models": [], "url": "https://api.anthropic.com"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "at least one pattern") {
		t.Errorf("stderr missing the empty-models problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ModelRoutes_InvalidGlobPatternReportsProblem
// proves a syntactically malformed glob (an unterminated character
// class) is caught at validate time rather than silently never matching
// anything at request time.
func TestExecute_Validate_ModelRoutes_InvalidGlobPatternReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [{"name": "anthropic", "models": ["claude-["], "url": "https://api.anthropic.com"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "not a valid glob pattern") {
		t.Errorf("stderr missing the invalid-glob problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ModelRoutes_DuplicatePatternReportsProblem
// proves the same literal model pattern can't appear in two different
// routes — the second would be permanently unreachable, since routes
// are checked in order and the first match wins.
func TestExecute_Validate_ModelRoutes_DuplicatePatternReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [
		{"name": "anthropic", "models": ["claude-3-opus"], "url": "https://api.anthropic.com"},
		{"name": "anthropic-backup", "models": ["claude-3-opus"], "url": "https://backup.anthropic.com"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "duplicates an earlier route") {
		t.Errorf("stderr missing the duplicate-pattern problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ModelRoutes_URLAndURLsMutuallyExclusiveReportsProblem
// proves a model route can't set both url and urls, same rule as a
// targets entry.
func TestExecute_Validate_ModelRoutes_URLAndURLsMutuallyExclusiveReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [{"name": "anthropic", "models": ["claude-*"], "url": "https://api.anthropic.com", "urls": ["https://backup.anthropic.com"]}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Errorf("stderr missing the mutually-exclusive problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ModelRoutes_NegativeMaxRequestsPerMinuteReportsProblem
// proves the per-route rate limit override can't be negative.
func TestExecute_Validate_ModelRoutes_NegativeMaxRequestsPerMinuteReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [{"name": "anthropic", "models": ["claude-*"], "url": "https://api.anthropic.com", "max_requests_per_minute": -5}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "max_requests_per_minute") {
		t.Errorf("stderr missing the negative-rate-limit problem: %q", stderr.String())
	}
}

func TestExecute_Validate_ModelRoutes_NegativeMaxTokensPerMinuteReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [{"name": "anthropic", "models": ["claude-*"], "url": "https://api.anthropic.com", "max_tokens_per_minute": -5}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "max_tokens_per_minute") {
		t.Errorf("stderr missing the negative-token-rate-limit problem: %q", stderr.String())
	}
}

// TestExecute_Validate_ValidConfig_WithModelRoutes_ReturnsZero proves a
// well-formed model_routes list passes validation and is reflected in
// the summary by count.
func TestExecute_Validate_ValidConfig_WithModelRoutes_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"model_routes": [
		{"name": "anthropic", "models": ["claude-*"], "url": "https://api.anthropic.com"},
		{"name": "openai", "models": ["gpt-*", "o1*"], "urls": ["https://api.openai.com", "https://backup.openai.com"], "max_requests_per_minute": 60}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "model routes:            2") {
		t.Fatalf("stdout missing model routes count: %q", stdout.String())
	}
}

// TestExecute_Validate_ReportsEffectiveMaxBodySize proves the summary
// shows what max_body_size_bytes actually resolves to: the configured
// value when set, or proxy.DefaultMaxBodyBytes when it's left at its
// zero-value default — not just the raw (possibly absent) config field.
func TestExecute_Validate_ReportsEffectiveMaxBodySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"max_body_size_bytes": 1048576}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "max request body size:   1048576 bytes") {
		t.Fatalf("stdout missing configured max body size: %q", stdout.String())
	}
}

// TestExecute_Validate_ValidConfig_MaxBodySizeReportsBuiltinDefaultWhenUnset
// covers max_body_size_bytes left absent: the effective limit shown
// must be proxy.DefaultMaxBodyBytes, since that's what would actually
// apply.
func TestExecute_Validate_ValidConfig_MaxBodySizeReportsBuiltinDefaultWhenUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), fmt.Sprintf("max request body size:   %d bytes", proxy.DefaultMaxBodyBytes)) {
		t.Fatalf("stdout missing default max body size: %q", stdout.String())
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

// TestExecute_Validate_UnsetEnvVarReference_IsHardError proves a
// ${VAR}-referencing field pointing at an environment variable that
// isn't set surfaces through "validate" as a hard failure — the same
// class of error as a config file that isn't valid JSON at all — rather
// than being folded into the "N problem(s)" summary, since the file
// can't even be turned into a Config without it.
func TestExecute_Validate_UnsetEnvVarReference_IsHardError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "${AIPROXY_CLI_TEST_DEFINITELY_NOT_SET}"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for an unset env var reference")
	}
	if !strings.Contains(stderr.String(), "AIPROXY_CLI_TEST_DEFINITELY_NOT_SET") {
		t.Fatalf("stderr = %q, want it to name the missing variable", stderr.String())
	}
}

// TestExecute_Validate_EnvVarReference_ExpandsAndValidatesNormally proves
// the happy path end to end through the CLI: a config referencing a set
// environment variable validates successfully, and the resolved value is
// never printed back out.
func TestExecute_Validate_EnvVarReference_ExpandsAndValidatesNormally(t *testing.T) {
	t.Setenv("AIPROXY_CLI_TEST_KEY", "s3cr3t-from-env")

	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"proxy_api_key": "${AIPROXY_CLI_TEST_KEY}"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "proxy authentication:    true") {
		t.Fatalf("stdout missing proxy authentication summary line: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "s3cr3t-from-env") {
		t.Fatalf("stdout leaked the resolved env var value: %q", stdout.String())
	}
}

// TestRunStart_CustomRuleUnknownTarget_FatalsWithClearMessage proves a
// cold start rejects an unrecognized custom_rules[].targets entry the
// same clean way runValidate reports it as a problem — not just at
// `aiproxy validate` time, but before the process ever starts serving.
func TestRunStart_CustomRuleUnknownTarget_FatalsWithClearMessage(t *testing.T) {
	if os.Getenv("AIPROXY_TEST_CRASHER") == "1" {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "aiproxy.json")
		invalidConfig := `{"custom_rules": [{"name": "scoped-rule", "pattern": "SECRET_[0-9]+", "targets": ["/does-not-exist"]}]}`
		if err := os.WriteFile(configPath, []byte(invalidConfig), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cli.Execute([]string{"start", "-target", "https://example.com", "-config", configPath}, os.Stdout, os.Stderr)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunStart_CustomRuleUnknownTarget_FatalsWithClearMessage")
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
	if !strings.Contains(output, "scoped-rule") || !strings.Contains(output, "/does-not-exist") {
		t.Fatalf("stderr missing expected fatal message: %q", output)
	}
}

// TestExecute_Validate_CustomRuleUnknownTarget_ReportsProblem proves a
// custom_rules entry referencing a target that doesn't actually exist in
// targets/model_routes (almost always a typo) is rejected, the same
// rigor resolveBuiltinRuleActions already applies to an unrecognized
// builtin_rule_actions key — rather than silently compiling a rule that
// can never match anything.
func TestExecute_Validate_CustomRuleUnknownTarget_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"targets": [{"prefix": "/openai", "url": "https://api.openai.com"}],
		"custom_rules": [{"name": "scoped-rule", "pattern": "SECRET_[0-9]+", "targets": ["/does-not-exist"]}]
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
	if !strings.Contains(errOut, "scoped-rule") || !strings.Contains(errOut, "/does-not-exist") {
		t.Errorf("stderr missing the unknown target problem: %q", errOut)
	}
}

// TestExecute_Validate_CustomRuleUnknownKey_ReportsProblem is the same
// check for an unrecognized keys entry.
func TestExecute_Validate_CustomRuleUnknownKey_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"proxy_api_keys": [{"name": "mobile-app", "key": "some-key"}],
		"custom_rules": [{"name": "scoped-rule", "pattern": "SECRET_[0-9]+", "keys": ["nonexistent-key"]}]
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
	if !strings.Contains(errOut, "scoped-rule") || !strings.Contains(errOut, "nonexistent-key") {
		t.Errorf("stderr missing the unknown key problem: %q", errOut)
	}
}

// TestExecute_Validate_CustomRuleKeyDefaultWithoutProxyAPIKey_ReportsProblem
// proves "default" is only a valid Keys entry when proxy_api_key is
// actually set — there's no anonymous "default" caller to scope to
// otherwise, the same reasoning ProxyAPIKeyEntry.Name reserves "default"
// for.
func TestExecute_Validate_CustomRuleKeyDefaultWithoutProxyAPIKey_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"custom_rules": [{"name": "scoped-rule", "pattern": "SECRET_[0-9]+", "keys": ["default"]}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout: %s)", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "scoped-rule") {
		t.Errorf("stderr missing the unknown key problem: %q", stderr.String())
	}
}

// TestExecute_Validate_CustomRuleValidTargetsAndKeys_ReturnsZero proves
// the happy path: a rule scoped to a real targets[] prefix, a real
// model_routes[] name (as "model:<name>"), "default" (with
// proxy_api_key set), and a real proxy_api_keys[] name all validate
// cleanly together.
func TestExecute_Validate_CustomRuleValidTargetsAndKeys_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{
		"proxy_api_key": "s3cr3t-shared-key",
		"targets": [{"prefix": "/openai", "url": "https://api.openai.com"}],
		"model_routes": [{"name": "fast", "models": ["gpt-4*"], "url": "https://api.openai.com"}],
		"proxy_api_keys": [{"name": "mobile-app", "key": "mobile-key"}],
		"custom_rules": [
			{"name": "rule-a", "pattern": "SECRET_[0-9]+", "targets": ["/openai", "model:fast", "default"]},
			{"name": "rule-b", "pattern": "TOKEN_[0-9]+", "keys": ["default", "mobile-app"]}
		]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
}
