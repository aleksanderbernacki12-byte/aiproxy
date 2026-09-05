package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
