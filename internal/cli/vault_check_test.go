package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVaultCheckRequiresKMSKeyAndBucket(t *testing.T) {
	for name, arguments := range map[string][]string{
		"neither":     {"vault-check"},
		"key only":    {"vault-check", "-kms-key-id", "alias/aiproxy"},
		"bucket only": {"vault-check", "-s3-bucket", "evidence"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Execute(arguments, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), "usage: aiproxy vault-check") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}
