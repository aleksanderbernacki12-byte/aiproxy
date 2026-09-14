package cli

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartTelemetryFlagsMustBeConfiguredTogether(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "endpoint only", args: []string{"-telemetry-endpoint", "https://control.example/api/telemetry/ingest"}},
		{name: "private key only", args: []string{"-telemetry-private-key", "telemetry-key.pem"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runStart(test.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2; stderr=%q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "must be set together") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestStartSecureVaultFlagsMustBeConfiguredTogether(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "KMS key only", args: []string{"-secure-vault-kms-key-id", "alias/aiproxy"}},
		{name: "S3 bucket only", args: []string{"-secure-vault-s3-bucket", "customer-vault"}},
		{name: "prefix without vault", args: []string{"-secure-vault-s3-prefix", "legal"}},
		{name: "region without vault", args: []string{"-secure-vault-aws-region", "eu-north-1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runStart(test.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2; stderr=%q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Secure Vault") && !strings.Contains(stderr.String(), "secure-vault") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestDecodeSecureVaultSpoolKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x7a}, 32)
	encoded := base64.StdEncoding.EncodeToString(want)
	got, err := decodeSecureVaultSpoolKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("decoded spool key mismatch")
	}
	for _, invalid := range []string{"", "not-base64", base64.StdEncoding.EncodeToString(want[:31])} {
		if _, err := decodeSecureVaultSpoolKey(invalid); err == nil {
			t.Fatalf("invalid spool key %q was accepted", invalid)
		}
	}
}

func TestStartSecureVaultRequiresSpoolKeyEnvironment(t *testing.T) {
	t.Setenv(secureVaultSpoolKeyEnvironment, "")
	var stdout, stderr bytes.Buffer
	code := runStart([]string{
		"-target", "https://api.openai.com",
		"-secure-vault-kms-key-id", "alias/aiproxy",
		"-secure-vault-s3-bucket", "customer-vault",
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), secureVaultSpoolKeyEnvironment) {
		t.Fatalf("exit code = %d stderr=%q", code, stderr.String())
	}
}

func TestStartInitializesSecureVaultWithStandardAWSCredentials(t *testing.T) {
	t.Setenv(secureVaultSpoolKeyEnvironment, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	spoolDir := filepath.Join(t.TempDir(), "vault-spool")
	var stdout, stderr bytes.Buffer
	code := runStart([]string{
		"-addr", "invalid-listen-address",
		"-target", "https://api.openai.com",
		"-secure-vault-kms-key-id", "alias/aiproxy",
		"-secure-vault-s3-bucket", "customer-vault",
		"-secure-vault-spool-dir", spoolDir,
		"-secure-vault-aws-region", "eu-north-1",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want listener failure 1; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Secure Vault: enabled") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "proxy:") {
		t.Fatalf("stderr = %q, want listener error", stderr.String())
	}
}
