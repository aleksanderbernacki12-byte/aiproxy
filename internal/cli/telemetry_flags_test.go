package cli

import (
	"bytes"
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
