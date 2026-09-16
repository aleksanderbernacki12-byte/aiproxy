package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aiproxy/internal/stats"
)

type statusRecorder struct{ status ComplianceStatus }

func (r statusRecorder) RecordAsync(ComplianceEvent) bool   { return true }
func (r statusRecorder) ComplianceStatus() ComplianceStatus { return r.status }

func TestServeStatsIncludesAggregateComplianceStatus(t *testing.T) {
	server := &Server{
		Stats: stats.New(),
		ComplianceRecorder: statusRecorder{status: ComplianceStatus{
			Telemetry:   &TelemetryStatus{Accepted: 7, Pending: 2, DeliveryFailures: 1},
			SecureVault: &SecureVaultStatus{Accepted: 6, SpoolPending: 3, UploadFailures: 1},
		}},
	}
	response := httptest.NewRecorder()
	server.serveStats(response, httptest.NewRequest("GET", statsPath, nil))
	var payload struct {
		Compliance ComplianceStatus `json:"compliance"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Compliance.Telemetry == nil || payload.Compliance.Telemetry.Accepted != 7 || payload.Compliance.Telemetry.Pending != 2 {
		t.Fatalf("compliance status = %#v", payload.Compliance)
	}
	if payload.Compliance.SecureVault == nil || payload.Compliance.SecureVault.Accepted != 6 || payload.Compliance.SecureVault.SpoolPending != 3 {
		t.Fatalf("secure vault status = %#v", payload.Compliance)
	}
}

func TestServeMetricsIncludesCompliancePipelineHealth(t *testing.T) {
	timestamp := time.Unix(1_800_000_000, 0).UTC()
	server := &Server{
		Stats: stats.New(),
		ComplianceRecorder: statusRecorder{status: ComplianceStatus{
			Telemetry:   &TelemetryStatus{Pending: 4, DeliveryFailures: 2, LastFailureAt: &timestamp, StorageFullFailures: 1, DatabaseBytes: 81920, DatabaseUsedBytes: 65536, DatabaseLimitBytes: 1048576},
			SecureVault: &SecureVaultStatus{SpoolPending: 3, Quarantined: 1, UploadFailures: 5},
		}},
	}
	response := httptest.NewRecorder()
	server.serveMetrics(response, httptest.NewRequest("GET", metricsPath, nil))
	body := response.Body.String()
	for _, expected := range []string{
		"aiproxy_telemetry_pending 4",
		"aiproxy_telemetry_storage_full_failures_total 1",
		"aiproxy_telemetry_database_bytes 81920",
		"aiproxy_telemetry_database_used_bytes 65536",
		"aiproxy_telemetry_database_limit_bytes 1048576",
		"aiproxy_telemetry_delivery_failures_total 2",
		"aiproxy_telemetry_last_failure_timestamp_seconds 1800000000",
		"aiproxy_secure_vault_spool_pending 3",
		"aiproxy_secure_vault_quarantined 1",
		"aiproxy_secure_vault_upload_failures_total 5",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics missing %q", expected)
		}
	}
}

func TestServeMetricsIncludesAggregatePIIRedactionsWithoutContent(t *testing.T) {
	server := &Server{Stats: stats.New()}
	server.Stats.RecordPIIRedact("chat")
	response := httptest.NewRecorder()
	server.serveMetrics(response, httptest.NewRequest("GET", metricsPath, nil))
	body := response.Body.String()
	if !strings.Contains(body, `aiproxy_pii_redacted_total{target="chat"} 1`) {
		t.Fatalf("metrics missing aggregate PII count: %q", body)
	}
	if strings.Contains(body, "alice@example.com") {
		t.Fatal("metrics exposed request content")
	}
}
