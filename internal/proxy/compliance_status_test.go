package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"aiproxy/internal/stats"
)

type statusRecorder struct{ status ComplianceStatus }

func (r statusRecorder) RecordAsync(ComplianceEvent) bool   { return true }
func (r statusRecorder) ComplianceStatus() ComplianceStatus { return r.status }

func TestServeStatsIncludesAggregateComplianceStatus(t *testing.T) {
	server := &Server{
		Stats: stats.New(),
		ComplianceRecorder: statusRecorder{status: ComplianceStatus{
			Telemetry: &TelemetryStatus{Accepted: 7, Pending: 2, DeliveryFailures: 1},
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
}
