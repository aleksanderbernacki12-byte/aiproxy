package compliance

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"aiproxy/internal/proxy"
	"aiproxy/internal/telemetry"
)

type vaultCall struct {
	eventID      string
	request      *http.Request
	response     *http.Response
	requestBody  []byte
	responseBody []byte
}

type fakeVault struct {
	call     vaultCall
	accepted bool
}

func (v *fakeVault) StoreAsync(eventID string, request *http.Request, response *http.Response) bool {
	v.call = vaultCall{eventID: eventID, request: request, response: response}
	v.call.requestBody, _ = io.ReadAll(request.Body)
	v.call.responseBody, _ = io.ReadAll(response.Body)
	return v.accepted
}

func (*fakeVault) Shutdown(context.Context) error { return nil }

type fakeTelemetry struct {
	submission telemetry.Submission
	accepted   bool
	snapshot   telemetry.Snapshot
}

func (t *fakeTelemetry) SubmitAsync(submission telemetry.Submission) bool {
	t.submission = submission
	return t.accepted
}

func (*fakeTelemetry) Shutdown(context.Context) error { return nil }
func (t *fakeTelemetry) Snapshot() telemetry.Snapshot { return t.snapshot }

func TestRecorderFansOutIndependentRawCopiesWithSameEventID(t *testing.T) {
	vault := &fakeVault{accepted: true}
	sender := &fakeTelemetry{accepted: true}
	recorder := &Recorder{Vault: vault, Telemetry: sender}
	timestamp := time.Date(2026, time.September, 14, 20, 0, 0, 0, time.UTC)
	event := proxy.ComplianceEvent{
		EventID:         "550e8400-e29b-41d4-a716-446655440000",
		Timestamp:       timestamp,
		ClientID:        "employee-42",
		ApplicationID:   "legal-assistant",
		Routing:         map[string]any{"model": "gpt-4o", "target": "openai"},
		ComplianceFlags: map[string]bool{"pii_detected": true, "pii_redacted": true},
		Metrics:         map[string]any{"total_tokens": 17},
		RequestMethod:   http.MethodPost,
		RequestURL:      "/v1/chat?case=7",
		RequestHeader:   http.Header{"Content-Type": {"application/json"}},
		RequestBody:     []byte(`{"prompt":"alice@example.com"}`),
		ResponseStatus:  http.StatusCreated,
		ResponseHeader:  http.Header{"Content-Type": {"application/json"}},
		ResponseBody:    []byte(`{"answer":"raw"}`),
	}
	if !recorder.RecordAsync(event) {
		t.Fatal("valid event was rejected")
	}
	if vault.call.eventID != event.EventID || sender.submission.EventID != event.EventID {
		t.Fatal("vault and telemetry did not receive the same event ID")
	}
	if string(vault.call.requestBody) != string(event.RequestBody) || string(vault.call.responseBody) != string(event.ResponseBody) {
		t.Fatal("vault did not receive the raw exchange")
	}
	if string(sender.submission.Request) != string(event.RequestBody) || string(sender.submission.Response) != string(event.ResponseBody) {
		t.Fatal("telemetry commitment did not receive the same raw exchange")
	}
	if sender.submission.ClientID != event.ClientID || sender.submission.ApplicationID != event.ApplicationID {
		t.Fatal("telemetry identity metadata mismatch")
	}
	if !reflect.DeepEqual(sender.submission.Routing, event.Routing) || !reflect.DeepEqual(sender.submission.Metrics, event.Metrics) {
		t.Fatal("telemetry metadata mismatch")
	}

	event.RequestBody[0] = 'X'
	event.ResponseBody[0] = 'Y'
	if sender.submission.Request[0] == 'X' || sender.submission.Response[0] == 'Y' || vault.call.requestBody[0] == 'X' || vault.call.responseBody[0] == 'Y' {
		t.Fatal("destinations retained caller-owned body buffers")
	}
}

func TestRecorderReportsPartialQueueAcceptance(t *testing.T) {
	recorder := &Recorder{
		Vault:     &fakeVault{accepted: false},
		Telemetry: &fakeTelemetry{accepted: true},
	}
	if recorder.RecordAsync(proxy.ComplianceEvent{}) {
		t.Fatal("recorder reported success when one destination rejected the event")
	}
}

func TestRecorderExposesAggregateTelemetryStatus(t *testing.T) {
	want := telemetry.Snapshot{Accepted: 4, Dropped: 1, Pending: 2, DeliveryFailures: 3}
	recorder := &Recorder{Telemetry: &fakeTelemetry{snapshot: want}}
	got := recorder.ComplianceStatus()
	if got.Telemetry == nil || got.Telemetry.Accepted != want.Accepted || got.Telemetry.Pending != want.Pending || got.Telemetry.DeliveryFailures != want.DeliveryFailures {
		t.Fatalf("ComplianceStatus() = %#v", got)
	}
}
