// Package compliance connects completed proxy exchanges to the customer-owned
// secure vault and the anonymized telemetry pipeline.
package compliance

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"aiproxy/internal/proxy"
	"aiproxy/internal/securevault"
	"aiproxy/internal/telemetry"
)

// Vault is implemented by *securevault.Vault.
type Vault interface {
	StoreAsync(eventID string, request *http.Request, response *http.Response) bool
	Shutdown(context.Context) error
}

type vaultStatus interface {
	Snapshot() securevault.Snapshot
}

// Telemetry is implemented by *telemetry.Client.
type Telemetry interface {
	SubmitAsync(telemetry.Submission) bool
	Shutdown(context.Context) error
}

type telemetryStatus interface {
	Snapshot() telemetry.Snapshot
}

// Recorder fans one immutable proxy snapshot out to independent bounded
// queues. Either destination may be nil while deployments are being migrated.
type Recorder struct {
	Vault     Vault
	Telemetry Telemetry
}

var _ proxy.ComplianceRecorder = (*Recorder)(nil)

// RecordAsync performs only local copies and non-blocking queue submissions.
// AWS, SQLite, and Control Plane requests remain inside their package workers.
func (r *Recorder) RecordAsync(event proxy.ComplianceEvent) bool {
	if r == nil || (r.Vault == nil && r.Telemetry == nil) {
		return false
	}
	accepted := true
	if r.Vault != nil {
		requestBody := append([]byte(nil), event.RequestBody...)
		responseBody := append([]byte(nil), event.ResponseBody...)
		request := &http.Request{
			Method:        event.RequestMethod,
			URL:           parseURL(event.RequestURL),
			Header:        event.RequestHeader.Clone(),
			Body:          io.NopCloser(bytes.NewReader(requestBody)),
			ContentLength: int64(len(requestBody)),
		}
		response := &http.Response{
			StatusCode:    event.ResponseStatus,
			Status:        strconv.Itoa(event.ResponseStatus) + " " + http.StatusText(event.ResponseStatus),
			Header:        event.ResponseHeader.Clone(),
			Body:          io.NopCloser(bytes.NewReader(responseBody)),
			ContentLength: int64(len(responseBody)),
			Request:       request,
		}
		accepted = r.Vault.StoreAsync(event.EventID, request, response) && accepted
	}
	if r.Telemetry != nil {
		accepted = r.Telemetry.SubmitAsync(telemetry.Submission{
			EventID:         event.EventID,
			Timestamp:       event.Timestamp,
			ClientID:        event.ClientID,
			ApplicationID:   event.ApplicationID,
			Routing:         cloneAnyMap(event.Routing),
			ComplianceFlags: cloneBoolMap(event.ComplianceFlags),
			Metrics:         cloneAnyMap(event.Metrics),
			Request:         append([]byte(nil), event.RequestBody...),
			Response:        append([]byte(nil), event.ResponseBody...),
		}) && accepted
	}
	return accepted
}

// Shutdown drains both destinations within the caller's deadline.
func (r *Recorder) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var firstErr error
	if r.Telemetry != nil {
		if err := r.Telemetry.Shutdown(ctx); err != nil {
			firstErr = err
		}
	}
	if r.Vault != nil {
		if err := r.Vault.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ComplianceStatus returns aggregate health without reading either queue.
func (r *Recorder) ComplianceStatus() proxy.ComplianceStatus {
	status := proxy.ComplianceStatus{}
	if provider, ok := r.Telemetry.(telemetryStatus); ok {
		snapshot := provider.Snapshot()
		status.Telemetry = &proxy.TelemetryStatus{
			Accepted: snapshot.Accepted, Dropped: snapshot.Dropped,
			PersistFailures: snapshot.PersistFailures, DeliveryFailures: snapshot.DeliveryFailures,
			DeliveredEvents: snapshot.DeliveredEvents, Pending: snapshot.Pending,
			LastDeliveredAt: snapshot.LastDeliveredAt, LastFailureAt: snapshot.LastFailureAt,
		}
	}
	if provider, ok := r.Vault.(vaultStatus); ok {
		snapshot := provider.Snapshot()
		status.SecureVault = &proxy.SecureVaultStatus{
			Accepted: snapshot.Accepted, Dropped: snapshot.Dropped, QueueDepth: snapshot.QueueDepth,
			SpoolPending: snapshot.SpoolPending, Quarantined: snapshot.Quarantined,
			LocalFailures: snapshot.LocalFailures, UploadFailures: snapshot.UploadFailures,
			Uploaded: snapshot.Uploaded, LastUploadedAt: snapshot.LastUploadedAt, LastFailureAt: snapshot.LastFailureAt,
		}
	}
	return status
}

func parseURL(value string) *url.URL {
	parsed, err := url.Parse(value)
	if err != nil {
		return &url.URL{}
	}
	return parsed
}

func cloneAnyMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func cloneBoolMap(source map[string]bool) map[string]bool {
	if source == nil {
		return nil
	}
	clone := make(map[string]bool, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
