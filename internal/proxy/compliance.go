package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	complianceClientIDHeader    = "X-Aiproxy-Client-Id"
	complianceApplicationHeader = "X-Aiproxy-Application-Id"
	maxComplianceIdentityLength = 160
)

// ComplianceEvent is an immutable snapshot of one completed upstream LLM
// exchange. RequestBody is the original client body before local PII or policy
// redaction. ResponseBody is the original upstream body before response rules.
type ComplianceEvent struct {
	EventID         string
	Timestamp       time.Time
	ClientID        string
	ApplicationID   string
	Routing         map[string]any
	ComplianceFlags map[string]bool
	Metrics         map[string]any
	RequestMethod   string
	RequestURL      string
	RequestHeader   http.Header
	RequestBody     []byte
	ResponseStatus  int
	ResponseHeader  http.Header
	ResponseBody    []byte
}

// ComplianceRecorder must return immediately after accepting or rejecting an
// event. Network and disk work belongs on the implementation's own bounded
// background queues so LLM traffic remains fail-open.
type ComplianceRecorder interface {
	RecordAsync(ComplianceEvent) bool
}

// ComplianceStatusProvider optionally exposes aggregate pipeline health.
type ComplianceStatusProvider interface {
	ComplianceStatus() ComplianceStatus
}

type ComplianceStatus struct {
	Telemetry *TelemetryStatus `json:"telemetry,omitempty"`
}

type TelemetryStatus struct {
	Accepted         uint64     `json:"accepted"`
	Dropped          uint64     `json:"dropped"`
	PersistFailures  uint64     `json:"persist_failures"`
	DeliveryFailures uint64     `json:"delivery_failures"`
	DeliveredEvents  uint64     `json:"delivered_events"`
	Pending          int64      `json:"pending"`
	LastDeliveredAt  *time.Time `json:"last_delivered_at,omitempty"`
	LastFailureAt    *time.Time `json:"last_failure_at,omitempty"`
}

func complianceIdentity(header http.Header, authenticatedLabel string) (clientID, applicationID string) {
	clientID = validComplianceIdentity(header.Get(complianceClientIDHeader))
	if clientID == "" {
		clientID = validComplianceIdentity(authenticatedLabel)
	}
	if clientID == "" {
		clientID = "anonymous"
	}
	applicationID = validComplianceIdentity(header.Get(complianceApplicationHeader))
	if applicationID == "" {
		applicationID = "aiproxy"
	}
	return clientID, applicationID
}

func validComplianceIdentity(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxComplianceIdentityLength {
		return ""
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return ""
		}
	}
	return value
}

func complianceRouting(targetLabel string, requestBody []byte) map[string]any {
	routing := map[string]any{"target": targetLabel}
	var request struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(requestBody, &request) == nil {
		if model := strings.TrimSpace(request.Model); model != "" && len(model) <= maxComplianceIdentityLength {
			routing["model"] = model
		}
	}
	return routing
}

func (s *Server) recordCompliance(event ComplianceEvent) {
	if s.ComplianceRecorder == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			s.logError("aiproxy: compliance recorder panic for %s: %v", event.EventID, recovered)
		}
	}()
	if !s.ComplianceRecorder.RecordAsync(event) {
		s.logError("aiproxy: compliance event %s was not accepted", event.EventID)
	}
}

func (s *Server) completeCompliance(
	reqCtx requestContextInfo,
	responseStatus int,
	responseHeader http.Header,
	responseBody []byte,
	responseComplete bool,
	responsePolicyRedacted bool,
	responsePolicyBlocked bool,
) {
	if reqCtx.complianceEventID == "" || s.ComplianceRecorder == nil {
		return
	}
	flags := map[string]bool{
		"pii_detected":             reqCtx.piiDetected,
		"pii_redacted":             reqCtx.piiRedacted,
		"request_policy_redacted":  reqCtx.requestPolicyRedacted,
		"response_policy_redacted": responsePolicyRedacted,
		"response_policy_blocked":  responsePolicyBlocked,
	}
	metrics := map[string]any{
		"status_code":       responseStatus,
		"response_complete": responseComplete,
	}
	if tokens := extractTotalTokens(responseBody); tokens > 0 {
		metrics["total_tokens"] = tokens
	}
	if reqCtx.latency != nil {
		metrics["latency_ms"] = reqCtx.latency.Milliseconds()
	}
	s.recordCompliance(ComplianceEvent{
		EventID:         reqCtx.complianceEventID,
		Timestamp:       reqCtx.complianceTimestamp,
		ClientID:        reqCtx.complianceClientID,
		ApplicationID:   reqCtx.complianceApplicationID,
		Routing:         complianceRouting(reqCtx.targetLabel, reqCtx.complianceRequestBody),
		ComplianceFlags: flags,
		Metrics:         metrics,
		RequestMethod:   reqCtx.method,
		RequestURL:      reqCtx.url,
		RequestHeader:   reqCtx.complianceRequestHeader,
		RequestBody:     reqCtx.complianceRequestBody,
		ResponseStatus:  responseStatus,
		ResponseHeader:  responseHeader,
		ResponseBody:    responseBody,
	})
}

type complianceReadCloser struct {
	httpBody io.ReadCloser
	onClose  func()
	once     sync.Once
}

func newComplianceReadCloser(body io.ReadCloser, onClose func()) *complianceReadCloser {
	return &complianceReadCloser{httpBody: body, onClose: onClose}
}

func (b *complianceReadCloser) Read(buffer []byte) (int, error) {
	return b.httpBody.Read(buffer)
}

func (b *complianceReadCloser) Close() error {
	err := b.httpBody.Close()
	b.once.Do(func() {
		if b.onClose != nil {
			b.onClose()
		}
	})
	return err
}
