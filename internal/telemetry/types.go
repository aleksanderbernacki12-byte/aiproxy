package telemetry

import (
	"encoding/json"
	"time"
)

const (
	SignatureAlgorithm = "ECDSA_P256_SHA256_ASN1"
	HashAlgorithm      = "SHA-256"
)

// Submission contains anonymized metadata plus the exact request and response
// bytes used to create the private commitment. Request and Response are never
// serialized into Payload or stored in the telemetry database.
type Submission struct {
	EventID   string
	Timestamp time.Time
	// ClientID is a data-plane-local identifier. SubmitAsync replaces it with
	// a rotating HMAC-SHA256 pseudonym before the event enters the queue.
	ClientID string
	// ClientIDHash is retained for source compatibility. Its value is treated
	// as an identifier and HMAC-hashed again; it is never sent directly.
	// Deprecated: use ClientID.
	ClientIDHash    string
	ApplicationID   string
	Routing         map[string]any
	ComplianceFlags map[string]bool
	Metrics         map[string]any
	Request         []byte
	Response        []byte
	clientIDHash    string
}

// Payload is the exact top-level event object sent to the control plane.
type Payload struct {
	EventID         string          `json:"event_id"`
	Timestamp       time.Time       `json:"timestamp"`
	ClientIDHash    string          `json:"client_id_hash"`
	ApplicationID   string          `json:"application_id"`
	Routing         map[string]any  `json:"routing"`
	ComplianceFlags map[string]bool `json:"compliance_flags"`
	Metrics         map[string]any  `json:"metrics"`
	Cryptography    Cryptography    `json:"cryptography"`
}

// Cryptography binds the anonymous metadata to a private request/response
// commitment and the preceding event from this data-plane instance.
type Cryptography struct {
	HashAlgorithm       string `json:"hash_algorithm"`
	RequestResponseHash string `json:"request_response_hash"`
	PreviousEventHash   string `json:"previous_event_hash"`
	EventHash           string `json:"event_hash"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	KeyID               string `json:"key_id"`
	Signature           string `json:"signature"`
}

type queuedEvent struct {
	sequence int64
	payload  json.RawMessage
	attempts int
}

// PIIComplianceFlags returns the required telemetry flags for a locally
// inspected request. A detected match is always also reported as redacted;
// the data plane never forwards a detected value unchanged.
func PIIComplianceFlags(detected bool) map[string]bool {
	return map[string]bool{
		"pii_detected": detected,
		"pii_redacted": detected,
	}
}
