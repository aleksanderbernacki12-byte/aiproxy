# Telemetry

`telemetry` sends anonymized compliance events from the customer data plane to
the control plane without putting SaaS availability in the LLM request path.
It has no dependency on the proxy, routing, cache, or secure-vault packages.

## Event format

Each event has exactly these top-level JSON fields:

```json
{
  "event_id": "...",
  "timestamp": "...",
  "client_id_hash": "...",
  "application_id": "...",
  "routing": {},
  "compliance_flags": {"pii_detected": false, "pii_redacted": false},
  "metrics": {},
  "cryptography": {}
}
```

The HTTP request body is an ordered JSON array of these objects. This permits
normal events and recovered backlog to use the same batch endpoint. The control
plane must treat `event_id` as an idempotency key because a response lost after
a successful POST can cause at-least-once redelivery.

`client_id_hash` must already be a SHA-256 hex digest. `SubmitAsync` rejects any
other shape to reduce accidental disclosure of a raw customer identifier. The
caller remains responsible for ensuring `application_id`, `routing`,
`compliance_flags`, and `metrics` contain anonymous values.

Raw request and response bytes are accepted only as hash material. They are
length-delimited and committed with SHA-256, then cleared on a best-effort basis
after sequencing. They are never included in the payload or SQLite database.

## Chain and signature

`cryptography.request_response_hash` commits to the raw exchange.
`cryptography.event_hash` commits to all eight top-level fields, including the
request/response commitment and `previous_event_hash`. The first event uses an
empty previous hash. Later events use the preceding event's `event_hash`.

The event hash is SHA-256 over:

```text
"aiproxy-telemetry-event-v1\0" || JCS(payload with event_hash="", signature="")
```

The ECDSA P-256 signature covers the RFC 8785 JSON Canonicalization Scheme (JCS)
representation with the final event hash present and `signature=""`.
Signatures use SHA-256 and ASN.1 DER, encoded as unpadded base64. `SigningBytes`
and `Verify` define the receiver contract. Next.js must apply the same RFC 8785
canonicalization before verification. `key_id` is the SHA-256 fingerprint of
the DER-encoded public key.

Values that JSON or JCS cannot encode, such as NaN, are rejected before they can
advance the durable chain head.

## Delivery and durability

A single sequencer hashes, links, signs, and commits an event together with the
new chain head in one SQLite transaction. This serializes concurrent LLM
completions and preserves the chain over restarts. A separate sender reads the
oldest events first and only deletes a batch after a successful 2xx response.
Failures and HTTP-client panics retain the exact signed bytes and use capped
exponential backoff.

The SQLite file is created with mode `0600`; it contains anonymous telemetry,
signatures, and chain state. The P-256 private-key file must also be a regular
file readable only by its owner. Keep both in customer-controlled persistent
storage. `Shutdown` drains every accepted in-memory submission into SQLite and
leaves unavailable batches there for the next process start.
