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

The caller supplies its local identifier as `Submission.ClientID`.
`SubmitAsync` replaces it with an HMAC-SHA256 pseudonym before the event enters
the asynchronous queue. The clear identifier is never written to SQLite or
sent to the control plane. The caller remains responsible for ensuring
`application_id`, `routing`, `compliance_flags`, and `metrics` contain
anonymous values.

The 256-bit HMAC salt is stored in `.aiproxy_salt` beside the telemetry SQLite
database by default, with mode `0600`. `Config.SaltPath` can place it elsewhere
on customer-controlled persistent storage. At startup the client loads the
existing salt or creates one with `crypto/rand`; salts that are at least 30 days
old rotate immediately. A background goroutine checks once every 24 hours and
atomically replaces expired salts. Successful rotations and background errors
are written through the local `OnError` callback or Go's standard logger. Salt
rotation deliberately prevents pseudonyms from linking a client across
long-lived reporting periods.

The `aiproxy start` command enables the pipeline when both
`-telemetry-endpoint` and `-telemetry-private-key` are set. It uses
`.aiproxy_telemetry.sqlite` as the durable queue unless `-telemetry-db` is
provided. `-telemetry-salt` can override the salt location. Set
`AIPROXY_TENANT_KEY` in the process environment; the key is never accepted as a
command-line argument because process arguments are commonly visible to other
local users.

Callers may identify themselves with `X-Aiproxy-Client-Id` and
`X-Aiproxy-Application-Id`. Aiproxy consumes these headers locally and removes
them before forwarding. If absent, the authenticated proxy-key label and
`aiproxy` are used. Completed upstream exchanges are captured for ordinary JSON
and streaming SSE responses; cache hits do not create an upstream telemetry
event.

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

`New` requires `AIPROXY_TENANT_KEY` in the process environment. Every batch is
sent with `Authorization: Bearer <AIPROXY_TENANT_KEY>`; a caller-supplied
Authorization header cannot override it. A 401 response is reported through
the local asynchronous `OnError` callback and retained for retry without
blocking or failing LLM traffic.
HTTP redirects are rejected and the batch remains queued for retry. Configure
the ingest endpoint directly: a redirect must never forward telemetry or tenant
credentials, or turn a redirected GET into a successful delivery. Supplied
`*http.Client` values are copied with redirects disabled; custom `HTTPDoer`
implementations must likewise return redirects without following them.
When no `OnError` callback is configured, the package writes the error through
Go's standard local logger.
Delivery diagnostics omit arbitrary transport error and panic text, which can
contain credentials, URL parameters, or payloads. They report HTTP status codes,
timeouts, cancellation, and generic transport or client-panic failures instead.

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

`Client.Snapshot()` exposes non-blocking aggregate health: accepted and
dropped submissions, pending durable work, persistence and delivery failures,
delivered events, and latest success/failure times. With the compliance
recorder these values appear under `compliance.telemetry` in
`GET /_aiproxy/stats`; no event data or secrets are included.
