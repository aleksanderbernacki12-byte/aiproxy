# Aiproxy Control Plane

Next.js App Router service for DPO-facing compliance evidence. It receives only
anonymous telemetry from the customer-hosted Go data plane. Raw LLM prompts,
responses, encryption keys, and PII do not belong in this application.

## Local setup

Use Node.js 24 or newer. Copy `.env.example` to `.env.local`, then start and
migrate PostgreSQL:

```sh
docker compose up -d postgres
set -a; source .env.local; set +a
npm run db:migrate
npm run dev
```

The runtime requires:

- `DATABASE_URL`: PostgreSQL connection string.
- `TELEMETRY_INGEST_TOKEN`: bearer token used by the Go telemetry client.
- `CRON_SECRET`: bearer token used by the internal worker route. Vercel adds
  this header automatically to configured cron invocations.
- `TELEMETRY_REORDER_WINDOW_SECONDS`: how long a chain gap remains buffered
  before it is classified as compromised; defaults to 30 seconds.

Register each data-plane instance's public P-256 key before processing its
events:

```sh
npm run keys:register -- ./instance-public-key.pem "customer / instance"
```

The command derives the same SHA-256 SPKI fingerprint that the Go client emits
as `cryptography.key_id`. The private key remains in the customer data plane.

## Ingestion

`POST /api/telemetry/ingest` accepts one event or the ordered event array sent
by the Go batch client. The route:

1. Requires `Authorization: Bearer <TELEMETRY_INGEST_TOKEN>`.
2. Enforces a 1 MiB request limit.
3. validates every field with strict Zod objects and rejects unknown top-level
   or cryptography properties.
4. Atomically reserves each `event_id` in a permanent deduplication ledger and
   writes new events to `telemetry_buffer`.
5. Returns HTTP 202 without doing signature or chain processing.

The raw request and response are represented only by
`request_response_hash`; they are not accepted anywhere in the JSON schema.

## Ordered worker

Vercel calls `GET /api/internal/telemetry/process` every minute. The route is
protected by `CRON_SECRET` and can also be invoked by another scheduler.

The worker partitions chains by `key_id`, sorts buffered rows by event
timestamp, and obtains a PostgreSQL transaction-level advisory lock for each
chain. The hash link remains authoritative when packets arrive out of order: a
row whose `previous_event_hash` matches the current head can advance the chain.
A missing predecessor remains buffered for the reorder window.

For each candidate, the worker:

1. Revalidates the stored event schema.
2. Loads the registered public key and confirms its SPKI fingerprint.
3. Recalculates `event_hash` with RFC 8785 JSON Canonicalization Scheme.
4. Verifies the ECDSA P-256/SHA-256 ASN.1 DER signature.
5. Checks `previous_event_hash` against `telemetry_chain_heads`.
6. Moves the row to `telemetry_events` and advances the head in the same
   transaction.

Cryptographically valid rows with a stale or unknown predecessor become
`COMPROMISED_CHAIN` after the reorder window. Invalid hashes, signatures,
revoked keys, or key fingerprints become `INVALID_SIGNATURE`. Neither status
advances the verified chain head.

The event ledger makes retries idempotent across both the buffer and main
tables. PostgreSQL advisory locks prevent concurrent cron executions from
advancing the same instance chain twice.

## Validation

```sh
npm test
npm run lint
npm run typecheck
npm run build
npm audit
```
