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
- `DASHBOARD_ORGANIZATION_ID`: organization UUID used as the dashboard's
  server-side tenant scope.
- `DASHBOARD_ACCESS_KEY`: a separate DPO login credential; do not reuse the
  data plane tenant key.
- `DASHBOARD_SESSION_SECRET`: at least 32 random characters used to sign the
  eight-hour HttpOnly DPO session cookie.
- `CRON_SECRET`: bearer token used by the internal worker route. Vercel adds
  this header automatically to configured cron invocations.
- `TELEMETRY_REORDER_WINDOW_SECONDS`: how long a chain gap remains buffered
  before it is classified as compromised; defaults to 30 seconds.

Create an organization first. The command prints its tenant key once; set that
value as `AIPROXY_TENANT_KEY` in the organization's Go data plane:

```sh
npm run orgs:create -- "Customer AB"
```

Register each data-plane instance's public P-256 key under that organization
before processing its events:

```sh
npm run keys:register -- <organization-id> ./instance-public-key.pem "production proxy"
```

The command derives the same SHA-256 SPKI fingerprint that the Go client emits
as `cryptography.key_id`. The private key remains in the customer data plane.

## Ingestion

`POST /api/telemetry/ingest` accepts one event or the ordered event array sent
by the Go batch client. The route:

1. Hashes the `Authorization: Bearer <AIPROXY_TENANT_KEY>` credential and
   resolves its organization. Plaintext tenant keys are never stored.
2. Enforces a 1 MiB request limit.
3. validates every field with strict Zod objects and rejects unknown top-level
   or cryptography properties.
4. Atomically reserves each `event_id` in a permanent deduplication ledger and
   writes new events plus the authenticated organization ID to
   `telemetry_buffer`.
5. Returns HTTP 202 without doing signature or chain processing.

The raw request and response are represented only by
`request_response_hash`; they are not accepted anywhere in the JSON schema.
`compliance_flags` requires boolean `pii_detected` and `pii_redacted` values.

## Ordered worker

Vercel calls `GET /api/internal/telemetry/process` every minute. The route is
protected by `CRON_SECRET` and can also be invoked by another scheduler.

The worker partitions chains by `(organization_id, key_id)`, sorts buffered rows by event
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

## Operations metrics

`GET /api/internal/metrics` exports tenant-neutral Prometheus metrics and
requires the same `Authorization: Bearer <CRON_SECRET>` protection as the
worker. It reports current buffer depth, age of the oldest buffered event, and
cumulative verified, compromised-chain, and invalid-signature outcomes. The
endpoint never exports organization IDs, event IDs, or telemetry payloads.
Shared alert rules for the Control Plane and Go data plane live in
`../deploy/prometheus/aiproxy-alerts.yml`; the corresponding runbook is
`../docs/operations/compliance-alerts.md`.

The event ledger makes retries idempotent across both the buffer and main
tables. Organization-scoped public-key lookups, chain heads, advisory locks,
and indexes prevent one tenant from reading or advancing another tenant's
chain.

## DPO dashboard

`/login` establishes a signed, HttpOnly, SameSite=Strict session scoped to the
server-configured organization. `/dashboard` rejects missing, expired, or
tampered sessions before reading telemetry. The DPO credential is separate
from the ingestion tenant key.

`/dashboard` aggregates processed telemetry for the configured organization.
It lists unique models, calls, token usage, policy violations, and locally
redacted PII incidents. `/dashboard/report` renders the same tenant-scoped data
as a formal EU AI Act evidence summary with A4 print styles. No raw telemetry
payloads or cross-organization rows are sent to the browser.

The inventory counts a policy violation when a true compliance flag ends in
`_violation`, `_breach`, `_blocked`, or `_failed`. A prevented PII leak requires
both `pii_detected` and `pii_redacted` to be true.

## Validation

```sh
npm test
npm run lint
npm run typecheck
npm run build
npm audit
```
