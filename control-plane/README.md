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

Set `POSTGRES_PORT` when port 5432 is already occupied, for example
`POSTGRES_PORT=55432 docker compose up -d postgres`.

For a complete self-hosted deployment, provide every runtime value listed
below. The session, cron, and anchor bearer secrets must be independent random
values of at least 32 characters. Then start the full stack:

```sh
export DASHBOARD_SESSION_SECRET='<random-session-secret>'
export CRON_SECRET='<different-random-worker-secret>'
export MERKLE_ANCHOR_TOKEN='<different-random-anchor-secret>'
# Also set the anchor URL/public key and report-signing private key.
docker compose up --build -d
```

Compose runs migrations to completion before starting the non-root standalone
Next.js container. A separate scheduler invokes telemetry processing every
minute and Merkle checkpoints every five minutes. `/api/health/live` checks the
process; `/api/health/ready` also requires PostgreSQL and migration
`0014_retention_and_legal_hold.sql`. It also validates every required secret,
the report and anchor Ed25519 keys, the production anchor HTTPS URL, and the
telemetry reorder window. Put a TLS-terminating reverse proxy in front of
port 3000 in production and back up the PostgreSQL volume independently. Every
route emits CSP, clickjacking, MIME-sniffing, referrer, browser-permission, and
one-year HTTPS transport policies. Keep production access on HTTPS so HSTS and
Secure session cookies are effective.

The dashboard login limiter allows five failed attempts per pseudonymous source
in 15 minutes and works across application instances through PostgreSQL. Source
addresses are HMAC-SHA256 hashed with the session secret and never stored. The
TLS reverse proxy must remove client-supplied forwarding headers and set a
trusted `X-Forwarded-For` or `X-Real-IP`; otherwise clients can evade source
throttling. Attempt rows expire opportunistically after 24 hours.

The runtime requires:

- `DATABASE_URL`: PostgreSQL connection string.
- `DASHBOARD_SESSION_SECRET`: at least 32 random characters used to sign the
  eight-hour HttpOnly DPO session cookie.
- `CRON_SECRET`: bearer token used by the internal worker route. Vercel adds
  this header automatically to configured cron invocations.
- `SCHEDULER_REQUEST_TIMEOUT_MS`: timeout for each self-hosted scheduler call;
  defaults to 70 seconds and must be between 5 and 300 seconds. A timed-out
  call is released so a later interval can retry it.
- `TELEMETRY_REORDER_WINDOW_SECONDS`: how long a chain gap remains buffered
  before it is classified as compromised; defaults to 30 seconds.
- `MERKLE_ANCHOR_URL`: HTTPS endpoint for an independent append-only anchor.
- `MERKLE_ANCHOR_TOKEN`: bearer credential sent only to the anchor endpoint.
- `MERKLE_ANCHOR_PUBLIC_KEY`: PEM-encoded Ed25519 public key used to verify
  anchor receipts. The corresponding private key stays with the independent
  anchor operator.
- `REPORT_SIGNING_PRIVATE_KEY`: PEM-encoded Ed25519 PKCS#8 private key used to
  seal compliance reports. Keep it separate from the anchor operator's key.

Create an organization first. The command prints its tenant key once; set that
value as `AIPROXY_TENANT_KEY` in the organization's Go data plane:

```sh
npm run orgs:create -- "Customer AB"
```

The initial credential is stored in `tenant_access_keys`; only its SHA-256
digest is retained. Rotate it without interrupting ingestion by creating an
overlapping credential, updating `AIPROXY_TENANT_KEY` in the data plane, and
then revoking the old credential ID:

```sh
npm run tenant-keys:create -- <organization-id> "production rotation" [expires-at-ISO]
npm run tenant-keys:revoke -- <organization-id> <old-credential-id>
```

Each organization can have multiple active data-plane credentials. Expired or
revoked credentials return HTTP 401 while LLM traffic remains fail-open in the
Go proxy. Existing installations are migrated automatically as a labelled
primary credential.

Register each data-plane instance's public P-256 key under that organization
before processing its events:

```sh
npm run keys:register -- <organization-id> ./instance-public-key.pem "production proxy"
```

The command derives the same SHA-256 SPKI fingerprint that the Go client emits
as `cryptography.key_id`. The private key remains in the customer data plane.

For a planned rotation, register the replacement key first, switch the data
plane to it, and then retire the old key. Retirement still accepts delayed
events whose signed timestamp precedes the cutoff:

```sh
npm run keys:register -- <organization-id> ./next-public-key.pem "rotation 2026-10"
npm run keys:retire -- <organization-id> <old-key-id> [cutoff-ISO]
```

Use immediate revocation only when a private key may be compromised. Revoked
keys reject every still-buffered event and require a local incident reason:

```sh
npm run keys:revoke -- <organization-id> <key-id> "suspected key exposure"
```

Create a separate DPO credential after applying migrations. Its plaintext is
printed once and its role can be `ADMIN`, `DPO`, or read-only `AUDITOR`:

```sh
npm run dpo:create -- <organization-id> "Primary DPO" DPO
npm run dpo:revoke -- <organization-id> <credential-id>
```

Only the SHA-256 digest is stored. An optional ISO expiry can be passed after
the role. Revocation invalidates existing sessions on their next request.

## AI system governance inventory

Telemetry automatically discovers each `(application_id, model)` combination.
Attach its EU AI Act governance profile with a strict JSON file:

```sh
npm run systems:upsert -- <organization-id> legal-assistant gpt-4o profile.json
```

```json
{
  "name": "Legal review assistant",
  "provider": "OpenAI",
  "intended_purpose": "Draft summaries for mandatory human review",
  "risk_class": "LIMITED",
  "system_owner": "Legal Operations",
  "legal_basis": "Legitimate interest assessment LIA-2026-04",
  "human_oversight": "A qualified reviewer approves every output",
  "data_categories": ["business contact data"],
  "deployment_regions": ["EU"],
  "status": "ACTIVE"
}
```

Risk classes are `UNCLASSIFIED`, `MINIMAL`, `LIMITED`, `HIGH`, and
`PROHIBITED`; lifecycle states are `ACTIVE`, `SUSPENDED`, and `RETIRED`.
Unknown JSON fields are rejected to prevent silent documentation mistakes.
Observed systems without a matching profile or final risk class appear as
governance gaps in both the DPO dashboard and formal report.

## Sealed compliance reports

Set `REPORT_SIGNING_PRIVATE_KEY` to an Ed25519 PKCS#8 PEM key and distribute
the corresponding public key through an independent trusted channel. A DPO or
administrator can use **Försegla och ladda ned** on the report page to persist
and download a versioned JSON evidence artifact. Auditors can read and print
the live report but cannot create sealed records.

Each artifact contains the complete tenant-scoped dashboard snapshot, schema
version, generation time, SHA-256 payload digest, signing-key fingerprint, and
Ed25519 signature. The signature covers the RFC 8785 canonical payload prefixed
with `aiproxy-compliance-report-v1\0`. Stored snapshots are never updated, so a
later governance or telemetry change cannot silently alter an issued report.
The signed evidence also records the administrative audit chain's verification
status, event count, latest sequence, and latest hash immediately before the
report's own sealing event is appended.
The tenant-scoped `/dashboard/reports` archive lists the 100 latest artifacts
with their issuer, payload digest, and signing-key fingerprint. DPOs and
auditors can download historical JSON without loading its payload into the
archive page.

The public half of every report key is archived automatically on first use and
linked from each report row. Rotating `REPORT_SIGNING_PRIVATE_KEY` therefore
does not make older reports unverifiable. A tenant can download a public key
only when at least one of its own reports references that key. The fingerprint
in the report and archive must still be compared with the copy distributed
through the independent trusted channel.

## Retention and legal hold

Automatic telemetry retention is opt-in per organization. Configure a period
from 30 to 3650 days, or place and release a legal hold with a case reference:

```sh
npm run retention -- set <organization-id> 365
npm run retention -- hold <organization-id> "CASE-2026-17"
npm run retention -- release <organization-id> "CASE-2026-17 closed"
```

The daily worker at `GET /api/internal/retention/run` requires `CRON_SECRET`.
It never purges a tenant without an explicit policy, and an active legal hold
stops all of that tenant's purging. Only `VERIFIED` events older than the policy
period and covered by an externally anchored chain head are eligible. Each run
moves at most 500 events per tenant into append-only tombstones containing only
event identity, timestamp, chain hashes, key ID, sequence, and purge metadata.
Deduplication IDs, chain heads, Merkle checkpoints, administrative audit events,
and sealed reports remain intact. Invalid-signature and compromised-chain rows
are retained for investigation. Policy changes, legal holds, releases, and
completed purge batches are recorded in the administrative audit chain. Use a
case reference rather than personal data in legal-hold reasons.

## Administrative security ledger

Credential creation and revocation, telemetry signing-key changes, AI-system
profile updates, organization creation, and report sealing append an event in
the same transaction as the protected change. PostgreSQL serializes each
tenant ledger and links entries with domain-separated SHA-256 hashes. Direct
updates and deletes are rejected by a database trigger.

Successful dashboard login and downloads of sealed reports or their public
verification keys are also recorded. These sensitive accesses fail closed if
their audit event cannot be appended; invalid credentials and missing resources
are not logged because they cannot be assigned safely to a tenant ledger.

`/dashboard/audit` recalculates the complete tenant chain against its stored
head before displaying the 200 latest events. Every scheduled checkpoint run
also verifies each audit chain, creates a tenant-bound SHA-256 checkpoint when
its head changes, and submits it through the independently verified anchor
channel. Audit and telemetry checkpoints share a global numeric ID sequence so
external receipts and idempotency keys cannot collide. Set `AIPROXY_OPERATOR_ID` to a
stable internal operator identifier when running administrative CLI commands;
it defaults to `local-cli` and must never contain credentials or personal data.
The maintenance setting is reserved for controlled restore and test cleanup;
a PostgreSQL owner can always disable database triggers.

Generate the signing-key pair without overwriting existing files. The private
key is created with owner-only permissions:

```sh
npm run reports:keygen -- report-private.pem report-public.pem
```

An auditor can verify a downloaded artifact entirely offline. The command
checks the strict envelope, canonical payload hash, Ed25519 public-key
fingerprint, and signature, and prints no report contents:

```sh
npm run reports:verify -- aiproxy-compliance-<report-id>.json report-public.pem
```

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
2. Confirms that the event timestamp is inside the registered key's validity
   interval and that the key has not been revoked.
3. Confirms the public key's SPKI fingerprint.
4. Recalculates `event_hash` with RFC 8785 JSON Canonicalization Scheme.
5. Verifies the ECDSA P-256/SHA-256 ASN.1 DER signature.
6. Checks `previous_event_hash` against `telemetry_chain_heads`.
7. Moves the row to `telemetry_events` and advances the head in the same
   transaction.

Cryptographically valid rows with a stale or unknown predecessor become
`COMPROMISED_CHAIN` after the reorder window. Invalid hashes, signatures,
revoked keys, or key fingerprints become `INVALID_SIGNATURE`. Neither status
advances the verified chain head.

## Merkle checkpoints

`GET /api/internal/telemetry/checkpoint` runs every five minutes with the same
`CRON_SECRET` protection. It sorts each organization's verified telemetry chain
heads, hashes tenant-bound leaves, and reduces them to a SHA-256 Merkle root. It
also verifies and checkpoints changed administrative audit heads. A new
checkpoint is stored only when the root changes. Its complete head snapshot
makes the root reproducible and is exposed in the tenant-scoped evidence
report.

`GET /api/internal/telemetry/anchor` sends pending telemetry and audit
checkpoints to the configured independent anchor in chronological batches of
five. The request contains only checkpoint ID,
root hash, hash algorithm, leaf count, and creation time; tenant IDs and
telemetry are excluded. The endpoint must return this strict JSON receipt:

```json
{
  "anchor_id": "append-only-ledger-reference",
  "checkpoint_id": "42",
  "root_hash": "64-lowercase-hex-characters",
  "anchored_at": "2026-09-15T18:00:00.000Z",
  "signature_algorithm": "Ed25519",
  "signature": "base64-signature"
}
```

The signature covers the RFC 8785 canonical receipt with an empty `signature`
field, prefixed by `aiproxy-merkle-anchor-receipt-v1\0`. Control Plane accepts
the receipt only when its checkpoint ID and root match and its Ed25519
signature verifies. Failures remain `PENDING`, record a bounded local error,
and retry on the next schedule. An idempotency key prevents duplicate external
records during retries.

## Operations metrics

`GET /api/internal/metrics` exports tenant-neutral Prometheus metrics and
requires the same `Authorization: Bearer <CRON_SECRET>` protection as the
worker. It reports current buffer depth, age of the oldest buffered event, and
cumulative verified, compromised-chain, and invalid-signature outcomes. It
also reports the number of administrative audit chains that fail complete
verification. The endpoint never exports organization IDs, event IDs, or
telemetry payloads.
Shared alert rules for the Control Plane and Go data plane live in
`../deploy/prometheus/aiproxy-alerts.yml`; the corresponding runbook is
`../docs/operations/compliance-alerts.md`.

The event ledger makes retries idempotent across both the buffer and main
tables. Organization-scoped public-key lookups, chain heads, advisory locks,
and indexes prevent one tenant from reading or advancing another tenant's
chain.

## DPO dashboard

`/login` resolves a hashed, active DPO credential to its organization and role,
then establishes a signed, HttpOnly, SameSite=Strict session. `/dashboard`
rechecks expiry and revocation before every tenant-scoped read. The DPO
credential is separate from the ingestion tenant key. All dashboard POST
actions require an exact same-origin `Origin` header to prevent cross-site
session creation, logout, and report sealing. Login accepts only URL-encoded
forms and stops reading after 4 KiB before any credential lookup.

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

The PostgreSQL integration test applies every migration to an explicitly
disposable database. It sends an out-of-order signed chain through ingestion,
runs the worker, and verifies the resulting dashboard aggregate:

```sh
TEST_DATABASE_URL=postgresql://aiproxy:aiproxy@localhost:5432/aiproxy_control \
  npm run test:integration
```
