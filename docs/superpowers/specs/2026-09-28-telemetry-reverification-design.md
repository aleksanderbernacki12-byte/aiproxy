# Re-verification of stored telemetry (finding 2B)

Date: 2026-09-28
Status: approved direction (owner, 2026-09-28)

## Purpose

Second half of finding 2 of `docs/reviews/2026-09-28-control-plane-review.md`.
Signatures and chain links are checked only on ingest. After that, dashboard
counts and sealed reports are computed from stored columns that nothing
re-checks. 2A made those rows append-only for the application; a database
administrator can still disable triggers. This part re-verifies stored
evidence against the signed payloads and the externally anchored checkpoints,
and puts the result into the dashboard and the sealed report.

## Design

### Storage (migration `0016_telemetry_reverification.sql`)

- `telemetry_events.signed_payload jsonb` (nullable). The worker writes the
  schema-validated payload it verified. The original timestamp string cannot
  be rebuilt from `event_timestamp` (microsecond `timestamptz` vs the data
  plane's nanosecond RFC 3339), so without it a stored event cannot be
  re-hashed. Rows written before this migration stay `NULL` ("legacy") and can
  only be checked for chain linkage and sequence.
- `telemetry_tombstones.status` (nullable). Retention copies the event status,
  so a purged declared gap (`COMPROMISED_CHAIN`) is still recognisable. `NULL`
  means a tombstone from before this migration; at that time only `VERIFIED`
  events were purged.
- `telemetry_verification_runs`: `id`, `organization_id`, `started_at`,
  `completed_at`, `complete boolean`, `events_checked`, `legacy_events`,
  `failures`, `failure_samples jsonb` (at most 20 `{kind, key_id, sequence,
  event_id, detail}`). Append-only, same triggers as 2A, including `TRUNCATE`.

### Verifier (`src/lib/telemetry/verification.ts`)

`verifyOrganization(organizationId, deadline)` walks, per key that has stored
events or tombstones, the union of tombstones and sequenced events ordered by
`chain_sequence`, in pages of 1000:

1. `SEQUENCE_GAP`: sequences run 1, 2, 3, … without holes or duplicates.
2. `LINK_MISMATCH`: each item's `previous_event_hash` equals the prior item's
   `event_hash` (the first item's equals `""`), except where the item is a
   declared gap (`COMPROMISED_CHAIN`).
3. For every stored event with `signed_payload`, sequenced or not:
   `PAYLOAD_MISMATCH` when any stored column (identity, timestamp, client
   hash, application, routing, compliance flags, metrics, cryptography fields)
   differs from the payload; `HASH_MISMATCH` when the recomputed event hash
   differs; `SIGNATURE_INVALID` when the signature does not verify with the
   registered key, for rows not already `INVALID_SIGNATURE`; `KEY_MISSING`
   when no key is registered.
4. `HEAD_MISMATCH`: `telemetry_chain_heads` equals the last item.
5. `ANCHOR_MISMATCH`, against the latest `ANCHORED` checkpoint: its
   `root_hash` equals `calculateMerkleRoot(organization, chain_heads)`; when
   `MERKLE_ANCHOR_PUBLIC_KEY` is set, its stored receipt verifies
   (`verifyAnchorReceipt`); and for each head of the key, the item at that
   sequence exists with that `event_hash`.

When the deadline passes between pages, the run is stored with
`complete = false`. Each run inserts one `telemetry_verification_runs` row.

`verifyStoredTelemetry(now)` verifies organizations that have telemetry,
least recently verified first, until a 45-second budget is spent.

### Scheduling

`GET /api/internal/telemetry/verify` (bearer `CRON_SECRET`, `maxDuration`
60), hourly in `scripts/scheduler.mjs` and `vercel.json`.

### Dashboard and report

`getDashboardData` gains `verification: { lastRunAt, complete, eventsChecked,
legacyEvents, failures, failureSamples } | null`, from the latest run. The
sealed report includes it automatically. `chainStatus` becomes
`ATTENTION_REQUIRED` also when the latest run has failures or is incomplete,
or when evidence exists and no run completed in the last 48 hours. The
dashboard and report pages show a "Verifierad i efterhand" line with time,
checked events and deviations.

Out of scope: data-plane changes; re-verifying events whose key was deleted
from `telemetry_public_keys` (reported as `KEY_MISSING`).

## Testing

Integration (`reverification.integration.test.ts`, own organization):

- Clean chain of 3 events, processed and anchored with a correct checkpoint:
  run is complete with 0 failures, `events_checked = 3`.
- With triggers disabled for the test (`ALTER TABLE … DISABLE TRIGGER`, inside
  a rolled-back transaction or restored afterwards): editing
  `compliance_flags` → `PAYLOAD_MISMATCH`; editing `event_hash` and the next
  row's `previous_event_hash` consistently → `HASH_MISMATCH`; deleting a middle
  row → `SEQUENCE_GAP`; changing a checkpoint head → `ANCHOR_MISMATCH`.
- A declared gap (chain-recovery scenario) and its purge to tombstones → 0
  failures.
- Legacy row (`signed_payload` NULL) → counted in `legacy_events`, no failure.
- Deadline in the past → run stored with `complete = false`.
- Dashboard: `chainStatus` is `ATTENTION_REQUIRED` after a failing run.

Unit: `chainStatusFor` with the new verification inputs; route returns 401
without the bearer token.
