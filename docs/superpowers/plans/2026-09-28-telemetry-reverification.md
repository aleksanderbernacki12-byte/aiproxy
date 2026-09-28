# Telemetry Re-verification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stored telemetry is periodically re-verified against signed payloads and anchored checkpoints, and the result is part of the dashboard and sealed report.

**Architecture:** Migration 0016 (signed payload, tombstone status, append-only run table); `src/lib/telemetry/verification.ts` walks each key's tombstones + events by sequence; an hourly internal route stores one run per organization; `getDashboardData` exposes the latest run and folds it into `chainStatus`. Spec: `docs/superpowers/specs/2026-09-28-telemetry-reverification-design.md`. Branch: `fix/telemetry-reverification`.

Verification (in `control-plane/`, disposable PostgreSQL as `TEST_DATABASE_URL`): `npm run lint && npm test && npm run typecheck && npm run test:integration`. One commit per task, each green.

---

### Task 1: Store what re-verification needs

- [ ] Migration `0016_telemetry_reverification.sql`: `ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS signed_payload jsonb`; `ALTER TABLE telemetry_tombstones ADD COLUMN IF NOT EXISTS status telemetry_verification_status` (check the enum type name in 0001); `telemetry_verification_runs` table with index `(organization_id, completed_at DESC, id DESC)`, `BEFORE UPDATE OR DELETE` trigger `reject_evidence_mutation()`, `BEFORE TRUNCATE` trigger `reject_evidence_truncate()`.
- [ ] `src/db/schema.ts`: `signedPayload` on `telemetryEvents`, `telemetryVerificationRuns` table.
- [ ] Worker `mainTableValues`: `signedPayload: payload`.
- [ ] Retention: tombstone insert copies `event.status`.
- [ ] Readiness `expectedMigration` → `0016_telemetry_reverification.sql`; README line that names it.
- [ ] Integration test (in `reverification.integration.test.ts`): a processed event has `signed_payload` deep-equal to the ingested event; a purged event's tombstone has its status.
- [ ] Commit `feat(control-plane): keep signed payloads for re-verification`.

### Task 2: Verifier

- [ ] Tests first (same file), per the spec's Testing section: clean chain; tampering cases with `ALTER TABLE telemetry_events DISABLE TRIGGER telemetry_events_immutable` restored in `finally` (and the same for checkpoints); declared gap + purge; legacy row; past deadline.
- [ ] `verification.ts`: `verifyOrganization(organizationId, deadline, now)` returning and inserting the run; `verifyStoredTelemetry(now, budgetMs = 45_000)`. Payload/column comparison via `canonicalize` of both sides' JSON fields and `Date` equality for the timestamp; hash via `calculateEventHash`; signature via `verifyTelemetryCryptography` (without key-validity checks); anchor via `calculateMerkleRoot` and `verifyAnchorReceipt`.
- [ ] Commit `feat(control-plane): re-verify stored telemetry`.

### Task 3: Scheduling

- [ ] `src/app/api/internal/telemetry/verify/route.ts` (pattern of `process/route.ts`), `route.test.ts` for 401/503.
- [ ] `scripts/scheduler.mjs`: run at start and hourly. `vercel.json`: `"path": "/api/internal/telemetry/verify", "schedule": "37 * * * *"`. Update `scripts/scheduler-config.node-test.mjs` only if it asserts the route list.
- [ ] Commit `feat(control-plane): schedule hourly telemetry re-verification`.

### Task 4: Dashboard and report

- [ ] `chainStatusFor(totalEvents, compromised, invalid, verification, now)`: attention on failures, incomplete run, or evidence without a completed run in 48 h. Unit tests in `dashboard.test.ts` (or create).
- [ ] `getDashboardData`: latest run → `verification`.
- [ ] `src/app/dashboard/page.tsx` and `src/app/dashboard/report/page.tsx`: "Verifierad i efterhand" line.
- [ ] Integration: dashboard `chainStatus` after a failing run.
- [ ] Commit `feat(control-plane): show re-verification in dashboard and report`.

### Task 5: Docs

- [ ] README: re-verification section (what it checks, schedule, legacy rows, 48 h rule). Review doc: finding 2 addressed.
- [ ] Commit `docs: describe telemetry re-verification`.
