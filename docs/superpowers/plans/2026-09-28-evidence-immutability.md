# Evidence Immutability — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evidence rows cannot be changed or removed outside retention and explicit maintenance.

**Architecture:** One migration with PL/pgSQL trigger functions, the retention purge enabling the existing maintenance setting for its own transaction, and integration tests. Spec: `docs/superpowers/specs/2026-09-28-evidence-immutability-design.md`. Branch: `fix/evidence-immutability`.

Verification (in `control-plane/`, with a disposable PostgreSQL as `TEST_DATABASE_URL`): `npm run lint && npm test && npm run typecheck && npm run test:integration`.

---

### Task 1: Failing tests

- [ ] Create `control-plane/src/integration/evidence-immutability.integration.test.ts`: own organization, one DPO key, one signed event processed into `telemetry_events` (via `bufferTelemetryEvents` + `processBufferedTelemetry`), one `compliance_reports` row, one `PENDING` and one `ANCHORED` `telemetry_merkle_checkpoints` row. Every mutation attempt runs inside `BEGIN … ROLLBACK` (or a savepoint) so a missing trigger can never damage other tests' data. Assertions per the spec's Testing section, using `rejects.toThrow(/append-only|immutable/)`.
- [ ] Move the deletes of `telemetry_events`, `compliance_reports`, `telemetry_merkle_checkpoints`, `security_audit_checkpoints` in `telemetry-flow.integration.test.ts` and `chain-recovery.integration.test.ts` cleanups inside the existing `aiproxy.audit_maintenance` on/off block.
- [ ] Run `npm run test:integration`: new tests fail, others pass.

### Task 2: Migration and retention

- [ ] Create `control-plane/db/migrations/0015_evidence_immutability.sql`:
  - `reject_evidence_mutation()` — returns `OLD` when maintenance is on, else raises `'% is append-only', TG_TABLE_NAME`; used `BEFORE UPDATE OR DELETE` on `compliance_reports`, `BEFORE DELETE` on both checkpoint tables.
  - `reject_telemetry_event_mutation()` — `UPDATE` always raises; `DELETE` as above; `BEFORE UPDATE OR DELETE` on `telemetry_events`.
  - `guard_checkpoint_update()` — maintenance → `NEW`; `OLD.anchor_status = 'ANCHORED'` → raise; `(to_jsonb(NEW) - array[anchor columns]) IS DISTINCT FROM (to_jsonb(OLD) - array[...])` → raise; else `NEW`. `BEFORE UPDATE` on both checkpoint tables.
  - `reject_evidence_truncate()` statement trigger, `BEFORE TRUNCATE` on the six tables.
  - Every trigger created with `DROP TRIGGER IF EXISTS` first (migrations are re-applied by the integration tests).
- [ ] `control-plane/src/lib/retention.ts`: in `purgeOrganization`, immediately before the purge statement, `await transaction.execute(sql\`SELECT set_config('aiproxy.audit_maintenance', 'on', true)\`)`.
- [ ] Run full verification: all green (existing retention tests prove the purge still works).
- [ ] Commit: `fix(control-plane): make stored evidence append-only`.

### Task 3: Docs

- [ ] `control-plane/README.md`: in the retention/evidence section, list the append-only tables, the maintenance setting as the only escape hatch, and that retention uses it for its own transaction.
- [ ] Review doc: note under finding 2 that 2A is addressed.
- [ ] Commit: `docs: describe evidence immutability`.
