# Evidence immutability in the database (finding 2A)

Date: 2026-09-28
Status: approved (owner, 2026-09-28)

## Purpose

First half of finding 2 of `docs/reviews/2026-09-28-control-plane-review.md`.
`security_audit_events` and `telemetry_tombstones` reject changes, but
`telemetry_events`, `compliance_reports` and both checkpoint tables accept any
`UPDATE`/`DELETE`, and no evidence table rejects `TRUNCATE`. A stored event's
`compliance_flags` can be edited and the next sealed report signs the edited
count. 2B (re-verification of stored events) closes the case of a database
administrator who disables triggers; this part stops the application, scripts
and ordinary SQL sessions from changing evidence.

## Design

Migration `0015_evidence_immutability.sql`. The existing escape hatch stays the
only one: `current_setting('aiproxy.audit_maintenance', true) = 'on'`.

1. **`telemetry_events`**: `UPDATE` always rejected. `DELETE` rejected unless
   the maintenance setting is on. The retention purge sets it for its own
   transaction only (`set_config('aiproxy.audit_maintenance', 'on', true)`)
   right before its purge statement.
2. **`compliance_reports`**: `UPDATE` and `DELETE` rejected unless maintenance.
3. **`telemetry_merkle_checkpoints`, `security_audit_checkpoints`**: `DELETE`
   rejected unless maintenance. `UPDATE` rejected unless maintenance when the
   row is already `ANCHORED`, or when anything other than the anchor columns
   (`anchor_status`, `anchor_attempts`, `anchor_last_error`, `anchor_id`,
   `anchored_at`, `anchor_receipt`) changes, compared generically via
   `to_jsonb(row)` minus those keys. `ANCHORED` → `PENDING` is thereby also
   rejected.
4. **`TRUNCATE`** rejected unless maintenance on all six evidence tables
   (the four above plus `security_audit_events`, `telemetry_tombstones`), via
   `BEFORE TRUNCATE ... FOR EACH STATEMENT` triggers.

Error messages name the table and say it is append-only, like the existing
triggers.

Out of scope: re-verification (2B), `telemetry_chain_heads` (mutable state
whose values are covered by anchored checkpoints).

## Testing

New integration test file `evidence-immutability.integration.test.ts` (own
organization, migrations applied like the other files):

- `UPDATE telemetry_events SET compliance_flags = ...` → rejected.
- `DELETE FROM telemetry_events` without maintenance → rejected; with
  `set_config(..., 'on', true)` inside a transaction → allowed.
- Retention still purges (covered by the existing retention tests).
- `UPDATE`/`DELETE compliance_reports` → rejected.
- Checkpoint: anchor-column update on `PENDING` → allowed; `root_hash` update
  → rejected; any update on `ANCHORED` → rejected; `DELETE` → rejected.
- `TRUNCATE telemetry_events` → rejected.
- Existing integration-test cleanups move their deletes of these tables under
  the maintenance setting.
