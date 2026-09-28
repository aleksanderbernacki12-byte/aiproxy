-- The verified payload is kept because the signed timestamp string cannot be
-- rebuilt from event_timestamp (microseconds vs the data plane's nanoseconds).
-- Rows from before this migration stay NULL and are checked for linkage only.
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS signed_payload jsonb;

-- NULL marks a tombstone from before this migration, when only VERIFIED
-- events were purged.
ALTER TABLE telemetry_tombstones ADD COLUMN IF NOT EXISTS status telemetry_verification_status;

CREATE TABLE IF NOT EXISTS telemetry_verification_runs (
  id bigserial PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  complete boolean NOT NULL,
  events_checked integer NOT NULL,
  legacy_events integer NOT NULL,
  failures integer NOT NULL,
  failure_samples jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS telemetry_verification_runs_latest_idx
  ON telemetry_verification_runs (organization_id, completed_at DESC, id DESC);

DROP TRIGGER IF EXISTS telemetry_verification_runs_immutable ON telemetry_verification_runs;
CREATE TRIGGER telemetry_verification_runs_immutable
BEFORE UPDATE OR DELETE ON telemetry_verification_runs
FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

DROP TRIGGER IF EXISTS telemetry_verification_runs_no_truncate ON telemetry_verification_runs;
CREATE TRIGGER telemetry_verification_runs_no_truncate
BEFORE TRUNCATE ON telemetry_verification_runs
FOR EACH STATEMENT EXECUTE FUNCTION reject_evidence_truncate();
