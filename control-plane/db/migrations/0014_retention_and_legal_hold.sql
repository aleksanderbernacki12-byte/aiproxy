CREATE TABLE IF NOT EXISTS organization_retention_policies (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id),
  telemetry_retention_days integer NOT NULL CHECK (telemetry_retention_days BETWEEN 30 AND 3650),
  legal_hold boolean NOT NULL DEFAULT false,
  legal_hold_reason varchar(500),
  legal_hold_set_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((legal_hold AND legal_hold_reason IS NOT NULL AND legal_hold_set_at IS NOT NULL)
    OR (NOT legal_hold AND legal_hold_reason IS NULL AND legal_hold_set_at IS NULL))
);

CREATE TABLE IF NOT EXISTS telemetry_tombstones (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  event_id uuid NOT NULL,
  event_timestamp timestamptz NOT NULL,
  event_hash varchar(64) NOT NULL,
  previous_event_hash varchar(64) NOT NULL,
  key_id varchar(64) NOT NULL,
  chain_sequence bigint NOT NULL,
  purged_at timestamptz NOT NULL,
  retention_days integer NOT NULL,
  PRIMARY KEY (organization_id, event_id)
);

CREATE INDEX IF NOT EXISTS telemetry_tombstones_org_time_idx
  ON telemetry_tombstones (organization_id, event_timestamp DESC);

CREATE OR REPLACE FUNCTION reject_telemetry_tombstone_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_setting('aiproxy.audit_maintenance', true) = 'on' THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'telemetry tombstones are append-only';
END $$;

DROP TRIGGER IF EXISTS telemetry_tombstones_immutable ON telemetry_tombstones;
CREATE TRIGGER telemetry_tombstones_immutable
BEFORE UPDATE OR DELETE ON telemetry_tombstones
FOR EACH ROW EXECUTE FUNCTION reject_telemetry_tombstone_mutation();
