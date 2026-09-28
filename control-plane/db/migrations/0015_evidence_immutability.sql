-- Stored evidence is append-only. The only escape hatch is the existing
-- transaction-scoped maintenance setting, which the retention purge sets for
-- its own transaction. A database administrator can still disable triggers;
-- re-verification against externally anchored checkpoints covers that case.

CREATE OR REPLACE FUNCTION reject_evidence_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_setting('aiproxy.audit_maintenance', true) = 'on' THEN RETURN OLD; END IF;
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;

CREATE OR REPLACE FUNCTION reject_telemetry_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('aiproxy.audit_maintenance', true) = 'on' THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'telemetry_events is append-only';
END $$;

CREATE OR REPLACE FUNCTION guard_checkpoint_update() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  anchor_columns text[] := ARRAY['anchor_status', 'anchor_attempts', 'anchor_last_error', 'anchor_id', 'anchored_at', 'anchor_receipt'];
BEGIN
  IF current_setting('aiproxy.audit_maintenance', true) = 'on' THEN RETURN NEW; END IF;
  IF OLD.anchor_status = 'ANCHORED'
    OR (to_jsonb(NEW) - anchor_columns) IS DISTINCT FROM (to_jsonb(OLD) - anchor_columns) THEN
    RAISE EXCEPTION '% is append-only apart from pending anchor fields', TG_TABLE_NAME;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION reject_evidence_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_setting('aiproxy.audit_maintenance', true) = 'on' THEN RETURN NULL; END IF;
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;

DROP TRIGGER IF EXISTS telemetry_events_immutable ON telemetry_events;
CREATE TRIGGER telemetry_events_immutable
BEFORE UPDATE OR DELETE ON telemetry_events
FOR EACH ROW EXECUTE FUNCTION reject_telemetry_event_mutation();

DROP TRIGGER IF EXISTS compliance_reports_immutable ON compliance_reports;
CREATE TRIGGER compliance_reports_immutable
BEFORE UPDATE OR DELETE ON compliance_reports
FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

DROP TRIGGER IF EXISTS telemetry_merkle_checkpoints_no_delete ON telemetry_merkle_checkpoints;
CREATE TRIGGER telemetry_merkle_checkpoints_no_delete
BEFORE DELETE ON telemetry_merkle_checkpoints
FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

DROP TRIGGER IF EXISTS telemetry_merkle_checkpoints_anchor_only ON telemetry_merkle_checkpoints;
CREATE TRIGGER telemetry_merkle_checkpoints_anchor_only
BEFORE UPDATE ON telemetry_merkle_checkpoints
FOR EACH ROW EXECUTE FUNCTION guard_checkpoint_update();

DROP TRIGGER IF EXISTS security_audit_checkpoints_no_delete ON security_audit_checkpoints;
CREATE TRIGGER security_audit_checkpoints_no_delete
BEFORE DELETE ON security_audit_checkpoints
FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

DROP TRIGGER IF EXISTS security_audit_checkpoints_anchor_only ON security_audit_checkpoints;
CREATE TRIGGER security_audit_checkpoints_anchor_only
BEFORE UPDATE ON security_audit_checkpoints
FOR EACH ROW EXECUTE FUNCTION guard_checkpoint_update();

DO $$
DECLARE
  evidence_table text;
BEGIN
  FOREACH evidence_table IN ARRAY ARRAY['telemetry_events', 'compliance_reports', 'telemetry_merkle_checkpoints',
    'security_audit_checkpoints', 'security_audit_events', 'telemetry_tombstones'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', evidence_table || '_no_truncate', evidence_table);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION reject_evidence_truncate()',
      evidence_table || '_no_truncate', evidence_table);
  END LOOP;
END $$;
