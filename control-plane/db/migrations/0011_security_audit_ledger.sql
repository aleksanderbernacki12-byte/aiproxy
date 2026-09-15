CREATE TABLE IF NOT EXISTS security_audit_events (
  event_id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  sequence bigint NOT NULL,
  previous_event_hash varchar(64) NOT NULL,
  event_hash varchar(64) NOT NULL,
  event_data jsonb NOT NULL,
  occurred_at timestamptz NOT NULL,
  UNIQUE (organization_id, sequence)
);

CREATE TABLE IF NOT EXISTS security_audit_heads (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id),
  sequence bigint NOT NULL,
  latest_event_hash varchar(64) NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS security_audit_events_org_time_idx
  ON security_audit_events (organization_id, occurred_at DESC, sequence DESC);

CREATE OR REPLACE FUNCTION reject_security_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_setting('aiproxy.audit_maintenance', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'security audit events are append-only';
END $$;

DROP TRIGGER IF EXISTS security_audit_events_immutable ON security_audit_events;
CREATE TRIGGER security_audit_events_immutable
BEFORE UPDATE OR DELETE ON security_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_security_audit_mutation();

CREATE OR REPLACE FUNCTION append_security_audit_event(
  p_organization_id uuid,
  p_actor_type text,
  p_actor_id text,
  p_action text,
  p_resource_type text,
  p_resource_id text,
  p_metadata jsonb
) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
  v_previous varchar(64) := '';
  v_sequence bigint := 1;
  v_event_id uuid := gen_random_uuid();
  v_occurred_at timestamptz := clock_timestamp();
  v_data jsonb;
  v_hash varchar(64);
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('security-audit:' || p_organization_id::text, 0));
  SELECT latest_event_hash, sequence + 1 INTO v_previous, v_sequence
    FROM security_audit_heads WHERE organization_id = p_organization_id FOR UPDATE;
  v_previous := coalesce(v_previous, '');
  v_sequence := coalesce(v_sequence, 1);
  v_data := jsonb_build_object(
    'actor_type', p_actor_type, 'actor_id', p_actor_id, 'action', p_action,
    'resource_type', p_resource_type, 'resource_id', p_resource_id,
    'metadata', coalesce(p_metadata, '{}'::jsonb), 'occurred_at', v_occurred_at
  );
  v_hash := encode(sha256(convert_to('aiproxy-security-audit-v1' || v_previous || v_data::text, 'UTF8')), 'hex');
  INSERT INTO security_audit_events VALUES (v_event_id, p_organization_id, v_sequence, v_previous, v_hash, v_data, v_occurred_at);
  INSERT INTO security_audit_heads VALUES (p_organization_id, v_sequence, v_hash, v_occurred_at)
    ON CONFLICT (organization_id) DO UPDATE SET sequence=EXCLUDED.sequence, latest_event_hash=EXCLUDED.latest_event_hash, updated_at=EXCLUDED.updated_at;
  RETURN v_event_id;
END $$;

CREATE OR REPLACE FUNCTION verify_security_audit_chain(p_organization_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
  WITH ordered AS (
    SELECT *, row_number() OVER (ORDER BY sequence) AS expected_sequence,
      coalesce(lag(event_hash) OVER (ORDER BY sequence), '') AS expected_previous
    FROM security_audit_events WHERE organization_id = p_organization_id
  ), checked AS (
    SELECT coalesce(bool_and(
      sequence = expected_sequence AND previous_event_hash = expected_previous AND
      event_hash = encode(sha256(convert_to('aiproxy-security-audit-v1' || previous_event_hash || event_data::text, 'UTF8')), 'hex')
    ), true) AS valid, coalesce(max(sequence), 0) AS sequence,
      coalesce((array_agg(event_hash ORDER BY sequence DESC))[1], '') AS latest_hash
    FROM ordered
  )
  SELECT checked.valid AND checked.sequence = coalesce(head.sequence, 0)
    AND checked.latest_hash = coalesce(head.latest_event_hash, '')
  FROM checked LEFT JOIN security_audit_heads head ON head.organization_id = p_organization_id
$$;
