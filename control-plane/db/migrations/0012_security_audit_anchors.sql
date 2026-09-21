CREATE SEQUENCE IF NOT EXISTS aiproxy_anchor_checkpoint_id_seq;
SELECT setval(
  'aiproxy_anchor_checkpoint_id_seq',
  coalesce((SELECT max(id) + 1 FROM telemetry_merkle_checkpoints), 1),
  false
);
ALTER TABLE telemetry_merkle_checkpoints
  ALTER COLUMN id SET DEFAULT nextval('aiproxy_anchor_checkpoint_id_seq');

CREATE TABLE IF NOT EXISTS security_audit_checkpoints (
  id bigint PRIMARY KEY DEFAULT nextval('aiproxy_anchor_checkpoint_id_seq'),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  sequence bigint NOT NULL,
  event_hash varchar(64) NOT NULL,
  root_hash varchar(64) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  anchor_status merkle_anchor_status NOT NULL DEFAULT 'PENDING',
  anchor_attempts integer NOT NULL DEFAULT 0,
  anchor_last_error text,
  anchor_id varchar(240),
  anchored_at timestamptz,
  anchor_receipt jsonb,
  UNIQUE (organization_id, root_hash),
  UNIQUE (organization_id, sequence)
);

CREATE INDEX IF NOT EXISTS security_audit_checkpoints_latest_idx
  ON security_audit_checkpoints (organization_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS security_audit_checkpoints_pending_anchor_idx
  ON security_audit_checkpoints (created_at, id) WHERE anchor_status = 'PENDING';
