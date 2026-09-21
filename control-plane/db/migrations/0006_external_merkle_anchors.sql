DO $$ BEGIN
  CREATE TYPE merkle_anchor_status AS ENUM ('PENDING', 'ANCHORED');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE telemetry_merkle_checkpoints
  ADD COLUMN IF NOT EXISTS anchor_status merkle_anchor_status NOT NULL DEFAULT 'PENDING';
ALTER TABLE telemetry_merkle_checkpoints
  ADD COLUMN IF NOT EXISTS anchor_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE telemetry_merkle_checkpoints ADD COLUMN IF NOT EXISTS anchor_last_error text;
ALTER TABLE telemetry_merkle_checkpoints ADD COLUMN IF NOT EXISTS anchor_id varchar(240);
ALTER TABLE telemetry_merkle_checkpoints ADD COLUMN IF NOT EXISTS anchored_at timestamptz;
ALTER TABLE telemetry_merkle_checkpoints ADD COLUMN IF NOT EXISTS anchor_receipt jsonb;

CREATE INDEX IF NOT EXISTS telemetry_merkle_checkpoints_pending_anchor_idx
  ON telemetry_merkle_checkpoints (created_at, id) WHERE anchor_status = 'PENDING';
