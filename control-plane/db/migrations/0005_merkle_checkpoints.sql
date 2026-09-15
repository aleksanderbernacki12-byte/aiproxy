CREATE TABLE IF NOT EXISTS telemetry_merkle_checkpoints (
  id bigserial PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  root_hash varchar(64) NOT NULL,
  leaf_count integer NOT NULL CHECK (leaf_count > 0),
  chain_heads jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, root_hash)
);

CREATE INDEX IF NOT EXISTS telemetry_merkle_checkpoints_latest_idx
  ON telemetry_merkle_checkpoints (organization_id, created_at DESC, id DESC);
