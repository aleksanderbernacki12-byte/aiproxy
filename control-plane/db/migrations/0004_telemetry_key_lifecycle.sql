ALTER TABLE telemetry_public_keys ADD COLUMN IF NOT EXISTS valid_from timestamptz;
ALTER TABLE telemetry_public_keys ADD COLUMN IF NOT EXISTS valid_until timestamptz;
ALTER TABLE telemetry_public_keys ADD COLUMN IF NOT EXISTS revoked_reason varchar(240);

DO $$ BEGIN
  ALTER TABLE telemetry_public_keys
    ADD CONSTRAINT telemetry_public_keys_validity_check
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS telemetry_public_keys_lifecycle_idx
  ON telemetry_public_keys (organization_id, revoked_at, valid_until);
