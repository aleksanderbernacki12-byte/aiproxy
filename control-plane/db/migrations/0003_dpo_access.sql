DO $$ BEGIN
  CREATE TYPE dpo_role AS ENUM ('ADMIN', 'DPO', 'AUDITOR');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS dpo_access_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  key_hash varchar(64) NOT NULL UNIQUE,
  label varchar(160) NOT NULL,
  role dpo_role NOT NULL DEFAULT 'DPO',
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS dpo_access_keys_organization_idx
  ON dpo_access_keys (organization_id, revoked_at);
