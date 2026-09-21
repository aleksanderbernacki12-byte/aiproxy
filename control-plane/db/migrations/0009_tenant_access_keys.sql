CREATE TABLE IF NOT EXISTS tenant_access_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  key_hash varchar(64) NOT NULL UNIQUE,
  label varchar(160) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz
);

INSERT INTO tenant_access_keys (organization_id, key_hash, label, created_at)
SELECT id, tenant_key, 'Migrated primary key', created_at FROM organizations
ON CONFLICT (key_hash) DO NOTHING;

CREATE INDEX IF NOT EXISTS tenant_access_keys_organization_idx
  ON tenant_access_keys (organization_id, revoked_at, expires_at);
