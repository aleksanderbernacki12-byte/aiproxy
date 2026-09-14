CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name varchar(160) NOT NULL,
  -- SHA-256 digest of the bearer key; the plaintext credential is never stored.
  tenant_key varchar(64) NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Existing pre-tenant telemetry remains attributable but cannot authenticate:
-- no practical bearer key hashes to 64 zeroes.
INSERT INTO organizations (id, name, tenant_key)
VALUES ('00000000-0000-0000-0000-000000000001', 'Legacy unscoped telemetry', repeat('0', 64))
ON CONFLICT DO NOTHING;

ALTER TABLE telemetry_public_keys ADD COLUMN IF NOT EXISTS organization_id uuid;
ALTER TABLE telemetry_event_ids ADD COLUMN IF NOT EXISTS organization_id uuid;
ALTER TABLE telemetry_buffer ADD COLUMN IF NOT EXISTS organization_id uuid;
ALTER TABLE telemetry_chain_heads ADD COLUMN IF NOT EXISTS organization_id uuid;
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS organization_id uuid;

UPDATE telemetry_public_keys SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
UPDATE telemetry_event_ids SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
UPDATE telemetry_buffer SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
UPDATE telemetry_chain_heads SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
UPDATE telemetry_events SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;

ALTER TABLE telemetry_public_keys ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE telemetry_event_ids ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE telemetry_buffer ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE telemetry_chain_heads ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE telemetry_events ALTER COLUMN organization_id SET NOT NULL;

DO $$ BEGIN
  ALTER TABLE telemetry_public_keys
    ADD CONSTRAINT telemetry_public_keys_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organizations(id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  ALTER TABLE telemetry_event_ids
    ADD CONSTRAINT telemetry_event_ids_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organizations(id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  ALTER TABLE telemetry_buffer
    ADD CONSTRAINT telemetry_buffer_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organizations(id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  ALTER TABLE telemetry_chain_heads
    ADD CONSTRAINT telemetry_chain_heads_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organizations(id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  ALTER TABLE telemetry_events
    ADD CONSTRAINT telemetry_events_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organizations(id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE telemetry_public_keys DROP CONSTRAINT IF EXISTS telemetry_public_keys_pkey;
ALTER TABLE telemetry_public_keys
  ADD CONSTRAINT telemetry_public_keys_pkey PRIMARY KEY (organization_id, key_id);
ALTER TABLE telemetry_chain_heads DROP CONSTRAINT IF EXISTS telemetry_chain_heads_pkey;
ALTER TABLE telemetry_chain_heads
  ADD CONSTRAINT telemetry_chain_heads_pkey PRIMARY KEY (organization_id, key_id);

ALTER TABLE telemetry_buffer DROP CONSTRAINT IF EXISTS telemetry_buffer_event_id_fkey;
ALTER TABLE telemetry_events DROP CONSTRAINT IF EXISTS telemetry_events_event_id_fkey;
ALTER TABLE telemetry_buffer DROP CONSTRAINT IF EXISTS telemetry_buffer_event_id_key;
ALTER TABLE telemetry_events DROP CONSTRAINT IF EXISTS telemetry_events_event_id_key;
ALTER TABLE telemetry_event_ids DROP CONSTRAINT IF EXISTS telemetry_event_ids_pkey;
ALTER TABLE telemetry_event_ids
  ADD CONSTRAINT telemetry_event_ids_pkey PRIMARY KEY (organization_id, event_id);
ALTER TABLE telemetry_buffer
  ADD CONSTRAINT telemetry_buffer_event_id_key UNIQUE (organization_id, event_id);
ALTER TABLE telemetry_events
  ADD CONSTRAINT telemetry_events_event_id_key UNIQUE (organization_id, event_id);
ALTER TABLE telemetry_buffer
  ADD CONSTRAINT telemetry_buffer_event_id_fkey
  FOREIGN KEY (organization_id, event_id)
  REFERENCES telemetry_event_ids(organization_id, event_id);
ALTER TABLE telemetry_events
  ADD CONSTRAINT telemetry_events_event_id_fkey
  FOREIGN KEY (organization_id, event_id)
  REFERENCES telemetry_event_ids(organization_id, event_id);

CREATE INDEX IF NOT EXISTS telemetry_buffer_tenant_chain_order_idx
  ON telemetry_buffer (organization_id, key_id, event_timestamp, received_at, id);
CREATE INDEX IF NOT EXISTS telemetry_events_tenant_chain_idx
  ON telemetry_events (organization_id, key_id, chain_sequence);
CREATE INDEX IF NOT EXISTS telemetry_events_organization_timestamp_idx
  ON telemetry_events (organization_id, event_timestamp DESC);
