DO $$ BEGIN
  CREATE TYPE ai_risk_class AS ENUM ('UNCLASSIFIED', 'MINIMAL', 'LIMITED', 'HIGH', 'PROHIBITED');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE ai_system_status AS ENUM ('ACTIVE', 'SUSPENDED', 'RETIRED');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS ai_systems (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  application_id varchar(160) NOT NULL,
  model varchar(160) NOT NULL,
  name varchar(200) NOT NULL,
  provider varchar(160),
  intended_purpose text NOT NULL,
  risk_class ai_risk_class NOT NULL DEFAULT 'UNCLASSIFIED',
  system_owner varchar(200) NOT NULL,
  legal_basis text NOT NULL,
  human_oversight text NOT NULL,
  data_categories jsonb NOT NULL DEFAULT '[]'::jsonb,
  deployment_regions jsonb NOT NULL DEFAULT '[]'::jsonb,
  status ai_system_status NOT NULL DEFAULT 'ACTIVE',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, application_id, model)
);

CREATE INDEX IF NOT EXISTS ai_systems_organization_risk_idx
  ON ai_systems (organization_id, risk_class, status);
