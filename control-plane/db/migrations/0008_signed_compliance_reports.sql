CREATE TABLE IF NOT EXISTS compliance_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  generated_by uuid NOT NULL REFERENCES dpo_access_keys(id),
  payload jsonb NOT NULL,
  payload_hash varchar(64) NOT NULL,
  signature_algorithm varchar(32) NOT NULL,
  signing_key_id varchar(64) NOT NULL,
  signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS compliance_reports_organization_created_idx
  ON compliance_reports (organization_id, created_at DESC, id DESC);
