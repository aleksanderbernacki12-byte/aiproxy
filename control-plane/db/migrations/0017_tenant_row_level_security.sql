-- Tenant isolation as defence in depth against a query that forgets its
-- organization filter. The application switches to aiproxy_app on every
-- connection (superusers bypass row-level security), so policies apply
-- whatever user the deployment connects with. Not FORCE: the owner, which
-- runs migrations and the operator CLI scripts, is unaffected.

DO $$ BEGIN
  CREATE ROLE aiproxy_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

GRANT aiproxy_app TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO aiproxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aiproxy_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aiproxy_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aiproxy_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO aiproxy_app;

CREATE OR REPLACE FUNCTION aiproxy_tenant_visible(organization uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT current_setting('aiproxy.cross_tenant', true) = 'on'
    OR organization = nullif(current_setting('aiproxy.organization_id', true), '')::uuid
$$;

DO $$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY['ai_systems', 'compliance_reports', 'dpo_access_keys',
    'organization_retention_policies', 'security_audit_checkpoints', 'security_audit_events',
    'security_audit_heads', 'telemetry_buffer', 'telemetry_chain_heads', 'telemetry_event_ids',
    'telemetry_events', 'telemetry_merkle_checkpoints', 'telemetry_public_keys', 'telemetry_tombstones',
    'telemetry_verification_runs', 'tenant_access_keys'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', tenant_table);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (aiproxy_tenant_visible(organization_id)) '
      'WITH CHECK (aiproxy_tenant_visible(organization_id))', tenant_table);
  END LOOP;
END $$;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON organizations;
CREATE POLICY tenant_isolation ON organizations
  USING (aiproxy_tenant_visible(id)) WITH CHECK (aiproxy_tenant_visible(id));
