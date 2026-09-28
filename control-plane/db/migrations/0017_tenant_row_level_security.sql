-- Tenant isolation as defence in depth against a query that forgets its
-- organization filter. Not FORCE: the owner, which runs migrations and the
-- operator CLI scripts, is unaffected. The restricted role the application
-- runs as is created per database by 0019 (roles are cluster-wide, so a
-- shared role cannot be granted by a second database's owner).

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
