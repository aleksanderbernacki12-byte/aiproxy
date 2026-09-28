-- The application runs as a restricted role so row-level security (0017)
-- applies even when the deployment connects as a superuser. Roles are
-- cluster-wide and only their creator may grant them, so each database gets
-- its own role, named from a hash of the database name; src/db/client.ts
-- derives the same name.

DO $$
DECLARE
  app_role text := 'aiproxy_app_' || left(md5(current_database()), 12);
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app_role) THEN
    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS', app_role);
  END IF;
  -- Unconditional: since PostgreSQL 16 a CREATEROLE creator is a member
  -- with ADMIN but without SET, which SET ROLE needs; this grant adds it.
  EXECUTE format('GRANT %I TO %I', app_role, current_user);
  EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', app_role);
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', app_role);
  EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', app_role);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', app_role);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I', app_role);
END $$;
