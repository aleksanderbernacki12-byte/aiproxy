# Tenant row-level security (Control Plane finding 5)

Date: 2026-09-28
Status: approved direction (owner chose session context, 2026-09-28)

## Purpose

Finding 5 of `docs/reviews/2026-09-28-control-plane-review.md`: tenant
isolation exists only in application code. Every reviewed query filters on
`organization_id`, but one future query without the filter would read or write
another customer's rows. This adds PostgreSQL row-level security as defence in
depth against that code mistake. It does not defend against an attacker who
can run arbitrary SQL (they can reset the role); separate database roles would
be the follow-up for that.

## Design

### Database (migration `0017_tenant_row_level_security.sql`)

- Role `aiproxy_app` (`NOLOGIN`, not superuser, no `BYPASSRLS`), created if
  missing, granted to the migrating user, with `USAGE` on schema `public`,
  `SELECT, INSERT, UPDATE, DELETE` on all tables, `USAGE, SELECT` on all
  sequences, and matching default privileges for later migrations. No
  `TRUNCATE`.
- Function `aiproxy_tenant_visible(organization uuid)`: true when
  `current_setting('aiproxy.cross_tenant', true) = 'on'`, or when
  `organization` equals `current_setting('aiproxy.organization_id', true)`.
- `ENABLE ROW LEVEL SECURITY` and one policy `tenant_isolation`
  (`USING` and `WITH CHECK` `aiproxy_tenant_visible(organization_id)`) on the
  16 tables with `organization_id`, and on `organizations` with `id`. Not
  `FORCE`: the owner (migrations and the operator CLI scripts) is unaffected.
- `report_signing_keys`, `dashboard_login_attempts` and
  `control_plane_migrations` hold no tenant data and stay without RLS.

### Application (`src/db/client.ts`)

Superusers bypass RLS even with `FORCE`, and the compose deployment connects
as the PostgreSQL superuser. Both pools therefore run `SET ROLE aiproxy_app`
on every new connection, so RLS applies whatever user the deployment connects
with.

- `getDatabase()`: the default pool. No tenant context, so tenant tables return
  no rows and reject writes. Used only for the global tables (login throttle,
  readiness).
- `withOrganization(organizationId, work)`: a transaction on the default pool
  that first sets `aiproxy.organization_id` for that transaction; `work`
  receives the transaction. Every request-driven tenant path uses it:
  dashboard, compliance reports, AI systems, access administration, retention
  administration and policy reads, security-audit append and evidence,
  telemetry ingest, DPO identity validation.
- `getCrossTenantDatabase()`: a second, smaller pool whose connections also
  set `aiproxy.cross_tenant = 'on'` for the session. Used only by code that is
  cross-tenant by nature: tenant and DPO key lookups by hash (the organization
  is not known yet), and the internal jobs (telemetry worker, checkpoints,
  anchoring, retention enforcement, re-verification, operations metrics,
  security-audit checkpoints).

Nested transactions inside `withOrganization` become savepoints and keep the
setting.

## Testing

Integration (`tenant-isolation.integration.test.ts`, two organizations with an
AI system each):

- `getDatabase()` without context: selecting `ai_systems` returns 0 rows;
  inserting one is rejected.
- `withOrganization(A)`: an unfiltered `select().from(aiSystems)` returns only
  A's row; inserting a row for B is rejected; `organizations` shows only A.
- `getCrossTenantDatabase()`: sees both rows.
- The role actually applies: `SELECT current_user` in the default pool is
  `aiproxy_app`, and it cannot `TRUNCATE`.
- The existing integration, recovery and browser tests pass unchanged, which
  proves every converted path still sets its context.

Unit tests that mock `@/db/client` add the new exports.
