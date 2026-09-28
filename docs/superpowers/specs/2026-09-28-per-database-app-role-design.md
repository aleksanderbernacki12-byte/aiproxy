# Per-database application role

Date: 2026-09-28
Status: decided (owner delegated, 2026-09-28)

## Problem

Migration 0017 (v0.77.0) creates the cluster-wide role `aiproxy_app` and runs
`GRANT aiproxy_app TO CURRENT_USER`. PostgreSQL roles are cluster-wide and only
the role's creator (or a superuser) may grant it. A second database in the same
cluster with a different owner (staging next to production, several managed
databases on one cluster) therefore fails at 0017 with `permission denied to
grant role "aiproxy_app"`, and cannot be deployed. Verified on PostgreSQL 17
with two non-superuser owners holding `CREATEROLE`.

## Design

- Each database gets its own role: `aiproxy_app_` followed by the first 12 hex
  characters of `md5(current_database())` (always a valid, short name).
- Migration 0017 keeps only the policy function and policies. Role creation,
  membership and grants move to new migration `0019_per_database_app_role.sql`,
  written idempotently. A database that already ran the old 0017 gets its
  per-database role from 0019; the old shared `aiproxy_app` stays unused.
- `src/db/client.ts` selects the role with
  `set_config('role', 'aiproxy_app_' || left(md5(current_database()), 12), …)`
  on connect (session) and in `withOrganization` (transaction).
- `scripts/run-e2e.mjs` drops the per-database role of its throwaway database
  after dropping the database, so local runs do not accumulate roles.
- Readiness requires 0019.

## Verification

- Two databases with different non-superuser owners (`CREATEROLE`) in one
  cluster both migrate, and the integration and browser suites pass against
  each.
- The integration test asserts the current user matches `aiproxy_app_%` and
  is not the connecting owner.
- The superuser test database (CI) passes unchanged.
