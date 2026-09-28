# Tenant Row-Level Security — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A query that forgets its organization filter sees and changes nothing outside its own tenant.

**Architecture:** Migration 0017 (role `aiproxy_app`, `aiproxy_tenant_visible()`, `tenant_isolation` policies); pools that `SET ROLE aiproxy_app`; `withOrganization()` for request paths and `getCrossTenantDatabase()` for key lookups and jobs. Spec: `docs/superpowers/specs/2026-09-28-tenant-row-level-security-design.md`. Branch: `feat/tenant-rls`.

Verification (in `control-plane/`, disposable PostgreSQL as `TEST_DATABASE_URL`): `npm run lint && npm test && npm run typecheck && npm run test:integration && npm run build && npm run test:e2e`.

---

### Task 1: Failing isolation test

- [ ] `src/integration/tenant-isolation.integration.test.ts` per the spec's Testing section (organizations A and B, one `ai_systems` row each, inserted with the raw superuser client; cleanup under the raw client).
- [ ] Run: fails (`withOrganization`/`getCrossTenantDatabase` do not exist).

### Task 2: Migration and client

- [ ] `db/migrations/0017_tenant_row_level_security.sql` per spec. Policies created with `DROP POLICY IF EXISTS` first (migrations are re-applied by the integration tests).
- [ ] `src/db/client.ts`: shared pool factory with a `connect` hook running `SET ROLE aiproxy_app` (plus `SET aiproxy.cross_tenant = 'on'` for the cross-tenant pool, max 5 connections); `getDatabase`, `getCrossTenantDatabase`, `withOrganization`; export a `Database` type usable for both the database and a transaction.
- [ ] `src/lib/readiness.ts`: `expectedMigration` → 0017; README line.
- [ ] Isolation test passes; the rest of the suite now fails where paths lack context (expected, fixed in Task 3).

### Task 3: Convert paths

- [ ] Cross-tenant pool: `tenant-auth.ts`, `dpo-auth.authenticateDPOAccessKey`, `telemetry/worker.ts`, `telemetry/checkpoint.ts`, `telemetry/anchor.ts`, `telemetry/verification.ts`, `retention.enforceRetentionPolicies`/`purgeOrganization`, `operations.ts`, `security-audit-checkpoint.ts`.
- [ ] `withOrganization`: `dashboard.getDashboardData`, `compliance-report.*`, `ai-systems.*`, `access-admin.*`, `retention-admin.*`, `retention.getRetentionPolicy`, `security-audit.*`, `telemetry/ingest.bufferTelemetryEvents`, `dpo-auth.validateDPOIdentity`. Functions already running in a transaction switch `getDatabase().transaction(` to `withOrganization(organizationId, `.
- [ ] Unit tests that mock `@/db/client` add `getCrossTenantDatabase`/`withOrganization` mocks.
- [ ] Full verification green.
- [ ] Commit `feat(control-plane): enforce tenant isolation with row-level security`.

### Task 4: Docs

- [ ] README: tenant isolation section (policies, role, contexts, scripts run as owner and are unaffected, what it does not protect against). Review doc: finding 5 addressed.
- [ ] Commit `docs: describe tenant row-level security`.
