import { createHash, randomUUID } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { sql } from "drizzle-orm";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { aiSystems, organizations } from "@/db/schema";

vi.mock("server-only", () => ({}));

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
const organizationA = randomUUID();
const organizationB = randomUUID();

function aiSystem(organizationId: string) {
  return {
    organizationId, applicationId: "isolation", model: "m", name: "Isolation system", provider: "p",
    intendedPurpose: "Testing tenant isolation", riskClass: "MINIMAL" as const, systemOwner: "Owner",
    legalBasis: "Legitimate interest", humanOversight: "Reviewer",
  };
}

// drizzle wraps the PostgreSQL error; the database's own message is the cause.
async function databaseError(work: Promise<unknown>) {
  try {
    await work;
  } catch (error) {
    return error instanceof Error && error.cause instanceof Error ? error.cause.message : String(error);
  }
  return "no error";
}

async function insertAISystem(organizationId: string) {
  await client.query(
    `INSERT INTO ai_systems (organization_id, application_id, model, name, provider, intended_purpose,
       risk_class, system_owner, legal_basis, human_oversight)
     VALUES ($1, 'isolation', 'm', 'Isolation system', 'p', 'Testing tenant isolation', 'MINIMAL', 'Owner', 'Legitimate interest', 'Reviewer')`,
    [organizationId],
  );
}

describe("tenant row-level security", () => {
  beforeAll(async () => {
    await client.connect();
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
    for (const organizationId of [organizationA, organizationB]) {
      await client.query(`INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
        [organizationId, "Isolation Organization", createHash("sha256").update(randomUUID()).digest("hex")]);
      await insertAISystem(organizationId);
    }
  });

  afterAll(async () => {
    await client.query(`DELETE FROM ai_systems WHERE organization_id = ANY($1::uuid[])`, [[organizationA, organizationB]]);
    await client.query(`DELETE FROM organizations WHERE id = ANY($1::uuid[])`, [[organizationA, organizationB]]);
    await client.end();
  });

  it("shows and accepts nothing without a tenant context", async () => {
    const { withoutTenant } = await import("@/db/client");
    const rows = await withoutTenant((transaction) =>
      transaction.select().from(aiSystems).where(sql`${aiSystems.applicationId} = 'isolation'`));
    expect(rows).toHaveLength(0);
    expect(await databaseError(withoutTenant((transaction) =>
      transaction.insert(aiSystems).values({ ...aiSystem(organizationA), model: "no-context" }))))
      .toMatch(/row-level security/);
  });

  it("confines an unfiltered query to the organization in context", async () => {
    const { withOrganization } = await import("@/db/client");
    const visible = await withOrganization(organizationA, (transaction) =>
      transaction.select({ organizationId: aiSystems.organizationId }).from(aiSystems));
    expect(visible).toEqual([{ organizationId: organizationA }]);
    const visibleOrganizations = await withOrganization(organizationA, (transaction) =>
      transaction.select({ id: organizations.id }).from(organizations));
    expect(visibleOrganizations).toEqual([{ id: organizationA }]);
    expect(await databaseError(withOrganization(organizationA, (transaction) =>
      transaction.insert(aiSystems).values({ ...aiSystem(organizationB), model: "cross-write" }))))
      .toMatch(/row-level security/);
  });

  it("lets cross-tenant jobs see every organization", async () => {
    const { withCrossTenant } = await import("@/db/client");
    const rows = await withCrossTenant((transaction) => transaction.select({ organizationId: aiSystems.organizationId })
      .from(aiSystems).where(sql`${aiSystems.applicationId} = 'isolation'`));
    expect(rows.map((row) => row.organizationId).sort()).toEqual([organizationA, organizationB].sort());
  });

  // A transaction-mode pooler (pgbouncer) hands the same server connection to
  // the next client, including session state someone else left on it.
  it("ignores tenant context left on the connection", async () => {
    const { withCrossTenant, withOrganization, withoutTenant } = await import("@/db/client");
    // Sequential use reuses one pooled connection; leave cross-tenant on for its session.
    await withoutTenant((transaction) => transaction.execute(sql`SELECT set_config('aiproxy.cross_tenant', 'on', false),
      set_config('aiproxy.organization_id', ${organizationB}, false)`));
    try {
      const unscoped = await withoutTenant((transaction) =>
        transaction.select().from(aiSystems).where(sql`${aiSystems.applicationId} = 'isolation'`));
      expect(unscoped).toHaveLength(0);
      const scoped = await withOrganization(organizationA, (transaction) =>
        transaction.select({ organizationId: aiSystems.organizationId }).from(aiSystems));
      expect(scoped).toEqual([{ organizationId: organizationA }]);
    } finally {
      await withCrossTenant((transaction) => transaction.execute(sql`SELECT set_config('aiproxy.cross_tenant', 'off', false),
        set_config('aiproxy.organization_id', '', false)`));
    }
  });

  it("runs application queries as the restricted role", async () => {
    const { withoutTenant } = await import("@/db/client");
    const role = await withoutTenant((transaction) => transaction.execute<{ current_user: string }>(sql`SELECT current_user`));
    const expected = await client.query<{ role: string }>(`SELECT 'aiproxy_app_' || left(md5(current_database()), 12) AS role`);
    expect(role.rows[0].current_user).toBe(expected.rows[0].role);
    const { applicationRoleActive } = await import("@/lib/readiness");
    expect(await applicationRoleActive()).toBe(true);
    expect(await databaseError(withoutTenant((transaction) => transaction.execute(sql`TRUNCATE ai_systems`)))).toMatch(/permission denied/);
  });
});
