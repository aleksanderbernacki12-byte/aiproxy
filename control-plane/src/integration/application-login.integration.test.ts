import { createHash, randomUUID } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { sql } from "drizzle-orm";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { aiSystems } from "@/db/schema";
import { ensureApplicationLogin } from "../../scripts/lib/application-login.mjs";

vi.mock("server-only", () => ({}));

const owner = new pg.Client({ connectionString: process.env.DATABASE_URL });
const organizationA = randomUUID();
const organizationB = randomUUID();
const password = randomUUID().replaceAll("-", "");
let loginRole = "";

function loginUrl(loginPassword: string) {
  const url = new URL(process.env.DATABASE_URL ?? "");
  url.username = loginRole;
  url.password = loginPassword;
  return url.toString();
}

async function connectAsLogin(loginPassword: string) {
  const client = new pg.Client({ connectionString: loginUrl(loginPassword) });
  await client.connect();
  return client;
}

describe("application login role", () => {
  beforeAll(async () => {
    await owner.connect();
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) await owner.query(await readFile(resolve("db/migrations", migration), "utf8"));
    for (const organizationId of [organizationA, organizationB]) {
      await owner.query(`INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
        [organizationId, "Login Organization", createHash("sha256").update(randomUUID()).digest("hex")]);
      await owner.query(
        `INSERT INTO ai_systems (organization_id, application_id, model, name, provider, intended_purpose,
           risk_class, system_owner, legal_basis, human_oversight)
         VALUES ($1, 'login', 'm', 'Login system', 'p', 'Testing the login role', 'MINIMAL', 'Owner', 'Legitimate interest', 'Reviewer')`,
        [organizationId]);
    }
    loginRole = await ensureApplicationLogin(owner, password);
  });

  afterAll(async () => {
    const pool = (globalThis as typeof globalThis & { aiproxyPool?: { end(): Promise<void> } }).aiproxyPool;
    await pool?.end();
    await owner.query(`DELETE FROM ai_systems WHERE organization_id = ANY($1::uuid[])`, [[organizationA, organizationB]]);
    await owner.query(`DELETE FROM organizations WHERE id = ANY($1::uuid[])`, [[organizationA, organizationB]]);
    await owner.query(`DROP ROLE IF EXISTS ${owner.escapeIdentifier(loginRole)}`);
    await owner.end();
    vi.unstubAllEnvs();
  });

  it("denies every table without the switch to the application role", async () => {
    const client = await connectAsLogin(password);
    try {
      await expect(client.query("SELECT count(*) FROM ai_systems")).rejects.toThrow(/permission denied/);
      await expect(client.query("SELECT count(*) FROM organizations")).rejects.toThrow(/permission denied/);
    } finally {
      await client.end();
    }
  });

  it("runs the application with tenant isolation", async () => {
    vi.stubEnv("DATABASE_URL", loginUrl(password));
    const { withOrganization } = await import("@/db/client");
    const { applicationRoleActive } = await import("@/lib/readiness");
    expect(await applicationRoleActive()).toBe(true);
    const visible = await withOrganization(organizationA, (transaction) =>
      transaction.select({ organizationId: aiSystems.organizationId }).from(aiSystems)
        .where(sql`${aiSystems.applicationId} = 'login'`));
    expect(visible).toEqual([{ organizationId: organizationA }]);
  });

  it("rotates the password on a second run", async () => {
    const rotated = randomUUID().replaceAll("-", "");
    expect(await ensureApplicationLogin(owner, rotated)).toBe(loginRole);
    await expect(connectAsLogin(password)).rejects.toThrow(/password authentication failed/);
    const client = await connectAsLogin(rotated);
    await client.end();
  });

  it("refuses to take over an unrelated role with the same name", async () => {
    await owner.query(`DROP ROLE ${owner.escapeIdentifier(loginRole)}`);
    await owner.query(`CREATE ROLE ${owner.escapeIdentifier(loginRole)} NOLOGIN`);
    await expect(ensureApplicationLogin(owner, password)).rejects.toThrow(/is not this database's login role/);
  });

  it("rejects a short password", async () => {
    await expect(ensureApplicationLogin(owner, "too-short")).rejects.toThrow(/at least 32/);
  });
});
