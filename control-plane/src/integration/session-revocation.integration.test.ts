import { createHash, randomUUID } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
const organizationId = randomUUID();
const credentialId = randomUUID();

describe("server-side dashboard logout", () => {
  beforeAll(async () => {
    await client.connect();
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
    await client.query(`INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
      [organizationId, "Logout Organization", createHash("sha256").update(randomUUID()).digest("hex")]);
    await client.query(`INSERT INTO dpo_access_keys (id, organization_id, key_hash, label, role) VALUES ($1, $2, $3, 'Logout DPO', 'DPO')`,
      [credentialId, organizationId, createHash("sha256").update(randomUUID()).digest("hex")]);
  });

  afterAll(async () => {
    await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'on', false)`);
    for (const table of ["security_audit_events", "security_audit_heads", "dpo_access_keys"]) {
      await client.query(`DELETE FROM ${table} WHERE organization_id = $1`, [organizationId]);
    }
    await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'off', false)`);
    await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
    await client.end();
  });

  it("ends every session of the access key and records it", async () => {
    const { endDPOSessions, validateDPOIdentity } = await import("@/lib/dpo-auth");
    const session = { credentialId, organizationId, role: "DPO" as const, sessionVersion: 0 };
    expect(await validateDPOIdentity(session)).toBe(true);

    await endDPOSessions(session);

    expect(await validateDPOIdentity(session)).toBe(false);
    expect(await validateDPOIdentity({ ...session, sessionVersion: 1 })).toBe(true);
    const audit = await client.query(
      `SELECT count(*)::integer AS count FROM security_audit_events
       WHERE organization_id = $1 AND event_data->>'action' = 'DASHBOARD_SESSION_ENDED'`,
      [organizationId],
    );
    expect(audit.rows[0].count).toBe(1);
  });
});
