import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
const organizationId = randomUUID();

describe("external anchor queue", () => {
  beforeAll(async () => {
    await client.connect();
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
    await client.query(`INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
      [organizationId, "Anchor Queue Organization", createHash("sha256").update(randomUUID()).digest("hex")]);
  });

  afterAll(async () => {
    await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'on', false)`);
    await client.query(`DELETE FROM telemetry_merkle_checkpoints WHERE organization_id = $1`, [organizationId]);
    await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'off', false)`);
    await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
    await client.end();
    vi.unstubAllEnvs();
  });

  it("keeps retrying failing checkpoints without blocking newer ones", async () => {
    for (let index = 0; index < 5; index += 1) {
      await client.query(
        `INSERT INTO telemetry_merkle_checkpoints (organization_id, root_hash, leaf_count, chain_heads, anchor_attempts, created_at)
         VALUES ($1, $2, 1, '[]'::jsonb, 50, now() - interval '1 day')`,
        [organizationId, String(index).repeat(64)],
      );
    }
    const fresh = await client.query<{ id: string }>(
      `INSERT INTO telemetry_merkle_checkpoints (organization_id, root_hash, leaf_count, chain_heads)
       VALUES ($1, $2, 1, '[]'::jsonb) RETURNING id::text AS id`,
      [organizationId, "f".repeat(64)],
    );
    vi.stubEnv("MERKLE_ANCHOR_URL", "https://anchor.test/v1/checkpoints");
    vi.stubEnv("MERKLE_ANCHOR_TOKEN", "t".repeat(32));
    vi.stubEnv("MERKLE_ANCHOR_PUBLIC_KEY", generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString());
    const attempted: string[] = [];
    const fetcher = async (_input: string | URL | Request, init?: RequestInit) => {
      attempted.push((JSON.parse(String(init?.body)) as { checkpoint_id: string }).checkpoint_id);
      return new Response("unavailable", { status: 503 });
    };

    const { anchorPendingCheckpoints } = await import("@/lib/telemetry/anchor");
    await anchorPendingCheckpoints(fetcher);
    expect(attempted).toContain(fresh.rows[0].id);
  });
});
