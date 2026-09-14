import { createHash, randomBytes } from "node:crypto";
import process from "node:process";
import pg from "pg";

const [, , organizationId, label, role = "DPO", expiresAt] = process.argv;
if (!organizationId || !label || !["ADMIN", "DPO", "AUDITOR"].includes(role)) {
  throw new Error("Usage: npm run dpo:create -- <organization-id> <label> [ADMIN|DPO|AUDITOR] [expires-at-ISO]");
}
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const expiration = expiresAt ? new Date(expiresAt) : null;
if (expiration && Number.isNaN(expiration.getTime())) throw new Error("expires-at must be an ISO timestamp");
const key = randomBytes(32).toString("base64url");
const digest = createHash("sha256").update(key, "utf8").digest("hex");
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  const result = await client.query(
    `INSERT INTO dpo_access_keys (organization_id, key_hash, label, role, expires_at)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [organizationId, digest, label, role, expiration?.toISOString() ?? null],
  );
  console.log(`DPO credential ID: ${result.rows[0].id}`);
  console.log(`DPO access key: ${key}`);
  console.log("Store this key now; the control plane retains only its SHA-256 digest.");
} finally { await client.end(); }
