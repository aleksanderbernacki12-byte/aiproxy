import { createHash, randomBytes } from "node:crypto";
import process from "node:process";
import pg from "pg";
import { appendSecurityAudit } from "./lib/security-audit.mjs";

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
  await client.query("BEGIN");
  const result = await client.query(
    `INSERT INTO dpo_access_keys (organization_id, key_hash, label, role, expires_at)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [organizationId, digest, label, role, expiration?.toISOString() ?? null],
  );
  await appendSecurityAudit(client, { organizationId, action: "DPO_CREDENTIAL_CREATED", resourceType: "DPO_CREDENTIAL", resourceId: result.rows[0].id, metadata: { label, role, expires_at: expiration?.toISOString() ?? null } });
  await client.query("COMMIT");
  console.log(`DPO credential ID: ${result.rows[0].id}`);
  console.log(`DPO access key: ${key}`);
  console.log("Store this key now; the control plane retains only its SHA-256 digest.");
} catch (error) { await client.query("ROLLBACK").catch(() => undefined); throw error; }
finally { await client.end(); }
