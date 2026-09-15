import { createHash, randomBytes } from "node:crypto";
import process from "node:process";
import pg from "pg";
import { appendSecurityAudit } from "./lib/security-audit.mjs";

const [, , organizationId, label, expiresAtInput] = process.argv;
if (!organizationId || !label?.trim()) throw new Error("Usage: npm run tenant-keys:create -- <organization-id> <label> [expires-at-ISO]");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
if (label.length > 160) throw new Error("label must contain at most 160 characters");
const expiresAt = expiresAtInput ? new Date(expiresAtInput) : null;
if (expiresAt && (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date())) throw new Error("expires-at must be a future ISO timestamp");
const key = randomBytes(32).toString("base64url");
const digest = createHash("sha256").update(key).digest("hex");
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  await client.query("BEGIN");
  const result = await client.query(
    `INSERT INTO tenant_access_keys (organization_id, key_hash, label, expires_at)
     VALUES ($1,$2,$3,$4) RETURNING id`,
    [organizationId, digest, label.trim(), expiresAt?.toISOString() ?? null],
  );
  await appendSecurityAudit(client, { organizationId, action: "TENANT_CREDENTIAL_CREATED", resourceType: "TENANT_CREDENTIAL", resourceId: result.rows[0].id, metadata: { label: label.trim(), expires_at: expiresAt?.toISOString() ?? null } });
  await client.query("COMMIT");
  console.log(`Tenant credential ID: ${result.rows[0].id}`);
  console.log(`AIPROXY_TENANT_KEY: ${key}`);
  console.log("Store this key now; the Control Plane retains only its SHA-256 digest.");
} catch (error) { await client.query("ROLLBACK").catch(() => undefined); throw error; }
finally { await client.end(); }
