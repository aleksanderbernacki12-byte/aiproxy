import { createHash, randomBytes } from "node:crypto";
import process from "node:process";
import pg from "pg";

const [, , name, suppliedTenantKey] = process.argv;
if (!name) {
  throw new Error("Usage: npm run orgs:create -- <name> [tenant-key]");
}
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}
const tenantKey = suppliedTenantKey || randomBytes(32).toString("base64url");
if (tenantKey.length < 32 || /\s/.test(tenantKey)) {
  throw new Error("tenant-key must contain at least 32 non-whitespace characters");
}
const tenantKeyDigest = createHash("sha256").update(tenantKey, "utf8").digest("hex");
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });

try {
  await client.connect();
  const result = await client.query(
    `INSERT INTO organizations(name, tenant_key)
     VALUES ($1, $2)
     RETURNING id`,
    [name, tenantKeyDigest],
  );
  console.log(`Organization ID: ${result.rows[0].id}`);
  console.log(`AIPROXY_TENANT_KEY: ${tenantKey}`);
  console.log("Store this key now; the control plane retains only its SHA-256 digest.");
} finally {
  await client.end();
}
