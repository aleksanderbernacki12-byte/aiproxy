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
let transactionOpen = false;

try {
  await client.connect();
  await client.query("BEGIN");
  transactionOpen = true;
  const result = await client.query(
    `INSERT INTO organizations(name, tenant_key)
     VALUES ($1, $2)
     RETURNING id`,
    [name, tenantKeyDigest],
  );
  const credential = await client.query(
    `INSERT INTO tenant_access_keys (organization_id, key_hash, label)
     VALUES ($1, $2, 'Initial data plane key') RETURNING id`,
    [result.rows[0].id, tenantKeyDigest],
  );
  await client.query("COMMIT");
  transactionOpen = false;
  console.log(`Organization ID: ${result.rows[0].id}`);
  console.log(`Tenant credential ID: ${credential.rows[0].id}`);
  console.log(`AIPROXY_TENANT_KEY: ${tenantKey}`);
  console.log("Store this key now; the control plane retains only its SHA-256 digest.");
} finally {
  if (transactionOpen) await client.query("ROLLBACK").catch(() => undefined);
  await client.end();
}
