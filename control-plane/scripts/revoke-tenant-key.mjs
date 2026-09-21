import process from "node:process";
import pg from "pg";
import { appendSecurityAudit } from "./lib/security-audit.mjs";

const [, , organizationId, credentialId] = process.argv;
if (!organizationId || !credentialId) throw new Error("Usage: npm run tenant-keys:revoke -- <organization-id> <credential-id>");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  await client.query("BEGIN");
  const result = await client.query(
    `UPDATE tenant_access_keys SET revoked_at=now()
     WHERE organization_id=$1 AND id=$2 AND revoked_at IS NULL RETURNING id`,
    [organizationId, credentialId],
  );
  if (result.rowCount !== 1) throw new Error("Active tenant credential not found");
  await appendSecurityAudit(client, { organizationId, action: "TENANT_CREDENTIAL_REVOKED", resourceType: "TENANT_CREDENTIAL", resourceId: credentialId });
  await client.query("COMMIT");
  console.log(`Revoked tenant credential: ${credentialId}`);
} catch (error) { await client.query("ROLLBACK").catch(() => undefined); throw error; }
finally { await client.end(); }
