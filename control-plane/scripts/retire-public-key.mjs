import process from "node:process";
import pg from "pg";
import { appendSecurityAudit } from "./lib/security-audit.mjs";

const [, , organizationId, keyId, validUntilInput] = process.argv;
if (!organizationId || !/^[a-f0-9]{64}$/.test(keyId ?? "")) {
  throw new Error("Usage: npm run keys:retire -- <organization-id> <key-id> [valid-until-ISO]");
}
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const validUntil = validUntilInput ? new Date(validUntilInput) : new Date();
if (Number.isNaN(validUntil.getTime())) throw new Error("valid-until must be an ISO timestamp");

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  await client.query("BEGIN");
  const result = await client.query(
    `UPDATE telemetry_public_keys
     SET valid_until = $3
     WHERE organization_id = $1 AND key_id = $2 AND revoked_at IS NULL
       AND (valid_from IS NULL OR valid_from < $3)
     RETURNING key_id`,
    [organizationId, keyId, validUntil.toISOString()],
  );
  if (result.rowCount !== 1) throw new Error("Active telemetry key not found or invalid retirement time");
  await appendSecurityAudit(client, { organizationId, action: "TELEMETRY_KEY_RETIRED", resourceType: "TELEMETRY_KEY", resourceId: keyId, metadata: { valid_until: validUntil.toISOString() } });
  await client.query("COMMIT");
  console.log(`Telemetry key ${keyId} accepts events timestamped before ${validUntil.toISOString()}`);
} catch (error) { await client.query("ROLLBACK").catch(() => undefined); throw error; }
finally { await client.end(); }
