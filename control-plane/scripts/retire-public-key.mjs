import process from "node:process";
import pg from "pg";

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
  const result = await client.query(
    `UPDATE telemetry_public_keys
     SET valid_until = $3
     WHERE organization_id = $1 AND key_id = $2 AND revoked_at IS NULL
       AND (valid_from IS NULL OR valid_from < $3)
     RETURNING key_id`,
    [organizationId, keyId, validUntil.toISOString()],
  );
  if (result.rowCount !== 1) throw new Error("Active telemetry key not found or invalid retirement time");
  console.log(`Telemetry key ${keyId} accepts events timestamped before ${validUntil.toISOString()}`);
} finally { await client.end(); }
