import process from "node:process";
import pg from "pg";

const [, , organizationId, keyId, ...reasonParts] = process.argv;
const reason = reasonParts.join(" ").trim();
if (!organizationId || !/^[a-f0-9]{64}$/.test(keyId ?? "") || !reason || reason.length > 240) {
  throw new Error("Usage: npm run keys:revoke -- <organization-id> <key-id> <reason-up-to-240-chars>");
}
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  const result = await client.query(
    `UPDATE telemetry_public_keys SET revoked_at = now(), revoked_reason = $3
     WHERE organization_id = $1 AND key_id = $2 AND revoked_at IS NULL RETURNING key_id`,
    [organizationId, keyId, reason],
  );
  if (result.rowCount !== 1) throw new Error("Active telemetry key not found");
  console.log(`Immediately revoked telemetry key ${keyId}`);
} finally { await client.end(); }
