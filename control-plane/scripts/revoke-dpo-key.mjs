import process from "node:process";
import pg from "pg";

const [, , credentialId] = process.argv;
if (!credentialId) throw new Error("Usage: npm run dpo:revoke -- <credential-id>");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  const result = await client.query(
    `UPDATE dpo_access_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING id`,
    [credentialId],
  );
  if (result.rowCount !== 1) throw new Error("Active DPO credential not found");
  console.log(`Revoked DPO credential: ${credentialId}`);
} finally { await client.end(); }
