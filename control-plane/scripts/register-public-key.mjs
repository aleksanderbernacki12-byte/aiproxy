import {
  createHash,
  createPublicKey,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import process from "node:process";
import pg from "pg";

const [, , organizationId, filename, label = null, validFromInput] = process.argv;
if (!organizationId || !filename) {
  throw new Error("Usage: npm run keys:register -- <organization-id> <public-key.pem> [label] [valid-from-ISO]");
}
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

const publicKeyPem = await readFile(filename, "utf8");
const publicKey = createPublicKey(publicKeyPem);
if (
  publicKey.asymmetricKeyType !== "ec" ||
  publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
) {
  throw new Error("The telemetry public key must be ECDSA P-256");
}
const der = publicKey.export({ type: "spki", format: "der" });
const keyId = createHash("sha256").update(der).digest("hex");
const validFrom = validFromInput ? new Date(validFromInput) : null;
if (validFrom && Number.isNaN(validFrom.getTime())) throw new Error("valid-from must be an ISO timestamp");
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });

try {
  await client.connect();
  await client.query(
    `INSERT INTO telemetry_public_keys(organization_id, key_id, public_key_pem, label, valid_from)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (organization_id, key_id) DO UPDATE
     SET public_key_pem = EXCLUDED.public_key_pem,
         label = EXCLUDED.label,
         valid_from = COALESCE(telemetry_public_keys.valid_from, EXCLUDED.valid_from)`,
    [organizationId, keyId, publicKeyPem, label, validFrom?.toISOString() ?? null],
  );
  console.log(`Registered telemetry key ${keyId}`);
} finally {
  await client.end();
}
