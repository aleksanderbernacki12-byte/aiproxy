import {
  createHash,
  createPublicKey,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import process from "node:process";
import pg from "pg";

const [, , organizationId, filename, label = null] = process.argv;
if (!organizationId || !filename) {
  throw new Error("Usage: npm run keys:register -- <organization-id> <public-key.pem> [label]");
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
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });

try {
  await client.connect();
  await client.query(
    `INSERT INTO telemetry_public_keys(organization_id, key_id, public_key_pem, label)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (organization_id, key_id) DO UPDATE
     SET public_key_pem = EXCLUDED.public_key_pem,
         label = EXCLUDED.label`,
    [organizationId, keyId, publicKeyPem, label],
  );
  console.log(`Registered telemetry key ${keyId}`);
} finally {
  await client.end();
}
