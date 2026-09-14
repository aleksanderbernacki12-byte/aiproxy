import {
  createHash,
  createPublicKey,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import process from "node:process";
import pg from "pg";

const [, , filename, label = null] = process.argv;
if (!filename) {
  throw new Error("Usage: npm run keys:register -- <public-key.pem> [label]");
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
    `INSERT INTO telemetry_public_keys(key_id, public_key_pem, label)
     VALUES ($1, $2, $3)
     ON CONFLICT (key_id) DO UPDATE
     SET public_key_pem = EXCLUDED.public_key_pem,
         label = EXCLUDED.label`,
    [keyId, publicKeyPem, label],
  );
  console.log(`Registered telemetry key ${keyId}`);
} finally {
  await client.end();
}
