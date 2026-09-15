import { createHash, generateKeyPairSync } from "node:crypto";
import { chmod, rm, writeFile } from "node:fs/promises";
import process from "node:process";

const [, , privateKeyPath, publicKeyPath] = process.argv;
if (!privateKeyPath || !publicKeyPath || privateKeyPath === publicKeyPath) {
  throw new Error("Usage: npm run reports:keygen -- <private-key.pem> <public-key.pem>");
}

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
const publicPem = publicKey.export({ type: "spki", format: "pem" });
let publicCreated = false;
let privateCreated = false;
try {
  await writeFile(publicKeyPath, publicPem, { flag: "wx", mode: 0o644 });
  publicCreated = true;
  await chmod(publicKeyPath, 0o644);
  await writeFile(privateKeyPath, privatePem, { flag: "wx", mode: 0o600 });
  privateCreated = true;
  await chmod(privateKeyPath, 0o600);
} catch (error) {
  if (privateCreated) await rm(privateKeyPath).catch(() => undefined);
  if (publicCreated) await rm(publicKeyPath).catch(() => undefined);
  throw new Error(`Refusing to overwrite signing-key files: ${error instanceof Error ? error.message : error}`);
}
const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
console.log(`Report signing key ID: ${keyId}`);
console.log(`Private key (owner-only): ${privateKeyPath}`);
console.log(`Public verification key: ${publicKeyPath}`);
