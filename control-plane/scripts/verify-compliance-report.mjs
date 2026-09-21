import { createHash, createPublicKey, verify } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import process from "node:process";
import canonicalize from "canonicalize";

const [, , reportPath, publicKeyPath] = process.argv;
if (!reportPath || !publicKeyPath) throw new Error("Usage: npm run reports:verify -- <sealed-report.json> <public-key.pem>");
const reportInfo = await lstat(reportPath);
const keyInfo = await lstat(publicKeyPath);
if (!reportInfo.isFile() || reportInfo.isSymbolicLink() || reportInfo.size > 10 * 1024 * 1024) throw new Error("Report must be a regular file no larger than 10 MiB");
if (!keyInfo.isFile() || keyInfo.isSymbolicLink()) throw new Error("Public key must be a regular file");

const report = JSON.parse(await readFile(reportPath, "utf8"));
const expectedFields = ["created_at", "payload", "payload_hash", "report_id", "signature", "signature_algorithm", "signing_key_id"];
if (!report || typeof report !== "object" || Array.isArray(report) || Object.keys(report).sort().join() !== expectedFields.join()) throw new Error("Report envelope has unexpected fields");
if (!report.payload || typeof report.payload !== "object" || Array.isArray(report.payload)) throw new Error("Report payload is invalid");
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(report.report_id) || !/^[a-f0-9]{64}$/.test(report.payload_hash) || !/^[a-f0-9]{64}$/.test(report.signing_key_id)) throw new Error("Report identifiers are invalid");
if (report.signature_algorithm !== "Ed25519" || !/^[A-Za-z0-9+/]+={0,2}$/.test(report.signature)) throw new Error("Report signature metadata is invalid");
if (typeof report.created_at !== "string" || Number.isNaN(Date.parse(report.created_at))) throw new Error("Report timestamp is invalid");

const canonical = canonicalize(report.payload);
if (!canonical) throw new Error("Report payload cannot be canonicalized");
const canonicalBytes = Buffer.from(canonical);
const payloadHash = createHash("sha256").update(canonicalBytes).digest("hex");
if (payloadHash !== report.payload_hash) throw new Error("Report payload hash does not match");
const publicKey = createPublicKey(await readFile(publicKeyPath, "utf8"));
if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Public key must be Ed25519");
const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
if (keyId !== report.signing_key_id) throw new Error("Signing key fingerprint does not match");
const signingBytes = Buffer.concat([Buffer.from("aiproxy-compliance-report-v1\0"), canonicalBytes]);
if (!verify(null, signingBytes, publicKey, Buffer.from(report.signature, "base64"))) throw new Error("Report signature is invalid");

console.log(`VERIFIED report ${report.report_id}`);
console.log(`Payload SHA-256: ${report.payload_hash}`);
console.log(`Signing key ID: ${report.signing_key_id}`);
