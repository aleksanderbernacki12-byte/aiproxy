import "server-only";

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import canonicalize from "canonicalize";
import { and, desc, eq } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { complianceReports, dpoAccessKeys, reportSigningKeys } from "@/db/schema";
import { getDashboardData } from "@/lib/dashboard";

const SIGNATURE_DOMAIN = Buffer.from("aiproxy-compliance-report-v1\0");

function canonicalPayload(payload: Record<string, unknown>) {
  const value = canonicalize(payload);
  if (!value) throw new Error("Compliance report cannot be canonicalized");
  return Buffer.from(value);
}

function reportSigningKey() {
  const configured = process.env.REPORT_SIGNING_PRIVATE_KEY?.replaceAll("\\n", "\n");
  if (!configured) throw new Error("REPORT_SIGNING_PRIVATE_KEY is required");
  const privateKey = createPrivateKey(configured);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("REPORT_SIGNING_PRIVATE_KEY must be Ed25519");
  const publicKey = createPublicKey(privateKey);
  const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  return { privateKey, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(), keyId };
}

export type SealedReport = {
  report_id: string;
  payload: Record<string, unknown>;
  payload_hash: string;
  signature_algorithm: "Ed25519";
  signing_key_id: string;
  signature: string;
  created_at: string;
};

export function verifySealedReport(report: SealedReport, publicKeyPem: string) {
  try {
    const canonical = canonicalPayload(report.payload);
    if (createHash("sha256").update(canonical).digest("hex") !== report.payload_hash) return false;
    const publicKey = createPublicKey(publicKeyPem);
    if (publicKey.asymmetricKeyType !== "ed25519") return false;
    const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
    return keyId === report.signing_key_id && report.signature_algorithm === "Ed25519" &&
      verify(null, Buffer.concat([SIGNATURE_DOMAIN, canonical]), publicKey, Buffer.from(report.signature, "base64"));
  } catch { return false; }
}

export async function sealComplianceReport(identity: { credentialId: string; organizationId: string }, now = new Date()) {
  const dashboard = await getDashboardData(identity.organizationId);
  if (!dashboard) throw new Error("Organization not found");
  const payload = JSON.parse(JSON.stringify({
    schema_version: "aiproxy-compliance-report-v1",
    generated_at: now.toISOString(),
    evidence: dashboard,
  })) as Record<string, unknown>;
  const canonical = canonicalPayload(payload);
  const payloadHash = createHash("sha256").update(canonical).digest("hex");
  const { privateKey, publicKeyPem, keyId } = reportSigningKey();
  const signature = sign(null, Buffer.concat([SIGNATURE_DOMAIN, canonical]), privateKey).toString("base64");
  const [stored] = await getDatabase().transaction(async (transaction) => {
    await transaction.insert(reportSigningKeys).values({
      keyId, publicKeyPem, firstUsedAt: now, lastUsedAt: now,
    }).onConflictDoUpdate({
      target: reportSigningKeys.keyId,
      set: { lastUsedAt: now },
    });
    return transaction.insert(complianceReports).values({
      organizationId: identity.organizationId,
      generatedBy: identity.credentialId,
      payload,
      payloadHash,
      signatureAlgorithm: "Ed25519",
      signingKeyId: keyId,
      signature,
      createdAt: now,
    }).returning({ id: complianceReports.id });
  });
  if (!stored) throw new Error("Compliance report was not stored");
  return stored.id;
}

export async function getSealedReport(reportId: string, organizationId: string): Promise<SealedReport | null> {
  const [report] = await getDatabase().select().from(complianceReports).where(and(
    eq(complianceReports.id, reportId), eq(complianceReports.organizationId, organizationId),
  )).limit(1);
  return report ? {
    report_id: report.id,
    payload: report.payload,
    payload_hash: report.payloadHash,
    signature_algorithm: "Ed25519",
    signing_key_id: report.signingKeyId,
    signature: report.signature,
    created_at: report.createdAt.toISOString(),
  } : null;
}

export async function listSealedReports(organizationId: string, limit = 100) {
  return getDatabase().select({
    id: complianceReports.id,
    createdAt: complianceReports.createdAt,
    payloadHash: complianceReports.payloadHash,
    signingKeyId: complianceReports.signingKeyId,
    generatedByLabel: dpoAccessKeys.label,
    generatedByRole: dpoAccessKeys.role,
  }).from(complianceReports)
    .innerJoin(dpoAccessKeys, eq(dpoAccessKeys.id, complianceReports.generatedBy))
    .where(eq(complianceReports.organizationId, organizationId))
    .orderBy(desc(complianceReports.createdAt), desc(complianceReports.id))
    .limit(Math.min(Math.max(limit, 1), 100));
}

export async function getReportVerificationKey(keyId: string, organizationId: string) {
  const [key] = await getDatabase().select({ publicKeyPem: reportSigningKeys.publicKeyPem })
    .from(reportSigningKeys)
    .innerJoin(complianceReports, eq(complianceReports.signingKeyId, reportSigningKeys.keyId))
    .where(and(eq(reportSigningKeys.keyId, keyId), eq(complianceReports.organizationId, organizationId)))
    .limit(1);
  return key?.publicKeyPem ?? null;
}
