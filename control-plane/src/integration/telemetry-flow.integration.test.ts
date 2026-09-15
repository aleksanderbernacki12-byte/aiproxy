import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { calculateEventHash, signingBytes } from "@/lib/telemetry/cryptography";
import type { TelemetryEvent } from "@/lib/telemetry/schema";

vi.mock("server-only", () => ({}));

const tenantKey = `integration-${randomUUID()}-${randomUUID()}`;
const organizationId = randomUUID();
const eventOneId = randomUUID();
const eventTwoId = randomUUID();
const dpoCredentialId = randomUUID();
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const keyId = createHash("sha256")
  .update(publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
let databaseConnected = false;
let organizationCreated = false;

function signedEvent(eventId: string, timestamp: string, previousHash: string, inputTokens: number, signer: KeyObject) {
  const event: TelemetryEvent = {
    event_id: eventId,
    timestamp,
    client_id_hash: "a".repeat(64),
    application_id: "integration-test",
    routing: { provider: "test-provider", model: "gpt-enterprise" },
    compliance_flags: { pii_detected: true, pii_redacted: true, policy_passed: true },
    metrics: { input_tokens: inputTokens, output_tokens: 5 },
    cryptography: {
      hash_algorithm: "SHA-256",
      request_response_hash: "b".repeat(64),
      previous_event_hash: previousHash,
      event_hash: "",
      signature_algorithm: "ECDSA_P256_SHA256_ASN1",
      key_id: keyId,
      signature: "",
    },
  };
  event.cryptography.event_hash = calculateEventHash(event);
  event.cryptography.signature = sign("sha256", signingBytes(event), {
    key: signer,
    dsaEncoding: "der",
  }).toString("base64").replace(/=+$/, "");
  return event;
}

describe("telemetry control-plane flow", () => {
  beforeAll(async () => {
    await client.connect();
    databaseConnected = true;
    await client.query(`CREATE TABLE IF NOT EXISTS control_plane_migrations (
      filename text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) {
      await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
      await client.query(`INSERT INTO control_plane_migrations(filename) VALUES ($1) ON CONFLICT DO NOTHING`, [migration]);
    }
    await client.query(
      `INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
      [organizationId, "Integration Test Organization", createHash("sha256").update(tenantKey).digest("hex")],
    );
    organizationCreated = true;
    await client.query(
      `INSERT INTO tenant_access_keys (organization_id, key_hash, label) VALUES ($1,$2,$3)`,
      [organizationId, createHash("sha256").update(tenantKey).digest("hex"), "Integration data plane"],
    );
    await client.query(
      `INSERT INTO telemetry_public_keys (organization_id, key_id, public_key_pem, label)
       VALUES ($1, $2, $3, $4)`,
      [organizationId, keyId, publicKeyPem, "integration-test"],
    );
    await client.query(
      `INSERT INTO dpo_access_keys (id, organization_id, key_hash, label, role) VALUES ($1,$2,$3,$4,$5)`,
      [dpoCredentialId, organizationId, "c".repeat(64), "Integration DPO", "DPO"],
    );
  });

  afterAll(async () => {
    if (!databaseConnected) return;
    if (!organizationCreated) {
      await client.end();
      return;
    }
    await client.query(`DELETE FROM ai_systems WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM compliance_reports WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_merkle_checkpoints WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_events WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_buffer WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_chain_heads WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_public_keys WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_event_ids WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM dpo_access_keys WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM tenant_access_keys WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
    await client.end();
  });

  it("preserves an out-of-order signed chain through ingest, worker, and dashboard", async () => {
    const first = signedEvent(eventOneId, "2026-09-15T08:00:00.000Z", "", 10, privateKey);
    const second = signedEvent(eventTwoId, "2026-09-15T08:00:01.000Z", first.cryptography.event_hash, 20, privateKey);
    const { POST } = await import("@/app/api/telemetry/ingest/route");

    for (const event of [second, first]) {
      const response = await POST(new Request("http://localhost/api/telemetry/ingest", {
        method: "POST",
        headers: { authorization: `Bearer ${tenantKey}`, "content-type": "application/json" },
        body: JSON.stringify(event),
      }));
      expect(response.status).toBe(202);
      expect(await response.json()).toMatchObject({ status: "BUFFERED", accepted: 1, duplicates: 0 });
    }

    const { processBufferedTelemetry } = await import("@/lib/telemetry/worker");
    expect(await processBufferedTelemetry(new Date("2026-09-15T08:01:00.000Z"))).toMatchObject({
      chains: 1, verified: 2, compromised: 0, invalid: 0, deferred: 0,
    });

    const rows = await client.query(
      `SELECT event_id, status, chain_sequence FROM telemetry_events
       WHERE organization_id = $1 ORDER BY chain_sequence`,
      [organizationId],
    );
    expect(rows.rows).toEqual([
      { event_id: eventOneId, status: "VERIFIED", chain_sequence: "1" },
      { event_id: eventTwoId, status: "VERIFIED", chain_sequence: "2" },
    ]);

    const { createMerkleCheckpoints } = await import("@/lib/telemetry/checkpoint");
    expect(await createMerkleCheckpoints()).toMatchObject({ created: 1 });
    expect(await createMerkleCheckpoints()).toMatchObject({ created: 0 });

    const anchorKeys = generateKeyPairSync("ed25519");
    vi.stubEnv("MERKLE_ANCHOR_URL", "http://independent-anchor.test/v1/checkpoints");
    vi.stubEnv("MERKLE_ANCHOR_TOKEN", "integration-anchor-token");
    vi.stubEnv("MERKLE_ANCHOR_PUBLIC_KEY", anchorKeys.publicKey.export({ type: "spki", format: "pem" }).toString());
    const { anchorPendingCheckpoints, anchorReceiptSigningBytes } = await import("@/lib/telemetry/anchor");
    const anchorResult = await anchorPendingCheckpoints(async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as { checkpoint_id: string; root_hash: string };
      const receipt = {
        anchor_id: "integration-ledger-1",
        checkpoint_id: request.checkpoint_id,
        root_hash: request.root_hash,
        anchored_at: new Date().toISOString(),
        signature_algorithm: "Ed25519" as const,
        signature: "placeholder-signature-value-long-enough",
      };
      receipt.signature = sign(null, anchorReceiptSigningBytes(receipt), anchorKeys.privateKey).toString("base64");
      return Response.json(receipt);
    });
    expect(anchorResult).toEqual({ configured: true, attempted: 1, anchored: 1, failed: 0 });

    await client.query(
      `INSERT INTO ai_systems (
         organization_id, application_id, model, name, provider, intended_purpose,
         risk_class, system_owner, legal_basis, human_oversight
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [organizationId, "integration-test", "gpt-enterprise", "Legal assistant", "test-provider",
        "Assist legal reviewers", "HIGH", "Legal Operations", "Legitimate interest", "Mandatory reviewer approval"],
    );

    const { getDashboardData } = await import("@/lib/dashboard");
    const dashboard = await getDashboardData(organizationId);
    expect(dashboard?.summary).toMatchObject({
      totalEvents: 2,
      totalTokens: 40,
      piiPrevented: 2,
      verifiedEvents: 2,
      compromisedEvents: 0,
      invalidSignatures: 0,
      chainStatus: "INTACT",
      unclassifiedSystems: 0,
    });
    expect(dashboard?.models).toHaveLength(1);
    expect(dashboard?.checkpoint).toMatchObject({
      leafCount: 1, anchorStatus: "ANCHORED", anchorId: "integration-ledger-1",
    });
    expect(dashboard?.checkpoint?.rootHash).toMatch(/^[a-f0-9]{64}$/);

    const { checkControlPlaneReadiness } = await import("@/lib/readiness");
    expect(await checkControlPlaneReadiness()).toBe(true);
    expect(dashboard?.models[0]).toMatchObject({
      applicationId: "integration-test", model: "gpt-enterprise", eventCount: 2,
      totalTokens: 40, piiIncidents: 2, governance: { riskClass: "HIGH", systemOwner: "Legal Operations" },
    });

    const reportKeys = generateKeyPairSync("ed25519");
    vi.stubEnv("REPORT_SIGNING_PRIVATE_KEY", reportKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const { sealComplianceReport, getSealedReport, listSealedReports, verifySealedReport } = await import("@/lib/compliance-report");
    const reportId = await sealComplianceReport({ credentialId: dpoCredentialId, organizationId });
    const sealedReport = await getSealedReport(reportId, organizationId);
    expect(sealedReport).not.toBeNull();
    expect(verifySealedReport(sealedReport!, reportKeys.publicKey.export({ type: "spki", format: "pem" }).toString())).toBe(true);
    expect(await listSealedReports(organizationId)).toMatchObject([{
      id: reportId,
      generatedByLabel: "Integration DPO",
      generatedByRole: "DPO",
      payloadHash: sealedReport!.payload_hash,
    }]);

    await client.query(`DELETE FROM ai_systems WHERE organization_id = $1`, [organizationId]);
    const unclassified = await getDashboardData(organizationId);
    expect(unclassified?.summary.unclassifiedSystems).toBe(1);
    expect(unclassified?.models[0].governance).toBeNull();

    await client.query(`UPDATE tenant_access_keys SET revoked_at=now() WHERE organization_id=$1`, [organizationId]);
    const rejected = await POST(new Request("http://localhost/api/telemetry/ingest", {
      method: "POST",
      headers: { authorization: `Bearer ${tenantKey}`, "content-type": "application/json" },
      body: JSON.stringify(first),
    }));
    expect(rejected.status).toBe(401);
  });
});
