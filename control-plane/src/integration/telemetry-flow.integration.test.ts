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
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) {
      await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
    }
    await client.query(
      `INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
      [organizationId, "Integration Test Organization", createHash("sha256").update(tenantKey).digest("hex")],
    );
    organizationCreated = true;
    await client.query(
      `INSERT INTO telemetry_public_keys (organization_id, key_id, public_key_pem, label)
       VALUES ($1, $2, $3, $4)`,
      [organizationId, keyId, publicKeyPem, "integration-test"],
    );
  });

  afterAll(async () => {
    if (!databaseConnected) return;
    if (!organizationCreated) {
      await client.end();
      return;
    }
    await client.query(`DELETE FROM telemetry_events WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_buffer WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_chain_heads WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_public_keys WHERE organization_id = $1`, [organizationId]);
    await client.query(`DELETE FROM telemetry_event_ids WHERE organization_id = $1`, [organizationId]);
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
    });
    expect(dashboard?.models).toHaveLength(1);
    expect(dashboard?.models[0]).toMatchObject({
      model: "gpt-enterprise", eventCount: 2, totalTokens: 40, piiIncidents: 2,
    });
  });
});
