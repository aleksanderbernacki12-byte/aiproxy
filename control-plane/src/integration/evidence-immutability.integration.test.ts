import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { calculateEventHash, signingBytes } from "@/lib/telemetry/cryptography";
import type { TelemetryEvent } from "@/lib/telemetry/schema";

vi.mock("server-only", () => ({}));

const organizationId = randomUUID();
const dpoCredentialId = randomUUID();
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
let organizationCreated = false;
let eventId = "";
let reportId = "";
let pendingCheckpointId = "";
let anchoredCheckpointId = "";

async function signedEventFor(): Promise<TelemetryEvent> {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  await client.query(
    `INSERT INTO telemetry_public_keys (organization_id, key_id, public_key_pem, label) VALUES ($1, $2, $3, $4)`,
    [organizationId, keyId, publicKey.export({ type: "spki", format: "pem" }).toString(), "immutability"],
  );
  const event: TelemetryEvent = {
    event_id: randomUUID(),
    timestamp: "2026-09-21T08:00:00.000Z",
    client_id_hash: "a".repeat(64),
    application_id: "immutability",
    routing: {},
    compliance_flags: { pii_detected: true, pii_redacted: true },
    metrics: {},
    cryptography: {
      hash_algorithm: "SHA-256", request_response_hash: "b".repeat(64), previous_event_hash: "",
      event_hash: "", signature_algorithm: "ECDSA_P256_SHA256_ASN1", key_id: keyId, signature: "",
    },
  };
  event.cryptography.event_hash = calculateEventHash(event);
  event.cryptography.signature = sign("sha256", signingBytes(event), { key: privateKey, dsaEncoding: "der" })
    .toString("base64").replace(/=+$/, "");
  return event;
}

// Runs statements in a transaction that is always rolled back, so an
// unprotected table can never lose rows other tests depend on.
async function rolledBack(...statements: Array<[string, unknown[]?]>) {
  await client.query("BEGIN");
  try {
    for (const [text, params] of statements) await client.query(text, params);
  } finally {
    await client.query("ROLLBACK");
  }
}

const maintenance: [string] = [`SELECT set_config('aiproxy.audit_maintenance', 'on', true)`];

describe("stored evidence is append-only", () => {
  beforeAll(async () => {
    await client.connect();
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
    await client.query(
      `INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
      [organizationId, "Immutability Organization", createHash("sha256").update(randomUUID()).digest("hex")],
    );
    organizationCreated = true;
    await client.query(
      `INSERT INTO dpo_access_keys (id, organization_id, key_hash, label, role) VALUES ($1, $2, $3, $4, 'DPO')`,
      [dpoCredentialId, organizationId, createHash("sha256").update(randomUUID()).digest("hex"), "Immutability DPO"],
    );
    const event = await signedEventFor();
    eventId = event.event_id;
    const { bufferTelemetryEvents } = await import("@/lib/telemetry/ingest");
    await bufferTelemetryEvents(organizationId, [event]);
    const { processBufferedTelemetry } = await import("@/lib/telemetry/worker");
    await processBufferedTelemetry(new Date(Date.now() + 3_600_000));
    const report = await client.query<{ id: string }>(
      `INSERT INTO compliance_reports (organization_id, generated_by, payload, payload_hash, signature_algorithm, signing_key_id, signature)
       VALUES ($1, $2, '{}'::jsonb, $3, 'Ed25519', $4, 'sig') RETURNING id`,
      [organizationId, dpoCredentialId, "e".repeat(64), "f".repeat(64)],
    );
    reportId = report.rows[0].id;
    const checkpoints = await client.query<{ id: string }>(
      `INSERT INTO telemetry_merkle_checkpoints (organization_id, root_hash, leaf_count, chain_heads, anchor_status)
       VALUES ($1, $2, 1, '[]'::jsonb, 'PENDING'), ($1, $3, 1, '[]'::jsonb, 'ANCHORED') RETURNING id`,
      [organizationId, "1".repeat(64), "2".repeat(64)],
    );
    [pendingCheckpointId, anchoredCheckpointId] = checkpoints.rows.map((row) => row.id);
  });

  afterAll(async () => {
    if (organizationCreated) {
      await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'on', false)`);
      for (const table of ["compliance_reports", "telemetry_merkle_checkpoints", "telemetry_events", "telemetry_buffer",
        "telemetry_chain_heads", "telemetry_public_keys", "telemetry_event_ids", "dpo_access_keys"]) {
        await client.query(`DELETE FROM ${table} WHERE organization_id = $1`, [organizationId]);
      }
      await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'off', false)`);
      await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
    }
    await client.end();
  });

  it("rejects edits of a stored telemetry event", async () => {
    await expect(rolledBack([
      `UPDATE telemetry_events SET compliance_flags = '{"pii_detected":false,"pii_redacted":false}'::jsonb WHERE organization_id = $1`,
      [organizationId],
    ])).rejects.toThrow(/append-only/);
    await expect(rolledBack(maintenance, [
      `UPDATE telemetry_events SET status = 'VERIFIED' WHERE organization_id = $1`, [organizationId],
    ])).rejects.toThrow(/append-only/);
  });

  it("allows deleting a telemetry event only under maintenance", async () => {
    await expect(rolledBack([`DELETE FROM telemetry_events WHERE event_id = $1`, [eventId]]))
      .rejects.toThrow(/append-only/);
    await expect(rolledBack(maintenance, [`DELETE FROM telemetry_events WHERE event_id = $1`, [eventId]]))
      .resolves.toBeUndefined();
  });

  it("rejects edits and deletion of a sealed report", async () => {
    await expect(rolledBack([`UPDATE compliance_reports SET payload = '{"x":1}'::jsonb WHERE id = $1`, [reportId]]))
      .rejects.toThrow(/append-only/);
    await expect(rolledBack([`DELETE FROM compliance_reports WHERE id = $1`, [reportId]]))
      .rejects.toThrow(/append-only/);
  });

  it("lets only the anchor fields of a pending checkpoint change", async () => {
    await expect(rolledBack([
      `UPDATE telemetry_merkle_checkpoints SET anchor_status = 'ANCHORED', anchor_attempts = 1, anchor_id = 'a-1',
       anchored_at = now(), anchor_receipt = '{}'::jsonb WHERE id = $1`, [pendingCheckpointId],
    ])).resolves.toBeUndefined();
    await expect(rolledBack([
      `UPDATE telemetry_merkle_checkpoints SET root_hash = $2 WHERE id = $1`, [pendingCheckpointId, "3".repeat(64)],
    ])).rejects.toThrow(/append-only/);
    await expect(rolledBack([
      `UPDATE telemetry_merkle_checkpoints SET anchor_status = 'PENDING' WHERE id = $1`, [anchoredCheckpointId],
    ])).rejects.toThrow(/append-only/);
    await expect(rolledBack([`DELETE FROM telemetry_merkle_checkpoints WHERE id = $1`, [pendingCheckpointId]]))
      .rejects.toThrow(/append-only/);
  });

  it("rejects truncating evidence tables", async () => {
    for (const table of ["telemetry_events", "compliance_reports", "telemetry_merkle_checkpoints",
      "security_audit_checkpoints", "security_audit_events", "telemetry_tombstones"]) {
      await expect(rolledBack([`TRUNCATE ${table} CASCADE`])).rejects.toThrow(/append-only/);
    }
  });
});
