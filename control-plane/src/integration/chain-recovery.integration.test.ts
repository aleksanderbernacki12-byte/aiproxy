import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { calculateEventHash, signingBytes } from "@/lib/telemetry/cryptography";
import type { TelemetryEvent } from "@/lib/telemetry/schema";

vi.mock("server-only", () => ({}));

const organizationId = randomUUID();
const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
let organizationCreated = false;

type SigningKey = { keyId: string; privateKey: KeyObject };

async function registerKey(): Promise<SigningKey> {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  await client.query(
    `INSERT INTO telemetry_public_keys (organization_id, key_id, public_key_pem, label) VALUES ($1, $2, $3, $4)`,
    [organizationId, keyId, publicKey.export({ type: "spki", format: "pem" }).toString(), "chain-recovery"],
  );
  return { keyId, privateKey };
}

function signedEvent(key: SigningKey, timestamp: string, previousHash: string, signer = key.privateKey) {
  const event: TelemetryEvent = {
    event_id: randomUUID(),
    timestamp,
    client_id_hash: "a".repeat(64),
    application_id: "chain-recovery",
    routing: { provider: "test-provider" },
    compliance_flags: { pii_detected: false, pii_redacted: false },
    metrics: { input_tokens: 1 },
    cryptography: {
      hash_algorithm: "SHA-256",
      request_response_hash: "b".repeat(64),
      previous_event_hash: previousHash,
      event_hash: "",
      signature_algorithm: "ECDSA_P256_SHA256_ASN1",
      key_id: key.keyId,
      signature: "",
    },
  };
  event.cryptography.event_hash = calculateEventHash(event);
  event.cryptography.signature = sign("sha256", signingBytes(event), { key: signer, dsaEncoding: "der" })
    .toString("base64").replace(/=+$/, "");
  return event;
}

async function ingest(...events: TelemetryEvent[]) {
  const { bufferTelemetryEvents } = await import("@/lib/telemetry/ingest");
  await bufferTelemetryEvents(organizationId, events);
}

async function processPastWindow() {
  const { processBufferedTelemetry } = await import("@/lib/telemetry/worker");
  return processBufferedTelemetry(new Date(Date.now() + 3_600_000));
}

async function stored(event: TelemetryEvent) {
  const result = await client.query<{ status: string; chain_sequence: string | null; status_reason: string | null }>(
    `SELECT status, chain_sequence, status_reason FROM telemetry_events WHERE organization_id = $1 AND event_id = $2`,
    [organizationId, event.event_id],
  );
  return result.rows[0];
}

async function head(key: SigningKey) {
  const result = await client.query<{ latest_event_hash: string; sequence: string }>(
    `SELECT latest_event_hash, sequence FROM telemetry_chain_heads WHERE organization_id = $1 AND key_id = $2`,
    [organizationId, key.keyId],
  );
  return result.rows[0];
}

const unknownHash = "c".repeat(64);

describe("telemetry chain recovery after a gap", () => {
  let gapKey: SigningKey;
  const gap: Record<string, TelemetryEvent> = {};

  beforeAll(async () => {
    await client.connect();
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
    await client.query(
      `INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
      [organizationId, "Chain Recovery Organization", createHash("sha256").update(randomUUID()).digest("hex")],
    );
    organizationCreated = true;
  });

  afterAll(async () => {
    if (organizationCreated) {
      await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'on', false)`);
      for (const table of ["telemetry_merkle_checkpoints", "telemetry_events", "telemetry_buffer", "telemetry_chain_heads", "telemetry_public_keys"]) {
        await client.query(`DELETE FROM ${table} WHERE organization_id = $1`, [organizationId]);
      }
      await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'on', false)`);
      await client.query(`DELETE FROM telemetry_tombstones WHERE organization_id = $1`, [organizationId]);
      await client.query(`DELETE FROM security_audit_events WHERE organization_id = $1`, [organizationId]);
      await client.query(`DELETE FROM security_audit_heads WHERE organization_id = $1`, [organizationId]);
      await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'off', false)`);
      await client.query(`DELETE FROM telemetry_event_ids WHERE organization_id = $1`, [organizationId]);
      await client.query(`DELETE FROM organization_retention_policies WHERE organization_id = $1`, [organizationId]);
      await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
    }
    await client.end();
  });

  it("flags a missing event once and verifies the events after it", async () => {
    gapKey = await registerKey();
    gap.e1 = signedEvent(gapKey, "2026-09-20T08:00:00.000Z", "");
    gap.e2 = signedEvent(gapKey, "2026-09-20T08:00:01.000Z", gap.e1.cryptography.event_hash);
    gap.e3 = signedEvent(gapKey, "2026-09-20T08:00:02.000Z", gap.e2.cryptography.event_hash);
    gap.e4 = signedEvent(gapKey, "2026-09-20T08:00:03.000Z", gap.e3.cryptography.event_hash);
    gap.e5 = signedEvent(gapKey, "2026-09-20T08:00:04.000Z", gap.e4.cryptography.event_hash);
    await ingest(gap.e1, gap.e2);
    await processPastWindow();
    await ingest(gap.e4, gap.e5);
    await processPastWindow();

    expect(await stored(gap.e1)).toMatchObject({ status: "VERIFIED", chain_sequence: "1" });
    expect(await stored(gap.e2)).toMatchObject({ status: "VERIFIED", chain_sequence: "2" });
    const discontinuity = await stored(gap.e4);
    expect(discontinuity).toMatchObject({ status: "COMPROMISED_CHAIN", chain_sequence: "3" });
    expect(discontinuity.status_reason).toMatch(/does not match chain head/);
    expect(await stored(gap.e5)).toMatchObject({ status: "VERIFIED", chain_sequence: "4" });
    expect(await head(gapKey)).toEqual({ latest_event_hash: gap.e5.cryptography.event_hash, sequence: "4" });
  });

  it("flags a late straggler without moving the head", async () => {
    await ingest(gap.e3);
    await processPastWindow();

    const straggler = await stored(gap.e3);
    expect(straggler).toMatchObject({ status: "COMPROMISED_CHAIN", chain_sequence: null });
    expect(straggler.status_reason).toMatch(/arrived after the chain continued/);
    expect(await head(gapKey)).toEqual({ latest_event_hash: gap.e5.cryptography.event_hash, sequence: "4" });
  });

  it("names a data-plane restart at genesis and continues after it", async () => {
    const key = await registerKey();
    const g1 = signedEvent(key, "2026-09-20T09:00:00.000Z", "");
    const g2 = signedEvent(key, "2026-09-20T09:00:01.000Z", g1.cryptography.event_hash);
    await ingest(g1, g2);
    await processPastWindow();
    const r1 = signedEvent(key, "2026-09-20T09:10:00.000Z", "");
    const r2 = signedEvent(key, "2026-09-20T09:10:01.000Z", r1.cryptography.event_hash);
    await ingest(r1, r2);
    await processPastWindow();

    const restart = await stored(r1);
    expect(restart).toMatchObject({ status: "COMPROMISED_CHAIN", chain_sequence: "3" });
    expect(restart.status_reason).toMatch(/chain restarted at genesis/);
    expect(await stored(r2)).toMatchObject({ status: "VERIFIED", chain_sequence: "4" });
  });

  it("never lets an invalid event become the discontinuity", async () => {
    const key = await registerKey();
    const forger = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    const k1 = signedEvent(key, "2026-09-20T10:00:00.000Z", "");
    await ingest(k1);
    await processPastWindow();
    const forged = signedEvent(key, "2026-09-20T10:00:01.000Z", unknownHash, forger);
    const valid = signedEvent(key, "2026-09-20T10:00:02.000Z", unknownHash);
    await ingest(forged, valid);
    await processPastWindow();

    expect(await stored(forged)).toMatchObject({ status: "INVALID_SIGNATURE", chain_sequence: null });
    expect(await stored(valid)).toMatchObject({ status: "COMPROMISED_CHAIN", chain_sequence: "2" });
    expect(await head(key)).toEqual({ latest_event_hash: valid.cryptography.event_hash, sequence: "2" });
  });

  it("ages out a discontinuity event together with its anchored chain", async () => {
    await client.query(
      `INSERT INTO telemetry_merkle_checkpoints (organization_id, root_hash, leaf_count, chain_heads, anchor_status)
       VALUES ($1, $2, 1, $3::jsonb, 'ANCHORED')`,
      [organizationId, "d".repeat(64), JSON.stringify([{ key_id: gapKey.keyId, event_hash: gap.e5.cryptography.event_hash, sequence: "4" }])],
    );
    await client.query(
      `INSERT INTO organization_retention_policies (organization_id, telemetry_retention_days) VALUES ($1, 30)`,
      [organizationId],
    );
    const { enforceRetentionPolicies } = await import("@/lib/retention");
    await enforceRetentionPolicies(new Date("2026-11-20T00:00:00.000Z"));

    for (const event of [gap.e1, gap.e2, gap.e4, gap.e5]) expect(await stored(event)).toBeUndefined();
    const tombstones = await client.query(
      `SELECT count(*)::integer AS count FROM telemetry_tombstones WHERE organization_id = $1 AND key_id = $2`,
      [organizationId, gapKey.keyId],
    );
    expect(tombstones.rows[0].count).toBe(4);
    expect(await stored(gap.e3)).toMatchObject({ status: "COMPROMISED_CHAIN", chain_sequence: null });
  });
});
