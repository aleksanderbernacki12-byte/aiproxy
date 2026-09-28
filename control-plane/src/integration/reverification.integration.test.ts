import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { calculateEventHash, signingBytes } from "@/lib/telemetry/cryptography";
import type { TelemetryEvent } from "@/lib/telemetry/schema";

vi.mock("server-only", () => ({}));

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
const organizations: string[] = [];

type Chain = { organizationId: string; keyId: string; privateKey: KeyObject; events: TelemetryEvent[] };

function signedEvent(chain: Pick<Chain, "keyId" | "privateKey">, timestamp: string, previousHash: string) {
  const event: TelemetryEvent = {
    event_id: randomUUID(),
    timestamp,
    client_id_hash: "a".repeat(64),
    application_id: "reverification",
    routing: { provider: "test-provider", model: "m" },
    compliance_flags: { pii_detected: true, pii_redacted: true },
    metrics: { input_tokens: 3, output_tokens: 4 },
    cryptography: {
      hash_algorithm: "SHA-256", request_response_hash: "b".repeat(64), previous_event_hash: previousHash,
      event_hash: "", signature_algorithm: "ECDSA_P256_SHA256_ASN1", key_id: chain.keyId, signature: "",
    },
  };
  event.cryptography.event_hash = calculateEventHash(event);
  event.cryptography.signature = sign("sha256", signingBytes(event), { key: chain.privateKey, dsaEncoding: "der" })
    .toString("base64").replace(/=+$/, "");
  return event;
}

async function ingestAndProcess(organizationId: string, events: TelemetryEvent[]) {
  const { bufferTelemetryEvents } = await import("@/lib/telemetry/ingest");
  await bufferTelemetryEvents(organizationId, events);
  const { processBufferedTelemetry } = await import("@/lib/telemetry/worker");
  await processBufferedTelemetry(new Date(Date.now() + 3_600_000));
}

async function anchor(organizationId: string) {
  const { createMerkleCheckpoints } = await import("@/lib/telemetry/checkpoint");
  await createMerkleCheckpoints();
  await client.query(
    `UPDATE telemetry_merkle_checkpoints SET anchor_status = 'ANCHORED', anchored_at = now()
     WHERE organization_id = $1 AND anchor_status = 'PENDING'`,
    [organizationId],
  );
}

// An organization with one key and a processed, anchored chain of `count`
// events, one second apart.
async function anchoredChain(count: number): Promise<Chain> {
  const organizationId = randomUUID();
  await client.query(`INSERT INTO organizations (id, name, tenant_key) VALUES ($1, $2, $3)`,
    [organizationId, "Reverification Organization", createHash("sha256").update(randomUUID()).digest("hex")]);
  organizations.push(organizationId);
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  await client.query(
    `INSERT INTO telemetry_public_keys (organization_id, key_id, public_key_pem, label) VALUES ($1, $2, $3, 'reverification')`,
    [organizationId, keyId, publicKey.export({ type: "spki", format: "pem" }).toString()],
  );
  const chain: Chain = { organizationId, keyId, privateKey, events: [] };
  let previous = "";
  for (let index = 0; index < count; index += 1) {
    const event = signedEvent(chain, new Date(Date.UTC(2026, 8, 22, 8, 0, index)).toISOString(), previous);
    chain.events.push(event);
    previous = event.cryptography.event_hash;
  }
  await ingestAndProcess(organizationId, chain.events);
  await anchor(organizationId);
  return chain;
}

// Tampering as a database administrator would: with the append-only
// triggers switched off for the duration of the statement.
async function tamper(table: string, text: string, params: unknown[]) {
  await client.query(`ALTER TABLE ${table} DISABLE TRIGGER USER`);
  try {
    await client.query(text, params);
  } finally {
    await client.query(`ALTER TABLE ${table} ENABLE TRIGGER USER`);
  }
}

async function verify(organizationId: string, deadline = new Date(Date.now() + 60_000)) {
  const { verifyOrganization } = await import("@/lib/telemetry/verification");
  return verifyOrganization(organizationId, deadline);
}

function kinds(run: { failureSamples: Array<{ kind: string }> }) {
  return run.failureSamples.map((sample) => sample.kind);
}

describe("re-verification of stored telemetry", () => {
  beforeAll(async () => {
    await client.connect();
    const migrations = (await readdir(resolve("db/migrations"))).filter((name) => name.endsWith(".sql")).sort();
    for (const migration of migrations) await client.query(await readFile(resolve("db/migrations", migration), "utf8"));
  });

  afterAll(async () => {
    await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'on', false)`);
    for (const organizationId of organizations) {
      for (const table of ["telemetry_verification_runs", "telemetry_merkle_checkpoints", "telemetry_events", "telemetry_buffer",
        "telemetry_chain_heads", "telemetry_public_keys", "telemetry_tombstones", "security_audit_events",
        "security_audit_heads", "telemetry_event_ids", "organization_retention_policies"]) {
        await client.query(`DELETE FROM ${table} WHERE organization_id = $1`, [organizationId]);
      }
      await client.query(`DELETE FROM organizations WHERE id = $1`, [organizationId]);
    }
    await client.query(`SELECT set_config('aiproxy.audit_maintenance', 'off', false)`);
    await client.end();
  });

  it("keeps the verified payload and the purged status", async () => {
    const chain = await anchoredChain(1);
    const stored = await client.query(`SELECT signed_payload FROM telemetry_events WHERE event_id = $1`, [chain.events[0].event_id]);
    expect(stored.rows[0].signed_payload).toEqual(chain.events[0]);

    await client.query(`INSERT INTO organization_retention_policies (organization_id, telemetry_retention_days) VALUES ($1, 30)`,
      [chain.organizationId]);
    const { enforceRetentionPolicies } = await import("@/lib/retention");
    await enforceRetentionPolicies(new Date("2026-12-01T00:00:00.000Z"));
    const tombstone = await client.query(`SELECT status FROM telemetry_tombstones WHERE event_id = $1`, [chain.events[0].event_id]);
    expect(tombstone.rows[0].status).toBe("VERIFIED");
  });

  it("finds nothing wrong with an untouched anchored chain", async () => {
    const chain = await anchoredChain(3);
    const run = await verify(chain.organizationId);
    expect(run).toMatchObject({ complete: true, eventsChecked: 3, legacyEvents: 0, failures: 0 });
    const stored = await client.query(`SELECT count(*)::integer AS count FROM telemetry_verification_runs WHERE organization_id = $1`,
      [chain.organizationId]);
    expect(stored.rows[0].count).toBe(1);
  });

  it("detects an edited compliance flag", async () => {
    const chain = await anchoredChain(3);
    await tamper("telemetry_events",
      `UPDATE telemetry_events SET compliance_flags = '{"pii_detected":false,"pii_redacted":false}'::jsonb WHERE event_id = $1`,
      [chain.events[1].event_id]);
    expect(kinds(await verify(chain.organizationId))).toContain("PAYLOAD_MISMATCH");
  });

  it("detects a payload edited consistently with its columns", async () => {
    const chain = await anchoredChain(3);
    await tamper("telemetry_events",
      `UPDATE telemetry_events SET compliance_flags = '{"pii_detected":false,"pii_redacted":false}'::jsonb,
         signed_payload = jsonb_set(signed_payload, '{compliance_flags}', '{"pii_detected":false,"pii_redacted":false}'::jsonb)
       WHERE event_id = $1`,
      [chain.events[1].event_id]);
    expect(kinds(await verify(chain.organizationId))).toContain("HASH_MISMATCH");
  });

  it("detects a removed event", async () => {
    const chain = await anchoredChain(3);
    await tamper("telemetry_events", `DELETE FROM telemetry_events WHERE event_id = $1`, [chain.events[1].event_id]);
    expect(kinds(await verify(chain.organizationId))).toContain("SEQUENCE_GAP");
  });

  it("detects an altered checkpoint", async () => {
    const chain = await anchoredChain(2);
    await tamper("telemetry_merkle_checkpoints",
      `UPDATE telemetry_merkle_checkpoints SET chain_heads = jsonb_set(chain_heads, '{0,event_hash}', to_jsonb($2::text))
       WHERE organization_id = $1`,
      [chain.organizationId, "9".repeat(64)]);
    expect(kinds(await verify(chain.organizationId))).toContain("ANCHOR_MISMATCH");
  });

  it("accepts a declared gap before and after it is purged", async () => {
    const chain = await anchoredChain(2);
    const missing = signedEvent(chain, "2026-09-22T08:00:05.000Z", chain.events[1].cryptography.event_hash);
    const afterGap = signedEvent(chain, "2026-09-22T08:00:06.000Z", missing.cryptography.event_hash);
    const next = signedEvent(chain, "2026-09-22T08:00:07.000Z", afterGap.cryptography.event_hash);
    await ingestAndProcess(chain.organizationId, [afterGap, next]);
    await anchor(chain.organizationId);
    expect(await verify(chain.organizationId)).toMatchObject({ failures: 0, eventsChecked: 4 });

    await client.query(`INSERT INTO organization_retention_policies (organization_id, telemetry_retention_days) VALUES ($1, 30)`,
      [chain.organizationId]);
    const { enforceRetentionPolicies } = await import("@/lib/retention");
    await enforceRetentionPolicies(new Date("2026-12-01T00:00:00.000Z"));
    expect(await verify(chain.organizationId)).toMatchObject({ failures: 0 });
  });

  it("counts events stored before payloads were kept as legacy", async () => {
    const chain = await anchoredChain(2);
    await tamper("telemetry_events", `UPDATE telemetry_events SET signed_payload = NULL WHERE event_id = $1`, [chain.events[0].event_id]);
    expect(await verify(chain.organizationId)).toMatchObject({ failures: 0, legacyEvents: 1, eventsChecked: 2 });
  });

  it("records a run that ran out of time as incomplete", async () => {
    const chain = await anchoredChain(2);
    expect(await verify(chain.organizationId, new Date(0))).toMatchObject({ complete: false });
  });
});
