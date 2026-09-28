import "server-only";

import canonicalize from "canonicalize";
import { and, eq, sql } from "drizzle-orm";
import { getCrossTenantDatabase } from "@/db/client";
import {
  telemetryChainHeads,
  telemetryPublicKeys,
  telemetryVerificationRuns,
  type MerkleCheckpointHead,
  type VerificationFailureSample,
} from "@/db/schema";
import { verifyAnchorReceipt } from "./anchor";
import { calculateMerkleRoot } from "./checkpoint";
import { calculateEventHash, verifyTelemetryCryptography } from "./cryptography";
import { telemetryEventSchema, type TelemetryEvent } from "./schema";

const PAGE_SIZE = 1000;
const MAX_SAMPLES = 20;
const DEFAULT_BUDGET_MS = 45_000;

export type VerificationRun = {
  startedAt: Date;
  completedAt: Date;
  complete: boolean;
  eventsChecked: number;
  legacyEvents: number;
  failures: number;
  failureSamples: VerificationFailureSample[];
};

type ChainItem = {
  chain_sequence: string;
  event_id: string;
  event_hash: string;
  previous_event_hash: string;
  status: string;
};

type StoredEvent = {
  id: string;
  event_id: string;
  event_timestamp: Date;
  client_id_hash: string;
  application_id: string;
  routing: unknown;
  compliance_flags: unknown;
  metrics: unknown;
  hash_algorithm: string;
  request_response_hash: string;
  previous_event_hash: string;
  event_hash: string;
  signature_algorithm: string;
  key_id: string;
  signature: string;
  status: string;
  signed_payload: unknown;
};

type AnchoredCheckpoint = {
  id: string;
  root_hash: string;
  chain_heads: MerkleCheckpointHead[];
  anchor_receipt: unknown;
};

class Findings {
  failures = 0;
  samples: VerificationFailureSample[] = [];

  add(kind: string, keyId: string, detail: string, sequence: string | null = null, eventId: string | null = null) {
    this.failures += 1;
    if (this.samples.length < MAX_SAMPLES) {
      this.samples.push({ kind, key_id: keyId, sequence, event_id: eventId, detail });
    }
  }
}

function sameJson(left: unknown, right: unknown) {
  return canonicalize(left) === canonicalize(right);
}

// Every stored column must still say what the signed payload says; the
// payload itself must still hash to its event_hash (a consistent edit of
// payload and columns breaks the hash) and carry a valid signature.
function payloadMismatch(row: StoredEvent, payload: TelemetryEvent) {
  const crypto = payload.cryptography;
  const mismatches = [
    payload.event_id.toLowerCase() !== row.event_id.toLowerCase() && "event_id",
    new Date(payload.timestamp).getTime() !== new Date(row.event_timestamp).getTime() && "timestamp",
    payload.client_id_hash !== row.client_id_hash && "client_id_hash",
    payload.application_id !== row.application_id && "application_id",
    !sameJson(payload.routing, row.routing) && "routing",
    !sameJson(payload.compliance_flags, row.compliance_flags) && "compliance_flags",
    !sameJson(payload.metrics, row.metrics) && "metrics",
    crypto.hash_algorithm !== row.hash_algorithm && "hash_algorithm",
    crypto.request_response_hash !== row.request_response_hash && "request_response_hash",
    crypto.previous_event_hash !== row.previous_event_hash && "previous_event_hash",
    crypto.event_hash !== row.event_hash && "event_hash",
    crypto.signature_algorithm !== row.signature_algorithm && "signature_algorithm",
    crypto.key_id !== row.key_id && "key_id",
    crypto.signature !== row.signature && "signature",
  ].filter(Boolean);
  return mismatches.length > 0 ? `stored columns differ from the signed payload: ${mismatches.join(", ")}` : null;
}

async function latestAnchoredCheckpoint(organizationId: string) {
  const result = await getCrossTenantDatabase().execute<AnchoredCheckpoint>(sql`
    SELECT id::text AS id, root_hash, chain_heads, anchor_receipt FROM telemetry_merkle_checkpoints
    WHERE organization_id = ${organizationId}::uuid AND anchor_status = 'ANCHORED'
    ORDER BY created_at DESC, id DESC LIMIT 1
  `);
  return result.rows[0] ?? null;
}

function verifyCheckpoint(organizationId: string, checkpoint: AnchoredCheckpoint, findings: Findings) {
  const { rootHash } = calculateMerkleRoot(organizationId, checkpoint.chain_heads);
  if (rootHash !== checkpoint.root_hash) {
    findings.add("ANCHOR_MISMATCH", "", `checkpoint ${checkpoint.id} heads no longer produce its root hash`);
  }
  const anchorKey = process.env.MERKLE_ANCHOR_PUBLIC_KEY?.replaceAll("\\n", "\n");
  if (anchorKey) {
    const receipt = verifyAnchorReceipt(checkpoint.anchor_receipt, anchorKey, checkpoint.id, checkpoint.root_hash);
    if (!receipt.ok) findings.add("ANCHOR_MISMATCH", "", `checkpoint ${checkpoint.id}: ${receipt.reason}`);
  }
}

async function verifyChain(
  organizationId: string,
  keyId: string,
  anchoredHeads: Map<string, string>,
  deadline: Date,
  findings: Findings,
) {
  const database = getCrossTenantDatabase();
  let expectedSequence = 1n;
  let priorHash = "";
  let last: ChainItem | null = null;
  const seenAnchored = new Set<string>();
  for (;;) {
    if (Date.now() > deadline.getTime()) return false;
    const page = await database.execute<ChainItem>(sql`
      SELECT chain_sequence::text AS chain_sequence, event_id::text AS event_id, event_hash, previous_event_hash, status FROM (
        SELECT chain_sequence, event_id, event_hash, previous_event_hash, status::text AS status
        FROM telemetry_events
        WHERE organization_id = ${organizationId}::uuid AND key_id = ${keyId} AND chain_sequence IS NOT NULL
        UNION ALL
        SELECT chain_sequence, event_id, event_hash, previous_event_hash, coalesce(status::text, 'VERIFIED')
        FROM telemetry_tombstones
        WHERE organization_id = ${organizationId}::uuid AND key_id = ${keyId}
      ) item
      WHERE chain_sequence >= ${expectedSequence.toString()}::bigint
      ORDER BY chain_sequence, event_id
      LIMIT ${PAGE_SIZE}
    `);
    for (const item of page.rows) {
      const sequence = BigInt(item.chain_sequence);
      if (sequence !== expectedSequence) {
        findings.add("SEQUENCE_GAP", keyId, sequence < expectedSequence
          ? `sequence ${sequence} appears more than once`
          : `sequences ${expectedSequence}..${sequence - 1n} are missing`, item.chain_sequence, item.event_id);
      }
      if (item.previous_event_hash !== priorHash && item.status !== "COMPROMISED_CHAIN") {
        findings.add("LINK_MISMATCH", keyId, "previous_event_hash does not match the prior event in the chain",
          item.chain_sequence, item.event_id);
      }
      const anchoredHash = anchoredHeads.get(item.chain_sequence);
      if (anchoredHash !== undefined) {
        seenAnchored.add(item.chain_sequence);
        if (anchoredHash !== item.event_hash) {
          findings.add("ANCHOR_MISMATCH", keyId, "the anchored chain head differs from the stored event",
            item.chain_sequence, item.event_id);
        }
      }
      priorHash = item.event_hash;
      expectedSequence = sequence + 1n;
      last = item;
    }
    if (page.rows.length < PAGE_SIZE) break;
  }
  for (const sequence of anchoredHeads.keys()) {
    if (!seenAnchored.has(sequence)) {
      findings.add("ANCHOR_MISMATCH", keyId, "an anchored chain head is no longer stored", sequence);
    }
  }
  const [head] = await database.select().from(telemetryChainHeads).where(and(
    eq(telemetryChainHeads.organizationId, organizationId), eq(telemetryChainHeads.keyId, keyId),
  )).limit(1);
  if (last && (!head || head.latestEventHash !== last.event_hash || head.sequence.toString() !== last.chain_sequence)) {
    findings.add("HEAD_MISMATCH", keyId, "the stored chain head does not match the last event in the chain", last.chain_sequence);
  }
  return true;
}

async function verifyPayloads(organizationId: string, keyId: string, deadline: Date, findings: Findings) {
  const database = getCrossTenantDatabase();
  const [registered] = await database.select({ publicKeyPem: telemetryPublicKeys.publicKeyPem }).from(telemetryPublicKeys)
    .where(and(eq(telemetryPublicKeys.organizationId, organizationId), eq(telemetryPublicKeys.keyId, keyId))).limit(1);
  let cursor = "0";
  let checked = 0;
  let legacy = 0;
  let keyMissingReported = false;
  for (;;) {
    if (Date.now() > deadline.getTime()) return { complete: false, checked, legacy };
    const page = await database.execute<StoredEvent>(sql`
      SELECT id::text AS id, event_id::text AS event_id, event_timestamp, client_id_hash, application_id, routing,
        compliance_flags, metrics, hash_algorithm, request_response_hash, previous_event_hash, event_hash,
        signature_algorithm, key_id, signature, status::text AS status, signed_payload
      FROM telemetry_events
      WHERE organization_id = ${organizationId}::uuid AND key_id = ${keyId} AND id > ${cursor}::bigint
      ORDER BY id LIMIT ${PAGE_SIZE}
    `);
    for (const row of page.rows) {
      checked += 1;
      cursor = row.id;
      if (row.signed_payload === null) {
        legacy += 1;
        continue;
      }
      const parsed = telemetryEventSchema.safeParse(row.signed_payload);
      if (!parsed.success) {
        findings.add("PAYLOAD_MISMATCH", keyId, "the stored payload no longer matches the telemetry schema", null, row.event_id);
        continue;
      }
      const mismatch = payloadMismatch(row, parsed.data);
      if (mismatch) {
        findings.add("PAYLOAD_MISMATCH", keyId, mismatch, null, row.event_id);
        continue;
      }
      if (calculateEventHash(parsed.data) !== parsed.data.cryptography.event_hash) {
        findings.add("HASH_MISMATCH", keyId, "the stored payload no longer hashes to its event_hash", null, row.event_id);
        continue;
      }
      if (row.status === "INVALID_SIGNATURE") continue;
      if (!registered) {
        if (!keyMissingReported) findings.add("KEY_MISSING", keyId, "no public key is registered for this key_id");
        keyMissingReported = true;
        continue;
      }
      const signature = verifyTelemetryCryptography(parsed.data, registered.publicKeyPem);
      if (!signature.ok) findings.add("SIGNATURE_INVALID", keyId, signature.reason, null, row.event_id);
    }
    if (page.rows.length < PAGE_SIZE) return { complete: true, checked, legacy };
  }
}

// Re-verifies everything stored for one organization and records the run.
// Stops between pages once deadline has passed; such a run is recorded as
// incomplete.
export async function verifyOrganization(organizationId: string, deadline: Date): Promise<VerificationRun> {
  const startedAt = new Date();
  const findings = new Findings();
  let complete = true;
  let eventsChecked = 0;
  let legacyEvents = 0;

  const checkpoint = await latestAnchoredCheckpoint(organizationId);
  if (checkpoint) verifyCheckpoint(organizationId, checkpoint, findings);
  const keys = await getCrossTenantDatabase().execute<{ key_id: string }>(sql`
    SELECT key_id FROM telemetry_events WHERE organization_id = ${organizationId}::uuid
    UNION SELECT key_id FROM telemetry_tombstones WHERE organization_id = ${organizationId}::uuid
    ORDER BY key_id
  `);
  for (const { key_id: keyId } of keys.rows) {
    const anchoredHeads = new Map(
      (checkpoint?.chain_heads ?? []).filter((head) => head.key_id === keyId).map((head) => [head.sequence, head.event_hash]),
    );
    if (!await verifyChain(organizationId, keyId, anchoredHeads, deadline, findings)) {
      complete = false;
      break;
    }
    const payloads = await verifyPayloads(organizationId, keyId, deadline, findings);
    eventsChecked += payloads.checked;
    legacyEvents += payloads.legacy;
    if (!payloads.complete) {
      complete = false;
      break;
    }
  }

  const run: VerificationRun = {
    startedAt, completedAt: new Date(), complete, eventsChecked, legacyEvents,
    failures: findings.failures, failureSamples: findings.samples,
  };
  await getCrossTenantDatabase().insert(telemetryVerificationRuns).values({ organizationId, ...run });
  return run;
}

// Verifies organizations that hold telemetry, least recently verified
// first, until the time budget is spent; later invocations continue with
// the rest.
export async function verifyStoredTelemetry(budgetMs = DEFAULT_BUDGET_MS) {
  const deadline = new Date(Date.now() + budgetMs);
  const candidates = await getCrossTenantDatabase().execute<{ organization_id: string }>(sql`
    SELECT organization.organization_id FROM (
      SELECT organization_id FROM telemetry_events UNION SELECT organization_id FROM telemetry_tombstones
    ) organization
    LEFT JOIN LATERAL (
      SELECT max(completed_at) AS last_run FROM telemetry_verification_runs run
      WHERE run.organization_id = organization.organization_id
    ) latest ON true
    ORDER BY latest.last_run ASC NULLS FIRST, organization.organization_id
  `);
  const totals = { organizations: 0, eventsChecked: 0, failures: 0, incomplete: 0 };
  for (const { organization_id: organizationId } of candidates.rows) {
    if (Date.now() > deadline.getTime()) break;
    const run = await verifyOrganization(organizationId, deadline);
    totals.organizations += 1;
    totals.eventsChecked += run.eventsChecked;
    totals.failures += run.failures;
    if (!run.complete) totals.incomplete += 1;
  }
  return totals;
}
