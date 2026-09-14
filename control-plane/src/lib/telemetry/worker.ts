import { and, asc, eq, sql } from "drizzle-orm";
import {
  telemetryBuffer,
  telemetryChainHeads,
  telemetryEvents,
  telemetryPublicKeys,
} from "@/db/schema";
import { getDatabase } from "@/db/client";
import { telemetryEventSchema, type TelemetryEvent } from "./schema";
import { verifyTelemetryCryptography } from "./cryptography";
import { findExtendingEventIndex } from "./ordering";

const DEFAULT_REORDER_WINDOW_SECONDS = 30;
const MAX_EVENTS_PER_CHAIN = 500;

type BufferedRow = typeof telemetryBuffer.$inferSelect;
type VerificationStatus = "VERIFIED" | "INVALID_SIGNATURE" | "COMPROMISED_CHAIN";

function reorderWindowMilliseconds() {
  const configured = Number(process.env.TELEMETRY_REORDER_WINDOW_SECONDS);
  const seconds =
    Number.isFinite(configured) && configured >= 0
      ? configured
      : DEFAULT_REORDER_WINDOW_SECONDS;
  return seconds * 1_000;
}

function mainTableValues(
  row: BufferedRow,
  payload: TelemetryEvent,
  status: VerificationStatus,
  statusReason: string | null,
  chainSequence: bigint | null,
) {
  return {
    eventId: payload.event_id,
    eventTimestamp: new Date(payload.timestamp),
    clientIdHash: payload.client_id_hash,
    applicationId: payload.application_id,
    routing: payload.routing,
    complianceFlags: payload.compliance_flags,
    metrics: payload.metrics,
    hashAlgorithm: payload.cryptography.hash_algorithm,
    requestResponseHash: payload.cryptography.request_response_hash,
    previousEventHash: payload.cryptography.previous_event_hash,
    eventHash: payload.cryptography.event_hash,
    signatureAlgorithm: payload.cryptography.signature_algorithm,
    keyId: payload.cryptography.key_id,
    signature: payload.cryptography.signature,
    status,
    statusReason,
    chainSequence,
    receivedAt: row.receivedAt,
  };
}

async function processKeyChain(keyId: string, now: Date) {
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    await transaction.execute(
      sql`SELECT pg_advisory_xact_lock(hashtextextended(${keyId}, 0))`,
    );
    const rows = await transaction
      .select()
      .from(telemetryBuffer)
      .where(eq(telemetryBuffer.keyId, keyId))
      .orderBy(
        asc(telemetryBuffer.eventTimestamp),
        asc(telemetryBuffer.receivedAt),
        asc(telemetryBuffer.id),
      )
      .limit(MAX_EVENTS_PER_CHAIN);
    if (rows.length === 0) {
      return { verified: 0, compromised: 0, invalid: 0, deferred: 0 };
    }

    const [registeredKey] = await transaction
      .select()
      .from(telemetryPublicKeys)
      .where(eq(telemetryPublicKeys.keyId, keyId))
      .limit(1);
    if (!registeredKey) {
      await transaction
        .update(telemetryBuffer)
        .set({
          processingAttempts: sql`${telemetryBuffer.processingAttempts} + 1`,
          lastError: "No public key is registered for key_id",
        })
        .where(eq(telemetryBuffer.keyId, keyId));
      return { verified: 0, compromised: 0, invalid: 0, deferred: rows.length };
    }

    const [storedHead] = await transaction
      .select()
      .from(telemetryChainHeads)
      .where(eq(telemetryChainHeads.keyId, keyId))
      .limit(1);
    let latestEventHash = storedHead?.latestEventHash ?? "";
    let sequence = storedHead?.sequence ?? 0n;
    let lastEventTimestamp = storedHead?.lastEventTimestamp;
    const remaining = [...rows];
    const result = { verified: 0, compromised: 0, invalid: 0, deferred: 0 };
    const cutoff = now.getTime() - reorderWindowMilliseconds();

    while (remaining.length > 0) {
      let rowIndex = findExtendingEventIndex(remaining, latestEventHash);
      let chainBroken = false;
      if (rowIndex < 0) {
        if (remaining[0].receivedAt.getTime() > cutoff) {
          result.deferred += remaining.length;
          break;
        }
        rowIndex = 0;
        chainBroken = true;
      }
      const [row] = remaining.splice(rowIndex, 1);
      const parsed = telemetryEventSchema.safeParse(row.payload);
      if (!parsed.success) {
        await transaction
          .update(telemetryBuffer)
          .set({
            processingAttempts: sql`${telemetryBuffer.processingAttempts} + 1`,
            lastError: "Buffered payload failed schema revalidation",
          })
          .where(eq(telemetryBuffer.id, row.id));
        result.deferred += 1;
        continue;
      }
      const payload = parsed.data;
      const verification = registeredKey.revokedAt
        ? { ok: false as const, reason: "The registered public key is revoked" }
        : verifyTelemetryCryptography(payload, registeredKey.publicKeyPem);

      let status: VerificationStatus;
      let reason: string | null;
      let eventSequence: bigint | null = null;
      if (!verification.ok) {
        status = "INVALID_SIGNATURE";
        reason = verification.reason;
        result.invalid += 1;
      } else if (chainBroken) {
        status = "COMPROMISED_CHAIN";
        reason = `previous_event_hash ${payload.cryptography.previous_event_hash || "<genesis>"} does not match chain head ${latestEventHash || "<genesis>"}`;
        result.compromised += 1;
      } else {
        status = "VERIFIED";
        reason = null;
        sequence += 1n;
        eventSequence = sequence;
        latestEventHash = payload.cryptography.event_hash;
        lastEventTimestamp = new Date(payload.timestamp);
        result.verified += 1;
      }

      await transaction.insert(telemetryEvents).values(
        mainTableValues(row, payload, status, reason, eventSequence),
      );
      await transaction
        .delete(telemetryBuffer)
        .where(and(eq(telemetryBuffer.id, row.id), eq(telemetryBuffer.eventId, row.eventId)));
    }

    if (result.verified > 0 && lastEventTimestamp) {
      await transaction
        .insert(telemetryChainHeads)
        .values({
          keyId,
          latestEventHash,
          sequence,
          lastEventTimestamp,
          updatedAt: now,
        })
        .onConflictDoUpdate({
          target: telemetryChainHeads.keyId,
          set: {
            latestEventHash,
            sequence,
            lastEventTimestamp,
            updatedAt: now,
          },
        });
    }
    return result;
  });
}

export async function processBufferedTelemetry(now = new Date()) {
  const database = getDatabase();
  const chains = await database
    .selectDistinct({ keyId: telemetryBuffer.keyId })
    .from(telemetryBuffer);
  const totals = { verified: 0, compromised: 0, invalid: 0, deferred: 0 };
  for (const { keyId } of chains) {
    const result = await processKeyChain(keyId, now);
    totals.verified += result.verified;
    totals.compromised += result.compromised;
    totals.invalid += result.invalid;
    totals.deferred += result.deferred;
  }
  return { chains: chains.length, ...totals };
}
