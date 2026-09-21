import "server-only";

import { eq, sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { organizationRetentionPolicies } from "@/db/schema";

const BATCH_SIZE = 500;

async function purgeOrganization(organizationId: string, now: Date) {
  return getDatabase().transaction(async (transaction) => {
    await transaction.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${"retention:" + organizationId}, 0))`);
    // Read the current policy under a row lock. Policy updates (including CLI
    // legal holds) must finish before this read or wait until this purge commits.
    const [policy] = await transaction.select().from(organizationRetentionPolicies)
      .where(eq(organizationRetentionPolicies.organizationId, organizationId)).for("update");
    if (!policy) return { held: 0, purged: 0 };
    if (policy.legalHold) return { held: 1, purged: 0 };
    const retentionDays = policy.telemetryRetentionDays;
    const result = await transaction.execute<{ purged: number }>(sql`
      WITH candidates AS (
        SELECT event.id
        FROM telemetry_events event
        WHERE event.organization_id = ${organizationId}::uuid
          AND event.status = 'VERIFIED'
          AND event.chain_sequence IS NOT NULL
          AND event.event_timestamp < ${now}::timestamptz - (${retentionDays}::integer * interval '1 day')
          AND EXISTS (
            SELECT 1 FROM telemetry_merkle_checkpoints checkpoint,
              jsonb_array_elements(checkpoint.chain_heads) head
            WHERE checkpoint.organization_id = event.organization_id
              AND checkpoint.anchor_status = 'ANCHORED'
              AND head->>'key_id' = event.key_id
              AND (head->>'sequence')::bigint >= event.chain_sequence
          )
        ORDER BY event.event_timestamp, event.id
        LIMIT ${BATCH_SIZE}
        FOR UPDATE OF event SKIP LOCKED
      ), archived AS (
        INSERT INTO telemetry_tombstones (
          organization_id, event_id, event_timestamp, event_hash,
          previous_event_hash, key_id, chain_sequence, purged_at, retention_days
        )
        SELECT event.organization_id, event.event_id, event.event_timestamp,
          event.event_hash, event.previous_event_hash, event.key_id,
          event.chain_sequence, ${now}, ${retentionDays}
        FROM telemetry_events event JOIN candidates ON candidates.id = event.id
        ON CONFLICT DO NOTHING
      ), deleted AS (
        DELETE FROM telemetry_events event USING candidates
        WHERE event.id = candidates.id RETURNING event.event_id
      )
      SELECT count(*)::integer AS purged FROM deleted
    `);
    const purged = result.rows[0]?.purged ?? 0;
    if (purged > 0) await transaction.execute(sql`SELECT append_security_audit_event(
      ${organizationId}::uuid, 'SYSTEM', 'retention-worker',
      'TELEMETRY_RETENTION_EXECUTED', 'TELEMETRY_BATCH', ${now.toISOString()},
      ${JSON.stringify({ purged, retention_days: retentionDays })}::jsonb
    )`);
    return { held: 0, purged };
  });
}

export async function enforceRetentionPolicies(now = new Date()) {
  const policies = await getDatabase().select({ organizationId: organizationRetentionPolicies.organizationId }).from(organizationRetentionPolicies);
  let purged = 0;
  let held = 0;
  for (const policy of policies) {
    const result = await purgeOrganization(policy.organizationId, now);
    held += result.held;
    purged += result.purged;
  }
  return { organizations: policies.length, held, purged };
}

export async function getRetentionPolicy(organizationId: string) {
  const [policy] = await getDatabase().select().from(organizationRetentionPolicies)
    .where(eq(organizationRetentionPolicies.organizationId, organizationId)).limit(1);
  return policy ?? null;
}
