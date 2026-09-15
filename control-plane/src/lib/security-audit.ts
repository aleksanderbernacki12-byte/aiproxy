import "server-only";

import { desc, eq, sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { securityAuditEvents } from "@/db/schema";

export type SecurityAuditEvidence = {
  status: "INTACT" | "ATTENTION_REQUIRED" | "NO_EVIDENCE";
  eventCount: number;
  latestSequence: string;
  latestEventHash: string;
  latestEventAt: Date | null;
  anchor: { rootHash: string; status: "PENDING" | "ANCHORED"; anchorId: string | null; anchoredAt: Date | null } | null;
};

export async function appendSecurityAuditEvent(input: {
  organizationId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata?: Record<string, unknown>;
}) {
  await getDatabase().execute(sql`SELECT append_security_audit_event(
    ${input.organizationId}::uuid, 'DPO_CREDENTIAL', ${input.actorId},
    ${input.action}, ${input.resourceType}, ${input.resourceId},
    ${JSON.stringify(input.metadata ?? {})}::jsonb
  )`);
}

export async function getSecurityAuditEvidence(organizationId: string): Promise<SecurityAuditEvidence> {
  const result = await getDatabase().execute<{
    valid: boolean;
    event_count: number;
    latest_sequence: string;
    latest_event_hash: string;
    latest_event_at: Date | null;
    anchor_root_hash: string | null;
    anchor_status: "PENDING" | "ANCHORED" | null;
    anchor_id: string | null;
    anchored_at: Date | null;
  }>(sql`
    SELECT verify_security_audit_chain(${organizationId}::uuid) AS valid,
      count(*)::integer AS event_count,
      coalesce(max(sequence), 0)::text AS latest_sequence,
      coalesce((array_agg(event_hash ORDER BY sequence DESC))[1], '') AS latest_event_hash,
      max(occurred_at) AS latest_event_at,
      (SELECT root_hash FROM security_audit_checkpoints WHERE organization_id = ${organizationId}::uuid ORDER BY created_at DESC, id DESC LIMIT 1) AS anchor_root_hash,
      (SELECT anchor_status FROM security_audit_checkpoints WHERE organization_id = ${organizationId}::uuid ORDER BY created_at DESC, id DESC LIMIT 1) AS anchor_status,
      (SELECT anchor_id FROM security_audit_checkpoints WHERE organization_id = ${organizationId}::uuid ORDER BY created_at DESC, id DESC LIMIT 1) AS anchor_id,
      (SELECT anchored_at FROM security_audit_checkpoints WHERE organization_id = ${organizationId}::uuid ORDER BY created_at DESC, id DESC LIMIT 1) AS anchored_at
    FROM security_audit_events
    WHERE organization_id = ${organizationId}::uuid
  `);
  const row = result.rows[0];
  const eventCount = row?.event_count ?? 0;
  return {
    status: eventCount === 0 ? "NO_EVIDENCE" : row?.valid === true ? "INTACT" : "ATTENTION_REQUIRED",
    eventCount,
    latestSequence: row?.latest_sequence ?? "0",
    latestEventHash: row?.latest_event_hash ?? "",
    latestEventAt: row?.latest_event_at ?? null,
    anchor: row?.anchor_root_hash && row.anchor_status ? {
      rootHash: row.anchor_root_hash, status: row.anchor_status,
      anchorId: row.anchor_id, anchoredAt: row.anchored_at,
    } : null,
  };
}

export async function getSecurityAuditLedger(organizationId: string) {
  const database = getDatabase();
  const [evidence, events] = await Promise.all([
    getSecurityAuditEvidence(organizationId),
    database.select({
      eventId: securityAuditEvents.eventId,
      sequence: securityAuditEvents.sequence,
      eventHash: securityAuditEvents.eventHash,
      eventData: securityAuditEvents.eventData,
      occurredAt: securityAuditEvents.occurredAt,
    }).from(securityAuditEvents)
      .where(eq(securityAuditEvents.organizationId, organizationId))
      .orderBy(desc(securityAuditEvents.sequence)).limit(200),
  ]);
  return { valid: evidence.status !== "ATTENTION_REQUIRED", evidence, events };
}
