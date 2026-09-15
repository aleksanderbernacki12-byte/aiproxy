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
};

export async function getSecurityAuditEvidence(organizationId: string): Promise<SecurityAuditEvidence> {
  const result = await getDatabase().execute<{
    valid: boolean;
    event_count: number;
    latest_sequence: string;
    latest_event_hash: string;
    latest_event_at: Date | null;
  }>(sql`
    SELECT verify_security_audit_chain(${organizationId}::uuid) AS valid,
      count(*)::integer AS event_count,
      coalesce(max(sequence), 0)::text AS latest_sequence,
      coalesce((array_agg(event_hash ORDER BY sequence DESC))[1], '') AS latest_event_hash,
      max(occurred_at) AS latest_event_at
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
