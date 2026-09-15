import "server-only";

import { desc, eq, sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { securityAuditEvents } from "@/db/schema";

export async function getSecurityAuditLedger(organizationId: string) {
  const database = getDatabase();
  const [verification, events] = await Promise.all([
    database.execute<{ valid: boolean }>(sql`SELECT verify_security_audit_chain(${organizationId}::uuid) AS valid`),
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
  return { valid: verification.rows[0]?.valid === true, events };
}
