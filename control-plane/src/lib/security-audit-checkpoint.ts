import "server-only";

import { createHash } from "node:crypto";
import { sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { securityAuditHeads } from "@/db/schema";

const AUDIT_ANCHOR_DOMAIN = Buffer.from("aiproxy-security-audit-anchor-v1\0");

export function calculateSecurityAuditAnchorRoot(organizationId: string, sequence: string, eventHash: string) {
  if (!/^[1-9][0-9]*$/.test(sequence) || !/^[a-f0-9]{64}$/.test(eventHash)) {
    throw new Error("Security audit head is invalid");
  }
  return createHash("sha256").update(AUDIT_ANCHOR_DOMAIN)
    .update(organizationId, "utf8").update(eventHash, "hex").update(sequence, "utf8").digest("hex");
}

async function checkpointOrganization(organizationId: string) {
  return getDatabase().transaction(async (transaction) => {
    await transaction.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${"security-audit:" + organizationId}, 0))`);
    const verification = await transaction.execute<{ valid: boolean }>(sql`
      SELECT verify_security_audit_chain(${organizationId}::uuid) AS valid
    `);
    if (verification.rows[0]?.valid !== true) return "invalid" as const;
    const head = await transaction.execute<{ sequence: string; latest_event_hash: string }>(sql`
      SELECT sequence::text, latest_event_hash FROM security_audit_heads
      WHERE organization_id = ${organizationId}::uuid
    `);
    const current = head.rows[0];
    if (!current) return "unchanged" as const;
    const rootHash = calculateSecurityAuditAnchorRoot(organizationId, current.sequence, current.latest_event_hash);
    const inserted = await transaction.execute(sql`
      INSERT INTO security_audit_checkpoints (organization_id, sequence, event_hash, root_hash)
      VALUES (${organizationId}::uuid, ${current.sequence}::bigint, ${current.latest_event_hash}, ${rootHash})
      ON CONFLICT DO NOTHING RETURNING id
    `);
    return inserted.rowCount === 1 ? "created" as const : "unchanged" as const;
  });
}

export async function createSecurityAuditCheckpoints() {
  const organizations = await getDatabase().select({ organizationId: securityAuditHeads.organizationId }).from(securityAuditHeads);
  let created = 0;
  let invalid = 0;
  for (const { organizationId } of organizations) {
    const result = await checkpointOrganization(organizationId);
    if (result === "created") created += 1;
    if (result === "invalid") invalid += 1;
  }
  return { organizations: organizations.length, created, invalid };
}
