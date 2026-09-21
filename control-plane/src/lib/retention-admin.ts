import "server-only";
import { sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import type { RetentionCommand } from "./retention-command";

export class RetentionConflictError extends Error {}

export async function updateRetentionPolicy(identity: { organizationId: string; credentialId: string }, input: RetentionCommand) {
  return getDatabase().transaction(async (tx) => {
    const organizationId = identity.organizationId;
    let action: string;
    let metadata: Record<string, unknown>;
    if (input.command === "set") {
      await tx.execute(sql`INSERT INTO organization_retention_policies (organization_id, telemetry_retention_days)
        VALUES (${organizationId}::uuid, ${input.days}) ON CONFLICT (organization_id) DO UPDATE
        SET telemetry_retention_days=EXCLUDED.telemetry_retention_days, updated_at=now()`);
      action = "RETENTION_POLICY_UPDATED";
      metadata = { telemetry_retention_days: input.days };
    } else {
      const result = input.command === "hold"
        ? await tx.execute(sql`UPDATE organization_retention_policies SET legal_hold=true,
            legal_hold_reason=${input.reason}, legal_hold_set_at=now(), updated_at=now()
            WHERE organization_id=${organizationId}::uuid RETURNING organization_id`)
        : await tx.execute(sql`UPDATE organization_retention_policies SET legal_hold=false,
            legal_hold_reason=NULL, legal_hold_set_at=NULL, updated_at=now()
            WHERE organization_id=${organizationId}::uuid AND legal_hold=true RETURNING organization_id`);
      if (result.rows.length !== 1) throw new RetentionConflictError();
      action = input.command === "hold" ? "LEGAL_HOLD_ENABLED" : "LEGAL_HOLD_RELEASED";
      metadata = { reason: input.reason };
    }
    await tx.execute(sql`SELECT append_security_audit_event(
      ${organizationId}::uuid, 'DPO_CREDENTIAL', ${identity.credentialId},
      ${action}, 'RETENTION_POLICY', ${organizationId}, ${JSON.stringify(metadata)}::jsonb
    )`);
  });
}
