import "server-only";
import { createHash, randomBytes } from "node:crypto";
import { sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import type { AccessCommand } from "./access-command";

export class AccessDeniedError extends Error {}
export class AccessConflictError extends Error {}
type Identity = { organizationId: string; credentialId: string; role: string };

export type AccessCredential = {
  id: string; label: string; role: "ADMIN" | "DPO" | "AUDITOR";
  created_at: string; expires_at: string | null; revoked_at: string | null; expired: boolean;
};

export async function listAccessCredentials(identity: Identity) {
  if (identity.role !== "ADMIN") throw new AccessDeniedError();
  const result = await getDatabase().execute<AccessCredential>(sql`
    SELECT id, label, role, created_at, expires_at, revoked_at,
      coalesce(expires_at <= clock_timestamp(), false) AS expired FROM dpo_access_keys
    WHERE organization_id=${identity.organizationId}::uuid ORDER BY created_at DESC, id DESC
  `);
  return result.rows;
}

export async function changeAccessCredential(identity: Identity, input: AccessCommand) {
  if (identity.role !== "ADMIN") throw new AccessDeniedError();
  if (input.command === "revoke" && input.credential_id.toLowerCase() === identity.credentialId.toLowerCase()) throw new AccessConflictError();
  return getDatabase().transaction(async (tx) => {
    // Serialize portal administrators so two admins cannot revoke each other
    // after both passed session validation. Recheck the actor under a row lock.
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${"access:" + identity.organizationId}, 0))`);
    const actor = await tx.execute(sql`SELECT id FROM dpo_access_keys
      WHERE id=${identity.credentialId}::uuid AND organization_id=${identity.organizationId}::uuid
      AND role='ADMIN' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > clock_timestamp()) FOR UPDATE`);
    if (actor.rows.length !== 1) throw new AccessDeniedError();
    let id: string;
    let key: string | undefined;
    let action: string;
    let metadata: Record<string, unknown> = {};
    if (input.command === "create") {
      key = randomBytes(32).toString("base64url");
      const digest = createHash("sha256").update(key).digest("hex");
      const result = await tx.execute<{ id: string; expires_at: string }>(sql`
        INSERT INTO dpo_access_keys(organization_id, key_hash, label, role, expires_at)
        VALUES (${identity.organizationId}::uuid, ${digest}, ${input.label}, ${input.role},
          clock_timestamp() + (${input.expires_in_days}::integer * interval '1 day')) RETURNING id, expires_at
      `);
      id = result.rows[0].id;
      action = "DPO_CREDENTIAL_CREATED";
      metadata = { label: input.label, role: input.role, expires_at: new Date(result.rows[0].expires_at).toISOString() };
    } else {
      const result = await tx.execute<{ id: string }>(sql`UPDATE dpo_access_keys SET revoked_at=clock_timestamp()
        WHERE id=${input.credential_id}::uuid AND organization_id=${identity.organizationId}::uuid
        AND revoked_at IS NULL RETURNING id`);
      if (result.rows.length !== 1) throw new AccessConflictError();
      id = result.rows[0].id;
      action = "DPO_CREDENTIAL_REVOKED";
    }
    await tx.execute(sql`SELECT append_security_audit_event(
      ${identity.organizationId}::uuid, 'DPO_CREDENTIAL', ${identity.credentialId},
      ${action}, 'DPO_CREDENTIAL', ${id}, ${JSON.stringify(metadata)}::jsonb
    )`);
    return { id, ...(key ? { access_key: key } : {}) };
  });
}
