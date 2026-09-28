import "server-only";

import { createHash } from "node:crypto";
import { and, eq, gt, isNull, or, sql } from "drizzle-orm";
import { getCrossTenantDatabase, withOrganization } from "@/db/client";
import { dpoAccessKeys } from "@/db/schema";

export type DPOIdentity = {
  credentialId: string;
  organizationId: string;
  role: "ADMIN" | "DPO" | "AUDITOR";
  label: string;
  sessionVersion: number;
};

export function hashDPOAccessKey(key: string) {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

export async function authenticateDPOAccessKey(key: string, now = new Date()): Promise<DPOIdentity | null> {
  if (key.length < 32 || /\s/.test(key)) return null;
  // The organization is not known until the key is found.
  const [identity] = await getCrossTenantDatabase()
    .select({
      credentialId: dpoAccessKeys.id, organizationId: dpoAccessKeys.organizationId, role: dpoAccessKeys.role,
      label: dpoAccessKeys.label, sessionVersion: dpoAccessKeys.sessionVersion,
    })
    .from(dpoAccessKeys)
    .where(and(
      eq(dpoAccessKeys.keyHash, hashDPOAccessKey(key)),
      isNull(dpoAccessKeys.revokedAt),
      or(isNull(dpoAccessKeys.expiresAt), gt(dpoAccessKeys.expiresAt, now)),
    ))
    .limit(1);
  return identity ?? null;
}

type SessionIdentity = Pick<DPOIdentity, "credentialId" | "organizationId" | "role" | "sessionVersion">;

export async function validateDPOIdentity(identity: SessionIdentity, now = new Date()) {
  const [active] = await withOrganization(identity.organizationId, (transaction) => transaction
    .select({ id: dpoAccessKeys.id })
    .from(dpoAccessKeys)
    .where(and(
      eq(dpoAccessKeys.id, identity.credentialId),
      eq(dpoAccessKeys.organizationId, identity.organizationId),
      eq(dpoAccessKeys.role, identity.role),
      eq(dpoAccessKeys.sessionVersion, identity.sessionVersion),
      isNull(dpoAccessKeys.revokedAt),
      or(isNull(dpoAccessKeys.expiresAt), gt(dpoAccessKeys.expiresAt, now)),
    ))
    .limit(1));
  return Boolean(active);
}

// Ends every dashboard session of the identity's access key by moving its
// session version on; sessions carrying an older version stop validating.
export async function endDPOSessions(identity: SessionIdentity) {
  await withOrganization(identity.organizationId, async (transaction) => {
    const ended = await transaction.update(dpoAccessKeys)
      .set({ sessionVersion: sql`${dpoAccessKeys.sessionVersion} + 1` })
      .where(and(
        eq(dpoAccessKeys.id, identity.credentialId),
        eq(dpoAccessKeys.organizationId, identity.organizationId),
        eq(dpoAccessKeys.sessionVersion, identity.sessionVersion),
      ))
      .returning({ id: dpoAccessKeys.id });
    if (ended.length === 0) return;
    await transaction.execute(sql`SELECT append_security_audit_event(
      ${identity.organizationId}::uuid, 'DPO_CREDENTIAL', ${identity.credentialId},
      'DASHBOARD_SESSION_ENDED', 'DASHBOARD_SESSION', ${identity.credentialId}, '{}'::jsonb
    )`);
  });
}
