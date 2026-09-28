import "server-only";

import { createHash } from "node:crypto";
import { and, eq, gt, isNull, or } from "drizzle-orm";
import { getCrossTenantDatabase, withOrganization } from "@/db/client";
import { dpoAccessKeys } from "@/db/schema";

export type DPOIdentity = {
  credentialId: string;
  organizationId: string;
  role: "ADMIN" | "DPO" | "AUDITOR";
  label: string;
};

export function hashDPOAccessKey(key: string) {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

export async function authenticateDPOAccessKey(key: string, now = new Date()): Promise<DPOIdentity | null> {
  if (key.length < 32 || /\s/.test(key)) return null;
  // The organization is not known until the key is found.
  const [identity] = await getCrossTenantDatabase()
    .select({ credentialId: dpoAccessKeys.id, organizationId: dpoAccessKeys.organizationId, role: dpoAccessKeys.role, label: dpoAccessKeys.label })
    .from(dpoAccessKeys)
    .where(and(
      eq(dpoAccessKeys.keyHash, hashDPOAccessKey(key)),
      isNull(dpoAccessKeys.revokedAt),
      or(isNull(dpoAccessKeys.expiresAt), gt(dpoAccessKeys.expiresAt, now)),
    ))
    .limit(1);
  return identity ?? null;
}

export async function validateDPOIdentity(identity: Pick<DPOIdentity, "credentialId" | "organizationId" | "role">, now = new Date()) {
  const [active] = await withOrganization(identity.organizationId, (transaction) => transaction
    .select({ id: dpoAccessKeys.id })
    .from(dpoAccessKeys)
    .where(and(
      eq(dpoAccessKeys.id, identity.credentialId),
      eq(dpoAccessKeys.organizationId, identity.organizationId),
      eq(dpoAccessKeys.role, identity.role),
      isNull(dpoAccessKeys.revokedAt),
      or(isNull(dpoAccessKeys.expiresAt), gt(dpoAccessKeys.expiresAt, now)),
    ))
    .limit(1));
  return Boolean(active);
}
