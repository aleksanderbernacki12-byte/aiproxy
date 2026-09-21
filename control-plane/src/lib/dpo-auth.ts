import "server-only";

import { createHash } from "node:crypto";
import { and, eq, gt, isNull, or } from "drizzle-orm";
import { getDatabase } from "@/db/client";
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
  const [identity] = await getDatabase()
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
  const [active] = await getDatabase()
    .select({ id: dpoAccessKeys.id })
    .from(dpoAccessKeys)
    .where(and(
      eq(dpoAccessKeys.id, identity.credentialId),
      eq(dpoAccessKeys.organizationId, identity.organizationId),
      eq(dpoAccessKeys.role, identity.role),
      isNull(dpoAccessKeys.revokedAt),
      or(isNull(dpoAccessKeys.expiresAt), gt(dpoAccessKeys.expiresAt, now)),
    ))
    .limit(1);
  return Boolean(active);
}
