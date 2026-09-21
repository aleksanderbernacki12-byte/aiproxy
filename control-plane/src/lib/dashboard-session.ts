import "server-only";

import { createHmac, timingSafeEqual } from "node:crypto";
import type { DPOIdentity } from "@/lib/dpo-auth";

export const dashboardSessionCookie = "aiproxy_dpo_session";
const sessionLifetimeSeconds = 8 * 60 * 60;

type Session = Pick<DPOIdentity, "credentialId" | "organizationId" | "role"> & { expiresAt: number };

function signature(payload: string, secret: string) {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createDashboardSession(identity: Pick<DPOIdentity, "credentialId" | "organizationId" | "role">, secret: string, now = Date.now()) {
  const payload = Buffer.from(
    JSON.stringify({ ...identity, expiresAt: Math.floor(now / 1000) + sessionLifetimeSeconds }),
  ).toString("base64url");
  return `${payload}.${signature(payload, secret)}`;
}

export function verifyDashboardSession(token: string | undefined, secret: string, now = Date.now()): Session | null {
  if (!token || !secret) return null;
  const [payload, supplied, extra] = token.split(".");
  if (!payload || !supplied || extra) return null;
  const expected = signature(payload, secret);
  const suppliedBytes = Buffer.from(supplied);
  const expectedBytes = Buffer.from(expected);
  if (suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Session;
    if (!session.credentialId || !session.organizationId || !["ADMIN", "DPO", "AUDITOR"].includes(session.role) || !Number.isInteger(session.expiresAt) || session.expiresAt <= Math.floor(now / 1000)) return null;
    return session;
  } catch {
    return null;
  }
}

export const dashboardSessionMaxAge = sessionLifetimeSeconds;
