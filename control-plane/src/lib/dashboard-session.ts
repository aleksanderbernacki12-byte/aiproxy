import "server-only";

import { createHmac, timingSafeEqual } from "node:crypto";

export const dashboardSessionCookie = "aiproxy_dpo_session";
const sessionLifetimeSeconds = 8 * 60 * 60;

type Session = { organizationId: string; expiresAt: number };

function signature(payload: string, secret: string) {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createDashboardSession(organizationId: string, secret: string, now = Date.now()) {
  const payload = Buffer.from(
    JSON.stringify({ organizationId, expiresAt: Math.floor(now / 1000) + sessionLifetimeSeconds }),
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
    if (!session.organizationId || !Number.isInteger(session.expiresAt) || session.expiresAt <= Math.floor(now / 1000)) return null;
    return session;
  } catch {
    return null;
  }
}

export function accessKeyMatches(supplied: string, expected: string | undefined) {
  if (!expected) return false;
  const suppliedBytes = Buffer.from(supplied);
  const expectedBytes = Buffer.from(expected);
  return suppliedBytes.length === expectedBytes.length && timingSafeEqual(suppliedBytes, expectedBytes);
}

export const dashboardSessionMaxAge = sessionLifetimeSeconds;
