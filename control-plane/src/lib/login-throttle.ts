import "server-only";

import { createHmac } from "node:crypto";
import { sql } from "drizzle-orm";
import { withoutTenant } from "@/db/client";

const WINDOW_MINUTES = 15;
const MAX_FAILURES = 5;

export function trustedProxyHops(value = process.env.TRUSTED_PROXY_HOPS) {
  const hops = Number(value ?? "1");
  return Number.isInteger(hops) && hops >= 1 && hops <= 10 ? hops : 1;
}

// Proxies append to X-Forwarded-For, so everything left of the entries our
// own trusted proxies added is client-controlled. Take the address the
// outermost trusted proxy appended: `hops` positions from the right.
function requestSource(request: Request, hops: number) {
  const forwarded = (request.headers.get("x-forwarded-for") ?? "")
    .split(",").map((entry) => entry.trim()).filter(Boolean);
  const source = forwarded.length > 0
    ? forwarded[Math.max(0, forwarded.length - hops)]
    : request.headers.get("x-real-ip")?.trim() || "unknown";
  return source.slice(0, 256);
}

export function hashLoginSource(request: Request, secret: string, hops = trustedProxyHops()) {
  return createHmac("sha256", secret)
    .update("aiproxy-dashboard-login-source-v1\0")
    .update(requestSource(request, hops), "utf8")
    .digest("hex");
}

export async function getLoginThrottle(sourceHash: string, now = new Date()) {
  const result = await withoutTenant((transaction) => transaction.execute<{ blocked_until: Date | null }>(sql`
    SELECT blocked_until FROM dashboard_login_attempts
    WHERE source_hash = ${sourceHash} AND blocked_until > ${now}
  `));
  const blockedUntil = result.rows[0]?.blocked_until ?? null;
  return {
    allowed: blockedUntil === null,
    retryAfterSeconds: blockedUntil ? Math.max(1, Math.ceil((new Date(blockedUntil).getTime() - now.getTime()) / 1000)) : 0,
  };
}

export async function recordLoginFailure(sourceHash: string, now = new Date()) {
  await withoutTenant((transaction) => transaction.execute(sql`
    WITH cleanup AS (
      DELETE FROM dashboard_login_attempts
      WHERE updated_at < ${now}::timestamptz - interval '24 hours'
    )
    INSERT INTO dashboard_login_attempts (source_hash, window_started_at, failures, blocked_until, updated_at)
    VALUES (${sourceHash}, ${now}, 1, NULL, ${now})
    ON CONFLICT (source_hash) DO UPDATE SET
      window_started_at = CASE
        WHEN dashboard_login_attempts.window_started_at <= ${now}::timestamptz - (${WINDOW_MINUTES}::integer * interval '1 minute') THEN ${now}
        ELSE dashboard_login_attempts.window_started_at END,
      failures = CASE
        WHEN dashboard_login_attempts.window_started_at <= ${now}::timestamptz - (${WINDOW_MINUTES}::integer * interval '1 minute') THEN 1
        ELSE least(dashboard_login_attempts.failures + 1, ${MAX_FAILURES}) END,
      blocked_until = CASE
        WHEN dashboard_login_attempts.window_started_at <= ${now}::timestamptz - (${WINDOW_MINUTES}::integer * interval '1 minute') THEN NULL
        WHEN dashboard_login_attempts.failures + 1 >= ${MAX_FAILURES} THEN ${now}::timestamptz + (${WINDOW_MINUTES}::integer * interval '1 minute')
        ELSE dashboard_login_attempts.blocked_until END,
      updated_at = ${now}
  `));
}

export async function clearLoginFailures(sourceHash: string) {
  await withoutTenant((transaction) => transaction.execute(sql`DELETE FROM dashboard_login_attempts WHERE source_hash = ${sourceHash}`));
}
