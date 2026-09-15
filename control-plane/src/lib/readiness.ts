import "server-only";

import { createPrivateKey, createPublicKey } from "node:crypto";
import { sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";

export const expectedMigration = "0014_retention_and_legal_hold.sql";

type ReadinessEnvironment = Partial<Record<
  "DASHBOARD_SESSION_SECRET" | "CRON_SECRET" | "REPORT_SIGNING_PRIVATE_KEY" |
  "MERKLE_ANCHOR_URL" | "MERKLE_ANCHOR_TOKEN" | "MERKLE_ANCHOR_PUBLIC_KEY" |
  "TELEMETRY_REORDER_WINDOW_SECONDS" | "NODE_ENV", string
>>;

export function configurationFailures(environment: ReadinessEnvironment = process.env) {
  const failures: string[] = [];
  const sessionSecret = environment.DASHBOARD_SESSION_SECRET ?? "";
  const cronSecret = environment.CRON_SECRET ?? "";
  const anchorToken = environment.MERKLE_ANCHOR_TOKEN ?? "";
  if (sessionSecret.length < 32) failures.push("dashboard_session_secret");
  if (cronSecret.length < 32) failures.push("cron_secret");
  if (anchorToken.length < 32) failures.push("anchor_token");
  if ([sessionSecret, cronSecret, anchorToken].filter(Boolean).some((value, index, values) => values.indexOf(value) !== index)) {
    failures.push("secret_reuse");
  }
  try {
    const url = new URL(environment.MERKLE_ANCHOR_URL ?? "");
    if (environment.NODE_ENV === "production" && url.protocol !== "https:") failures.push("anchor_https");
    if (!["https:", "http:"].includes(url.protocol)) failures.push("anchor_url");
  } catch { failures.push("anchor_url"); }
  try {
    const key = createPublicKey((environment.MERKLE_ANCHOR_PUBLIC_KEY ?? "").replaceAll("\\n", "\n"));
    if (key.asymmetricKeyType !== "ed25519") failures.push("anchor_public_key");
  } catch { failures.push("anchor_public_key"); }
  try {
    const key = createPrivateKey((environment.REPORT_SIGNING_PRIVATE_KEY ?? "").replaceAll("\\n", "\n"));
    if (key.asymmetricKeyType !== "ed25519") failures.push("report_private_key");
  } catch { failures.push("report_private_key"); }
  const reorderWindow = Number(environment.TELEMETRY_REORDER_WINDOW_SECONDS ?? "30");
  if (!Number.isInteger(reorderWindow) || reorderWindow < 1 || reorderWindow > 3600) failures.push("reorder_window");
  return [...new Set(failures)];
}

export async function checkControlPlaneReadiness() {
  if (configurationFailures().length > 0) return false;
  const result = await getDatabase().execute<{ migration_ready: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1 FROM control_plane_migrations WHERE filename = ${expectedMigration}
    ) AS migration_ready
  `);
  return result.rows[0]?.migration_ready === true;
}
