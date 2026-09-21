import process from "node:process";
import pg from "pg";
import { appendSecurityAudit } from "./lib/security-audit.mjs";

const [, , command, organizationId, value] = process.argv;
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
if (!organizationId || !["set", "hold", "release"].includes(command)) {
  throw new Error("Usage: npm run retention -- <set|hold|release> <organization-id> <days|reason>");
}
if (!value?.trim()) throw new Error(`${command} requires a value`);
const days = command === "set" ? Number(value) : null;
if (command === "set" && (!Number.isInteger(days) || days < 30 || days > 3650)) {
  throw new Error("retention days must be an integer between 30 and 3650");
}
if (command !== "set" && value.length > 500) throw new Error("legal-hold reason must contain at most 500 characters");

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  await client.query("BEGIN");
  if (command === "set") {
    await client.query(
      `INSERT INTO organization_retention_policies (organization_id, telemetry_retention_days)
       VALUES ($1,$2) ON CONFLICT (organization_id) DO UPDATE
       SET telemetry_retention_days=EXCLUDED.telemetry_retention_days, updated_at=now()`,
      [organizationId, days],
    );
    await appendSecurityAudit(client, { organizationId, action: "RETENTION_POLICY_UPDATED", resourceType: "RETENTION_POLICY", resourceId: organizationId, metadata: { telemetry_retention_days: days } });
  } else if (command === "hold") {
    const result = await client.query(
      `UPDATE organization_retention_policies SET legal_hold=true, legal_hold_reason=$2,
       legal_hold_set_at=now(), updated_at=now() WHERE organization_id=$1`,
      [organizationId, value.trim()],
    );
    if (result.rowCount !== 1) throw new Error("Configure a retention policy before enabling legal hold");
    await appendSecurityAudit(client, { organizationId, action: "LEGAL_HOLD_ENABLED", resourceType: "RETENTION_POLICY", resourceId: organizationId, metadata: { reason: value.trim() } });
  } else {
    const result = await client.query(
      `UPDATE organization_retention_policies SET legal_hold=false, legal_hold_reason=NULL,
       legal_hold_set_at=NULL, updated_at=now() WHERE organization_id=$1 AND legal_hold=true`,
      [organizationId],
    );
    if (result.rowCount !== 1) throw new Error("No active legal hold exists for the organization");
    await appendSecurityAudit(client, { organizationId, action: "LEGAL_HOLD_RELEASED", resourceType: "RETENTION_POLICY", resourceId: organizationId, metadata: { reason: value.trim() } });
  }
  await client.query("COMMIT");
  console.log(`Retention command ${command} completed for ${organizationId}`);
} catch (error) {
  await client.query("ROLLBACK").catch(() => undefined);
  throw error;
} finally { await client.end(); }
