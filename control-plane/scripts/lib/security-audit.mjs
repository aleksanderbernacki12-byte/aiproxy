import process from "node:process";

export async function appendSecurityAudit(client, {
  organizationId, action, resourceType, resourceId, metadata = {}, actorType = "CLI",
}) {
  await client.query(
    `SELECT append_security_audit_event($1,$2,$3,$4,$5,$6,$7::jsonb)`,
    [organizationId, actorType, process.env.AIPROXY_OPERATOR_ID ?? "local-cli", action,
      resourceType, String(resourceId), JSON.stringify(metadata)],
  );
}
