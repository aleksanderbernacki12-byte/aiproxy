import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { getReportVerificationKey } from "@/lib/compliance-report";
import { appendSecurityAuditEvent } from "@/lib/security-audit";

export const runtime = "nodejs";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const identity = await requireDashboardIdentity();
  const { id } = await context.params;
  if (!/^[a-f0-9]{64}$/.test(id)) return Response.json({ error: "Not found" }, { status: 404 });
  const publicKey = await getReportVerificationKey(id, identity.organizationId);
  if (!publicKey) return Response.json({ error: "Not found" }, { status: 404 });
  try {
    await appendSecurityAuditEvent({
      organizationId: identity.organizationId,
      actorId: identity.credentialId,
      action: "REPORT_VERIFICATION_KEY_DOWNLOADED",
      resourceType: "REPORT_SIGNING_KEY",
      resourceId: id,
    });
  } catch (error) {
    console.error("Report verification-key access audit failed", error);
    return Response.json({ error: "Key access could not be recorded" }, { status: 503 });
  }
  return new Response(publicKey, {
    headers: {
      "Content-Type": "application/x-pem-file",
      "Content-Disposition": `attachment; filename="aiproxy-report-key-${id}.pem"`,
      "Cache-Control": "private, no-store",
    },
  });
}
