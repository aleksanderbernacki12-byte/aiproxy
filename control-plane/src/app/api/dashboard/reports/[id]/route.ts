import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { getSealedReport } from "@/lib/compliance-report";

export const runtime = "nodejs";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const identity = await requireDashboardIdentity();
  const { id } = await context.params;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    return Response.json({ error: "Not found" }, { status: 404 });
  }
  const report = await getSealedReport(id, identity.organizationId);
  if (!report) return Response.json({ error: "Not found" }, { status: 404 });
  return Response.json(report, {
    headers: {
      "Cache-Control": "private, no-store",
      "Content-Disposition": `attachment; filename="aiproxy-compliance-${report.report_id}.json"`,
    },
  });
}
