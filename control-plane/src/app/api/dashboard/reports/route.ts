import { NextResponse } from "next/server";
import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { sealComplianceReport } from "@/lib/compliance-report";
import { hasSameOrigin } from "@/lib/auth";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const identity = await requireDashboardIdentity();
  if (identity.role === "AUDITOR") return Response.json({ error: "Forbidden" }, { status: 403 });
  if (!hasSameOrigin(request)) return Response.json({ error: "Forbidden" }, { status: 403 });
  try {
    const reportId = await sealComplianceReport(identity);
    return NextResponse.redirect(new URL(`/api/dashboard/reports/${reportId}`, request.url), 303);
  } catch (error) {
    console.error("Compliance report sealing failed", error);
    return Response.json({ error: "Compliance report could not be sealed" }, { status: 503 });
  }
}
