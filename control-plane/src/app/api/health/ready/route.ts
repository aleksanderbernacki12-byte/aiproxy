import { checkControlPlaneReadiness } from "@/lib/readiness";

export const runtime = "nodejs";

export async function GET() {
  try {
    if (!await checkControlPlaneReadiness()) {
      return Response.json({ status: "NOT_READY" }, { status: 503, headers: { "Cache-Control": "no-store" } });
    }
    return Response.json({ status: "READY" }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    console.error("Control Plane readiness check failed", error);
    return Response.json({ status: "NOT_READY" }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
