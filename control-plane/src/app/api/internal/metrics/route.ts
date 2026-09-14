import { hasBearerToken } from "@/lib/auth";
import { formatControlPlaneMetrics, getControlPlaneMetrics } from "@/lib/operations";

export const runtime = "nodejs";

export async function GET(request: Request) {
  if (!process.env.CRON_SECRET) return Response.json({ error: "Metrics endpoint is not configured" }, { status: 503 });
  if (!hasBearerToken(request, process.env.CRON_SECRET)) return Response.json({ error: "Unauthorized" }, { status: 401 });
  try {
    return new Response(formatControlPlaneMetrics(await getControlPlaneMetrics()), {
      headers: { "Content-Type": "text/plain; version=0.0.4; charset=utf-8", "Cache-Control": "no-store" },
    });
  } catch (error) {
    console.error("Control Plane metrics failed", error);
    return Response.json({ error: "Metrics collection failed" }, { status: 500 });
  }
}
