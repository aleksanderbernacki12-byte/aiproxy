import { hasBearerToken } from "@/lib/auth";
import { verifyStoredTelemetry } from "@/lib/telemetry/verification";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function GET(request: Request) {
  if (!process.env.CRON_SECRET) return Response.json({ error: "Verification worker is not configured" }, { status: 503 });
  if (!hasBearerToken(request, process.env.CRON_SECRET)) return Response.json({ error: "Unauthorized" }, { status: 401 });
  try {
    return Response.json({ status: "VERIFIED_STORED_TELEMETRY", ...await verifyStoredTelemetry() });
  } catch (error) {
    console.error("Telemetry re-verification failed", error);
    return Response.json({ error: "Telemetry re-verification failed" }, { status: 500 });
  }
}
