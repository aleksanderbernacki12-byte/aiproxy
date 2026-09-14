import { hasBearerToken } from "@/lib/auth";
import { processBufferedTelemetry } from "@/lib/telemetry/worker";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function GET(request: Request) {
  if (!process.env.CRON_SECRET) {
    return Response.json({ error: "Telemetry worker is not configured" }, { status: 503 });
  }
  if (!hasBearerToken(request, process.env.CRON_SECRET)) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  try {
    const result = await processBufferedTelemetry();
    return Response.json({ status: "PROCESSED", ...result });
  } catch (error) {
    console.error("Telemetry worker failed", error);
    return Response.json({ error: "Telemetry worker failed" }, { status: 500 });
  }
}
