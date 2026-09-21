import { hasBearerToken } from "@/lib/auth";
import { anchorPendingCheckpoints } from "@/lib/telemetry/anchor";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function GET(request: Request) {
  if (!process.env.CRON_SECRET) return Response.json({ error: "Anchor worker is not configured" }, { status: 503 });
  if (!hasBearerToken(request, process.env.CRON_SECRET)) return Response.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const result = await anchorPendingCheckpoints();
    if (!result.configured) return Response.json({ error: "External anchor is not configured" }, { status: 503 });
    return Response.json({ status: "ANCHORED", ...result });
  } catch (error) {
    console.error("External anchor worker failed", error);
    return Response.json({ error: "External anchor worker failed" }, { status: 500 });
  }
}
