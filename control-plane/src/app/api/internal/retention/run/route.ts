import { hasBearerToken } from "@/lib/auth";
import { enforceRetentionPolicies } from "@/lib/retention";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function GET(request: Request) {
  if (!process.env.CRON_SECRET) return Response.json({ error: "Retention worker is not configured" }, { status: 503 });
  if (!hasBearerToken(request, process.env.CRON_SECRET)) return Response.json({ error: "Unauthorized" }, { status: 401 });
  try {
    return Response.json({ status: "RETENTION_ENFORCED", ...await enforceRetentionPolicies() });
  } catch (error) {
    console.error("Retention worker failed", error);
    return Response.json({ error: "Retention worker failed" }, { status: 500 });
  }
}
