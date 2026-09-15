import { hasBearerToken } from "@/lib/auth";
import { createMerkleCheckpoints } from "@/lib/telemetry/checkpoint";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function GET(request: Request) {
  if (!process.env.CRON_SECRET) return Response.json({ error: "Checkpoint worker is not configured" }, { status: 503 });
  if (!hasBearerToken(request, process.env.CRON_SECRET)) return Response.json({ error: "Unauthorized" }, { status: 401 });
  try {
    return Response.json({ status: "CHECKPOINTED", ...await createMerkleCheckpoints() });
  } catch (error) {
    console.error("Merkle checkpoint worker failed", error);
    return Response.json({ error: "Checkpoint worker failed" }, { status: 500 });
  }
}
