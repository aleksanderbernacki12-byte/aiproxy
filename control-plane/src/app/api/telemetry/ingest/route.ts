import { bufferTelemetryEvents } from "@/lib/telemetry/ingest";
import { telemetryBatchSchema } from "@/lib/telemetry/schema";
import { hasBearerToken } from "@/lib/auth";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 1_048_576;

export async function POST(request: Request) {
  if (!process.env.TELEMETRY_INGEST_TOKEN) {
    return Response.json({ error: "Telemetry ingest is not configured" }, { status: 503 });
  }
  if (!hasBearerToken(request, process.env.TELEMETRY_INGEST_TOKEN)) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return Response.json({ error: "Payload too large" }, { status: 413 });
  }

  let input: unknown;
  try {
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES) {
      return Response.json({ error: "Payload too large" }, { status: 413 });
    }
    input = JSON.parse(body);
  } catch {
    return Response.json({ error: "Request body must be valid JSON" }, { status: 400 });
  }
  const parsed = telemetryBatchSchema.safeParse(input);
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid telemetry payload", issues: parsed.error.issues },
      { status: 400 },
    );
  }

  try {
    const result = await bufferTelemetryEvents(parsed.data);
    return Response.json({ status: "BUFFERED", ...result }, { status: 202 });
  } catch (error) {
    console.error("Failed to buffer telemetry", error);
    return Response.json({ error: "Telemetry buffer unavailable" }, { status: 503 });
  }
}
