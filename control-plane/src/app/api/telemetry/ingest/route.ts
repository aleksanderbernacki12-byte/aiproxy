import { bufferTelemetryEvents } from "@/lib/telemetry/ingest";
import { exceedsJsonDepth, telemetryBatchSchema } from "@/lib/telemetry/schema";
import { authenticateTenant } from "@/lib/tenant-auth";
import { readBoundedTextBody, RequestBodyTooLargeError } from "@/lib/request-body";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 1_048_576;

export async function POST(request: Request) {
  let organization;
  try {
    organization = await authenticateTenant(request);
  } catch (error) {
    console.error("Failed to authenticate telemetry tenant", error);
    return Response.json({ error: "Telemetry authentication unavailable" }, { status: 503 });
  }
  if (!organization) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  let input: unknown;
  try {
    input = JSON.parse(await readBoundedTextBody(request, MAX_BODY_BYTES));
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) {
      return Response.json({ error: "Payload too large" }, { status: 413 });
    }
    return Response.json({ error: "Request body must be valid JSON" }, { status: 400 });
  }
  if (exceedsJsonDepth(input)) {
    return Response.json({ error: "Telemetry payload is nested too deeply" }, { status: 400 });
  }
  const parsed = telemetryBatchSchema.safeParse(input);
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid telemetry payload", issues: parsed.error.issues },
      { status: 400 },
    );
  }

  try {
    const result = await bufferTelemetryEvents(organization.id, parsed.data);
    return Response.json({ status: "BUFFERED", ...result }, { status: 202 });
  } catch (error) {
    console.error("Failed to buffer telemetry", error);
    return Response.json({ error: "Telemetry buffer unavailable" }, { status: 503 });
  }
}
