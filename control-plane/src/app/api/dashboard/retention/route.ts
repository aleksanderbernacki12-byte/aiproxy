import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { hasSameOrigin } from "@/lib/auth";
import { retentionCommandSchema } from "@/lib/retention-command";
import { updateRetentionPolicy, RetentionConflictError } from "@/lib/retention-admin";
import { readBoundedTextBody, RequestBodyTooLargeError } from "@/lib/request-body";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const identity = await requireDashboardIdentity();
  if (!["DPO", "ADMIN"].includes(identity.role) || !hasSameOrigin(request)) {
    return Response.json({ error: "Du saknar behörighet att ändra gallringspolicyn." }, { status: 403 });
  }
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return Response.json({ error: "Ogiltigt format." }, { status: 415 });
  }
  let body;
  try {
    body = JSON.parse(await readBoundedTextBody(request, 4096));
  } catch (error) {
    return Response.json({ error: "Begäran är för stor eller har ogiltigt format." }, {
      status: error instanceof RequestBodyTooLargeError ? 413 : 400,
    });
  }
  const parsed = retentionCommandSchema.safeParse(body);
  if (!parsed.success) return Response.json({ error: "Kontrollera obligatoriska fält och fältens längd." }, { status: 400 });
  try {
    await updateRetentionPolicy(identity, parsed.data);
    return Response.json({ saved: true });
  } catch (error) {
    if (error instanceof RetentionConflictError) return Response.json({ error: "Konfigurera en policy först. Ett bevarandestopp måste vara aktivt för att kunna hävas." }, { status: 409 });
    return Response.json({ error: "Begäran kunde inte sparas. Försök igen." }, { status: 503 });
  }
}
