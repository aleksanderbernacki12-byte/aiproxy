import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { hasSameOrigin } from "@/lib/auth";
import { aiSystemProfileSchema } from "@/lib/ai-system-profile";
import { saveAISystem } from "@/lib/ai-systems";
import { readBoundedTextBody, RequestBodyTooLargeError } from "@/lib/request-body";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const identity = await requireDashboardIdentity();
  if (!["DPO", "ADMIN"].includes(identity.role) || !hasSameOrigin(request)) {
    return Response.json({ error: "Du saknar behörighet att spara profilen." }, { status: 403 });
  }
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return Response.json({ error: "Ogiltigt format." }, { status: 415 });
  }
  let body;
  try {
    body = JSON.parse(await readBoundedTextBody(request, 64 * 1024));
  } catch (error) {
    return Response.json({ error: "Profilen är för stor eller har ogiltigt format." }, {
      status: error instanceof RequestBodyTooLargeError ? 413 : 400,
    });
  }
  const parsed = aiSystemProfileSchema.safeParse(body);
  if (!parsed.success) return Response.json({ error: "Kontrollera obligatoriska fält och fältens längd." }, { status: 400 });
  try {
    const id = await saveAISystem(identity, parsed.data);
    return Response.json({ id });
  } catch {
    return Response.json({ error: "Profilen kunde inte sparas. Försök igen." }, { status: 503 });
  }
}
