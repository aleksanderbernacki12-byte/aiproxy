import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { hasSameOrigin } from "@/lib/auth";
import { accessCommandSchema } from "@/lib/access-command";
import { changeAccessCredential, AccessConflictError, AccessDeniedError } from "@/lib/access-admin";
import { readBoundedTextBody, RequestBodyTooLargeError } from "@/lib/request-body";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const identity = await requireDashboardIdentity();
  if (identity.role !== "ADMIN" || !hasSameOrigin(request)) {
    return Response.json({ error: "Du saknar behörighet att administrera åtkomst." }, { status: 403 });
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
  const parsed = accessCommandSchema.safeParse(body);
  if (!parsed.success) return Response.json({ error: "Kontrollera obligatoriska fält och fältens längd." }, { status: 400 });
  try {
    const result = await changeAccessCredential(identity, parsed.data);
    return Response.json(result, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof AccessDeniedError) return Response.json({ error: "Din administratörsåtkomst är inte längre giltig." }, { status: 403 });
    if (error instanceof AccessConflictError) return Response.json({ error: "Nyckeln kan inte återkallas. Din egen nyckel är skyddad; övriga måste tillhöra organisationen och inte redan vara återkallade." }, { status: 409 });
    return Response.json({ error: "Begäran kunde inte sparas. Försök igen." }, { status: 503 });
  }
}
