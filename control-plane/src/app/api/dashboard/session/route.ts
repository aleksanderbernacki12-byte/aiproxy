import { NextResponse } from "next/server";
import { createDashboardSession, dashboardSessionCookie, dashboardSessionMaxAge } from "@/lib/dashboard-session";
import { authenticateDPOAccessKey } from "@/lib/dpo-auth";
import { appendSecurityAuditEvent } from "@/lib/security-audit";
import { hasSameOrigin } from "@/lib/auth";

export async function POST(request: Request) {
  if (!hasSameOrigin(request)) return Response.json({ error: "Forbidden" }, { status: 403 });
  const form = await request.formData();
  const accessKey = form.get("access_key");
  const sessionSecret = process.env.DASHBOARD_SESSION_SECRET ?? "";
  if (sessionSecret.length < 32) return Response.json({ error: "Dashboard sessions are not configured" }, { status: 503 });
  let identity;
  try {
    identity = typeof accessKey === "string" ? await authenticateDPOAccessKey(accessKey) : null;
  } catch (error) {
    console.error("DPO authentication failed", error);
    return Response.json({ error: "Authentication service unavailable" }, { status: 503 });
  }
  if (!identity) {
    return NextResponse.redirect(new URL("/login?error=invalid", request.url), 303);
  }
  try {
    await appendSecurityAuditEvent({
      organizationId: identity.organizationId,
      actorId: identity.credentialId,
      action: "DASHBOARD_SESSION_CREATED",
      resourceType: "DASHBOARD_SESSION",
      resourceId: identity.credentialId,
      metadata: { role: identity.role },
    });
  } catch (error) {
    console.error("Dashboard session audit failed", error);
    return Response.json({ error: "Authentication service unavailable" }, { status: 503 });
  }
  const response = NextResponse.redirect(new URL("/dashboard", request.url), 303);
  response.cookies.set(dashboardSessionCookie, createDashboardSession(identity, sessionSecret), {
    httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: dashboardSessionMaxAge,
  });
  return response;
}
