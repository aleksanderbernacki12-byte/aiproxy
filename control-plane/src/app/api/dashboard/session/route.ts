import { NextResponse } from "next/server";
import { createDashboardSession, dashboardSessionCookie, dashboardSessionMaxAge } from "@/lib/dashboard-session";
import { authenticateDPOAccessKey } from "@/lib/dpo-auth";
import { appendSecurityAuditEvent } from "@/lib/security-audit";
import { hasSameOrigin } from "@/lib/auth";
import { readBoundedTextBody, RequestBodyTooLargeError } from "@/lib/request-body";
import { clearLoginFailures, getLoginThrottle, hashLoginSource, recordLoginFailure } from "@/lib/login-throttle";

const MAX_LOGIN_BODY_BYTES = 4096;

export async function POST(request: Request) {
  if (!hasSameOrigin(request)) return Response.json({ error: "Forbidden" }, { status: 403 });
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/x-www-form-urlencoded") {
    return Response.json({ error: "Unsupported media type" }, { status: 415 });
  }
  const sessionSecret = process.env.DASHBOARD_SESSION_SECRET ?? "";
  if (sessionSecret.length < 32) return Response.json({ error: "Dashboard sessions are not configured" }, { status: 503 });
  const sourceHash = hashLoginSource(request, sessionSecret);
  try {
    const throttle = await getLoginThrottle(sourceHash);
    if (!throttle.allowed) {
      return Response.json({ error: "Too many login attempts" }, {
        status: 429, headers: { "Retry-After": String(throttle.retryAfterSeconds) },
      });
    }
  } catch (error) {
    console.error("DPO login throttling failed", error);
    return Response.json({ error: "Authentication service unavailable" }, { status: 503 });
  }
  let form: URLSearchParams;
  try {
    form = new URLSearchParams(await readBoundedTextBody(request, MAX_LOGIN_BODY_BYTES));
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return Response.json({ error: "Payload too large" }, { status: 413 });
    return Response.json({ error: "Invalid request body" }, { status: 400 });
  }
  const accessKeys = form.getAll("access_key");
  const accessKey = accessKeys.length === 1 ? accessKeys[0] : null;
  let identity;
  try {
    identity = typeof accessKey === "string" ? await authenticateDPOAccessKey(accessKey) : null;
  } catch (error) {
    console.error("DPO authentication failed", error);
    return Response.json({ error: "Authentication service unavailable" }, { status: 503 });
  }
  if (!identity) {
    try {
      await recordLoginFailure(sourceHash);
    } catch (error) {
      console.error("DPO login failure could not be recorded", error);
      return Response.json({ error: "Authentication service unavailable" }, { status: 503 });
    }
    return NextResponse.redirect(new URL("/login?error=invalid", request.url), 303);
  }
  try {
    await clearLoginFailures(sourceHash);
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
