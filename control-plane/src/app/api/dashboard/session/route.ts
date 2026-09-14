import { NextResponse } from "next/server";
import { accessKeyMatches, createDashboardSession, dashboardSessionCookie, dashboardSessionMaxAge } from "@/lib/dashboard-session";
import { dashboardOrganizationId } from "@/lib/dashboard";

export async function POST(request: Request) {
  const form = await request.formData();
  const accessKey = form.get("access_key");
  const organizationId = dashboardOrganizationId();
  const sessionSecret = process.env.DASHBOARD_SESSION_SECRET ?? "";
  if (typeof accessKey !== "string" || !organizationId || sessionSecret.length < 32 || !accessKeyMatches(accessKey, process.env.DASHBOARD_ACCESS_KEY)) {
    return NextResponse.redirect(new URL("/login?error=invalid", request.url), 303);
  }
  const response = NextResponse.redirect(new URL("/dashboard", request.url), 303);
  response.cookies.set(dashboardSessionCookie, createDashboardSession(organizationId, sessionSecret), {
    httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: dashboardSessionMaxAge,
  });
  return response;
}
