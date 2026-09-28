import { NextResponse } from "next/server";
import { dashboardSessionCookie, verifyDashboardSession } from "@/lib/dashboard-session";
import { endDPOSessions, validateDPOIdentity } from "@/lib/dpo-auth";
import { hasSameOrigin } from "@/lib/auth";

export async function POST(request: Request) {
  if (!hasSameOrigin(request)) return Response.json({ error: "Forbidden" }, { status: 403 });
  const token = request.headers.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${dashboardSessionCookie}=`))?.slice(dashboardSessionCookie.length + 1);
  const session = verifyDashboardSession(token, process.env.DASHBOARD_SESSION_SECRET ?? "");
  if (session) {
    try {
      if (await validateDPOIdentity(session)) await endDPOSessions(session);
    } catch (error) {
      console.error("Dashboard session could not be ended on the server", error);
      return Response.json({ error: "Logout could not be completed" }, { status: 503 });
    }
  }
  const response = NextResponse.redirect(new URL("/login", request.url), 303);
  response.cookies.set(dashboardSessionCookie, "", { httpOnly: true, path: "/", maxAge: 0, sameSite: "strict" });
  return response;
}
