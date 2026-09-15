import { NextResponse } from "next/server";
import { dashboardSessionCookie } from "@/lib/dashboard-session";
import { hasSameOrigin } from "@/lib/auth";

export async function POST(request: Request) {
  if (!hasSameOrigin(request)) return Response.json({ error: "Forbidden" }, { status: 403 });
  const response = NextResponse.redirect(new URL("/login", request.url), 303);
  response.cookies.set(dashboardSessionCookie, "", { httpOnly: true, path: "/", maxAge: 0, sameSite: "strict" });
  return response;
}
