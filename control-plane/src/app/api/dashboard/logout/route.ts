import { NextResponse } from "next/server";
import { dashboardSessionCookie } from "@/lib/dashboard-session";

export async function POST(request: Request) {
  const response = NextResponse.redirect(new URL("/login", request.url), 303);
  response.cookies.set(dashboardSessionCookie, "", { httpOnly: true, path: "/", maxAge: 0, sameSite: "strict" });
  return response;
}
