import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { dashboardSessionCookie, verifyDashboardSession } from "@/lib/dashboard-session";
import { validateDPOIdentity } from "@/lib/dpo-auth";

export async function requireDashboardOrganizationId() {
  const token = (await cookies()).get(dashboardSessionCookie)?.value;
  const session = verifyDashboardSession(token, process.env.DASHBOARD_SESSION_SECRET ?? "");
  if (!session || !(await validateDPOIdentity(session))) redirect("/login");
  return session.organizationId;
}
