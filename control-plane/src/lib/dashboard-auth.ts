import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { dashboardOrganizationId } from "@/lib/dashboard";
import { dashboardSessionCookie, verifyDashboardSession } from "@/lib/dashboard-session";

export async function requireDashboardOrganizationId() {
  const configuredOrganizationId = dashboardOrganizationId();
  const token = (await cookies()).get(dashboardSessionCookie)?.value;
  const session = verifyDashboardSession(token, process.env.DASHBOARD_SESSION_SECRET ?? "");
  if (!configuredOrganizationId || session?.organizationId !== configuredOrganizationId) redirect("/login");
  return configuredOrganizationId;
}
