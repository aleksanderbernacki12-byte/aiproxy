import type { Metadata } from "next";
import { DashboardShell } from "@/components/dashboard-shell";
import { requireDashboardOrganizationId } from "@/lib/dashboard-auth";

export const metadata: Metadata = {
  title: "AI-inventering | Aiproxy Compliance",
  description: "Organisationsscopad AI-inventering och revisionsbevis",
};

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  await requireDashboardOrganizationId();
  return <DashboardShell>{children}</DashboardShell>;
}
