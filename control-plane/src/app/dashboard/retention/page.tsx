import Link from "next/link";
import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { getRetentionPolicy } from "@/lib/retention";
import { RetentionForm } from "@/components/retention-form";

export default async function RetentionPage() {
  const identity = await requireDashboardIdentity();
  const policy = await getRetentionPolicy(identity.organizationId);
  const canEdit = ["DPO", "ADMIN"].includes(identity.role);
  return <div className="space-y-7 p-5 sm:p-8">
    <Link href="/dashboard" className="text-sm text-government underline">Till AI-inventeringen</Link>
    <header><h1 className="font-serif text-3xl">Lagring och bevarandestopp</h1><p className="mt-2 text-sm text-muted">Hantera organisationens gallring av telemetri. Endast verifierade händelser som omfattas av extern förankring kan gallras. Revisionsbevis och rapporter bevaras.</p></header>
    <section aria-label="Aktuell gallringspolicy" className="space-y-3 rounded-sm border border-line bg-panel p-5">
      <p>{policy ? `Lagringstid: ${policy.telemetryRetentionDays} dagar` : "Ingen policy är konfigurerad. Automatisk gallring är avstängd."}</p>
      <p>Bevarandestopp: {policy?.legalHold ? "Aktivt" : "Inaktivt"}</p>
      {policy?.legalHold && <p className="break-words text-sm">Skäl: {policy.legalHoldReason}</p>}
    </section>
    <section className="rounded-sm border border-line bg-panel p-5">
      {canEdit ? <RetentionForm days={policy?.telemetryRetentionDays ?? null} held={policy?.legalHold ?? false} /> : <p className="text-sm text-muted">Du har läsbehörighet. En DPO eller administratör kan ändra policyn.</p>}
    </section>
  </div>;
}
